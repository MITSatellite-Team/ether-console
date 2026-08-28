import struct
from dataclasses import dataclass, field

from .config import ARG_RENDERERS, Config, WARNING, render_unknown
from .protocol import Frame, FRAME_NAMES, FRAME_FAST, FRAME_MED, FRAME_SLOW, FRAME_DIAG, FRAME_EVENT, FRAME_ACK, PAYLOAD_FMT, PAYLOAD_LEN

# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------

class TimeUnwrapper:
    _WRAP = 1 << 32

    def __init__(self, tick_s: float) -> None:
        self._tick_s = tick_s
        self._last_timestamps: dict[int, int] = {}
        self._wrap_counts: dict[int, int] = {}

    def unwrap(self, frame_type: int, t_raw: int) -> float:
        last_timestamp = self._last_timestamps.get(frame_type)
        wrap_count = self._wrap_counts.get(frame_type, 0)
        if last_timestamp is not None and t_raw < last_timestamp:
            # Account for jitter
            if last_timestamp - t_raw > self._WRAP // 2:
                wrap_count += 1
                self._wrap_counts[frame_type] = wrap_count
        self._last_timestamps[frame_type] = t_raw
        return (wrap_count * self._WRAP + t_raw) * self._tick_s

# --------------------------------------------------------------------------
# Sample (Decoded output)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Event:
    """
    One entry in the chronological log.

    `source` distinguishes a firmware EVENT frame from an event the console
    derives itself, which are merged into the same log.
    """
    t_s: float
    code: int
    severity: str
    text: str
    args: tuple[int, ...] = ()
    source: str = "payload"

@dataclass(frozen=True)
class Ack:
    t_s: float
    cmd_seq: int
    status: str
    status_label: str
    severity: str
    reason: str
    reason_label: str

@dataclass
class Sample:
    t_s: float
    frame_type: int
    seq: int
    values: dict[str, float] = field(default_factory = dict)
    flags: dict[str, bool] = field(default_factory = dict)
    enums: dict[str, str] = field(default_factory = dict)
    absent: set[str] = field(default_factory = set)
    events: list[Event] = field(default_factory = list)
    acks: list[Ack] = field(default_factory = list)

    @property
    def frame_name(self) -> str:
        return FRAME_NAMES.get(self.frame_type, f"0x{self.frame_type:02X}")

# --------------------------------------------------------------------------
# Decoder
# --------------------------------------------------------------------------

class Decoder:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._time_unwrapper = TimeUnwrapper(cfg.tick_s)

    def decode(self, frame: Frame) -> Sample | None:
        handler = {
            FRAME_FAST: self._fast,
            FRAME_MED: self._med,
            FRAME_SLOW: self._slow,
            FRAME_DIAG: self._diag,
            FRAME_EVENT: self._event,
            FRAME_ACK: self._ack,
        }.get(frame.frame_type)

        if handler is None:
            return None

        sample = Sample(
            t_s = self._time_unwrapper.unwrap(frame.frame_type, frame.t_raw),
            frame_type = frame.frame_type,
            seq = frame.seq,
        )
        handler(frame.payload, sample)
        return sample

    # 0x01
    def _fast(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != PAYLOAD_LEN[FRAME_FAST]:
            raise ValueError(f"FAST payload is {len(payload)} bytes, expected {PAYLOAD_LEN[FRAME_FAST]} bytes")
        keys = ("ACC_X", "ACC_Y", "ACC_Z", "GYR_X", "GYR_Y", "GYR_Z", "MAG_X", "MAG_Y", "MAG_Z", "MOTOR_I", "MOTOR_V")
        values = struct.unpack(PAYLOAD_FMT[FRAME_FAST], payload)
        for key, raw_value in zip(keys, values):
            sample.values[key] = self.cfg.channels[key].to_eng(raw_value)

    # 0x02
    def _med(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != PAYLOAD_LEN[FRAME_MED]:
            raise ValueError(f"MED payload is {len(payload)} bytes, expected {PAYLOAD_LEN[FRAME_MED]} bytes")
        values = struct.unpack(PAYLOAD_FMT[FRAME_MED], payload)
        press_mask, ina_mask = values[0], values[1]

        for channel in self.cfg.pressure:
            if press_mask >> channel.bit & 1:
                sample.values[channel.key] = channel.to_eng(values[2 + channel.bit])
            else:
                sample.absent.add(channel.key)

        for key, rail in self.cfg.rails.items():
            slot = rail["bit"]
            valid = ina_mask >> slot & 1
            raws = values[5 + 3 * slot : 8 + 3 * slot]
            for suffix, raw in zip(("V", "I", "P"), raws):
                channel = self.cfg.channels[f"{key}_{suffix}"]
                if valid:
                    sample.values[channel.key] = channel.to_eng(raw)
                else:
                    sample.absent.add(channel.key)

    # 0x03
    def _slow(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != PAYLOAD_LEN[FRAME_SLOW]:
            raise ValueError(f"SLOW payload is {len(payload)} bytes, expected {PAYLOAD_LEN[FRAME_SLOW]} bytes")
        values = struct.unpack(PAYLOAD_FMT[FRAME_SLOW], payload)
        tc_mask = values[0]

        present: list[float] = []
        for channel in self.cfg.thermocouples:
            if tc_mask >> channel.bit & 1:
                value = channel.to_eng(values[1 + channel.bit])
                sample.values[channel.key] = value
                present.append(value)
            else:
                sample.absent.add(channel.key)

        if len(present) >= 2:
            sample.values["TANK_STRAT_DT"] = max(present) - min(present)
        else:
            sample.absent.add("TANK_STRAT_DT")

    # 0x04
    def _diag(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != PAYLOAD_LEN[FRAME_DIAG]:
            raise ValueError(f"DIAG payload is {len(payload)} bytes, expected {PAYLOAD_LEN[FRAME_DIAG]} bytes")

        (time_in_mode_ms, latch_flags, mcu_temp, mcu_vref,
         cpu_load, heap_free, fsm_state, power_mode,
         motor_fault, status_bits, imu_cfg, rx_crc_errors) = struct.unpack(PAYLOAD_FMT[FRAME_DIAG], payload)

        for key, raw in (("MCU_TEMP", mcu_temp), ("MCU_VREF", mcu_vref), ("MCU_CPU_LOAD", cpu_load), ("MCU_HEAP_FREE", heap_free), ("STATE_TIME_IN_MODE", time_in_mode_ms), ("LINK_RX_CRC_ERRORS", rx_crc_errors)):
            sample.values[key] = self.cfg.channels[key].to_eng(raw)

        sample.enums["FSM_STATE"] = self.cfg.fsm_states.get(fsm_state, render_unknown("FSM", fsm_state))
        sample.enums["POWER_MODE"] = self.cfg.power_modes.get(power_mode, render_unknown("MODE", power_mode))

        for table, word in ((self.cfg.motor_fault_bits, motor_fault),
                            (self.cfg.status_bits, status_bits),
                            (self.cfg.latch_bits, latch_flags)):
            for bit, spec in table.items():
                sample.flags[spec["key"]] = bool(word >> int(bit) & 1)

        self._decode_imu_cfg(imu_cfg, sample)

    def _decode_imu_cfg(self, imu_cfg: int, sample: Sample) -> None:
        """
        Report the FSR the payload says it is actually using, and flag any disagreement with the config.
        """
        mismatch = False
        for sensor in ("accel", "gyro", "mag"):
            spec = self.cfg.imu[sensor]
            lsb, msb = spec["bits"]
            fsr_code = (imu_cfg >> lsb) & ((1 << (msb - lsb + 1)) - 1) # Width is derived, not assumed to be 2.
            fsr = spec["fsr"].get(fsr_code)
            key = f"IMU_{sensor.upper()}_FSR"
            if fsr is None:
                sample.absent.add(key)
                mismatch = True
                continue
            sample.values[key] = float(fsr)
            if fsr_code != spec["expected_fsr_code"]:
                mismatch = True
        sample.flags["IMU_FSR_MISMATCH"] = mismatch

    # 0x05
    def _event(self, payload: bytes, sample: Sample) -> None:
        if len(payload) < 2 or (len(payload) - 2) % 4:
            raise ValueError(f"EVENT payload is {len(payload)} bytes, expected 2 + 4*n_args")
        (code,) = struct.unpack_from("<H", payload, 0)
        n_args = (len(payload) - 2) // 4
        args = list(struct.unpack_from(f"<{n_args}i", payload, 2)) if n_args else []

        spec = self.cfg.events.get(code)
        if spec is None:
            # Firmware is ahead of the ground config. Surfaced as a warning.
            sample.events.append(Event(
                t_s=sample.t_s,
                code=code,
                severity=WARNING,
                text=f"Unknown event 0x{code:04X} {args}",
                args=tuple(args)
            ))
            return

        kinds = spec.get("args", [])
        if len(kinds) != n_args:
            raise ValueError(
                f"EVENT 0x{code:04X} carries {n_args} args, config declares {len(kinds)}")

        rendered = [ARG_RENDERERS[kind](self.cfg, value) for kind, value in zip(kinds, args)]
        try:
            text = spec["text"].format(*rendered)
        except (IndexError, KeyError, ValueError):
            # A template that cannot take its own arguments is a config bug, but
            # losing the event entirely would be worse than losing its wording.
            text = f"{spec['text']} {rendered}"
        sample.events.append(Event(
            t_s=sample.t_s,
            code=code,
            severity=spec.get("severity", "info"),
            text=text,
            args=tuple(args)
        ))

    # 0x06
    def _ack(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != PAYLOAD_LEN[FRAME_ACK]:
            raise ValueError(f"ACK payload is {len(payload)} bytes, expected {PAYLOAD_LEN[FRAME_ACK]} bytes")

        cmd_seq, status, reason = struct.unpack(PAYLOAD_FMT[FRAME_ACK], payload)

        status_spec = self.cfg.ack_status.get(status)
        reason_spec = self.cfg.ack_reasons.get(reason)

        sample.acks.append(Ack(
            t_s=sample.t_s,
            cmd_seq=cmd_seq,
            status=status_spec["key"] if status_spec else render_unknown("STATUS", status),
            status_label=status_spec["label"] if status_spec else f"Unknown status {status}",
            severity=status_spec.get("severity", WARNING) if status_spec else WARNING,
            reason=reason_spec["key"] if reason_spec else render_unknown("REASON", reason, 2),
            reason_label=reason_spec["label"] if reason_spec else f"Unknown reason 0x{reason:02X}"
        ))
