import struct
from dataclasses import dataclass, field

from .config import ARG_RENDERERS, Config, WARNING, render_unknown
from .protocol import Frame, FRAME_NAMES, FRAME_FAST, FRAME_MED, FRAME_SLOW, FRAME_DIAG, FRAME_EVENT, FRAME_ACK, PAYLOAD_FMT, FIXED_PAYLOAD_LEN, VAR_PAYLOAD_LEN

# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------

class TimeUnwrapper:
    """
    Recover a monotonic timestamp (for downlink frames) from the payload's 32-bit tick counter.
    """
    _WRAP = 1 << 32
    _HALF_WRAP = _WRAP // 2

    def __init__(self, tick_s: float) -> None:
        self._tick_s = tick_s
        self._newest_timestamp: int | None = None
        self._wraps = 0

    def unwrap(self, t_raw: int) -> float:
        if self._newest_timestamp is None:
            self._newest_timestamp = t_raw
            return t_raw * self._tick_s

        delta = t_raw - self._newest_timestamp
        wraps = self._wraps

        # Four cases, by how far this timestamp sits from the newest one seen.
        # The fourth needs no branch: a little behind is ordinary, because
        # frame types interleave and a slower frame can be assembled before a
        # faster one that ships first. Stamp it in the current epoch and leave
        # the reference where it is.
        if delta < -self._HALF_WRAP:
            # Far behind: time rolled over, so a new epoch begins.
            self._wraps = wraps = wraps + 1
            self._newest_timestamp = t_raw
        elif delta > self._HALF_WRAP:
            # Far ahead: stamped just before the last rollover but delivered
            # just after it, so it belongs to the previous epoch.
            wraps -= 1
        elif delta > 0:
            # Ahead: a new high, and the reference follows it.
            self._newest_timestamp = t_raw

        return (wraps * self._WRAP + t_raw) * self._tick_s

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
    severity: str
    text: str
    code: int | None = None      # None for console-derived entries
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
            t_s = self._time_unwrapper.unwrap(frame.t_raw),
            frame_type = frame.frame_type,
            seq = frame.seq,
        )
        try:
            handler(frame.payload, sample)
        except (ValueError, KeyError, struct.error) as exc:
            # The CRC has already passed, so this is not line corruption: the
            # firmware and this config disagree.
            sample = Sample(t_s=sample.t_s, frame_type=sample.frame_type, seq=sample.seq)
            sample.events.append(Event(
                t_s=sample.t_s,
                severity=WARNING,
                source="console",
                text=f"{sample.frame_name} seq {sample.seq} decode failed: {exc}",
            ))
        return sample

    # 0x01
    def _fast(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != FIXED_PAYLOAD_LEN[FRAME_FAST]:
            raise ValueError(f"FAST payload is {len(payload)} bytes, expected {FIXED_PAYLOAD_LEN[FRAME_FAST]} bytes")
        keys = ("ACC_X", "ACC_Y", "ACC_Z", "GYR_X", "GYR_Y", "GYR_Z", "MAG_X", "MAG_Y", "MAG_Z", "MOTOR_I", "MOTOR_V")
        values = struct.unpack(PAYLOAD_FMT[FRAME_FAST], payload)
        for key, raw_value in zip(keys, values):
            sample.values[key] = self.cfg.channels[key].to_eng(raw_value)

    # 0x02
    def _med(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != FIXED_PAYLOAD_LEN[FRAME_MED]:
            raise ValueError(f"MED payload is {len(payload)} bytes, expected {FIXED_PAYLOAD_LEN[FRAME_MED]} bytes")
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
        if len(payload) != FIXED_PAYLOAD_LEN[FRAME_SLOW]:
            raise ValueError(f"SLOW payload is {len(payload)} bytes, expected {FIXED_PAYLOAD_LEN[FRAME_SLOW]} bytes")
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
        if len(payload) != FIXED_PAYLOAD_LEN[FRAME_DIAG]:
            raise ValueError(f"DIAG payload is {len(payload)} bytes, expected {FIXED_PAYLOAD_LEN[FRAME_DIAG]} bytes")

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
        if len(payload) not in VAR_PAYLOAD_LEN:
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
        if len(payload) != FIXED_PAYLOAD_LEN[FRAME_ACK]:
            raise ValueError(f"ACK payload is {len(payload)} bytes, expected {FIXED_PAYLOAD_LEN[FRAME_ACK]} bytes")

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
