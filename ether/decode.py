import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

import yaml

from .protocol import Frame, FRAME_NAMES, FRAME_FAST, FRAME_MED, FRAME_SLOW, FRAME_DIAG, FRAME_EVENT, FRAME_ACK

NOMINAL = "nominal"
CAUTION = "caution"
WARNING = "warning"
STALE = "stale"
ABSENT = "absent"

# --------------------------------------------------------------------------
# Config
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

@dataclass(frozen=True)
class ChannelDef:
    key: str
    label: str
    scale: float
    offset: float
    units: str
    bit: int | None = None
    caution: tuple[float, float] | None = None
    warning: tuple[float, float] | None = None
    grid: tuple[int, int] | None = None

    def to_eng(self, raw: int) -> float:
        return raw * self.scale + self.offset

    def classify(self, value: float) -> str:
        if self.warning and not (self.warning[0] <= value <= self.warning[1]):
            return WARNING
        if self.caution and not (self.caution[0] <= value <= self.caution[1]):
            return CAUTION
        return NOMINAL

@dataclass
class Config:
    digest: str # hashing of the config file that goes in the log header
    tick_s: float
    frames: dict[str, dict[str, Any]]
    thermocouples: list[ChannelDef]
    pressure: list[ChannelDef]
    rails: dict[str, dict[str, Any]]
    channels: dict[str, ChannelDef] = field(default_factory=dict)
    imu: dict[str, dict[str, Any]] = field(default_factory=dict)
    fsm_states: dict[int, str] = field(default_factory=dict)
    power_modes: dict[int, str] = field(default_factory=dict)
    motor_fault_bits: dict[int, dict[str, Any]] = field(default_factory=dict)
    status_bits: dict[int, dict[str, Any]] = field(default_factory=dict)
    latch_bits: dict[int, dict[str, Any]] = field(default_factory=dict)
    events: dict[int, dict[str, Any]] = field(default_factory=dict)
    ack_status: dict[int, dict[str, Any]] = field(default_factory=dict)
    ack_reasons: dict[int, dict[str, Any]] = field(default_factory=dict)
    safe_mode_causes: dict[int, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> Self:
        data = Path(path).read_bytes()
        digest = hashlib.sha256(data).hexdigest()[:16]
        cfg = yaml.safe_load(data)

        obj = cls(
            digest=digest,
            tick_s=cfg["protocol"]["timestamp_unit_s"],
            frames=cfg["frames"],
            thermocouples=_channel_list(cfg["thermocouples"]),
            pressure=_channel_list(cfg["pressure"]),
            rails=cfg["rails"],
            imu=cfg["imu"],
            fsm_states=cfg["fsm_states"],
            power_modes=cfg["power_modes"],
            motor_fault_bits=cfg["motor_fault_bits"],
            status_bits=cfg["status_bits"],
            latch_bits=cfg["latch_bits"],
            events=cfg["events"],
            ack_status=cfg["ack_status"],
            ack_reasons=cfg["ack_reasons"],
            safe_mode_causes=cfg["safe_mode_causes"],
        )

        seen: dict[str, ChannelDef] = {}
        for channel in (*obj.thermocouples, *obj.pressure, *_rail_channels(cfg), *_scalar_channels(cfg), *_derived_channels(cfg)):
            if channel.key in seen:
                raise ValueError(f"duplicate channel key {channel.key!r}")
            seen[channel.key] = channel

        obj.channels = seen

        _validate_event_args(obj.events)

        return obj

def _channel_list(group: dict[str, Any]) -> list[ChannelDef]:
    scale = float(group.get("scale", 1.0))
    offset = float(group.get("offset", 0.0))
    units = group.get("units", "")
    channels = []
    for key, channel in group["channels"].items():
        channels.append(ChannelDef(
            key=key,
            label=channel.get("label", key),
            scale=scale,
            offset=offset,
            units=units,
            bit=channel.get("bit"),
            caution=_band(channel.get("caution"), key),
            warning=_band(channel.get("warning"), key),
            grid=_grid(channel.get("grid"), key),
        ))
    return channels

def _rail_channels(cfg: dict[str, Any]) -> list[ChannelDef]:
    """
    Three channels per INA232: bus voltage, current, power.
    """
    bus_v_lsb = float(cfg["ina232"]["bus_v_lsb"])
    power_ratio = float(cfg["ina232"]["power_lsb_ratio"])
    out: list[ChannelDef] = []
    for key, rail in cfg["rails"].items():
        current_lsb = float(rail["current_lsb"])
        label = rail.get("label", key)
        bit = rail["bit"]
        out.append(ChannelDef(
            key=f"{key}_V",
            label=f"{label} voltage",
            scale=bus_v_lsb,
            offset=0.0,
            units="V",
            bit=bit,
            caution=_band(rail.get("caution_v"), key),
            warning=_band(rail.get("warning_v"), key)
        ))
        out.append(ChannelDef(
            key=f"{key}_I",
            label=f"{label} current",
            scale=current_lsb,
            offset=0.0,
            units="A",
            bit=bit,
            caution=_band(rail.get("caution_i"), key),
            warning=_band(rail.get("warning_i"), key)
        ))
        out.append(ChannelDef(
            key=f"{key}_P",
            label=f"{label} power",
            scale=current_lsb * power_ratio,
            offset=0.0,
            units="W",
            bit=bit
        ))
    return out

def _imu_scale(spec: dict[str, Any]) -> float:
    """
    Fixed IMU scale: expected_fsr / 32768.

    The payload reports the FSR code it is actually using in DIAG's imu_cfg
    byte, but decoding deliberately does NOT follow it. The config is
    authoritative so that a given log always replays to the same engineering
    values, no matter whether the reader has seen a DIAG frame yet. Instead,
    a disagreement raises an IMU_FSR_MISMATCH flag.
    """
    return float(spec["fsr"][spec["expected_fsr_code"]]) / 32768.0

def _scalar_channels(cfg: dict[str, Any]) -> list[ChannelDef]:
    """Flatten the single-valued groups (IMU, motor, MCU) into ChannelDefs."""
    out: list[ChannelDef] = []

    def add(key: str, label: str, spec: dict[str, Any], scale: float | None = None) -> None:
        out.append(ChannelDef(
            key=key,
            label=label,
            scale=float(spec.get("scale", 1.0)) if scale is None else scale,
            offset=float(spec.get("offset", 0.0)),
            units=spec.get("units", ""),
            caution=_band(spec.get("caution"), key),
            warning=_band(spec.get("warning"), key),
        ))

    # IMU
    for axis in "xyz":
        add(f"ACC_{axis.upper()}", f"Accel {axis}", cfg["imu"]["accel"],
            scale=_imu_scale(cfg["imu"]["accel"]))
        add(f"GYR_{axis.upper()}", f"Gyro {axis}", cfg["imu"]["gyro"],
            scale=_imu_scale(cfg["imu"]["gyro"]))
        add(f"MAG_{axis.upper()}", f"Mag {axis}", cfg["imu"]["mag"],
            scale=_imu_scale(cfg["imu"]["mag"]))

    # Motor
    add("MOTOR_I", "Motor current", cfg["motor"]["current"])
    add("MOTOR_V", "Motor voltage", cfg["motor"]["voltage"])
    for name, label in (("temp", "MCU temperature"), ("vref", "MCU Vref"), ("cpu_load", "CPU load"), ("heap_free", "Heap free")):
        add(f"MCU_{name.upper()}", label, cfg["mcu"][name])

    # DIAG
    add("STATE_TIME_IN_MODE", "Time in power mode", cfg["state"]["time_in_mode"])
    add("LINK_RX_CRC_ERRORS", "Uplink CRC errors", cfg["link"]["rx_crc_errors"])

    return out

def _derived_channels(cfg: dict[str, Any]) -> list[ChannelDef]:
    """
    Channels the ground computes rather than reads off the wire.
    """
    out: list[ChannelDef] = []

    spec = cfg["derived"]["tank_strat_dt"]
    out.append(ChannelDef(
        key="TANK_STRAT_DT",
        label="Stratification dT",
        scale=float(spec.get("scale", 1.0)),
        offset=float(spec.get("offset", 0.0)),
        units=spec.get("units", ""),
        caution=_band(spec.get("caution"), "tank_strat_dt"),
        warning=_band(spec.get("warning"), "tank_strat_dt")
    ))

    for sensor in ("accel", "gyro", "mag"):
        units = cfg["imu"][sensor].get("units", "")
        out.append(ChannelDef(
            key=f"IMU_{sensor.upper()}_FSR",
            label=f"{sensor.capitalize()} full-scale range",
            scale=1.0,
            offset=0.0,
            units=units
        ))

    return out

def _band(values: Any, key: str) -> tuple[float, float] | None:
    if not values:
        return None
    if len(values) != 2:
        raise ValueError(f"{key}: band must be [low, high], got {values!r}")
    return (float(values[0]), float(values[1]))

def _grid(values: Any, key: str) -> tuple[int, int] | None:
    if not values:
        return None
    if len(values) != 2 or not all(isinstance(x, int) for x in values):
        raise ValueError(f"{key}: grid must be [row, col] integers, got {values!r}")
    return (values[0], values[1])

# --------------------------------------------------------------------------
# Misc Helpers
# --------------------------------------------------------------------------

def _unknown(tag: str, value: int, hex_digits: int = 0) -> str:
    """
    Single rendering for a value no config table explains.
    The value is shown in the base its table is declared in.
    """
    shown = f"0x{value:0{hex_digits}X}" if hex_digits else str(value)
    return f"{tag}?({shown})"

# --------------------------------------------------------------------------
# Event argument rendering
# --------------------------------------------------------------------------

def _render_safe_mode_cause(cfg: "Config", value: int) -> Any:
    spec = cfg.safe_mode_causes.get(value)
    return spec["label"] if spec else _unknown("CAUSE", value, 4)

def _render_tc_index(cfg: "Config", value: int) -> Any:
    for channel in cfg.thermocouples:
        if channel.bit == value:
            return channel.label
    return _unknown("TC", value)

def _render_rail_index(cfg: "Config", value: int) -> Any:
    for key, rail in cfg.rails.items():
        if rail.get("bit") == value:
            return rail.get("label", key)
    return _unknown("RAIL", value)

_ARG_RENDERERS: dict[str, Callable[["Config", int], Any]] = {
    "raw": lambda cfg, value: value,
    "fsm_states": lambda cfg, value: cfg.fsm_states.get(value, _unknown("FSM", value)),
    "power_modes": lambda cfg, value: cfg.power_modes.get(value, _unknown("MODE", value)),
    "safe_mode_causes": _render_safe_mode_cause,
    "tc_index": _render_tc_index,
    "rail_index": _render_rail_index,
}

def _validate_event_args(events: dict[int, dict[str, Any]]) -> None:
    """
    Every kind named in an event's `args:` must have a renderer.

    Without this an arg type typo is silently rendered as a bare integer instead of being loudly flagged as an error.
    """
    problems = [
        f"  event 0x{code:04X} arg {i}: unknown kind {kind!r}"
        for code, spec in events.items()
        for i, kind in enumerate(spec.get("args", []))
        if kind not in _ARG_RENDERERS
    ]
    if problems:
        raise ValueError("\n".join([
            "config declares event argument kinds this build cannot render:",
            *problems,
            f"  known kinds: {', '.join(sorted(_ARG_RENDERERS))}",
        ]))

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

_FAST_FMT = "<9h2H"
_MED_FMT  = "<2B3H" + "HhH" * 4
_SLOW_FMT = "<H15H"
_DIAG_FMT = "<I5H6B"
_ACK_FMT  = "<HBB"

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
        if len(payload) != struct.calcsize(_FAST_FMT):
            raise ValueError(f"FAST payload is {len(payload)} bytes, expected {struct.calcsize(_FAST_FMT)} bytes")
        keys = ("ACC_X", "ACC_Y", "ACC_Z", "GYR_X", "GYR_Y", "GYR_Z", "MAG_X", "MAG_Y", "MAG_Z", "MOTOR_I", "MOTOR_V")
        values = struct.unpack(_FAST_FMT, payload)
        for key, raw_value in zip(keys, values):
            sample.values[key] = self.cfg.channels[key].to_eng(raw_value)

    # 0x02
    def _med(self, payload: bytes, sample: Sample) -> None:
        if len(payload) != struct.calcsize(_MED_FMT):
            raise ValueError(f"MED payload is {len(payload)} bytes, expected {struct.calcsize(_MED_FMT)} bytes")
        values = struct.unpack(_MED_FMT, payload)
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
        if len(payload) != struct.calcsize(_SLOW_FMT):
            raise ValueError(f"SLOW payload is {len(payload)} bytes, expected {struct.calcsize(_SLOW_FMT)} bytes")
        values = struct.unpack(_SLOW_FMT, payload)
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
        if len(payload) != struct.calcsize(_DIAG_FMT):
            raise ValueError(f"DIAG payload is {len(payload)} bytes, expected {struct.calcsize(_DIAG_FMT)} bytes")

        (time_in_mode_ms, latch_flags, mcu_temp, mcu_vref,
         cpu_load, heap_free, fsm_state, power_mode,
         motor_fault, status_bits, imu_cfg, rx_crc_errors) = struct.unpack(_DIAG_FMT, payload)

        for key, raw in (("MCU_TEMP", mcu_temp), ("MCU_VREF", mcu_vref), ("MCU_CPU_LOAD", cpu_load), ("MCU_HEAP_FREE", heap_free), ("STATE_TIME_IN_MODE", time_in_mode_ms), ("LINK_RX_CRC_ERRORS", rx_crc_errors)):
            sample.values[key] = self.cfg.channels[key].to_eng(raw)

        sample.enums["FSM_STATE"] = self.cfg.fsm_states.get(fsm_state, _unknown("FSM", fsm_state))
        sample.enums["POWER_MODE"] = self.cfg.power_modes.get(power_mode, _unknown("MODE", power_mode))

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

        rendered = [_ARG_RENDERERS[kind](self.cfg, value) for kind, value in zip(kinds, args)]
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
        if len(payload) != struct.calcsize(_ACK_FMT):
            raise ValueError(f"ACK payload is {len(payload)} bytes, expected {struct.calcsize(_ACK_FMT)} bytes")

        cmd_seq, status, reason = struct.unpack(_ACK_FMT, payload)

        status_spec = self.cfg.ack_status.get(status)
        reason_spec = self.cfg.ack_reasons.get(reason)

        sample.acks.append(Ack(
            t_s=sample.t_s,
            cmd_seq=cmd_seq,
            status=status_spec["key"] if status_spec else _unknown("STATUS", status),
            status_label=status_spec["label"] if status_spec else f"Unknown status {status}",
            severity=status_spec.get("severity", WARNING) if status_spec else WARNING,
            reason=reason_spec["key"] if reason_spec else _unknown("REASON", reason, 2),
            reason_label=reason_spec["label"] if reason_spec else f"Unknown reason 0x{reason:02X}"
        ))
