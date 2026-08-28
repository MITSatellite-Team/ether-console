import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

import yaml

NOMINAL = "nominal"
CAUTION = "caution"
WARNING = "warning"
STALE = "stale"
ABSENT = "absent"

# --------------------------------------------------------------------------
# Channels
# --------------------------------------------------------------------------

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

def render_unknown(tag: str, value: int, hex_digits: int = 0) -> str:
    """
    Single rendering for a value no config table explains.
    The value is shown in the base its table is declared in.
    """
    shown = f"0x{value:0{hex_digits}X}" if hex_digits else str(value)
    return f"{tag}?({shown})"

# --------------------------------------------------------------------------
# Event argument rendering
# --------------------------------------------------------------------------

def _render_safe_mode_cause(cfg: Config, value: int) -> Any:
    spec = cfg.safe_mode_causes.get(value)
    return spec["label"] if spec else render_unknown("CAUSE", value, 4)

def _render_tc_index(cfg: Config, value: int) -> Any:
    for channel in cfg.thermocouples:
        if channel.bit == value:
            return channel.label
    return render_unknown("TC", value)

def _render_rail_index(cfg: Config, value: int) -> Any:
    for key, rail in cfg.rails.items():
        if rail.get("bit") == value:
            return rail.get("label", key)
    return render_unknown("RAIL", value)

ARG_RENDERERS: dict[str, Callable[[Config, int], Any]] = {
    "raw": lambda cfg, value: value,
    "fsm_states": lambda cfg, value: cfg.fsm_states.get(value, render_unknown("FSM", value)),
    "power_modes": lambda cfg, value: cfg.power_modes.get(value, render_unknown("MODE", value)),
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
        if kind not in ARG_RENDERERS
    ]
    if problems:
        raise ValueError("\n".join([
            "config declares event argument kinds this build cannot render:",
            *problems,
            f"  known kinds: {', '.join(sorted(ARG_RENDERERS))}",
        ]))
