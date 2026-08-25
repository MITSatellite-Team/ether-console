import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

import yaml

from .protocol import Frame, FRAME_NAMES, FRAME_FAST, FRAME_MED, FRAME_SLOW, FRAME_DIAG, FRAME_EVENT, FRAME_ACK, FRAME_CMD

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
    raw: dict[str, Any]
    digest: str
    tick_s: float
    frames: dict[str, dict[str, Any]]
    thermocouples: list[ChannelDef]
    pressure: list[ChannelDef]
    rails: dict[str, dict[str, Any]]
    channels: dict[str, ChannelDef] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> Self:
        data = Path(path).read_bytes()
        digest = hashlib.sha256(data).hexdigest()[:16]
        cfg = yaml.safe_load(data)

        obj = cls(
            raw=cfg,
            digest=digest,
            tick_s=cfg["protocol"]["timestamp_unit_s"],
            frames=cfg["frames"],
            thermocouples=_channel_list(cfg["thermocouples"]),
            pressure=_channel_list(cfg["pressure"]),
            rails=cfg["rails"],
        )

        seen = set()
        for channel in (*obj.thermocouples, *obj.pressure, *_scalar_channels(cfg)):
            if channel.key in seen:
                raise ValueError(f"duplicate channel key {channel.key!r}")
            seen[channel.key] = channel

        obj.channels = seen

        return obj

    def stale_after(self, frame_name: str) -> float | None:
        return self.frames.get(frame_name, {}).get("stale_after_s")

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

def _imu_scale(spec: dict[str, Any]) -> float:
    """IMU scale is runtime-variable: fsr / 32768.

    The fsr code is reported by the payload in DIAG's imu_cfg byte; until the
    first DIAG arrives the ground uses `expected_fsr_code`. There is no `scale`
    key for the IMU, so a plain spec.get("scale", 1.0) would silently yield raw
    counts.
    """
    return float(spec["fsr"][spec["expected_fsr_code"]]) / 32768.0


def _scalar_channels(cfg: dict[str, Any]) -> list[ChannelDef]:
    """Flatten the single-valued groups (IMU, motor, MCU) into ChannelDefs."""
    out: list[ChannelDef] = []

    def add(key: str, label: str, spec: dict[str, Any],
            scale: float | None = None) -> None:
        out.append(ChannelDef(
            key=key,
            label=label,
            scale=float(spec.get("scale", 1.0)) if scale is None else scale,
            offset=float(spec.get("offset", 0.0)),
            units=spec.get("units", ""),
            caution=_band(spec.get("caution"), key),
            warning=_band(spec.get("warning"), key),
        ))

    for axis in "xyz":
        add(f"ACC_{axis.upper()}", f"Accel {axis}", cfg["imu"]["accel"],
            scale=_imu_scale(cfg["imu"]["accel"]))
        add(f"GYR_{axis.upper()}", f"Gyro {axis}", cfg["imu"]["gyro"],
            scale=_imu_scale(cfg["imu"]["gyro"]))
        add(f"MAG_{axis.upper()}", f"Mag {axis}", cfg["imu"]["mag"],
            scale=_imu_scale(cfg["imu"]["mag"]))
    add("MOTOR_I", "Motor current", cfg["motor"]["current"])
    add("MOTOR_V", "Motor voltage", cfg["motor"]["voltage"])
    for name, label in (("temp", "MCU temperature"), ("vref", "MCU Vref"),
                        ("cpu_load", "CPU load"), ("heap_free", "Heap free")):
        add(f"MCU_{name.upper()}", label, cfg["mcu"][name])
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
# Sample (Decoded output)
# --------------------------------------------------------------------------

@dataclass
class Sample:
    t_s: float
    frame_type: int
    seq: int
    # dropped_before: int = 0
    values: dict[str, float] = field(default_factory = dict)
    flags: dict[str, bool] = field(default_factory = dict)
    enums: dict[str, str] = field(default_factory = dict)
    absent: set[str] = field(default_factory = set)
    # events: list[dict[str, Any]] = field(default_factory = list)
    # acks: list[dict[str, Any]] = field(default_factory = list)

    @property
    def frame_name(self) -> str:
        return FRAME_NAMES.get(self.frame_type, f"0x{self.frame_type:02X}")

# --------------------------------------------------------------------------
# Decoder
# --------------------------------------------------------------------------

_FAST_FMT = "<9h2H"

class Decoder:
    def __init__(self, cfg: Config) -> None:
        self._time_unwrapper = TimeUnwrapper(cfg.tick_s)

    def decode(self, frame: Frame):
        handler = {
            FRAME_FAST: self._fast
        }.get(frame.frame_type)

        if handler is None:
            return None

        sample = Sample(
            t_s = self._time_unwrapper.unwrap(frame.frame_type, frame.t_raw),
            frame_type = frame.frame_type,
            seq = frame.seq,
            # dropped_before = dropped_before
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