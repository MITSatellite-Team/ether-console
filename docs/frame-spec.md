# ETHER wire protocol

**Global conventions**

- **Endianness: little-endian**, everywhere, matching the STM32.
- **No implicit padding.** Firmware structs must be `__attribute__((packed))`, or built field-by-field. All payload layouts below are additionally arranged so that every field lands on its natural alignment, so packed and unpacked layouts agree — but declare packed anyway so a compiler change can't silently break the interface.
- **All multi-byte values are the raw sensor/register value.** Conversion to engineering units happens on the ground, using the scale and offset in the config file. Firmware never does floating point.
- **Schema version is in every frame.** The ground refuses to decode a version it doesn't have a config for.

---

## 1. Frame structure

Every frame in both directions has the same 12-byte header and a trailing CRC.

```
offset  size  type      field
------  ----  --------  -----------------------------------------------
  0      2    uint16    sync          0xA55A  (on the wire: A5 5A)
  2      1    uint8     schema_ver    protocol version, currently 1
  3      1    uint8     frame_type    see table below
  4      4    uint32    t_100us       MCU monotonic time since boot, in 100 µs ticks
  8      2    uint16    seq           per-frame-type counter, wraps at 65535
 10      2    uint16    length        payload length in bytes
 12   length  bytes     payload
12+len   2    uint16    crc16         CRC-16/IBM-3740 over bytes [0, 12+length)
```

Header is 12 bytes, so the payload starts 4-byte aligned. Total overhead is 14 bytes per frame.

**Sync word.** `0xA55A` is an alternating bit pattern, unlikely to appear in sensor data and trivially recognizable on a scope. It exists so the ground can resynchronize after corruption without restarting the connection.

**t_100us.** payload → ground: MCU monotonic time since boot, in 100 µs ticks. Ground → payload: bits are zero-filled.

**Span and wrap.** 2³² ticks at 100 µs is **119.3 hours — just under 5 days**. In practice, the ground should never have to unwrap for the zero G flight. We should implement it just in case though, especially if we make the ticks finer.

**Sequence numbers are per frame type.** Each type ticks at its own rate, so a shared counter would make gap detection useless. With per-type counters, a single missing 50 Hz frame is immediately visible as a `seq` gap and nothing else is disturbed.

[**CRC-16/IBM-3740**](https://reveng.sourceforge.io/crc-catalogue/16.htm): polynomial `0x1021`, init `0xFFFF`, no input or output reflection, no final XOR. Computed over the header *and* payload, so a corrupted length field is caught rather than acted on.

> **Note**: The 16-bit CRC is stored little-endian like every other uint16. Noted explicitly since CRC is normally stored big-endian.

> **Note**: USB includes CRC and whole packet enforcement by default, so the sync word + length + CRC combo is in preparation for the Oligo launch.

> **Note**: `t_100us` should be derived from a hardware timer so ticks aren't lost under CPU load.

---

## 2. Frame types

| ID | Name | Direction | Rate | Contents |
|---|---|---|---:|---|
| 0x01 | `FAST` | payload → ground | 50 Hz | IMU (accel, gyro, mag), motor current and voltage |
| 0x02 | `MED` | payload → ground | 10 Hz | Tank pressure, INA232 rail monitors |
| 0x03 | `SLOW` | payload → ground | 5 Hz | Tank thermocouples |
| 0x04 | `DIAG` | payload → ground | 1 Hz | FSM state, power mode, fault and latch registers, MCU health |
| 0x05 | `EVENT` | payload → ground | async | Event code, arguments |
| 0x06 | `ACK` | payload → ground | async | Response to a ground command |
| 0x10 | `CMD` | ground → payload | async | Command |

Separate frame types per rate group, rather than one frame padded to 50 Hz, keeps each frame small and lets the ground track staleness independently.

---

## 3. Payload layouts

### 0x01 `FAST` — 22 bytes, fixed

```
offset  size  type    field
  0      2    int16   accel_x        raw counts
  2      2    int16   accel_y
  4      2    int16   accel_z
  6      2    int16   gyro_x
  8      2    int16   gyro_y
 10      2    int16   gyro_z
 12      2    int16   mag_x
 14      2    int16   mag_y
 16      2    int16   mag_z
 18      2    uint16  motor_current  raw counts
 20      2    uint16  motor_voltage  raw counts
```

IMU values are transmitted as **raw counts**, not converted. An IMU only ever outputs ADC integers; what those integers mean depends on the full-scale range (±16 g, ±2000 °/s, ±8 gauss), which is a runtime configuration register on most parts. The scale lives in the ground config as `FSR / 32768`, the payload reports its **actual** FSR setting in `imu_cfg` of the `DIAG` frame so the ground can verify rather than assume, and the ground applies `value = raw × scale`.

### 0x02 `MED` — 32 bytes, fixed

```
offset  size  type    field
  0      1    uint8   press_mask     bit i set = pressure channel i valid
  1      1    uint8   ina_mask       bit i set = INA232 chip i valid
  2      6    uint16  pressure[3]    raw counts, slot i = channel i
  8     24            ina[4]         slot i = chip i, 6 bytes each:
                                       uint16 bus_voltage_raw
                                       int16  current_raw
                                       uint16 power_raw
```

**The masks are validity indicators, not length fields.** Every slot is always present on the wire; the mask says which slots hold real data vs `n/c`.

Slots for invalid channels are **zero-filled**.

Note that `press_mask` and `ina_mask` are `uint8` and so have spare bits — **spare mask bits do not imply spare slots.**

INA232 raw registers are passed through untouched. The bus-voltage LSB is likely fixed by the part; the current and power LSBs depend on the calibration value you program into the chip.

> **Note**: If we choose to have 3 tanks and 4 INA232 chips, then the press_mask and ina_mask fields can be compressed into one uint8.

### 0x03 `SLOW` — 32 bytes, fixed

```
offset  size  type    field
  0      2    uint16  tc_mask          bit i set = thermocouple i valid
  2     30    uint16  temperature[15]  raw counts, slot i = junction i
```

`tc_mask` reports the thermocouples actually sampled this cycle, one that stops converting clears its bit and reads `n/c` on the ground.

One frame carries every tank's junctions, numbered globally across the payload.

The spare bit in tc_mask does not map to a thermocouple.

> **Note**: If we end up with less than 9 thermocouples, we can change tc_mask to uint8 and drop the number of temperature entries to match.

### 0x04 `DIAG` — 20 bytes, fixed

```
offset  size  type    field
  0      4    uint32  time_in_mode_ms   milliseconds since last power-mode change
  4      2    uint16  latch_flags       sticky protection latches, see config
  6      2    uint16  mcu_temp          raw
  8      2    uint16  mcu_vref          raw
 10      2    uint16  cpu_load          raw
 12      2    uint16  heap_free         bytes
 14      1    uint8   fsm_state         see config enum
 15      1    uint8   power_mode        see config enum
 16      1    uint8   motor_fault       motor driver fault register, see config
 17      1    uint8   status_bits       bits 3-7 spare, see config
 18      1    uint8   imu_cfg           IMU full-scale range fields, see config
 19      1    uint8   rx_crc_errors     saturating count of uplink frames discarded
```

For `motor_fault`, `latch_flags`, and `status_bits`: **0 = healthy, 1 = fault triggered**. This polarity is universal — every bitfield in the protocol and in `ether_config.yaml` uses it.

`motor_fault` carries the 8-bit driver register directly (bit 7 FAULT, 6 SPI_ERROR, 5 UVLO, 4 CPUV, 3 OCP, 2 STL, 1 TF, 0 OL).

`latch_flags` is the sticky protection state: two bits per rail (over-current, over-voltage) across the four monitored rails, plus spares. These do not clear on their own — the ground clears them with `CMD_CLEAR_LATCH`.

> **Note**: The sticky bits only help if the firmware is checked in its fast control loop, not at the frequency that DIAG is assembled.

`imu_cfg` carries the IMU's full-scale range register fields — accel, gyro, magnetometer — packed into one byte. These are small enums selecting from the handful of ranges the part supports (typically 2 bits each), not the scale factor itself; the ground maps them to `FSR / 32768` via the config.

> **Note**: Firmware must read these fields back from the device when assembling `DIAG`, not report a cached copy of what init wrote.

`status_bits` carries subsystem health. These exist because `FAST` is a fixed-layout frame with no validity indication of its own — if the IMU stops responding, firmware still has to put *something* in those nine fields, and zeros decode as a plausible free-fall reading. A set fault bit tells the ground to disregard them.

### 0x05 `EVENT` — 2 + 4·n_args bytes

```
offset  size  type    field
  0      2    uint16  code       event code, decoded via the ground config table
  2    4·n    int32   args[]
```

Firmware never sends strings — it sends a numeric code and up to four integer arguments, and the ground renders it from a template in the config.

The console then merges these firmware events with events it derives itself (state transitions, limit crossings, staleness, connect/disconnect, every command sent) into one chronological log.

> **Note**: `args[]` starts at payload offset 2, so every `int32` is 2-aligned, not 4. Firmware must `memcpy` them into the frame rather than casting a struct over it.

> **Note**: One of the EVENTs is "Safe mode triggered by watchdog reset". The cause has to be written somewhere that survives into the next boot (an STM32 backup register or a noinit RAM section) or it's unreportable by definition.

### 0x06 `ACK` — 4 bytes

```
offset  size  type    field
  0      2    uint16  cmd_seq    echoes the seq of the CMD being answered
  2      1    uint8   status     transaction outcome, see config enum
  3      1    uint8   reason     why it was not accepted, see config enum
```

**Firmware `ACK`s after `CMD` validation and before execution.**

`status` carries the outcome only — `ACCEPTED`, `REJECTED`, `BUSY` — and it alone sets the severity of the log line.

`reason` explains a non-acceptance and has no severity of its own. When `status` is `ACCEPTED`, `reason` is `NONE` (0).

`BUSY` is kept distinct from `REJECTED` because the command may succeed if
retried; the console offers a retry on one and not the other.

### 0x10 `CMD` — 2 + 4·n_args bytes, ground → payload

```
offset  size  type    field
  0      2    uint16  cmd_id     see config command table
  2    4·n    int32   args[]
```

Deliberately the same shape as `EVENT` — a `uint16` code followed by fixed-width argument slots — so both directions share one length rule and one serializer. `n_args` follows from `length`. The config command table gives each argument's **semantic** type (`uint8` for a power mode, `uint16` for a latch mask), which the ground range-checks before sending and firmware range-checks on receipt. That check is now firmware logic rather than a property of the frame length, so it has to be written rather than assumed.

The command's own `seq` lives in the standard header, and the payload echoes it in the `ACK`. Every command is logged by the console at transmit time, before any response arrives, so a command that is never acknowledged still appears in the record.

> **Note**: `args[]` starts at payload offset 2, so every `int32` is 2-aligned, not 4. Firmware must `memcpy` them out of the receive buffer rather than casting a struct over it.

> **Note**: `int32` is the slot width, not a range the argument must fit in. `SYNC_CLOCK` carries a `uint32` and occupies one slot with its bits unchanged — the ground writes it as `uint32`, firmware reads it back as `uint32`. Only the config's semantic type decides how a slot is interpreted.

---

## 4. Receiver behaviour

**Resynchronization.** The ground scans for the sync word, reads the header, sanity-checks `length` against a maximum (128 bytes), waits for the full frame, then verifies the CRC. On any failure it advances two bytes past the candidate sync and rescans. Bytes discarded this way are counted and surfaced in the link health panel — a rising discard count is an early symptom of a baud mismatch or a marginal cable.

**Length validation.** Every frame type has an exactly known `length` — fixed for the four periodic frames, `2 + 4·n_args` for `EVENT` and `CMD` — so `length` is checked against that value rather than against an upper bound:

| Frame type | Expected `length` |
|---|---:|
| `FAST` | 22 |
| `MED` | 32 |
| `SLOW` | 32 |
| `DIAG` | 20 |
| `ACK` | 4 |
| `EVENT` | `2 + 4·n_args`, so 2, 6, 10, 14, or 18 |
| `CMD` | `2 + 4·n_args`, so 2, 6, 10, 14, or 18 |

A mismatch is rejected as corruption, counted, and surfaced alongside the CRC error count — never decoded on a best-effort basis.

**Gap detection.** Per frame type, the receiver tracks the last `seq`. A jump of more than one is logged as dropped frames and counted.

**Staleness.** Each frame type has a configured nominal rate and a staleness threshold (roughly 2–3 nominal periods). When no frame of a type has arrived within its threshold, every channel carried by that type displays as stale — greyed, with the age shown — rather than continuing to display the last value as if it were live.

**Command timeout.** A sent command remains pending with elapsed time shown until an `ACK` arrives or the session ends; whether the payload acted is determined from DIAG, and whether the downlink is alive is determined from telemetry staleness.

---

## 5. Bandwidth

The four periodic frames are fixed-size, so the steady-state rate is constant regardless of how many channels are populated. `EVENT`, `ACK` and `CMD` are async and excluded here:

| Frame | Rate | Wire bytes | B/s |
|---|---:|---:|---:|
| `FAST` | 50 Hz | 36 | 1800 |
| `MED` | 10 Hz | 46 | 460 |
| `SLOW` | 5 Hz | 46 | 230 |
| `DIAG` | 1 Hz | 34 | 34 |
| **Total** | | | **≈2.5 kB/s (≈25 kbit/s at 8N1)** |

This is *not* a plausible continuous orbital downlink allocation for a hosted secondary payload, which is the concrete reason the console needs a transport abstraction: the flight configuration will involve decimated or burst telemetry, and the UI above the transport layer should not have to care.
