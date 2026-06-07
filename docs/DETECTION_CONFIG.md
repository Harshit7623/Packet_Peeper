# Detection Configuration

This document explains how the network detection engine can be tuned at runtime.

## Warm‑up Period
- Controlled by the environment variable **DETECTION_WARMUP_SECONDS** (default: `120`).
- The `NetworkSecurityMonitor` will ignore all packets for the first *warm‑up* seconds after start. This lets the system settle and prevents false alerts on startup. *(Note: The previously known dead-code bug affecting this feature has been resolved).*

## Profiles & Threshold Table
Profiles determine the sensitivity of the threat detection engine. The default profile is `balanced`.

| Threshold Key | `strict` | `balanced` | `sensitive` | `test` |
| --- | --- | --- | --- | --- |
| `port_scan_count` | 15 | 10 | 6 | 5 |
| `syn_flood_rate` | 100 | 50 | 20 | 10 |
| `brute_force_attempts` | 12 | 7 | 5 | 4 |
| `max_alerts_per_type` | 3 | 4 | 6 | 10 |
| `max_total_alerts` | 30 | 50 | 75 | 100 |
| `alert_cooldown` (seconds) | 120 | 60 | 30 | 10 |

## Threshold Overrides
- Any detection threshold can be overridden with an environment variable prefixed with **NSM_**.
- Example: `NSM_SYN_FLOOD_RATE=30` lowers the SYN‑flood packet‑per‑second threshold to `30`.
- Values are automatically parsed as `int` or `float`.

## Dynamic Profile Switching (Test Mode)
You can dynamically change the active profile without restarting the backend via the API:
- Endpoint: **POST /api/test-mode**
- Payload: `{ "enabled": true }` (Switches to `test` profile)
- Payload: `{ "enabled": false }` (Restores default profile)

## Alert Cooldown & Limits
To prevent alert spam, the engine enforces cooldowns and maximum limits based on the active profile:
- **`alert_cooldown`**: Minimum seconds before the same alert type from the same source is broadcast again.
- **`max_alerts_per_type`**: Maximum times a specific alert type is allowed.
- **`max_total_alerts`**: Maximum total alerts allowed before the system requires a reset.

## Resetting Tracking Counters
When performing multiple attack simulations, you may need to reset the internal tracking state:
- Use the **Reset Alerts** button in the UI, or the relevant API endpoint, which calls `NetworkSecurityMonitor.reset_counters()`.
- This clears all historical state (connection tracking, alert counts, brute force counters), allowing fresh detection.

---
*These settings are read from `backend/config/config.py` and do not require a code change to adjust.*