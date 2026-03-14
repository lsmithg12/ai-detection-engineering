# Cribl Pipeline Changes — 2026-03-14 (Phase 3)

## Summary

Added raw Sysmon text parsing capability to the `cim_normalize` pipeline.
Previously, the pipeline only handled ECS JSON events (via `serde` JSON extract).
Phase 3 adds regex_extract functions that fire when `_raw` contains raw vendor text
instead of JSON, enabling end-to-end validation of the normalization chain.

## Changes Made

### New Pipeline Functions (inserted between serde and final eval)

| Function | Filter | Description |
|----------|--------|-------------|
| regex_extract (EventID) | `!__e.event \|\| !__e.event.code` | Extract EventID from raw Sysmon text |
| regex_extract (EID 1/4688) | `_raw_event_code && /^(1\|4688)$/.test(...)` | Process create fields: Image, CommandLine, ParentImage |
| regex_extract (EID 3) | `_raw_event_code == '3'` | Network fields: DestinationIp, DestinationPort, SourceIp |
| regex_extract (EID 7) | `_raw_event_code == '7'` | Image load: Image, ImageLoaded |
| regex_extract (EID 8/10) | `_raw_event_code == '8' \|\| '10'` | Injection: SourceImage, TargetImage |
| regex_extract (EID 10 access) | `_raw_event_code == '10'` | GrantedAccess extraction |
| regex_extract (EID 13) | `_raw_event_code == '13'` | Registry: TargetObject, Details |
| regex_extract (EID 22) | `_raw_event_code == '22'` | DNS: QueryName |
| eval (raw→ECS) | `_raw_event_code && !__e.event` | Map regex-extracted fields to ECS dotted notation |

### Design Decisions

1. **Conditional execution**: Raw text parsers only fire when `serde` (JSON) fails to
   produce `event.code`. This means existing ECS JSON events are unaffected.

2. **Temporary field names**: Regex captures use `_raw_*` prefix (e.g., `_raw_image`)
   to avoid conflicts with ECS fields during extraction. These are cleaned up by the
   mapping eval function.

3. **Backward compatible**: The final CIM alias eval function is unchanged — it still
   reads from ECS fields regardless of how they were populated (JSON or regex).

### EIDs Covered

| EID | Source | Fields Extracted |
|-----|--------|-----------------|
| 1 | Sysmon Process Create | Image, CommandLine, ParentImage |
| 3 | Sysmon Network Connect | Image, DestinationIp, DestinationPort, SourceIp |
| 7 | Sysmon Image Load | Image, ImageLoaded |
| 8 | Sysmon CreateRemoteThread | SourceImage, TargetImage |
| 10 | Sysmon Process Access | SourceImage, TargetImage, GrantedAccess |
| 13 | Sysmon Registry Value Set | Image, TargetObject, Details |
| 22 | Sysmon DNS Query | Image, QueryName |
| 4688 | Windows Security | shares EID 1 regex |

### EIDs NOT Covered (Future Work)

- EID 2 (FileCreateTime) — GAP-006
- EID 11 (FileCreate) — partially available
- EID 17/18 (PipeEvent) — partially available
- EID 19/20/21 (WMI) — GAP-003
- EID 25 (ProcessTampering) — GAP-009

## Impact Assessment

- **Existing ECS JSON flow**: No change (serde handles it, regex functions skip)
- **New raw text flow**: Enables Cribl-based validation in validation.py
- **Reduction rate**: No change (no drop rules added in this update)
- **Risk**: Low — all new functions are conditional on serde failure

## Related Files

- `pipeline/configure-cribl.sh` — updated pipeline creation
- `autonomous/orchestration/validation.py` — Cribl preview validation method
- `simulator/raw_events.py` — ECS-to-raw event converter
