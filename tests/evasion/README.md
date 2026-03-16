# Evasion Test Suite

Evasion tests validate that detection rules are resilient against common
adversary tradecraft variants that attempt to bypass detection.

## Structure

```
tests/evasion/
  README.md              # This file
  <technique>_evasion_<variant>.json   # Evasion test case
```

## Evasion Test Format

Each evasion test is a JSON file with:
- `_evasion`: metadata about the evasion technique
- `events`: the modified events that attempt to bypass detection

### Example
```json
{
  "_evasion": {
    "technique": "T1055.001",
    "evasion_variant": "ppid_spoofing",
    "description": "Attacker spoofs parent PID to appear as explorer.exe",
    "bypass_attempt": "parent_process_name filter",
    "expected_result": "SHOULD_ALERT or EVASION_SUCCEEDS",
    "fawkes_command": "vanilla-injection"
  },
  "events": [ ... ]
}
```

## Expected Results

- `SHOULD_ALERT`: The detection SHOULD catch this variant (evasion attempt fails)
- `EVASION_SUCCEEDS`: The detection does NOT catch this variant (documents a known gap)

## Running Evasion Tests

```bash
python autonomous/orchestration/cli.py evasion test <technique>
python autonomous/orchestration/cli.py evasion report
```

## Adding Evasion Tests

1. Copy an existing evasion test as a template
2. Modify the event fields to represent the evasion technique
3. Set expected_result based on whether the rule catches it
4. Run: `python autonomous/orchestration/cli.py evasion test <technique>`
