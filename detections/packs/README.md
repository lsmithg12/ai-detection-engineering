# Detection Content Packs

Content packs group related detection rules into versioned, deployable units.
Each pack has a manifest (`pack.yml`) defining its rules, quality gates, and test suite.

## Available Packs

| Pack | Rules | Status | Avg F1 |
|------|-------|--------|--------|
| process-injection | 1 | validated | 1.00 |
| persistence | 3 | monitoring | 0.95 |
| defense-evasion | 7 | monitoring | 0.97 |
| execution | 10 | mixed | 0.84 |
| credential-access | 2 | partial | 0.50 |
| discovery | 2 | validated | 1.00 |
| initial-access | 2 | monitoring | 1.00 |
| command-and-control | 1 | monitoring | 1.00 |

## CLI Usage

```bash
# List all packs
python autonomous/orchestration/cli.py pack list

# Validate a pack (check F1 against quality gates)
python autonomous/orchestration/cli.py pack validate process-injection

# Deploy a pack to active SIEMs
python autonomous/orchestration/cli.py pack deploy process-injection
```

## Pack Manifest Schema

Each `pack.yml` contains:
- `name`, `version`, `description`, `author`, `status`
- `threat_actors`: mapped threat groups
- `mitre_tactics` + `mitre_techniques`: ATT&CK coverage
- `platforms`: OS targets
- `data_requirements`: required log sources
- `rules`: list of detection rules with path, technique, type, status, F1
- `quality`: min_f1, min_evasion_resilience, max_fp_rate gates
- `test_suite`: integration scenarios and evasion variants
- `changelog`: version history

## Pack Statuses
- `monitoring`: all required rules deployed to SIEM
- `validated`: all required rules validated (F1 >= gate), deploy-ready
- `mixed`: some rules deployed, others still in progress
- `partial`: one or more required rules below quality gate
- `draft`: work in progress, not yet validated
