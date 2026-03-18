# Pipeline Performance: March 2026

## Agent Run Summary

| Agent | Runs | Total Duration | Avg Duration | Errors | Retries |
|-------|------|----------------|--------------|--------|---------|
| intel | 9 | 16.7m | 1.9m | 0 | 0 |
| red-team | 8 | 5.3m | 39.6s | 0 | 0 |
| blue-team | 11 | 4.0m | 21.7s | 1 | 0 |
| quality | 9 | 12.3s | 1.4s | 0 | 0 |
| security | 1 | 1.0s | 1.0s | 0 | 0 |

## Token Usage

- Total estimated tokens: 318,800
- Most expensive agent: blue-team (64.0% of tokens)

## Effectiveness

### F1 Score Distribution
- Rules evaluated: 27
- Mean F1: 0.871
- Auto-deploy tier (F1 >= 0.90): 17
- Validated tier (0.75 <= F1 < 0.90): 7
- Needs rework (F1 < 0.75): 3

### Coverage
- Fawkes technique coverage: 14 / 21 core techniques (67%)

## Budget vs Target

| Agent | Budget (tokens) | Used (tokens) | % |
|-------|-----------------|---------------|---|
| intel | 50,000 | 18,000 | 36.0% |
| red-team | 30,000 | 9,600 | 32.0% |
| blue-team | 500,000 | 204,000 | 40.8% |
| quality | 50,000 | 84,800 | 169.6% |
| security | 40,000 | 2,400 | 6.0% |

## Pipeline Metrics (Phase 7)

> No pipeline metrics yet — run agents to generate `autonomous\orchestration\pipeline-metrics.jsonl`

*Generated 2026-03-17T13:34:23Z*