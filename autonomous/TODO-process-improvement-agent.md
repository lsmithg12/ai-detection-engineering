# TODO: Process Improvement Agent

**Status**: Planning
**Priority**: Phase 6+ (after core pipeline is built)

## Purpose

A dedicated agent that reviews the pipeline itself — not detection quality,
but operational efficiency, scalability, and developer experience. The Quality
Agent focuses on detection health (FP/TP rates, alert volumes). This agent
focuses on the pipeline processes that produce those detections.

## Distinct from Quality Agent

| Concern | Quality Agent | Process Improvement Agent |
|---------|--------------|--------------------------|
| Focus | Detection output quality | Pipeline workflow efficiency |
| Questions | "Is this detection good?" | "Is how we built it efficient?" |
| Metrics | FP rate, TP rate, health score | Token usage, cycle time, bottlenecks |
| Actions | Tune/retire detections | Refactor agents, optimize prompts |
| Schedule | Daily | Weekly or on-demand |

## Key Responsibilities

### 1. Token Budget Analysis
- Read `budget-log.jsonl` and analyze token spend per agent per run
- Identify which agents are over-budget or wasteful
- Propose prompt optimizations to reduce token usage
- Track cost-per-detection metric over time

### 2. Cycle Time Tracking
- Measure: how long does a detection take from REQUESTED -> DEPLOYED?
- Identify bottlenecks: which state transition takes the longest?
- Are detections stuck in a state? Why?
- Compare cycle times across technique categories

### 3. Pipeline Throughput
- Detections per week (trend)
- Scenario generation rate vs detection authoring rate
- Is any agent a bottleneck? (e.g., red-team generates faster than blue-team consumes)
- Backlog growth/shrinkage over time

### 4. Agent Performance Review
- Review each agent's learnings journal for recurring issues
- Cross-reference: are the same problems hitting multiple agents?
- Propose agent code improvements (not detection improvements)
- Track which agents fail most often and why

### 5. Prompt Engineering Optimization
- Analyze agent prompts for unnecessary verbosity
- Identify where structured output could replace prose
- Propose prompt template improvements
- A/B test different prompt strategies (measure by output quality + token usage)

### 6. Infrastructure Health
- Are SIEMs keeping up with data volume?
- Is the simulator generating the right mix of events?
- Are Cribl pipelines efficient? (check reduction_pct)
- Any data source gaps that multiple detections are blocked on?

### 7. Scaling Recommendations
- When should we add more scenario generators?
- When should we parallelize agent runs?
- What's the maximum throughput of the current pipeline design?
- Recommend architectural changes for scaling beyond current capacity

## Output Artifacts
- `monitoring/process-reports/YYYY-MM-DD.md` — weekly process health report
- `monitoring/metrics/pipeline-metrics.jsonl` — structured metrics over time
- Updates to `orchestration/config.yml` — tuned agent parameters
- PRs with agent code improvements

## Implementation Notes
- Should run on Sonnet (analytical, not creative)
- Schedule: weekly (doesn't need to run daily like quality agent)
- Reads ALL agent journals (like quality agent, but for process insights)
- Can propose changes to orchestration/ code (unlike other agents)
- Should NOT modify detection rules or requests — that's quality agent's domain

## When to Build
After Phase 5 (Quality + Security agents) are operational and generating data.
The process improvement agent needs historical data to analyze — running it
before there's a track record would be premature.
