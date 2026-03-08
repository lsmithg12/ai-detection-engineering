"""
Claude LLM Integration — Invoke Claude Code CLI from agent Python code.

Uses `claude -p` (print mode) to get non-interactive responses, powered by
the user's Claude Pro subscription. No API key needed.

Model selection is driven by config.yml per-agent settings:
  - opus: complex reasoning (blue-team rule authoring, security review)
  - sonnet: fast tasks (intel parsing, quality scoring, red-team scenarios)

Security notes:
  - Claude CLI authenticates via OAuth tokens in ~/.claude/ (local machine only)
  - In CI (GitHub Actions), CLI is not authenticated — agents fall back to
    deterministic Python logic. This is intentional.
  - No API keys or credentials are stored in this module
  - All Claude invocations use --tools "" (no file/shell access) for pure reasoning
  - Responses are validated by downstream logic (F1 scoring, schema checks)
    before being trusted

Budget tracking integrates with the existing budget.py module.
"""

import json
import os
import subprocess
import shutil
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parent.parent / "orchestration" / "config.yml"

# Model aliases -> full model IDs for --model flag
MODEL_MAP = {
    "opus": "opus",
    "sonnet": "sonnet",
    "haiku": "haiku",
}


def _load_agent_config(agent_name: str) -> dict:
    """Load agent-specific config from config.yml."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("agents", {}).get(agent_name, {})
    return {}


def _find_claude_cli() -> str | None:
    """Find the claude CLI executable.

    On Windows, shutil.which resolves .cmd/.bat extensions, but
    subprocess.run needs the full path to avoid FileNotFoundError.
    """
    # Direct path first
    claude = shutil.which("claude")
    if claude:
        return claude

    # Try npx as fallback — return full resolved path for Windows .cmd compat
    npx = shutil.which("npx")
    if npx:
        return npx  # Returns full path like "C:\\Program Files\\nodejs\\npx.CMD"

    return None


def is_available() -> bool:
    """
    Check if Claude CLI is available and authenticated.

    Returns False in CI environments (GitHub Actions) where no OAuth
    session exists. Agents should fall back to deterministic logic.
    """
    import os

    # Explicit CI detection — Claude CLI won't be authenticated
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        return False

    # Nested session detection — can't invoke claude -p from inside Claude Code
    if os.environ.get("CLAUDECODE"):
        return False

    cli = _find_claude_cli()
    if not cli:
        return False

    # Check if auth tokens exist (without invoking Claude)
    claude_dir = Path.home() / ".claude"
    if not claude_dir.exists():
        return False

    return True


def ask(
    prompt: str,
    agent_name: str = "blue-team",
    system_prompt: str | None = None,
    model: str | None = None,
    output_format: str = "text",
    allowed_tools: list[str] | None = None,
    max_turns: int = 3,
    timeout_seconds: int = 120,
) -> dict:
    """
    Send a prompt to Claude CLI and return the response.

    Args:
        prompt: The user prompt to send
        agent_name: Agent name (used to look up model from config)
        system_prompt: Override system prompt (optional)
        model: Override model (optional, defaults to config.yml setting)
        output_format: "text" or "json"
        allowed_tools: List of tools to allow (default: none for pure reasoning)
        max_turns: Max agentic turns (default 3, use 1 for single-shot)
        timeout_seconds: Subprocess timeout

    Returns:
        {"success": bool, "response": str, "model": str, "error": str | None}
    """
    # Resolve model
    if not model:
        agent_cfg = _load_agent_config(agent_name)
        model = agent_cfg.get("model", "sonnet")

    model_id = MODEL_MAP.get(model, model)

    # Build command
    cli = _find_claude_cli()
    if not cli:
        return {
            "success": False,
            "response": "",
            "model": model_id,
            "error": "Claude CLI not found. Install: npm install -g @anthropic-ai/claude-code",
        }

    if "npx" in cli.lower():
        cmd = [cli, "--yes", "@anthropic-ai/claude-code"]
    else:
        cmd = [cli]

    cmd += [
        "--print",
        "--model", model_id,
        "--output-format", output_format,
        "--no-session-persistence",
    ]

    if system_prompt:
        cmd += ["--system-prompt", system_prompt]

    if allowed_tools is not None:
        if not allowed_tools:
            cmd += ["--tools", ""]  # Disable all tools — pure reasoning
        else:
            # --tools takes plain names: "Bash,Edit,Read"
            # --allowed-tools takes restriction patterns: "Bash(curl:*) Edit"
            # Split: patterns with parens go to --allowed-tools, plain go to --tools
            plain = [t for t in allowed_tools if "(" not in t]
            restricted = [t for t in allowed_tools if "(" in t]
            if plain:
                cmd += ["--tools", ",".join(plain)]
            if restricted:
                cmd += ["--allowed-tools", " ".join(restricted)]

    if max_turns:
        cmd += ["--max-turns", str(max_turns)]

    # On Windows, .CMD wrappers re-parse args through cmd.exe which
    # mangles parentheses, backslashes, semicolons, etc. Pass the
    # prompt via stdin to avoid all arg-parsing issues.
    use_stdin = os.name == "nt"
    if not use_stdin:
        cmd.append(prompt)

    try:
        result = subprocess.run(
            cmd,
            input=prompt if use_stdin else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            cwd=str(Path(__file__).resolve().parent.parent.parent),  # repo root
        )

        response_text = (result.stdout or "").strip()

        if result.returncode != 0:
            error_text = result.stderr.strip()[:500] if result.stderr else "Unknown error"
            # Still return partial output if available
            return {
                "success": bool(response_text),
                "response": response_text,
                "model": model_id,
                "error": f"Exit code {result.returncode}: {error_text}",
            }

        # Parse JSON output if requested
        if output_format == "json" and response_text:
            try:
                parsed = json.loads(response_text)
                response_text = parsed.get("result", response_text)
            except json.JSONDecodeError:
                pass  # Return raw text if JSON parse fails

        return {
            "success": True,
            "response": response_text,
            "model": model_id,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "response": "",
            "model": model_id,
            "error": f"Claude CLI timed out after {timeout_seconds}s",
        }
    except Exception as e:
        return {
            "success": False,
            "response": "",
            "model": model_id,
            "error": f"{type(e).__name__}: {e}",
        }


def ask_for_sigma_rule(
    technique_id: str,
    technique_name: str,
    attack_events: list[dict],
    benign_events: list[dict],
    existing_rule_yaml: str = "",
    lessons: list[str] | None = None,
) -> dict:
    """
    Ask Claude to write or improve a Sigma detection rule.

    Uses opus model (configured for blue-team agent).
    Returns {"success": bool, "sigma_yaml": str, "reasoning": str, "error": str | None}
    """
    events_summary = json.dumps(attack_events[:3], indent=2)[:2000]
    benign_summary = json.dumps(benign_events[:3], indent=2)[:2000]

    lessons_block = ""
    if lessons:
        lessons_block = "\n\nPast lessons learned:\n" + "\n".join(f"- {l}" for l in lessons)

    if existing_rule_yaml:
        prompt = f"""Review and improve this Sigma detection rule for {technique_id} ({technique_name}).

Current rule:
```yaml
{existing_rule_yaml}
```

Sample attack events (should trigger):
```json
{events_summary}
```

Sample benign events (should NOT trigger):
```json
{benign_summary}
```
{lessons_block}

Respond with ONLY the improved Sigma YAML rule — no markdown fences, no explanation before or after. The YAML must be valid and complete."""
    else:
        prompt = f"""Write a Sigma detection rule for {technique_id} ({technique_name}).

Sample attack events (should trigger):
```json
{events_summary}
```

Sample benign events (should NOT trigger):
```json
{benign_summary}
```
{lessons_block}

Requirements:
- Include proper logsource (category, product)
- Include selection and filter blocks
- Map to MITRE ATT&CK tags
- Set appropriate severity level
- Add false positive documentation

Respond with ONLY the Sigma YAML rule — no markdown fences, no explanation before or after. The YAML must be valid and complete."""

    system = (
        "You are a senior detection engineer writing Sigma rules. "
        "Output ONLY valid Sigma YAML. No markdown, no explanation, no commentary. "
        "Focus on behavioral patterns over IOCs. Minimize false positives."
    )

    result = ask(
        prompt=prompt,
        agent_name="blue-team",
        system_prompt=system,
        allowed_tools=[],  # Pure reasoning, no tools
        max_turns=1,
        timeout_seconds=90,
    )

    if result["success"]:
        # Clean up response — strip markdown fences if Claude added them
        response = result["response"]
        if response.startswith("```"):
            lines = response.split("\n")
            # Remove first and last lines if they're fences
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            response = "\n".join(lines)

        return {
            "success": True,
            "sigma_yaml": response.strip(),
            "model": result["model"],
            "error": None,
        }

    return {
        "success": False,
        "sigma_yaml": "",
        "model": result.get("model", "unknown"),
        "error": result.get("error", "Unknown error"),
    }


def ask_for_analysis(
    question: str,
    context: str = "",
    agent_name: str = "quality",
) -> dict:
    """
    Ask Claude for analysis/reasoning. Used by quality and intel agents.

    Uses the model configured for the given agent (typically sonnet).
    Returns {"success": bool, "response": str, "error": str | None}
    """
    prompt = question
    if context:
        prompt = f"{context}\n\n{question}"

    return ask(
        prompt=prompt,
        agent_name=agent_name,
        allowed_tools=[],  # Pure reasoning
        max_turns=3,
        timeout_seconds=90,
    )


def ask_with_web_search(
    prompt: str,
    agent_name: str = "intel",
    system_prompt: str | None = None,
    timeout_seconds: int = 300,
) -> dict:
    """
    Ask Claude with web access via Bash(curl:*).

    In --print mode, Claude CLI only has built-in tools (Bash, Edit, Read,
    etc.) — not WebSearch/WebFetch. We allow Bash restricted to curl commands
    so Claude can fetch web pages for threat intel research.

    Timeout is 300s (5 min) because fetching + parsing HTML pages takes time.

    Returns {"success": bool, "response": str, "model": str, "error": str | None}
    """
    return ask(
        prompt=prompt,
        agent_name=agent_name,
        system_prompt=system_prompt,
        allowed_tools=["Bash(curl:*)"],
        max_turns=6,
        timeout_seconds=timeout_seconds,
    )
