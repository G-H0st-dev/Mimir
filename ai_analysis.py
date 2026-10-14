"""
ai_analysis.py — an entirely optional narrative-analysis layer on top of
a scan's already-collected, verified data. Everything else in this app
works identically whether or not this feature is configured at all;
nothing here is ever called automatically from the main scan pipeline
or the Company/Vulnerability modules.

Talks to any OpenAI-compatible chat-completions endpoint — confirmed
directly that Ollama (running locally), Groq, OpenRouter, and most
other providers all speak the same request/response shape, so this is
one generic client, not per-provider code. Configuration is just a base
URL, an optional API key (Ollama needs none), and a model name — see
core.get_ai_config()/set_ai_config().

The prompt this builds is deliberately constrained: it only ever
includes real, already-verified findings from this scan (vulnerability/
leak counts, company profile facts, pages the company's own site
reviewed, tech stack, employees found), and explicitly instructs the
model not to invent additional facts about the target. The output is
reasoning *about* that data — a threat-modeling narrative — not a new
source of facts, and is always stored and displayed with a clear
AI-generated label so it can never be mistaken for the rest of this
app's sourced, verified findings.
"""

import asyncio
import json
import urllib.error
import urllib.request
from typing import Optional

from core import get_ai_config, get_db, log_line, now_iso, store_intel


def _post_chat_completion(base_url: str, api_key: Optional[str], model: str, system_prompt: str, user_prompt: str, timeout: int = 120) -> str:
    """Raw call to POST {base_url}/chat/completions. Timeout is
    deliberately generous — local inference on modest hardware can
    genuinely take a couple of minutes for a longer analysis, and this
    is always a manually-triggered action, never something blocking an
    automatic scan step."""
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"HTTP {e.code} from {base_url}: {body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"couldn't reach {base_url}: {e.reason}")
    except json.JSONDecodeError:
        raise RuntimeError(f"{base_url} didn't return valid JSON — is this genuinely an OpenAI-compatible endpoint?")

    # Defensive parsing — this is a de facto standard, not a guaranteed
    # one; most providers match it, but not verified against every
    # possible provider, so a mismatch here should be a clear error,
    # not a crash.
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(
            f"{base_url}'s response didn't match the expected OpenAI-compatible shape "
            f"(choices[0].message.content) — got: {json.dumps(data)[:300]}"
        )


def check_ai_configured() -> bool:
    return get_ai_config() is not None


SYSTEM_PROMPT = """You are assisting a security researcher by reasoning about attack-surface data already collected for a specific scan. You will be given a structured summary of real, verified findings — do not treat this as an invitation to invent additional facts about the organization that aren't in the data provided.

Your job is to produce a threat-modeling narrative that helps a human analyst think through the implications of what was found: which finding types matter most together, what a realistic attacker might prioritize given this specific combination of findings, and what a defender should look at first. Reason from the data given — do not assert specific incidents, breaches, or events that aren't in the provided findings, and do not claim external threat-intelligence context (named threat actor groups, regional crime statistics) unless it's common, well-established public knowledge you're confident in and you clearly flag it as general background rather than something specific to this organization.

Write in clear, direct prose, organized under these headings: "Overall assessment", "What matters most here", "How an attacker might approach this", "What to prioritize". Be honest if the findings are sparse — a short, honest analysis is more useful than padding. Do not fabricate confidence you don't have."""


def build_analysis_prompt(scan_data: dict) -> str:
    """Builds the user-facing prompt from a scan's already-collected
    data — every line here traces to something this app itself found or
    was told during a Company/Vulnerability run, never invented."""
    lines = [f"Target domain: {scan_data['domain']}"]

    if scan_data.get("company_name"):
        lines.append(f"Company (from public record): {scan_data['company_name']}")
    if scan_data.get("industry"):
        lines.append(f"Industry (from public record): {scan_data['industry']}")
    if scan_data.get("employee_count"):
        lines.append(f"Employees found (via CrossLinked/LinkedIn search): {scan_data['employee_count']}")
    if scan_data.get("pages_reviewed"):
        lines.append(f"Company's own pages reviewed: {', '.join(scan_data['pages_reviewed'])}")
    if scan_data.get("compliance_mentions"):
        lines.append(f"Compliance frameworks the company's own Privacy/Terms pages mention: {scan_data['compliance_mentions']}")

    lines.append(f"\nHosts discovered: {scan_data.get('host_count', 0)}")
    lines.append(f"Live web assets: {scan_data.get('live_asset_count', 0)}")
    lines.append(f"Open ports: {scan_data.get('port_count', 0)}")

    vuln_summary = scan_data.get("vulnerability_summary")
    if vuln_summary:
        lines.append(f"\nVulnerability findings: {vuln_summary}")
    else:
        lines.append("\nVulnerability findings: none (or the Vulnerability module hasn't been run for this scan)")

    if scan_data.get("leak_summary"):
        lines.append(f"Breach/leak findings: {scan_data['leak_summary']}")
    else:
        lines.append("Breach/leak findings: none found")

    if scan_data.get("tech_stack"):
        lines.append(f"\nDetected technology stack: {scan_data['tech_stack']}")

    return "\n".join(lines)


async def generate_ai_analysis(scan_id: int, scan_data: dict) -> dict:
    """Returns {ok: bool, error: str|None}. Storing the result is this
    function's job, not the caller's — on success it writes the
    narrative plus generation metadata (model, timestamp) so the
    frontend can always show exactly what generated it, right next to
    the content itself."""
    config = get_ai_config()
    if not config:
        return {"ok": False, "error": "AI analysis isn't configured — see Settings."}

    await log_line(scan_id, f"[ai] generating analysis via {config['base_url']} ({config['model']})...", "meta")
    user_prompt = build_analysis_prompt(scan_data)

    try:
        narrative = await _run_completion_async(config["base_url"], config["api_key"], config["model"], SYSTEM_PROMPT, user_prompt)
    except Exception as e:
        await log_line(scan_id, f"[ai] generation failed: {e}", "warn")
        return {"ok": False, "error": str(e)}

    conn = get_db()
    store_intel(conn, scan_id, scan_data["domain"], "ai_analysis", "narrative", narrative)
    store_intel(conn, scan_id, scan_data["domain"], "ai_analysis", "generated_at", now_iso())
    store_intel(conn, scan_id, scan_data["domain"], "ai_analysis", "model", f"{config['model']} @ {config['base_url']}")
    conn.commit()
    conn.close()
    await log_line(scan_id, "[+] ai: analysis generated and saved", "meta")
    return {"ok": True, "error": None}


async def _run_completion_async(base_url, api_key, model, system_prompt, user_prompt) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _post_chat_completion(base_url, api_key, model, system_prompt, user_prompt))
