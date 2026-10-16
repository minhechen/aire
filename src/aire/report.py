"""Self-contained reports; package and model text is always escaped."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from .workspace import Workspace


def validate_report(report: dict, evidence: list[dict]) -> dict:
    report = dict(report)
    known = {item["id"]: item for item in evidence}
    claims = []
    invalid = 0
    for original in report.get("claims", []):
        if not isinstance(original, dict) or not isinstance(original.get("text"), str):
            invalid += 1
            continue
        claim = dict(original)
        refs = claim.get("evidence_ids", [])
        if not isinstance(refs, list):
            refs = []
        valid = [ref for ref in refs if isinstance(ref, str) and ref in known]
        supports = [ref for ref in valid if known[ref]["result"]["status"] in ("ok", "partial")]
        kind = claim.get("kind", "unknown")
        if kind not in ("observation", "inference", "unknown"):
            kind = "unknown"
        if len(valid) != len(refs) or (kind != "unknown" and not supports):
            kind = "unknown"
            invalid += 1
        claim.update(kind=kind, evidence_ids=valid)
        claims.append(claim)
    report["claims"] = claims
    report.setdefault("limitations", [])
    if invalid:
        report["status"] = "partial"
        report["limitations"] = [*report["limitations"],
            f"{invalid} claim(s) had missing, invalid, or unsuccessful evidence and were removed or marked unknown."]
        supported = [claim["text"] for claim in claims if claim["kind"] != "unknown"]
        report["summary"] = " ".join(supported[:3]) if supported else "Insufficient verified evidence; review the unresolved findings."
    report["validation"] = {"citations_checked": True,
                            "semantic_correctness_verified": False, "demoted_claims": invalid}
    return report


def export_case(workspace: Workspace, case_id: str, format: str = "html",
                output: Path | None = None) -> Path:
    case = workspace.case(case_id)
    evidence = workspace.evidence_for_case(case_id)
    report = validate_report(case["report"], evidence)
    project = workspace.project(case["project_id"])
    packet = {"schema_version": 1, "case_id": case_id, "project": project,
              "question": report.get("question", case["question"]), "report": report,
              "evidence": evidence}
    if format == "json":
        content = json.dumps(packet, ensure_ascii=False, indent=2) + "\n"
    elif format in ("md", "markdown"):
        format = "md"
        content = render_markdown(packet)
    elif format == "html":
        content = render_html(packet)
    else:
        raise ValueError("Report format must be html, md, or json")
    if output is None:
        output = workspace.root / "reports" / f"{case_id}.{format}"
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return output


def render_html(packet: dict) -> str:
    escape = lambda value: html.escape(str(value), quote=True)
    report = packet["report"]
    claims = []
    for claim in report.get("claims", []):
        refs = " ".join(f'<a href="#{escape(ref)}">{escape(ref)}</a>'
                        for ref in claim.get("evidence_ids", []))
        claims.append(f'<li class="claim"><span class="tag {escape(claim["kind"])}">'
                      f'{escape(claim["kind"])}</span><p>{escape(claim["text"])}</p>'
                      f'<div class="refs">{refs}</div></li>')
    evidence_parts = []
    for item in packet["evidence"]:
        evidence_parts.append(
            f'<details id="{escape(item["id"])}"><summary>{escape(item["id"])} · '
            f'{escape(item["tool"])} · {escape(item["result"]["status"])}</summary>'
            f'<p>Output SHA-256: <code>{escape(item["digest"])}</code></p>'
            f'<pre>{escape(json.dumps({"parameters": item["params"], "result": item["result"], "provenance": item["provenance"]}, ensure_ascii=False, indent=2))}</pre></details>'
        )
    limits = "".join(f"<li>{escape(value)}</li>" for value in report.get("limitations", []))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>aire · {escape(packet['question'])}</title>
<style>
:root{{color-scheme:dark;--bg:#0c111b;--card:#151d2b;--text:#e8edf5;--muted:#a8b7ce;--accent:#82d6c3}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.65 system-ui,sans-serif}}
main{{max-width:1000px;margin:auto;padding:48px 24px}}header{{border-bottom:1px solid #344155;padding-bottom:24px}}
.brand{{font-size:27px;letter-spacing:.1em;color:var(--accent)}}h1{{font-size:32px;line-height:1.3}}h2{{margin-top:38px}}
.meta,.refs{{font-size:13px;color:var(--muted);overflow-wrap:anywhere}}a{{color:var(--accent)}}
ul.claims{{padding:0;list-style:none}}.claim,details{{background:var(--card);padding:20px;margin:14px 0;border-radius:10px}}
.tag{{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--accent)}}.unknown{{color:#f4c477}}.inference{{color:#b7a2f0}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,monospace;color:#c7d7ec}}summary{{cursor:pointer}}
footer{{color:var(--muted);font-size:13px;margin-top:40px}}code{{overflow-wrap:anywhere}}
</style></head><body><main>
<header><div class="brand">aire</div><h1>{escape(packet['question'])}</h1>
<p>{escape(report.get('summary', 'Investigation in progress'))}</p>
<div class="meta">{escape(packet['project']['app_name'])} · {escape(packet['case_id'])} · {escape(report.get('status', 'partial'))}<br>
IPA SHA-256: {escape(packet['project']['input_sha256'])}</div></header>
<h2>Findings</h2><ul class="claims">{''.join(claims) or '<li>No supported findings yet.</li>'}</ul>
<h2>Limitations and unresolved questions</h2><ul>{limits or '<li>No additional limitations recorded.</li>'}</ul>
<h2>Evidence</h2>{''.join(evidence_parts)}
<footer>Citations are structurally checked. Semantic correctness requires review. Pseudocode is an approximate decompiler output, never original source. This report loads no external resources.</footer>
</main></body></html>"""


def render_markdown(packet: dict) -> str:
    def prose(value) -> str:
        return re.sub(r"([\\`*_{}\[\]()#+.!|>\-])", r"\\\1", html.escape(str(value), quote=True))

    report = packet["report"]
    parts = ["# aire investigation", "", prose(packet["question"]), "",
             prose(report.get("summary", "")), "", f"Status: {prose(report.get('status', 'partial'))}", "",
             f"IPA SHA-256: `{packet['project']['input_sha256']}`", "", "## Findings", ""]
    for claim in report.get("claims", []):
        refs = ", ".join(claim.get("evidence_ids", []))
        parts.extend([f"- **{claim['kind']}**: {prose(claim['text'])} ({refs})", ""])
    parts.extend(["## Limitations", ""])
    parts.extend("- " + prose(value) for value in report.get("limitations", []))
    parts.extend(["", "## Evidence", ""])
    for item in packet["evidence"]:
        payload = json.dumps(item, ensure_ascii=False, indent=2)
        fence = "`" * max(3, max((len(m.group()) + 1 for m in re.finditer(r"`+", payload)), default=3))
        parts.extend([f"### {item['id']}", "", fence + "json", payload, fence, ""])
    parts.extend(["Citation validity does not establish semantic correctness.", ""])
    return "\n".join(parts)
