from __future__ import annotations

import json
import mimetypes
import re
import webbrowser
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Timer
from typing import Any
from urllib.parse import unquote, urlparse

_RUN_ID = re.compile(r"^[A-Za-z0-9._-]+$")
_SECRET = re.compile(
    r"(api[_-]?key|authorization|password|secret|^(?:access_|refresh_|id_|auth_)?token$)",
    re.IGNORECASE,
)
_STAGES = (
    ("stage1_candidates", "Candidate localisation"),
    ("stage2_context", "Context enrichment"),
    ("stage3_hypotheses", "CWE hypotheses"),
    ("stage4_judge", "Vulnerability validation"),
    ("stage5_filter", "Finding filter"),
)


def _safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "***REDACTED***" if _SECRET.search(str(key)) else _safe(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_safe(item) for item in value]
    return value


def _json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return fallback


def _events(path: Path, limit: int = 300) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except OSError:
        return []
    output: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            output.append(_safe(value))
    return output


def _stage_state(
    events: list[dict[str, Any]], result: dict[str, Any]
) -> list[dict[str, Any]]:
    completed = {
        str(stage.get("name")): stage
        for stage in result.get("stages", [])
        if isinstance(stage, dict)
    }
    active = ""
    failed = ""
    for event in events:
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            continue
        event_type = event.get("type")
        stage = str(payload.get("stage") or "")
        if event_type == "stage_started" or payload.get("message") == "stage_started":
            active = stage
        if event_type == "stage_failed" or payload.get("message") == "stage_failed":
            failed = stage
            active = ""
        if (
            event_type == "stage_completed"
            or payload.get("message") == "stage_completed"
        ):
            if active == stage:
                active = ""
    states: list[dict[str, Any]] = []
    for index, (name, label) in enumerate(_STAGES, 1):
        stage = completed.get(name, {})
        status = "completed" if stage else "pending"
        if name == active:
            status = "running"
        if name == failed:
            status = "failed"
        states.append(
            {
                "index": index,
                "name": name,
                "label": label,
                "status": status,
                "duration_ms": float(stage.get("duration_ms") or 0),
                "metadata": _safe(stage.get("metadata", {})),
            }
        )
    return states


def _run_summary(run_dir: Path) -> dict[str, Any]:
    result = _json(run_dir / "result.json", {})
    config = _json(run_dir / "config.json", {})
    provenance = _json(run_dir / "provenance.json", {})
    events = _events(run_dir / "events.jsonl")
    stat = run_dir.stat()
    stages = _stage_state(events, result)
    status = str(result.get("status") or "running")
    pipeline = config.get("pipeline", {}) if isinstance(config, dict) else {}
    llm = config.get("llm", {}) if isinstance(config, dict) else {}
    findings = result.get("findings", []) if isinstance(result, dict) else []
    comments = result.get("comments", []) if isinstance(result, dict) else []
    active = next(
        (stage["label"] for stage in stages if stage["status"] == "running"), ""
    )
    return {
        "run_id": run_dir.name,
        "status": status,
        "updated_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
        "model": provenance.get("model") or llm.get("model") or "unknown",
        "provider": provenance.get("provider") or llm.get("provider") or "unknown",
        "threshold": pipeline.get("confidence_threshold"),
        "max_candidates": pipeline.get("max_candidates"),
        "findings": len(findings) if isinstance(findings, list) else 0,
        "comments": len(comments) if isinstance(comments, list) else 0,
        "active_stage": active,
        "completed_stages": sum(stage["status"] == "completed" for stage in stages),
        "error": _safe(result.get("error")) if isinstance(result, dict) else None,
    }


class RunStore:
    def __init__(self, repo: Path):
        self.repo = repo.resolve()
        self.runs = self.repo / ".agenticbughunter" / "runs"

    def list(self) -> list[dict[str, Any]]:
        if not self.runs.is_dir():
            return []
        values = [_run_summary(path) for path in self.runs.iterdir() if path.is_dir()]
        return sorted(values, key=lambda item: item["updated_at"], reverse=True)

    def detail(self, run_id: str) -> dict[str, Any]:
        if not _RUN_ID.fullmatch(run_id):
            raise FileNotFoundError(run_id)
        run_dir = (self.runs / run_id).resolve()
        if run_dir.parent != self.runs.resolve() or not run_dir.is_dir():
            raise FileNotFoundError(run_id)
        result = _safe(_json(run_dir / "result.json", {}))
        config = _safe(_json(run_dir / "config.json", {}))
        provenance = _safe(_json(run_dir / "provenance.json", {}))
        events = _events(run_dir / "events.jsonl")
        return {
            "summary": _run_summary(run_dir),
            "stages": _stage_state(events, result),
            "result": result,
            "config": config,
            "provenance": provenance,
            "events": events,
        }


class DashboardHandler(BaseHTTPRequestHandler):
    store: RunStore

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, value: Any, status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path == "/api/health":
            self._send_json({"ok": True, "repo": str(self.store.repo)})
            return
        if path == "/api/runs":
            self._send_json({"runs": self.store.list()})
            return
        if path.startswith("/api/runs/"):
            try:
                value = self.store.detail(path.removeprefix("/api/runs/"))
            except FileNotFoundError:
                self._send_json({"error": "run not found"}, 404)
                return
            self._send_json(value)
            return
        if path in {"/", "/index.html"}:
            self._send(200, "text/html; charset=utf-8", _HTML.encode("utf-8"))
            return
        content_type = mimetypes.guess_type(path)[0] or "text/plain"
        self._send(404, content_type, b"Not found")


def serve_dashboard(
    repo: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> None:
    root = Path(repo).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Repository not found: {root}")
    handler = type(
        "BoundDashboardHandler", (DashboardHandler,), {"store": RunStore(root)}
    )
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_port}"
    print(f"AgenticBugHunter dashboard: {url}")
    print(f"Watching: {root / '.agenticbughunter' / 'runs'}")
    if open_browser:
        Timer(0.25, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgenticBugHunter</title><style>
:root{color-scheme:dark;--bg:#070a0e;--panel:#10151d;--panel2:#151c25;--line:#26303d;--text:#eef4f8;--muted:#8996a5;--cyan:#52e5c4;--blue:#699cff;--amber:#ffbd66;--red:#ff6b7a;--green:#62e69a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#173049 0,transparent 35%),radial-gradient(circle at -10% 80%,#12352e 0,transparent 30%),var(--bg);font:14px/1.5 Inter,ui-sans-serif,system-ui;color:var(--text);min-height:100vh}button{font:inherit}.shell{max-width:1480px;margin:auto;padding:28px}.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}.brand{display:flex;align-items:center;gap:13px}.mark{width:42px;height:42px;border:1px solid #3a776c;border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,#18362f,#101820);box-shadow:0 0 30px #35e8c31f;font-weight:900;color:var(--cyan)}h1{font-size:18px;margin:0;letter-spacing:.02em}.subtitle{color:var(--muted);font-size:12px}.live{display:flex;gap:8px;align-items:center;color:var(--muted)}.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green)}.layout{display:grid;grid-template-columns:350px 1fr;gap:18px;min-height:720px}.panel{background:linear-gradient(160deg,#131922ef,#0d1219ed);border:1px solid var(--line);border-radius:17px;box-shadow:0 18px 60px #0006;overflow:hidden}.side-head,.detail-head{padding:18px 20px;border-bottom:1px solid var(--line)}.side-head{display:flex;justify-content:space-between}.count{color:var(--muted)}#runs{max-height:780px;overflow:auto}.run{width:100%;text-align:left;color:inherit;border:0;border-bottom:1px solid #202936;background:transparent;padding:16px 20px;cursor:pointer;transition:.16s}.run:hover,.run.active{background:#18212b}.run.active{box-shadow:inset 3px 0 var(--cyan)}.run-top{display:flex;justify-content:space-between;gap:8px}.run-id{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.meta{color:var(--muted);font-size:12px;margin-top:7px;display:flex;gap:9px}.badge{font-size:10px;text-transform:uppercase;letter-spacing:.08em;padding:3px 7px;border-radius:99px;background:#26303d;color:#dce5ed}.badge.running{background:#173d3a;color:var(--cyan)}.badge.pass{background:#173b28;color:var(--green)}.badge.block{background:#4a3518;color:var(--amber)}.badge.error{background:#471d25;color:var(--red)}.empty{padding:60px 25px;text-align:center;color:var(--muted)}.detail-head{display:flex;justify-content:space-between;align-items:flex-start}.detail-head h2{font-size:21px;margin:0 0 4px}.detail-head .id{font:12px ui-monospace,SFMono-Regular;color:var(--muted)}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border-bottom:1px solid var(--line)}.metric{background:#111720;padding:17px 20px}.metric b{font-size:23px;display:block}.metric span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.content{padding:20px}.section{margin-bottom:26px}.section h3{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:#a8b4c0;margin:0 0 12px}.stages{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.stage{border:1px solid var(--line);background:var(--panel2);border-radius:12px;padding:13px;min-height:100px}.stage .n{font-size:10px;color:var(--muted)}.stage strong{display:block;margin:7px 0;font-size:12px}.stage.completed{border-color:#295d4c}.stage.running{border-color:var(--cyan);box-shadow:0 0 20px #52e5c41a}.stage.failed{border-color:var(--red)}.bar{height:3px;background:#27313c;border-radius:3px;margin-top:11px;overflow:hidden}.bar i{display:block;height:100%;background:var(--cyan);width:0}.stage.completed .bar i{width:100%}.stage.running .bar i{width:45%;animation:pulse 1.2s infinite alternate}@keyframes pulse{to{width:78%}}.findings{display:grid;gap:10px}.finding{border:1px solid var(--line);border-radius:12px;padding:14px;background:#111821}.finding-top{display:flex;gap:9px;align-items:center}.score{color:var(--amber);font-weight:800}.path{font:12px ui-monospace,SFMono-Regular;color:var(--blue)}.comment{margin-top:8px;color:#c7d1da}.events{max-height:230px;overflow:auto;border:1px solid var(--line);border-radius:12px;background:#090d12;font:11px/1.7 ui-monospace,SFMono-Regular}.event{padding:7px 11px;border-bottom:1px solid #192029;display:grid;grid-template-columns:170px 130px 1fr;gap:8px}.event time,.event .type{color:var(--muted)}.errorbox{border:1px solid #71313a;background:#2b161a;color:#ffb9c1;padding:12px;border-radius:10px;margin-bottom:18px}@media(max-width:900px){.shell{padding:14px}.layout{grid-template-columns:1fr}.summary{grid-template-columns:repeat(2,1fr)}.stages{grid-template-columns:1fr}.event{grid-template-columns:1fr}.panel:first-child{max-height:320px}}
</style></head><body><main class="shell"><header class="top"><div class="brand"><div class="mark">ABH</div><div><h1>AgenticBugHunter</h1><div class="subtitle">Secure review observatory</div></div></div><div class="live"><i class="dot"></i><span id="sync">Live</span></div></header><div class="layout"><aside class="panel"><div class="side-head"><strong>Runs</strong><span class="count" id="count">0</span></div><div id="runs"><div class="empty">Waiting for run data…</div></div></aside><section class="panel" id="detail"><div class="empty">Select a run to inspect its pipeline.</div></section></div></main><script>
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let selected='';
const when=s=>{if(!s)return '—';const d=new Date(s),sec=Math.max(0,(Date.now()-d)/1000);return sec<60?Math.floor(sec)+'s ago':sec<3600?Math.floor(sec/60)+'m ago':d.toLocaleString()};
async function api(path){const r=await fetch(path);if(!r.ok)throw Error(await r.text());return r.json()}
function runRow(r){return `<button class="run ${r.run_id===selected?'active':''}" data-id="${esc(r.run_id)}"><div class="run-top"><span class="run-id">${esc(r.run_id)}</span><span class="badge ${esc(r.status)}">${esc(r.status)}</span></div><div class="meta"><span>${esc(r.model)}</span><span>${r.completed_stages}/5 stages</span><span>${when(r.updated_at)}</span></div>${r.active_stage?`<div class="meta">Running · ${esc(r.active_stage)}</div>`:''}</button>`}
async function refreshRuns(){try{const d=await api('/api/runs');document.querySelector('#count').textContent=d.runs.length;document.querySelector('#runs').innerHTML=d.runs.length?d.runs.map(runRow).join(''):'<div class="empty">No runs yet.<br>Start a review to see it here.</div>';document.querySelectorAll('.run').forEach(x=>x.onclick=()=>{selected=x.dataset.id;refreshRuns();refreshDetail()});if(!selected&&d.runs[0]){selected=d.runs[0].run_id;refreshDetail()}document.querySelector('#sync').textContent='Live · '+new Date().toLocaleTimeString()}catch(e){document.querySelector('#sync').textContent='Disconnected'}}
function findingCard(f){const score=f.final_score??f.score??f.assessment?.score;return `<article class="finding"><div class="finding-top"><span class="badge block">${esc(f.cwe_id||'Finding')}</span>${score!=null?`<span class="score">${(Number(score)*100).toFixed(0)}%</span>`:''}<span class="path">${esc(f.filepath)}:${esc(f.changed_line)}</span></div><div class="comment">${esc(f.review_comment||f.statement||'No review comment')}</div></article>`}
async function refreshDetail(){if(!selected)return;try{const d=await api('/api/runs/'+encodeURIComponent(selected)),s=d.summary,r=d.result||{},findings=Array.isArray(r.findings)?r.findings:[],events=d.events.slice(-40).reverse();document.querySelector('#detail').innerHTML=`<div class="detail-head"><div><h2>${esc(s.model)}</h2><div class="id">${esc(s.run_id)}</div></div><span class="badge ${esc(s.status)}">${esc(s.status)}</span></div><div class="summary"><div class="metric"><b>${s.completed_stages}/5</b><span>Stages</span></div><div class="metric"><b>${s.findings}</b><span>Findings</span></div><div class="metric"><b>${s.comments}</b><span>Comments</span></div><div class="metric"><b>${s.threshold??'—'}</b><span>Threshold</span></div></div><div class="content">${s.error?`<div class="errorbox"><strong>${esc(s.error.type||'Error')}</strong><br>${esc(s.error.message||s.error)}</div>`:''}<div class="section"><h3>Pipeline</h3><div class="stages">${d.stages.map(x=>`<div class="stage ${x.status}"><span class="n">0${x.index}</span><strong>${esc(x.label)}</strong><span class="badge ${x.status==='running'?'running':''}">${esc(x.status)}</span><div class="bar"><i></i></div><div class="meta">${x.duration_ms?`${(x.duration_ms/1000).toFixed(1)}s`:''}</div></div>`).join('')}</div></div><div class="section"><h3>Findings</h3><div class="findings">${findings.length?findings.map(findingCard).join(''):'<div class="empty">No supported findings in this run.</div>'}</div></div><div class="section"><h3>Recent events</h3><div class="events">${events.length?events.map(e=>`<div class="event"><time>${esc(e.timestamp)}</time><span class="type">${esc(e.type)}</span><span>${esc(e.payload?.message||e.payload?.stage||JSON.stringify(e.payload||{}))}</span></div>`).join(''):'<div class="empty">No events recorded yet.</div>'}</div></div></div>`}catch(e){document.querySelector('#detail').innerHTML='<div class="empty">Unable to load this run.</div>'}}
refreshRuns();setInterval(()=>{refreshRuns();refreshDetail()},2000);
</script></body></html>"""
