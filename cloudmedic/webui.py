"""Local web demo (standard library only).

    python -m cloudmedic.webui            # http://127.0.0.1:8765
    python -m cloudmedic.webui --llm      # also allow LLM intent extraction from the ticket text
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .diagnose import diagnose
from .edits import apply_edits
from .eval.metrics import score
from .taxonomy import FAULT_CLASSES

SCN: dict = {}
LLM = None

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudMedic</title>
<style>
:root{--bg:#f7f7f5;--fg:#1d1d1f;--mut:#6b6b70;--card:#fff;--line:#e3e3e0;--ok:#1f8a4c;--bad:#c62f2f;--warn:#b7791f;--acc:#2856d6;--code:#f1f1ee}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececee;--mut:#9a9aa1;--card:#1d1d20;--line:#2e2e33;--ok:#4cc27c;--bad:#f06a6a;--warn:#e0aa4a;--acc:#7ea0ff;--code:#26262a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
h1{font-size:20px;margin:0}header p{margin:0;color:var(--mut)}
main{display:grid;grid-template-columns:320px 1fr;min-height:calc(100vh - 70px)}
@media(max-width:860px){main{grid-template-columns:1fr}}
aside{border-right:1px solid var(--line);padding:12px;overflow:auto;max-height:calc(100vh - 70px)}
aside input,aside select{width:100%;padding:8px;margin-bottom:8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
.item{padding:8px 10px;border-radius:8px;cursor:pointer;margin-bottom:2px}.item:hover,.item.on{background:var(--card)}
.item b{font-size:12px;color:var(--mut);font-weight:500}.item div{font-size:13px}
section{padding:20px 24px;overflow:auto}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:16px}
h2{font-size:15px;margin:0 0 10px}pre{background:var(--code);padding:12px;border-radius:8px;overflow:auto;font-size:12.5px;white-space:pre-wrap;margin:0}
.hop{display:grid;grid-template-columns:72px 190px 1fr;gap:8px;padding:6px 0;border-bottom:1px dashed var(--line);font-size:13px}
.st{font-weight:600}.pass{color:var(--ok)}.fail{color:var(--bad)}.partial{color:var(--warn)}.skip{color:var(--mut)}
.row{display:flex;gap:16px;flex-wrap:wrap}.row .card{flex:1;min-width:280px}
.big{font-size:26px;font-weight:650}.lbl{color:var(--mut);font-size:12px}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer}button:disabled{opacity:.5}
.pill{display:inline-block;padding:2px 8px;border-radius:99px;background:var(--code);font-size:12px;margin-right:6px}
</style></head><body>
<header><h1>CloudMedic</h1><p>Verified, least-privilege troubleshooting for AWS network and IAM faults</p></header>
<main><aside><input id="q" placeholder="Filter by class, template, text"><select id="mode"><option value="oracle">Intent: gold (benchmark)</option><option value="llm">Intent: extract from ticket with local LLM</option></select><div id="list"></div></aside>
<section id="out"><div class="card">Pick a ticket on the left.</div></section></main>
<script>
let all=[],cur=null;const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
fetch('/api/scenarios').then(r=>r.json()).then(d=>{all=d;draw()});
$('#q').oninput=draw;
function draw(){const q=$('#q').value.toLowerCase();$('#list').innerHTML=all.filter(s=>JSON.stringify(s).toLowerCase().includes(q)).slice(0,400).map(s=>
`<div class="item ${cur==s.id?'on':''}" onclick="pick('${s.id}')"><b>${s.id} · ${s.difficulty} · ${s.template}</b><div>${esc(s.subject)}</div></div>`).join('')}
function pick(id){cur=id;draw();fetch('/api/scenario?id='+id).then(r=>r.json()).then(s=>{
$('#out').innerHTML=`<div class="card"><h2>${esc(s.ticket.subject)}</h2><pre>${esc(s.ticket.body)}</pre><p style="margin-top:12px"><button id="go" onclick="run('${id}')">Diagnose</button></p></div><div id="res"></div>`})}
function hops(tr){return tr.map(c=>`<div class="hop"><span class="st ${c.status}">${c.status}</span><span>${c.id}</span><span>${esc(c.detail)}</span></div>`).join('')}
function stat(t,v,good){return `<div><div class="big" style="color:var(${good?'--ok':'--bad'})">${v}</div><div class="lbl">${t}</div></div>`}
function run(id){$('#go').disabled=true;$('#res').innerHTML='<div class="card">Diagnosing…</div>';
fetch('/api/diagnose',{method:'POST',body:JSON.stringify({id,mode:$('#mode').value})}).then(r=>r.json()).then(d=>{
if(d.error){$('#res').innerHTML=`<div class="card">${esc(d.error)}</div>`;return}
const lp=d.cloudmedic,nl=d.no_lp;
$('#res').innerHTML=`<div class="card"><h2>Extracted intent</h2><pre>${esc(JSON.stringify(d.intent))}</pre></div>
<div class="card"><h2>Path trace (${esc(d.symptom)})</h2>${hops(d.trace)}</div>
<div class="card"><h2>Root causes</h2>${d.root_causes.map((r,i)=>`<p><span class="pill">${i+1}</span><b>${r.fault_class}</b> on <code>${esc(r.resource)}</code><br><span class="lbl">${esc(r.explanation)}</span></p>`).join('')}
<p class="lbl">Gold: ${d.gold.map(g=>g.fault_class+' on '+g.resource).join(', ')}</p></div>
<div class="row"><div class="card"><h2>CloudMedic fix (least privilege)</h2><div class="row" style="gap:28px;margin-bottom:10px">${stat('fixes the ticket',lp.score.fix_success?'yes':'no',lp.score.fix_success)}${stat('excess privilege',lp.score.excess_total,lp.score.excess_total==0)}${stat('broken flows',lp.score.regression_lost,lp.score.regression_lost==0)}</div><pre>${esc(lp.fix.map(e=>JSON.stringify(e)).join('\n'))}</pre></div>
<div class="card"><h2>Same engine, edit-count only (ablation)</h2><div class="row" style="gap:28px;margin-bottom:10px">${stat('fixes the ticket',nl.score.fix_success?'yes':'no',nl.score.fix_success)}${stat('excess privilege',nl.score.excess_total,nl.score.excess_total==0)}${stat('broken flows',nl.score.regression_lost,nl.score.regression_lost==0)}</div><pre>${esc(nl.fix.map(e=>JSON.stringify(e)).join('\n'))}</pre><p class="lbl">${esc((nl.score.excess_examples||[]).join('  '))}</p></div></div>
<div class="card"><h2>Repair log</h2><pre>${esc(d.repair_log.join('\n'))}</pre></div>`;$('#go').disabled=false})}
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/api/scenarios":
            self._json([{"id": s["id"], "subject": s["ticket"]["subject"], "difficulty": s["difficulty"], "template": s["template"],
                         "classes": [l["fault_class"] for l in s["gold"]["labels"]]} for s in SCN.values()])
        elif u.path == "/api/scenario":
            s = SCN.get(parse_qs(u.query).get("id", [""])[0])
            self._json({"id": s["id"], "ticket": s["ticket"]} if s else {"error": "not found"})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
        s = SCN.get(req.get("id"))
        if not s:
            return self._json({"error": "unknown scenario"}, 404)
        intent = s["gold"]["intent"]
        if req.get("mode") == "llm":
            if LLM is None:
                return self._json({"error": "start the server with --llm to extract intents from ticket text"})
            from .systems import extract_intent
            intent, _ = extract_intent(s, LLM)
            if intent is None:
                return self._json({"error": "the language model could not produce a valid intent for this ticket"})
        d = diagnose(s["snapshot"], intent)
        nolp = diagnose(s["snapshot"], intent, least_privilege=False)
        out = {**{k: d[k] for k in ("intent", "symptom", "trace", "root_causes", "repair_log")},
               "gold": s["gold"]["labels"],
               "cloudmedic": {"fix": d["fix"], "score": score(s, {"root_causes": d["root_causes"], "fix": d["fix"]})},
               "no_lp": {"fix": nolp["fix"], "score": score(s, {"root_causes": nolp["root_causes"], "fix": nolp["fix"]})}}
        self._json(out)


def main():
    global LLM
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/test.jsonl")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--llm", action="store_true")
    a = ap.parse_args()
    for line in open(a.data):
        s = json.loads(line)
        SCN[s["id"]] = s
    if a.llm:
        from .llm.backend import MLXBackend
        LLM = MLXBackend("qwen2.5-7b")
    print(f"CloudMedic demo on http://127.0.0.1:{a.port}  ({len(SCN)} scenarios)")
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
