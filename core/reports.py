"""core/reports.py — All four report formats (HTML, PDF, JSON, TXT) with multi-chart support."""
from __future__ import annotations
import html, json, os, re, textwrap
from datetime import datetime, timezone
from typing import Dict, Optional
from core.owasp_mapping import OWASP_TOP_10_2021, all_owasp_ids
from core import database as db
from config import SEVERITY_ORDER, REPORTS_DIR

SEV_COLORS = {"Critical":"#ff003c","High":"#ff6600","Medium":"#ffe600",
               "Low":"#00e5ff","Info":"#5a6e82"}

# ── Domain slug for folder naming ────────────────────────────────────
def _domain_slug(scan_id: str) -> str:
    scan = db.get_scan(scan_id)
    if scan and scan.get("target"):
        target = scan["target"]
        url = target.split("//")[-1]
        domain = url.split("/")[0].split(":")[0]
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
        return slug[:40] if slug else scan_id[:16]
    return scan_id[:16]

# ── Context builder ──────────────────────────────────────────────────
def build_context(scan_id: str) -> Optional[Dict]:
    scan = db.get_scan(scan_id)
    if not scan: return None
    findings = db.get_findings(scan_id)
    sev_counts = db.severity_counts(scan_id)
    cat_counts = db.category_counts(scan_id)
    owasp_raw  = db.owasp_counts(scan_id)
    owasp_matrix = []
    for oid in all_owasp_ids():
        info = OWASP_TOP_10_2021[oid]
        counts = owasp_raw.get(oid, {})
        total  = sum(counts.values())
        highest = next((s for s in SEVERITY_ORDER if counts.get(s,0)>0), None)
        owasp_matrix.append({"id":oid,"name":info["name"],"summary":info["summary"],
                              "total":total,"highest_severity":highest,
                              "highest_color":SEV_COLORS.get(highest,"#1a3a5c") if highest else "#1a3a5c",
                              "counts":counts})
    # Chart data for HTML/PDF reports
    cat_by_sev: Dict[str, Dict[str,int]] = {}
    confidence_buckets = [0]*10
    for f in findings:
        cat = f.get("category","Unknown")
        sev = f.get("severity","Info")
        if cat not in cat_by_sev:
            cat_by_sev[cat] = {s:0 for s in SEVERITY_ORDER}
        cat_by_sev[cat][sev] = cat_by_sev[cat].get(sev,0)+1
        conf = float(f.get("confidence") or 0)
        confidence_buckets[min(int(conf*10),9)] += 1

    duration = None
    try:
        st = datetime.fromisoformat(scan["started_at"].replace("Z","+00:00"))
        ft = scan.get("finished_at")
        if ft: duration = (datetime.fromisoformat(ft.replace("Z","+00:00"))-st).total_seconds()
    except: pass
    return {"scan":scan,"findings":findings,"total_findings":sum(sev_counts.values()),
            "severity_counts":{s:sev_counts.get(s,0) for s in SEVERITY_ORDER},
            "category_counts":cat_counts,"owasp_matrix":owasp_matrix,
            "owasp_raw":owasp_raw,
            "duration_seconds":duration,"severity_colors":SEV_COLORS,
            "severity_order":SEVERITY_ORDER,
            "categories":sorted({f["category"] for f in findings}),
            "cat_by_sev":cat_by_sev,
            "confidence_buckets":confidence_buckets,
            "generated_at":datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

def ensure_dir(scan_id: str) -> str:
    domain = _domain_slug(scan_id)
    d = os.path.join(REPORTS_DIR, domain, scan_id[:8])
    os.makedirs(d, exist_ok=True)
    return d

# ── JSON ─────────────────────────────────────────────────────────────
def generate_json(ctx: Dict, path: str) -> str:
    scan = dict(ctx.get("scan") or {})
    try: scan["config"] = json.loads(scan.pop("config_json","{}") or "{}")
    except: pass
    out = {"report_type":"Web Application Vulnerability Scan",
           "generated_at":ctx["generated_at"],
           "scan":scan,
           "summary":{"total":ctx["total_findings"],"severity":ctx["severity_counts"],
                       "categories":ctx["category_counts"],"duration_s":ctx["duration_seconds"]},
           "owasp_top10":ctx["owasp_matrix"],
           "findings":ctx["findings"]}
    with open(path,"w",encoding="utf-8") as f:
        json.dump(out,f,indent=2,default=str,ensure_ascii=False)
    return path

# ── TXT ──────────────────────────────────────────────────────────────
def generate_txt(ctx: Dict, path: str) -> str:
    LINE, SUB = "="*80, "-"*80
    def w(t): return "\n".join("      "+l for l in textwrap.wrap(str(t or ""),72)) or "      (none)"
    scan = ctx.get("scan") or {}
    lines = [LINE," WEB APPLICATION VULNERABILITY SCAN REPORT",LINE,
             f"Target:   {scan.get('target','N/A')}",
             f"Scan ID:  {scan.get('scan_id','N/A')}",
             f"Status:   {scan.get('status','N/A')}",
             f"Started:  {scan.get('started_at','N/A')}",
             f"Finished: {scan.get('finished_at','N/A')}",
             f"Duration: {ctx['duration_seconds']:.1f}s" if ctx["duration_seconds"] else "Duration: -",
             f"Generated:{ctx['generated_at']}",""]
    lines += [SUB," SUMMARY",SUB,f"Total Findings: {ctx['total_findings']}"]
    for s in SEVERITY_ORDER:
        lines.append(f"  {s:<10} {ctx['severity_counts'].get(s,0)}")
    lines += ["",SUB," OWASP TOP 10 (2021)",SUB]
    for e in ctx["owasp_matrix"]:
        lines.append(f"{e['id']:<10} {e['name']:<40} {e['total']} finding(s) | highest: {e['highest_severity'] or '-'}")
    lines += ["",SUB," FINDINGS",SUB]
    for i,f in enumerate(ctx["findings"],1):
        lines += ["",f"[{i}] {f['severity'].upper()} — {f['category']} / {f['subtype']}",
                  f"    OWASP: {f['owasp_id']} {f['owasp_name']}" + (f" | {f['cwe']}" if f.get('cwe') else ""),
                  f"    URL: {f['url']}"]
        if f.get("parameter"): lines.append(f"    Parameter: {f['parameter']} ({f['method']})")
        if f.get("payload"):   lines.append(f"    Payload: {f['payload']}")
        lines += [f"    Confidence: {f['confidence']:.0%}","","    Description:"]
        lines.append(w(f.get("description","")))
        lines += ["","    Evidence:"]
        lines.append(w(f.get("evidence","")))
        lines += ["","    Remediation:"]
        lines.append(w(f.get("remediation","")))
        lines.append(SUB)
    with open(path,"w",encoding="utf-8") as fh:
        fh.write("\n".join(lines)+"\n")
    return path

# ── HTML ─────────────────────────────────────────────────────────────
_HTML_CHARTS_JS = """
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
(function(){
  var SEV_COLORS = {Critical:'#ff003c',High:'#ff6600',Medium:'#ffe600',Low:'#00e5ff',Info:'#5a6e82'};
  var sevOrder = ['Critical','High','Medium','Low','Info'];
  var chartBg = 'rgba(0,0,0,0)';
  Chart.defaults.color = '#c8d6e5';
  Chart.defaults.borderColor = 'rgba(0,229,255,0.1)';

  // 1. Severity Donut
  var sdEl = document.getElementById('chart-sev-donut');
  if(sdEl) {
    var sd = JSON.parse(sdEl.dataset.counts);
    new Chart(sdEl, { type:'doughnut', data:{
      labels: sevOrder, datasets:[{data: sevOrder.map(s=>sd[s]||0),
        backgroundColor: sevOrder.map(s=>SEV_COLORS[s]),
        borderColor: '#030509', borderWidth:2, hoverOffset:8}]},
      options:{responsive:true, plugins:{legend:{position:'right',
        labels:{font:{size:11},padding:12}},
        tooltip:{callbacks:{label:function(c){return c.label+': '+c.raw+' ('+Math.round(c.percent)+'%)';}}}},
        cutout:'62%'}});
  }

  // 2. OWASP Horizontal Bar
  var owEl = document.getElementById('chart-owasp-bar');
  if(owEl) {
    var od = JSON.parse(owEl.dataset.counts);
    var owaspIds = JSON.parse(owEl.dataset.ids);
    var stacks = sevOrder.map(function(sev){
      return { label:sev, data:owaspIds.map(function(id){ return (od[id]||{})[sev]||0; }),
        backgroundColor:SEV_COLORS[sev], borderColor:SEV_COLORS[sev], borderWidth:0, borderRadius:2 };
    });
    new Chart(owEl, { type:'bar', data:{labels:owaspIds, datasets:stacks},
      options:{indexAxis:'y', responsive:true, scales:{
        x:{stacked:true,grid:{color:'rgba(0,229,255,0.07)'},ticks:{precision:0}},
        y:{stacked:true,grid:{display:false},ticks:{font:{family:'Share Tech Mono',size:10}}}},
        plugins:{legend:{position:'top',labels:{font:{size:10},padding:10}}}}});
  }

  // 3. Risk Matrix (Heatmap) — custom canvas
  var rmEl = document.getElementById('chart-risk-matrix');
  if(rmEl) {
    var rmd = JSON.parse(rmEl.dataset.owasp);
    var owaspIds2 = JSON.parse(rmEl.dataset.ids);
    var ctx = rmEl.getContext('2d');
    var cellW = (rmEl.width-80)/owaspIds2.length, cellH = 36;
    var rows = sevOrder.slice(0,-1); // no Info row
    rmEl.height = rows.length*cellH+60;
    ctx.fillStyle = '#030509'; ctx.fillRect(0,0,rmEl.width,rmEl.height);
    ctx.font = '10px Share Tech Mono'; ctx.textAlign='center'; ctx.textBaseline='middle';
    // Column labels
    ctx.fillStyle='rgba(0,229,255,0.6)';
    owaspIds2.forEach(function(id,i){
      ctx.fillText(id.split(':')[0],80+i*cellW+cellW/2,12);
    });
    // Row labels + cells
    rows.forEach(function(sev,ri){
      var y=30+ri*cellH;
      ctx.fillStyle=SEV_COLORS[sev]; ctx.textAlign='right';
      ctx.fillText(sev,74,y+cellH/2);
      owaspIds2.forEach(function(id,ci){
        var val=(rmd[id]||{})[sev]||0;
        var x=80+ci*cellW;
        var alpha=val>0?Math.min(0.2+val*0.25,0.95):0.04;
        ctx.fillStyle=val>0?SEV_COLORS[sev].replace('#','rgba(')+',' +alpha+')':'rgba(255,255,255,0.03)';
        // parse hex to rgb
        var r=parseInt(SEV_COLORS[sev].slice(1,3),16),g=parseInt(SEV_COLORS[sev].slice(3,5),16),b=parseInt(SEV_COLORS[sev].slice(5,7),16);
        ctx.fillStyle='rgba('+r+','+g+','+b+','+alpha+')';
        ctx.fillRect(x+1,y+1,cellW-2,cellH-2);
        if(val>0){ctx.fillStyle='#fff';ctx.textAlign='center';ctx.font='bold 11px Share Tech Mono';ctx.fillText(val,x+cellW/2,y+cellH/2);ctx.font='10px Share Tech Mono';}
      });
    });
  }

  // 4. Stacked Bar — Category × Severity
  var cbEl = document.getElementById('chart-cat-stacked');
  if(cbEl) {
    var cbd = JSON.parse(cbEl.dataset.catbysev);
    var cats = Object.keys(cbd);
    var stacks2 = sevOrder.map(function(sev){
      return { label:sev, data:cats.map(function(c){ return (cbd[c]||{})[sev]||0; }),
        backgroundColor:SEV_COLORS[sev], borderWidth:0, borderRadius:3 };
    });
    new Chart(cbEl, { type:'bar', data:{labels:cats, datasets:stacks2},
      options:{responsive:true, scales:{
        x:{stacked:true,grid:{color:'rgba(0,229,255,0.07)'},ticks:{font:{size:10}}},
        y:{stacked:true,grid:{color:'rgba(0,229,255,0.07)'},ticks:{precision:0}}},
        plugins:{legend:{position:'top',labels:{font:{size:10},padding:8}}}}});
  }

  // 5. Confidence Histogram
  var chEl = document.getElementById('chart-conf-hist');
  if(chEl) {
    var chd = JSON.parse(chEl.dataset.buckets);
    var labels = ['0-10%','10-20%','20-30%','30-40%','40-50%','50-60%','60-70%','70-80%','80-90%','90-100%'];
    new Chart(chEl, { type:'bar', data:{labels:labels, datasets:[{
      label:'Findings', data:chd,
      backgroundColor:'rgba(0,229,255,0.5)', borderColor:'#00e5ff', borderWidth:1, borderRadius:4}]},
      options:{responsive:true, scales:{
        x:{grid:{display:false},ticks:{font:{size:9}}},
        y:{grid:{color:'rgba(0,229,255,0.07)'},ticks:{precision:0}}},
        plugins:{legend:{display:false},title:{display:true,text:'Confidence Distribution',color:'#c8d6e5',font:{size:11}}}}});
  }

  // 6. Technique / Subtype Donut
  var tdEl = document.getElementById('chart-tech-donut');
  if(tdEl) {
    var tdd = JSON.parse(tdEl.dataset.techs);
    var techLabels=Object.keys(tdd), techVals=Object.values(tdd);
    var palette=['#ff003c','#ff6600','#ffe600','#00e5ff','#00ff41','#a855f7','#ec4899','#14b8a6','#f97316','#3b82f6'];
    new Chart(tdEl, { type:'doughnut', data:{labels:techLabels,datasets:[{
      data:techVals, backgroundColor:palette.slice(0,techLabels.length),
      borderColor:'#030509', borderWidth:2}]},
      options:{responsive:true, plugins:{legend:{position:'right',labels:{font:{size:10},padding:8}}}, cutout:'55%'}});
  }
})();
</script>
"""

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vuln Report — {target}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
:root{{--bg:#030509;--s:#0b1120;--s2:#0f1929;--bd:#0f2540;--bdb:#1a3a5c;
      --green:#00ff41;--cyan:#00e5ff;--red:#ff003c;--orange:#ff6600;--yellow:#ffe600;--info:#5a6e82;
      --text:#c8d6e5;--tb:#e8f4fd;--tm:#4a6077;--mono:'Share Tech Mono',monospace;--ui:'Rajdhani',sans-serif;}}
*{{box-sizing:border-box;}}body{{margin:0;font-family:var(--ui);background:var(--bg);color:var(--text);font-size:15px;
background-image:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,.012) 2px,rgba(0,255,65,.012) 4px);}}
a{{color:var(--cyan);text-decoration:none;}}code{{font-family:var(--mono);background:var(--s2);border:1px solid var(--bd);
color:var(--green);border-radius:4px;padding:2px 7px;font-size:.85em;}}
.wrap{{max-width:1200px;margin:0 auto;padding:0 24px 80px;}}
header{{background:linear-gradient(135deg,#060d1a,#030509);border-bottom:2px solid var(--bd);padding:28px 0;}}
.hdr{{max-width:1200px;margin:0 auto;padding:0 24px;display:flex;flex-wrap:wrap;gap:20px;justify-content:space-between;align-items:flex-end;}}
.htitle{{font-size:1.6rem;font-weight:700;color:var(--tb);margin:0 0 4px;}}
.htitle .g{{color:var(--green);text-shadow:0 0 12px #00ff4166;}}
.htarget{{font-family:var(--mono);font-size:.88rem;color:var(--cyan);word-break:break-all;}}
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px 20px;text-align:right;}}
.ml{{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;color:var(--tm);margin-bottom:2px;}}
.mv{{font-size:.86rem;font-weight:700;font-family:var(--mono);}}
.chip{{display:inline-block;padding:3px 12px;border-radius:2px;font-family:var(--mono);font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;border:1px solid;}}
.chip-completed{{color:var(--green);background:#001a09;border-color:var(--green);}}
.chip-failed{{color:var(--red);background:#1a000a;border-color:var(--red);}}
section{{padding:24px 0;border-bottom:1px solid var(--bd);}}
h2.st{{font-size:.7rem;text-transform:uppercase;letter-spacing:.14em;color:var(--cyan);font-weight:700;margin:0 0 14px;font-family:var(--ui);}}.st::before{{content:'// ';color:var(--tm);font-family:var(--mono);}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;}}
.sb{{background:var(--s2);border:1px solid var(--bd);border-radius:6px;padding:14px;position:relative;overflow:hidden;}}
.sb::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:var(--ac,var(--green));box-shadow:0 0 8px var(--ac,var(--green));}}
.sb .num{{font-family:var(--mono);font-size:1.8rem;font-weight:700;color:var(--ac,var(--green));text-shadow:0 0 12px var(--ac,var(--green));line-height:1;}}
.sb .lbl{{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--tm);margin-top:5px;}}
.sev-cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin-bottom:10px;}}
.sc{{border-radius:6px;padding:10px 12px;border:1px solid var(--bd);background:var(--s2);border-top:3px solid var(--c);}}
.sc .num{{font-family:var(--mono);font-size:1.5rem;font-weight:800;color:var(--c);text-shadow:0 0 10px var(--c);}}
.sc .lbl{{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;color:var(--tm);}}
.sev-bar{{display:flex;height:6px;border-radius:999px;overflow:hidden;background:var(--s2);border:1px solid var(--bd);gap:1px;}}
.seg{{height:100%;}}
.badge{{display:inline-block;font-size:.65rem;font-weight:700;padding:3px 9px;border-radius:2px;text-transform:uppercase;letter-spacing:.06em;font-family:var(--mono);}}
.sev-critical{{background:#1a000a;color:var(--red);border:1px solid var(--red);text-shadow:0 0 8px #ff003c88;}}
.sev-high{{background:#1a0900;color:var(--orange);border:1px solid var(--orange);}}
.sev-medium{{background:#1a1500;color:var(--yellow);border:1px solid var(--yellow);}}
.sev-low{{background:#001a1f;color:var(--cyan);border:1px solid var(--cyan);}}
.sev-info{{background:#0d1520;color:var(--info);border:1px solid var(--info);}}
.badge-owasp{{background:var(--s2);color:var(--cyan);border:1px solid var(--bdb);}}
.og{{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px;}}
.oc{{background:var(--s2);border:1px solid var(--bd);border-left:3px solid var(--oa,var(--bd));border-radius:6px;padding:10px 12px;cursor:pointer;transition:.15s;}}
.oc:hover,.oc.active{{border-color:var(--cyan);}}
.oc .oid{{font-family:var(--mono);font-size:.72rem;color:var(--cyan);}}
.oc .oname{{font-size:.82rem;font-weight:700;color:var(--tb);margin:3px 0 4px;}}
.oc .ocnt{{font-size:.68rem;color:var(--tm);}}
/* Charts grid */
.charts-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px;}}
.charts-grid-3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:8px;}}
.chart-card{{background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:16px;}}
.chart-card h3{{font-size:.68rem;text-transform:uppercase;letter-spacing:.12em;color:var(--cyan);margin:0 0 12px;font-family:var(--ui);}}
.chart-card h3::before{{content:'// ';color:var(--tm);font-family:var(--mono);}}
.chart-container{{position:relative;height:240px;}}
.chart-matrix-container{{overflow-x:auto;}}
.filters{{display:flex;flex-wrap:wrap;gap:10px;align-items:center;background:var(--s2);border:1px solid var(--bd);border-radius:6px;padding:10px 14px;margin-bottom:12px;}}
.chk{{display:flex;align-items:center;gap:5px;font-size:.8rem;cursor:pointer;user-select:none;}}
.chk input{{accent-color:var(--green);}}
select.fs,input.fsrch{{background:var(--s);color:var(--text);border:1px solid var(--bd);border-radius:4px;padding:5px 10px;font-size:.8rem;font-family:var(--mono);outline:none;}}
.btnf{{background:var(--s2);color:var(--text);border:1px solid var(--bd);border-radius:4px;padding:5px 13px;font-size:.76rem;cursor:pointer;font-family:var(--ui);font-weight:600;text-transform:uppercase;letter-spacing:.05em;}}
.btnf:hover{{border-color:var(--cyan);color:var(--cyan);}}
.ml-auto{{margin-left:auto;}}.flex{{display:flex;}}.gap8{{gap:8px;}}
.finding{{background:var(--s);border:1px solid var(--bd);border-left:4px solid var(--c);border-radius:6px;margin-bottom:8px;overflow:hidden;}}
.fhdr{{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 14px;}}
.fhdr h3{{margin:0;font-size:.94rem;font-weight:700;flex:1;}}
.fhdr h3 .sub{{color:var(--tm);font-weight:400;}}
.fmeta{{padding:0 14px 10px;font-size:.8rem;color:var(--tm);display:flex;flex-wrap:wrap;gap:5px 18px;}}
.finding details{{border-top:1px solid var(--bd);}}
.finding summary{{padding:8px 14px;cursor:pointer;font-size:.8rem;color:var(--cyan);font-weight:600;user-select:none;list-style:none;}}
.finding summary:hover{{background:var(--s2);}}
.fbody{{padding:4px 14px 14px;}}
.fbody h4{{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;color:var(--cyan);margin:10px 0 4px;}}
.fbody h4::before{{content:'// ';font-family:var(--mono);color:var(--tm);}}
.fbody p{{margin:0;font-size:.85rem;}}
.fbody pre{{background:#000;border:1px solid var(--bd);border-radius:4px;padding:8px 10px;white-space:pre-wrap;word-break:break-word;font-size:.76rem;color:#aed6f1;max-height:180px;overflow:auto;font-family:var(--mono);}}
#no-res{{display:none;text-align:center;color:var(--tm);padding:40px;font-family:var(--mono);}}
footer{{padding:20px 0;border-top:1px solid var(--bd);text-align:center;font-family:var(--mono);font-size:.7rem;color:var(--tm);}}
footer .g{{color:var(--green);}}footer .r{{color:var(--red);}}
::-webkit-scrollbar{{width:5px;height:5px;}}..::-webkit-scrollbar-thumb{{background:var(--bdb);border-radius:3px;}}
@media print{{.filters,.chart-card{{display:none!important;}}.finding details{{display:block!important;}}.finding summary{{display:none!important;}}}}
@media(max-width:900px){{.charts-grid,.charts-grid-3{{grid-template-columns:1fr;}}}}
</style></head><body>
<header><div class="hdr">
  <div>
    <div style="font-family:var(--mono);font-size:.68rem;letter-spacing:.15em;color:var(--tm);margin-bottom:5px;">☠ EVIL WEB REAPER — VULNERABILITY SCANNER</div>
    <h1 class="htitle"><span class="g">[ VULN_</span>REPORT <span class="g">]</span></h1>
    <div class="htarget">{target}</div>
  </div>
  <div class="meta-grid">
    <div><div class="ml">Status</div><div class="mv"><span class="chip chip-{status_low}">{status}</span></div></div>
    <div><div class="ml">Scan ID</div><div class="mv" style="font-size:.7rem;">{scan_id}</div></div>
    <div><div class="ml">Started</div><div class="mv" style="font-size:.72rem;">{started}</div></div>
    <div><div class="ml">Duration</div><div class="mv">{duration}</div></div>
  </div>
</div></header>
<div class="wrap">
<section><h2 class="st">Scope & Summary</h2>
<div class="sg" style="margin-bottom:14px;">
  <div class="sb" style="--ac:var(--cyan)"><div class="num">{pages}</div><div class="lbl">Pages Crawled</div></div>
  <div class="sb" style="--ac:var(--green)"><div class="num">{endpoints}</div><div class="lbl">Endpoints Tested</div></div>
  <div class="sb" style="--ac:var(--orange)"><div class="num">{requests}</div><div class="lbl">HTTP Requests</div></div>
  <div class="sb" style="--ac:var(--red)"><div class="num">{total}</div><div class="lbl">Total Findings</div></div>
</div>
<div class="sev-cards">{sev_cards}</div>
<div class="sev-bar">{sev_bar}</div>
</section>

<section><h2 class="st">Vulnerability Analysis — Charts</h2>
<div class="charts-grid" style="margin-bottom:14px;">
  <div class="chart-card">
    <h3>Severity Distribution</h3>
    <div class="chart-container"><canvas id="chart-sev-donut" data-counts='{sev_json}'></canvas></div>
  </div>
  <div class="chart-card">
    <h3>Vulnerability Type Breakdown</h3>
    <div class="chart-container"><canvas id="chart-tech-donut" data-techs='{tech_json}'></canvas></div>
  </div>
</div>
<div class="charts-grid" style="margin-bottom:14px;">
  <div class="chart-card">
    <h3>Category × Severity (Stacked)</h3>
    <div class="chart-container"><canvas id="chart-cat-stacked" data-catbysev='{cat_by_sev_json}'></canvas></div>
  </div>
  <div class="chart-card">
    <h3>Confidence Distribution</h3>
    <div class="chart-container"><canvas id="chart-conf-hist" data-buckets='{conf_buckets_json}'></canvas></div>
  </div>
</div>
<div class="chart-card" style="margin-bottom:14px;">
  <h3>OWASP Top 10 — Findings by Category & Severity (Stacked Bar)</h3>
  <div class="chart-container" style="height:200px;"><canvas id="chart-owasp-bar" data-counts='{owasp_stacked_json}' data-ids='{owasp_ids_json}'></canvas></div>
</div>
<div class="chart-card" style="margin-bottom:0;">
  <h3>Risk Matrix — OWASP Category × Severity</h3>
  <div class="chart-matrix-container"><canvas id="chart-risk-matrix" width="960" height="200" data-owasp='{owasp_stacked_json}' data-ids='{owasp_ids_json}'></canvas></div>
</div>
</section>

<section><h2 class="st">OWASP Top 10 (2021) Coverage</h2>
<div class="og">{owasp_grid}</div>
</section>
<section><h2 class="st">Detailed Findings ({total})</h2>
{filter_bar}
<div id="fl">{findings_html}</div>
<div id="no-res">[ NO FINDINGS MATCH FILTERS ]</div>
</section>
</div>
<footer><span class="g">☠ EVIL WEB REAPER</span> | Generated {generated} | <span class="r">⚠ AUTHORISED TESTING ONLY</span></footer>
<script>
(function(){{
  var sc=document.querySelectorAll('.f-sev'),cs=document.getElementById('f-cat'),
      sr=document.getElementById('f-srch'),cards=document.querySelectorAll('.finding'),
      nr=document.getElementById('no-res'),oc=document.querySelectorAll('.oc'),ao='all';
  function flt(){{
    var sv={{}};sc.forEach(function(c){{if(c.checked)sv[c.value]=1;}});
    var cat=cs?cs.value:'all',q=sr?sr.value.toLowerCase():'';var vis=0;
    cards.forEach(function(el){{
      var ok=!!sv[el.dataset.sev]&&(cat==='all'||el.dataset.cat===cat)
             &&(ao==='all'||el.dataset.owasp===ao)&&(!q||(el.dataset.s||'').includes(q));
      el.style.display=ok?'':'none';if(ok)vis++;
    }});
    if(nr)nr.style.display=(vis===0&&cards.length>0)?'':'none';
  }}
  sc.forEach(function(c){{c.addEventListener('change',flt);}});
  if(cs)cs.addEventListener('change',flt);
  if(sr)sr.addEventListener('input',flt);
  oc.forEach(function(card){{
    card.addEventListener('click',function(){{
      var id=card.getAttribute('data-oid');
      if(ao===id){{ao='all';card.classList.remove('active');}}
      else{{oc.forEach(function(c){{c.classList.remove('active');}});ao=id;card.classList.add('active');}}
      flt();
    }});
  }});
  var ea=document.getElementById('ea'),ca=document.getElementById('ca'),cl=document.getElementById('cl');
  if(ea)ea.onclick=function(){{document.querySelectorAll('.finding details').forEach(function(d){{d.open=true;}});}};
  if(ca)ca.onclick=function(){{document.querySelectorAll('.finding details').forEach(function(d){{d.open=false;}});}};
  if(cl)cl.onclick=function(){{
    sc.forEach(function(c){{c.checked=true;}});
    if(cs)cs.value='all';if(sr)sr.value='';ao='all';
    oc.forEach(function(c){{c.classList.remove('active');}});flt();
  }};
}})();
</script>
{charts_js}
</body></html>"""


def generate_html(ctx: Dict, path: str) -> str:
    scan = ctx.get("scan") or {}
    findings = ctx["findings"]
    sev_order = SEVERITY_ORDER

    # Severity cards
    sev_cards = ""
    for s in sev_order:
        c = SEV_COLORS[s]; n = ctx["severity_counts"].get(s,0)
        sev_cards += f'<div class="sc" style="--c:{c}"><div class="num">{n}</div><div class="lbl">{s}</div></div>'

    # Severity bar
    total = ctx["total_findings"]
    sev_bar = ""
    for s in sev_order:
        n = ctx["severity_counts"].get(s,0)
        if n and total:
            sev_bar += f'<div class="seg" style="background:{SEV_COLORS[s]};flex:{n} 0 auto;" title="{s}:{n}"></div>'
    if not sev_bar: sev_bar = '<div class="seg" style="width:100%;background:var(--s2);"></div>'

    # OWASP grid
    owasp_grid = ""
    for e in ctx["owasp_matrix"]:
        highest_badge = f'<span class="badge sev-{e["highest_severity"].lower()}">{e["highest_severity"]}</span>' if e["highest_severity"] else ""
        owasp_grid += (f'<div class="oc" data-oid="{e["id"]}" style="--oa:{e["highest_color"]}">'
                       f'<div class="oid">{e["id"]}</div><div class="oname">{html.escape(e["name"])}</div>'
                       f'<div class="ocnt">{e["total"]} finding{"s" if e["total"]!=1 else ""}</div>'
                       f'{highest_badge}</div>')

    # Chart data
    tech_counts: Dict[str,int] = {}
    for f in findings:
        sub = f.get("subtype","Unknown")
        tech_counts[sub] = tech_counts.get(sub,0)+1

    sev_json = json.dumps({s: ctx["severity_counts"].get(s,0) for s in sev_order})
    tech_json = json.dumps(tech_counts)
    cat_by_sev_json = json.dumps(ctx.get("cat_by_sev",{}))
    conf_buckets_json = json.dumps(ctx.get("confidence_buckets",[0]*10))
    owasp_stacked_json = json.dumps(ctx.get("owasp_raw",{}))
    owasp_ids_json = json.dumps(list(OWASP_TOP_10_2021.keys()))

    # Filter bar
    cats = sorted({f["category"] for f in findings})
    cat_opts = "".join(f'<option value="{html.escape(c)}">{html.escape(c)}</option>' for c in cats)
    chks = "".join(f'<label class="chk"><input type="checkbox" class="f-sev" value="{s}" checked>'
                   f'<span class="badge sev-{s.lower()}">{s}</span></label>' for s in sev_order)
    filter_bar = (f'<div class="filters">'
                  f'<div style="display:flex;flex-wrap:wrap;gap:6px;">{chks}</div>'
                  f'<select class="fs" id="f-cat"><option value="all">All categories</option>{cat_opts}</select>'
                  f'<input class="fsrch" id="f-srch" type="search" placeholder="search url/param/payload...">'
                  f'<div class="ml-auto flex gap8"><button class="btnf" id="ea">Expand All</button>'
                  f'<button class="btnf" id="ca">Collapse All</button>'
                  f'<button class="btnf" id="cl">Clear</button></div></div>') if findings else ""

    # Findings HTML
    fhtml = ""
    if not findings:
        fhtml = '<div style="text-align:center;padding:40px;color:var(--tm);font-family:var(--mono);">[ NO FINDINGS ]</div>'
    for f in findings:
        sev_low = f["severity"].lower()
        sc = SEV_COLORS.get(f["severity"],"#ccc")
        param_row = f'<div><strong>Param:</strong> <code>{html.escape(str(f.get("parameter","")))} </code> <strong>Method:</strong> {html.escape(f["method"])}</div>' if f.get("parameter") else ""
        payload_row = f'<div><strong>Payload:</strong> <code>{html.escape(str(f.get("payload","")))} </code></div>' if f.get("payload") else ""
        auto_open = "open" if f["severity"] in ("Critical","High") else ""
        ds = f" {f['url']} {f.get('parameter','')} {f.get('payload','')} {f['subtype']}".lower()
        fhtml += (f'<article class="finding" style="--c:{sc}" '
                  f'data-sev="{f["severity"]}" data-cat="{html.escape(f["category"])}" '
                  f'data-owasp="{f["owasp_id"]}" data-s="{html.escape(ds)}">'
                  f'<div class="fhdr">'
                  f'<span class="badge sev-{sev_low}">{f["severity"]}</span>'
                  f'<span class="badge badge-owasp">{f["owasp_id"]}</span>'
                  f'<h3>{html.escape(f["category"])} <span class="sub">/ {html.escape(f["subtype"])}</span></h3>'
                  f'<span style="font-size:.7rem;color:var(--tm);font-family:var(--mono);margin-left:auto;">{f["confidence"]:.0%}</span>'
                  f'</div>'
                  f'<div class="fmeta"><div><strong>URL:</strong> <code>{html.escape(f["url"])}</code></div>'
                  f'{param_row}{payload_row}</div>'
                  f'<details {auto_open}><summary>▶ Details &amp; Remediation</summary>'
                  f'<div class="fbody"><h4>Description</h4><p>{html.escape(f.get("description",""))}</p>'
                  f'<h4>Evidence</h4><pre>{html.escape(f.get("evidence","") or "(no evidence)")}</pre>'
                  f'<h4>Remediation</h4><p>{html.escape(f.get("remediation",""))}</p>'
                  f'</div></details></article>')

    out = _HTML_TEMPLATE.format(
        target=html.escape(scan.get("target","N/A")),
        status=scan.get("status","unknown"), status_low=(scan.get("status","unknown")).lower(),
        scan_id=scan.get("scan_id","N/A"),
        started=(scan.get("started_at","")[:19].replace("T"," ") or "N/A"),
        duration=f"{ctx['duration_seconds']:.1f}s" if ctx["duration_seconds"] else "—",
        pages=scan.get("pages_crawled",0), endpoints=scan.get("endpoints_tested",0),
        requests=scan.get("requests_sent",0), total=ctx["total_findings"],
        sev_cards=sev_cards, sev_bar=sev_bar, owasp_grid=owasp_grid,
        filter_bar=filter_bar, findings_html=fhtml,
        generated=ctx["generated_at"],
        sev_json=sev_json, tech_json=tech_json,
        cat_by_sev_json=cat_by_sev_json, conf_buckets_json=conf_buckets_json,
        owasp_stacked_json=owasp_stacked_json, owasp_ids_json=owasp_ids_json,
        charts_js=_HTML_CHARTS_JS,
    )
    with open(path,"w",encoding="utf-8") as fh: fh.write(out)
    return path


# ── PDF ──────────────────────────────────────────────────────────────
def generate_pdf(ctx: Dict, path: str) -> str:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable,
                                         KeepTogether, PageBreak)
        from reportlab.graphics.shapes import Drawing, Rect, String, Line
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart

        DARK=colors.HexColor("#141A22"); MUTED=colors.HexColor("#5b6b7c"); GRID=colors.HexColor("#dddddd")
        PAGE_M = 0.65*inch
        SEV_PDF = {
            "Critical": colors.HexColor("#ff003c"),
            "High":     colors.HexColor("#ff6600"),
            "Medium":   colors.HexColor("#ffe600"),
            "Low":      colors.HexColor("#00e5ff"),
            "Info":     colors.HexColor("#5a6e82"),
        }

        def esc(t): return html.escape(str(t or ""),quote=False)
        def escp(t): return esc(t).replace("\n","<br/>")

        ss=getSampleStyleSheet()
        ss.add(ParagraphStyle("RT",parent=ss["Title"],fontSize=16,spaceAfter=2,textColor=colors.HexColor("#0B0F14")))
        ss.add(ParagraphStyle("RS",parent=ss["Normal"],textColor=MUTED,fontSize=9))
        ss.add(ParagraphStyle("RH",parent=ss["Heading2"],fontSize=11,spaceBefore=10,spaceAfter=5,textColor=colors.HexColor("#0B0F14")))
        ss.add(ParagraphStyle("RB",parent=ss["Normal"],fontSize=9,leading=12))
        ss.add(ParagraphStyle("RM",parent=ss["Normal"],fontName="Courier",fontSize=7,leading=9,textColor=colors.HexColor("#1a1a1a")))
        ss.add(ParagraphStyle("RL",parent=ss["Normal"],fontSize=7.5,textColor=MUTED,spaceBefore=4,spaceAfter=2))

        def footer(canvas,doc):
            canvas.saveState();canvas.setFont("Helvetica",8);canvas.setFillColor(MUTED)
            canvas.drawRightString(LETTER[0]-PAGE_M,0.4*inch,f"Page {doc.page}")
            canvas.drawString(PAGE_M,0.4*inch,"☠ Evil Web Reaper — Vulnerability Scan Report")
            canvas.restoreState()

        scan=ctx.get("scan") or {}
        doc=SimpleDocTemplate(path,pagesize=LETTER,
            leftMargin=PAGE_M,rightMargin=PAGE_M,topMargin=PAGE_M,bottomMargin=PAGE_M)
        story=[]

        # Title
        story.append(Paragraph("Web Application Vulnerability Scan Report",ss["RT"]))
        story.append(Paragraph("☠ Evil Web Reaper",ss["RS"]))
        story.append(Paragraph(esc(scan.get("target","N/A")),ss["RS"]))
        story.append(Spacer(1,8))

        # Meta table
        d=ctx.get("duration_seconds")
        meta=[[esc(scan.get("scan_id","N/A")),esc(scan.get("status","N/A")),
                esc((scan.get("started_at","")[:19].replace("T"," "))),
                f"{d:.1f}s" if d else "—"]]
        hdr=[["Scan ID","Status","Started","Duration"]]
        mt=Table(hdr+meta,colWidths=[130,80,140,80])
        mt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),0.5,GRID),("BOTTOMPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4)]))
        story.append(mt);story.append(Spacer(1,10));story.append(HRFlowable(width="100%",color=GRID))

        # Severity summary
        story.append(Paragraph("SEVERITY SUMMARY",ss["RH"]))
        sev_data=[["Severity"]+SEVERITY_ORDER+["Total"],
                   ["Count"]+[str(ctx["severity_counts"].get(s,0)) for s in SEVERITY_ORDER]+[str(ctx["total_findings"])]]
        st=Table(sev_data,colWidths=[55]+[58]*5+[50])
        sc_style=[("BACKGROUND",(0,0),(-1,0),DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8.5),
            ("ALIGN",(1,0),(-1,-1),"CENTER"),("GRID",(0,0),(-1,-1),0.5,GRID),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4)]
        for i,sev in enumerate(SEVERITY_ORDER,1):
            c=colors.HexColor(SEV_COLORS[sev]); tc=colors.white if sev in("Critical","High") else colors.HexColor("#1a1208")
            sc_style.extend([("BACKGROUND",(i,1),(i,1),c),("TEXTCOLOR",(i,1),(i,1),tc),("FONTNAME",(i,1),(i,1),"Helvetica-Bold")])
        st.setStyle(TableStyle(sc_style));story.append(st);story.append(Spacer(1,10))

        # Chart 1: Severity Pie chart (reportlab graphics)
        sev_vals = [ctx["severity_counts"].get(s,0) for s in SEVERITY_ORDER]
        if sum(sev_vals) > 0:
            story.append(Paragraph("SEVERITY DISTRIBUTION (PIE CHART)",ss["RH"]))
            d_draw = Drawing(440, 160)
            pie = Pie()
            pie.x = 20; pie.y = 10; pie.width = 140; pie.height = 140
            pie.data = [v for v in sev_vals if v > 0]
            pie.labels = [s for s, v in zip(SEVERITY_ORDER, sev_vals) if v > 0]
            pie_colors = [SEV_PDF[s] for s, v in zip(SEVERITY_ORDER, sev_vals) if v > 0]
            for i, c in enumerate(pie_colors):
                pie.slices[i].fillColor = c
                pie.slices[i].strokeColor = colors.HexColor("#141A22")
                pie.slices[i].strokeWidth = 1
            pie.slices.fontName = "Helvetica"; pie.slices.fontSize = 7
            d_draw.add(pie)
            # Legend
            lx, ly = 180, 140
            for i, (sev, val) in enumerate(zip(SEVERITY_ORDER, sev_vals)):
                if val > 0:
                    row_y = ly - i*18
                    rect = Rect(lx, row_y, 12, 10, fillColor=SEV_PDF[sev], strokeColor=None)
                    d_draw.add(rect)
                    d_draw.add(String(lx+16, row_y+2, f"{sev}: {val}", fontSize=8, fontName="Helvetica"))
            story.append(d_draw); story.append(Spacer(1,8))

        # Chart 2: OWASP findings horizontal bar
        owasp_totals = [(e["id"], e["total"]) for e in ctx["owasp_matrix"] if e["total"]>0]
        if owasp_totals:
            story.append(Paragraph("OWASP TOP 10 — FINDINGS PER CATEGORY",ss["RH"]))
            d_draw2 = Drawing(440, max(80, len(owasp_totals)*18+30))
            bc = HorizontalBarChart()
            bc.x = 90; bc.y = 10; bc.height = max(60, len(owasp_totals)*16); bc.width = 320
            bc.data = [[t for _,t in owasp_totals]]
            bc.categoryAxis.categoryNames = [oid for oid,_ in owasp_totals]
            bc.categoryAxis.labels.fontSize = 7; bc.categoryAxis.labels.fontName = "Helvetica"
            bc.valueAxis.labels.fontSize = 7
            bc.bars[0].fillColor = colors.HexColor("#00e5ff"); bc.bars[0].strokeColor = None
            bc.groupSpacing = 2; bc.barSpacing = 1
            d_draw2.add(bc); story.append(d_draw2); story.append(Spacer(1,8))

        # Chart 3: Category × Severity table (risk matrix style)
        cat_by_sev = ctx.get("cat_by_sev", {})
        if cat_by_sev:
            story.append(Paragraph("VULNERABILITY TYPE × SEVERITY MATRIX",ss["RH"]))
            hdr_row = ["Category"] + SEVERITY_ORDER + ["Total"]
            rows = [hdr_row]
            for cat, sevmap in sorted(cat_by_sev.items()):
                row = [cat] + [str(sevmap.get(s,0)) for s in SEVERITY_ORDER]
                row.append(str(sum(sevmap.values())))
                rows.append(row)
            mat = Table(rows, colWidths=[200]+[52]*5+[42])
            mat_style = [("BACKGROUND",(0,0),(-1,0),DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("ALIGN",(1,0),(-1,-1),"CENTER"),("GRID",(0,0),(-1,-1),0.4,GRID),
                ("BOTTOMPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3)]
            for ri, row in enumerate(rows[1:],1):
                for ci, sev in enumerate(SEVERITY_ORDER,1):
                    val_str = row[ci]
                    if val_str != '0':
                        c = colors.HexColor(SEV_COLORS[sev])
                        mat_style.append(("BACKGROUND",(ci,ri),(ci,ri),c))
                        tc = colors.white if sev in("Critical","High") else colors.HexColor("#1a1208")
                        mat_style.append(("TEXTCOLOR",(ci,ri),(ci,ri),tc))
                        mat_style.append(("FONTNAME",(ci,ri),(ci,ri),"Helvetica-Bold"))
            mat.setStyle(TableStyle(mat_style)); story.append(mat); story.append(Spacer(1,10))

        # OWASP Top 10 table
        story.append(Paragraph("OWASP TOP 10 (2021)",ss["RH"]))
        orows=[["ID","Category","Findings","Highest"]]+[[e["id"],esc(e["name"]),str(e["total"]),e["highest_severity"] or "—"] for e in ctx["owasp_matrix"]]
        ot=Table(orows,colWidths=[50,260,60,80])
        os_style=[("BACKGROUND",(0,0),(-1,0),DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),0.5,GRID),("ALIGN",(2,0),(3,-1),"CENTER"),
            ("BOTTOMPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3)]
        for i,e in enumerate(ctx["owasp_matrix"],1):
            if e["highest_severity"]:
                c=colors.HexColor(SEV_COLORS[e["highest_severity"]]); tc=colors.white if e["highest_severity"] in("Critical","High") else colors.HexColor("#1a1208")
                os_style.extend([("BACKGROUND",(3,i),(3,i),c),("TEXTCOLOR",(3,i),(3,i),tc)])
        ot.setStyle(TableStyle(os_style));story.append(ot);story.append(PageBreak())

        # Detailed findings
        story.append(Paragraph(f"DETAILED FINDINGS ({ctx['total_findings']})",ss["RH"]))
        for i,f in enumerate(ctx["findings"],1):
            sc=colors.HexColor(f.get("severity_color") or SEV_COLORS.get(f["severity"],"#ccc"))
            block=[]
            badge=Table([[Paragraph(f['severity'].upper(),ParagraphStyle("B",parent=ss["RS"],textColor=colors.white,alignment=1,fontName="Helvetica-Bold",fontSize=7.5))]],
                         colWidths=[58],rowHeights=[14])
            badge.setStyle(TableStyle([("BACKGROUND",(0,0),(0,0),sc),("ALIGN",(0,0),(0,0),"CENTER"),("VALIGN",(0,0),(0,0),"MIDDLE")]))
            title=Paragraph(f"<b>{i}. {esc(f['category'])} / {esc(f['subtype'])}</b><br/>"
                             f"<font size=7.5 color='#5b6b7c'>{esc(f['owasp_id'])} — {esc(f['owasp_name'])}" + (f" | {esc(f['cwe'])}" if f.get('cwe') else "") + "</font>",ss["RB"])
            ht=Table([[badge,title]],colWidths=[64,396])
            ht.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(1,0),(1,0),8)]))
            block.append(ht);block.append(Spacer(1,3))
            meta=f"<b>URL:</b> {esc(f['url'])}"
            if f.get("parameter"): meta+=f" &nbsp; <b>Param:</b> {esc(f['parameter'])} ({esc(f['method'])})"
            if f.get("payload"):   meta+=f"<br/><b>Payload:</b> {esc(f['payload'])}"
            meta+=f"<br/><b>Confidence:</b> {f['confidence']:.0%}"
            block.append(Paragraph(meta,ss["RB"]))
            block.append(Paragraph("DESCRIPTION",ss["RL"]));block.append(Paragraph(esc(f.get("description","")) or "—",ss["RB"]))
            block.append(Paragraph("EVIDENCE",ss["RL"]));block.append(Paragraph(escp(f.get("evidence","") or "(none)"),ss["RM"]))
            block.append(Paragraph("REMEDIATION",ss["RL"]));block.append(Paragraph(esc(f.get("remediation","")) or "—",ss["RB"]))
            block.append(Spacer(1,5));block.append(HRFlowable(width="100%",color=GRID));block.append(Spacer(1,5))
            story.append(KeepTogether(block))

        story.append(HRFlowable(width="100%",color=GRID))
        story.append(Paragraph(f"Generated {esc(ctx['generated_at'])} — For authorised security testing only.",ss["RS"]))
        doc.build(story,onFirstPage=footer,onLaterPages=footer)
    except Exception as e:
        with open(path,"w") as fh: fh.write(f"PDF generation failed: {e}\nInstall: pip install reportlab")
    return path


# ── Generate all ─────────────────────────────────────────────────────
def generate_all(scan_id: str) -> Dict[str,str]:
    ctx = build_context(scan_id)
    if not ctx: return {}
    d = ensure_dir(scan_id)
    paths = {}
    for fmt,fn in [("html",generate_html),("json",generate_json),
                    ("txt",generate_txt),("pdf",generate_pdf)]:
        try:
            p = os.path.join(d, f"report.{fmt}")
            fn(ctx, p)
            paths[fmt] = p
        except Exception as e:
            paths[fmt] = f"error:{e}"
    return paths
