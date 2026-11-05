#!/usr/bin/env python3
"""Build a self-contained HTML dashboard from the honeypot event log.

Example:
    python dashboard.py --log logs/events.jsonl --out dashboard.html
"""

import argparse
import html
import json
from collections import Counter, defaultdict
from datetime import datetime

SEVERITIES = ["critical", "high", "medium", "low"]
SEV_COLOR = {"critical": "#ff4d6d", "high": "#ff9f43", "medium": "#f6d365", "low": "#7bdff2"}
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES), 1)}


def load(path):
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    for e in events:
        e["_t"] = datetime.fromisoformat(e["ts"])
    return events


def esc(x):
    return html.escape(str(x))


def pill(sev):
    return f'<span class="pill" style="--c:{SEV_COLOR[sev]}">{sev}</span>'


def timeline_svg(requests, bins=24):
    if not requests:
        return "<p class='muted'>No requests recorded.</p>"
    start = min(e["_t"] for e in requests)
    end = max(e["_t"] for e in requests)
    span = max((end - start).total_seconds(), 1)
    counts = [Counter() for _ in range(bins)]
    for e in requests:
        i = min(int((e["_t"] - start).total_seconds() / span * bins), bins - 1)
        counts[i][e.get("max_severity", "none")] += 1
    peak = max(sum(c.values()) for c in counts) or 1
    w, h, pad = 720, 180, 28
    bw = (w - pad) / bins
    parts = [f'<svg viewBox="0 0 {w} {h + 30}" class="chart" role="img" aria-label="Requests over time">']
    for frac in (0.5, 1.0):
        y = h - (h - 10) * frac
        parts.append(f'<line x1="{pad}" x2="{w}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                     f'<text x="{pad - 6}" y="{y + 4:.1f}" class="axis" text-anchor="end">{round(peak * frac)}</text>')
    for i, c in enumerate(counts):
        x = pad + i * bw + 2
        y = h
        for key in ["none", "low", "medium", "high", "critical"]:
            n = c.get(key, 0)
            if not n:
                continue
            bh = (h - 10) * n / peak
            y -= bh
            color = SEV_COLOR.get(key, "#3a4256")
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw - 4:.1f}" height="{bh:.1f}" rx="2" fill="{color}">'
                         f'<title>{n} {key} request(s)</title></rect>')
    parts.append(f'<text x="{pad}" y="{h + 22}" class="axis">{start:%H:%M:%S}</text>'
                 f'<text x="{w}" y="{h + 22}" class="axis" text-anchor="end">{end:%H:%M:%S} UTC</text></svg>')
    return "".join(parts)


def hbars(items, color="#f472b6"):
    if not items:
        return "<p class='muted'>None.</p>"
    peak = max(n for _, n in items)
    rows = []
    for label, n in items:
        rows.append(f'<div class="hbar"><span class="hl">{esc(label)}</span>'
                    f'<span class="track"><span class="fill" style="width:{n / peak * 100:.1f}%;background:{color}"></span></span>'
                    f'<span class="hn">{n}</span></div>')
    return "".join(rows)


def build(events, title):
    requests = [e for e in events if e["event"] == "request"]
    connects = [e for e in events if e["event"] == "connect"]
    alerts = [(e, a) for e in requests for a in e.get("alerts", [])]
    sev_counts = Counter(a["severity"] for _, a in alerts)
    writes = [(e, w) for e in requests for w in e.get("writes", [])]

    sources = defaultdict(lambda: {"sessions": set(), "requests": 0, "alerts": 0, "max": None,
                                   "first": None, "last": None, "rules": set()})
    for e in events:
        s = sources[e["src_ip"]]
        s["first"] = min(filter(None, [s["first"], e["_t"]]))
        s["last"] = max(filter(None, [s["last"], e["_t"]]))
        s["sessions"].add(e["session"])
        if e["event"] == "request":
            s["requests"] += 1
            for a in e.get("alerts", []):
                s["alerts"] += 1
                s["rules"].add(a["title"])
                if s["max"] is None or SEV_RANK[a["severity"]] > SEV_RANK[s["max"]]:
                    s["max"] = a["severity"]

    fc_counts = Counter(f'{e.get("function")} - {e.get("function_name", "?")}' for e in requests).most_common(8)
    techniques = Counter(a["attack"] for _, a in alerts).most_common()

    first = min((e["_t"] for e in events), default=None)
    last = max((e["_t"] for e in events), default=None)
    period = f"{first:%Y-%m-%d %H:%M:%S} to {last:%H:%M:%S} UTC" if first else "no data"

    kpis = [("Connections", len(connects)), ("Unique sources", len(sources)),
            ("Requests", len(requests)), ("Alerts", len(alerts)),
            ("Critical", sev_counts.get("critical", 0)), ("Writes", len(writes))]
    kpi_html = "".join(f'<div class="kpi{" crit" if k == "Critical" and v else ""}"><div class="kv">{v}</div><div class="kl">{k}</div></div>'
                       for k, v in kpis)

    sev_bar = "".join(f'<span style="flex:{sev_counts[s]};background:{SEV_COLOR[s]}" title="{sev_counts[s]} {s}"></span>'
                      for s in SEVERITIES if sev_counts.get(s))
    sev_legend = "".join(f'<span class="lg"><i style="background:{SEV_COLOR[s]}"></i>{s} {sev_counts.get(s, 0)}</span>'
                         for s in SEVERITIES) + '<span class="lg"><i style="background:#3a4256"></i>no alert</span>'

    src_rows = "".join(
        f'<tr><td class="mono">{esc(ip)}</td><td>{len(s["sessions"])}</td><td>{s["requests"]}</td>'
        f'<td>{s["alerts"]}</td><td>{pill(s["max"]) if s["max"] else "<span class=muted>none</span>"}</td>'
        f'<td>{esc(", ".join(sorted(s["rules"])) or "-")}</td></tr>'
        for ip, s in sorted(sources.items(), key=lambda kv: (-(SEV_RANK.get(kv[1]["max"], 0)), -kv[1]["requests"])))

    alert_rows = "".join(
        f'<tr><td class="mono">{e["_t"]:%H:%M:%S}</td><td>{pill(a["severity"])}</td><td>{esc(a["title"])}</td>'
        f'<td class="mono">{esc(e["src_ip"])}</td><td>{esc(a["detail"])}</td><td class="muted">{esc(a["attack"])}</td></tr>'
        for e, a in sorted(alerts, key=lambda ea: (-SEV_RANK[ea[1]["severity"]], ea[0]["_t"]))[:60])

    write_rows = "".join(
        f'<tr><td class="mono">{e["_t"]:%H:%M:%S}</td><td class="mono">{esc(e["src_ip"])}</td><td>{esc(w["name"])}</td>'
        f'<td>{esc(w["old_text"])}</td><td><b>{esc(w["new_text"])}</b></td></tr>'
        for e, w in writes)

    tech_html = hbars(techniques, color="#c084fc")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<style>
:root{{--bg:#0f0d16;--panel:#191623;--line:#2a2638;--text:#ece8f4;--muted:#9a93ad;--accent:#f472b6}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:28px 20px 48px}}
header{{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:22px}}
h1{{margin:0;font-size:24px;letter-spacing:-.01em}}h1 span{{color:var(--accent);font-family:ui-monospace,Consolas,monospace}}
.sub{{color:var(--muted);margin-top:4px}}h2{{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 14px}}
.kpis{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:16px}}
.kpi{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
.kpi.crit{{border-color:#ff4d6d66;box-shadow:inset 0 0 0 1px #ff4d6d33}}.kpi.crit .kv{{color:#ff4d6d}}
.kv{{font-size:26px;font-weight:700}}.kl{{color:var(--muted);font-size:12px}}
.grid2{{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:16px}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px;overflow:auto}}
.sevbar{{display:flex;height:12px;border-radius:6px;overflow:hidden;gap:2px;margin:6px 0 10px}}
.lg{{display:inline-flex;align-items:center;gap:6px;margin-right:14px;color:var(--muted);font-size:12px;text-transform:capitalize}}
.lg i{{width:10px;height:10px;border-radius:3px;display:inline-block}}
.chart{{width:100%;height:auto}}.chart .grid{{stroke:var(--line)}}.chart .axis{{fill:var(--muted);font-size:11px}}
.hbar{{display:grid;grid-template-columns:minmax(190px,1.6fr) 1.4fr 36px;align-items:center;gap:10px;margin:7px 0;font-size:13px}}
.hl{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.track{{height:8px;background:#26223399;border-radius:4px}}
.fill{{display:block;height:100%;border-radius:4px}}.hn{{text-align:right;color:var(--muted)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th{{text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:8px}}
td{{padding:8px;border-bottom:1px solid #221f2e;vertical-align:top}}.mono{{font-family:ui-monospace,Consolas,monospace}}
.muted{{color:var(--muted)}}.pill{{display:inline-block;padding:1px 9px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;
color:var(--c);background:color-mix(in srgb,var(--c) 16%,transparent);border:1px solid color-mix(in srgb,var(--c) 45%,transparent)}}
footer{{color:var(--muted);font-size:12px;margin-top:20px}}
@media(max-width:860px){{.kpis{{grid-template-columns:repeat(3,1fr)}}.grid2{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">
<header><div><h1><span>&gt; bms_honeypot_</span> Threat Dashboard</h1>
<div class="sub">{esc(title)} &middot; {esc(period)}</div></div></header>
<section class="kpis">{kpi_html}</section>
<section class="grid2">
  <div class="panel"><h2>Requests over time</h2>{timeline_svg(requests)}
  <div class="sevbar">{sev_bar}</div>{sev_legend}</div>
  <div class="panel"><h2>Function codes used</h2>{hbars(fc_counts)}</div>
</section>
<section class="panel"><h2>MITRE ATT&amp;CK for ICS techniques observed</h2>{tech_html}</section>
<section class="panel"><h2>Attack sources</h2><table><thead><tr><th>Source IP</th><th>Sessions</th><th>Requests</th>
<th>Alerts</th><th>Highest severity</th><th>Behavior</th></tr></thead><tbody>{src_rows}</tbody></table></section>
<section class="panel"><h2>What attackers changed</h2><table><thead><tr><th>Time</th><th>Source</th><th>Point</th>
<th>Before</th><th>After</th></tr></thead><tbody>{write_rows or '<tr><td colspan=5 class=muted>No writes recorded.</td></tr>'}</tbody></table></section>
<section class="panel"><h2>Alerts</h2><table><thead><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Source</th>
<th>Detail</th><th>ATT&amp;CK for ICS</th></tr></thead><tbody>{alert_rows or '<tr><td colspan=6 class=muted>No alerts.</td></tr>'}</tbody></table></section>
<footer>Generated by bms-modbus-honeypot from {len(events)} logged events.</footer>
</div></body></html>"""


def main():
    parser = argparse.ArgumentParser(description="Build the honeypot dashboard")
    parser.add_argument("--log", default="logs/events.jsonl")
    parser.add_argument("--out", default="dashboard.html")
    parser.add_argument("--title", default="Falcon BC-200 decoy, Tower A")
    args = parser.parse_args()
    events = load(args.log)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(build(events, args.title))
    print(f"dashboard written to {args.out} ({len(events)} events)")


if __name__ == "__main__":
    main()
