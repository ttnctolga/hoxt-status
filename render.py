#!/usr/bin/env python3
"""status.json + history.json + incidents.json -> statik, kendi içinde tam HTML (index.html [EN], tr/index.html [TR]). JS YOK, dış kaynak YOK, sır YOK.
Tüm metin kaçışlanır; olay (incident) metni düz metindir. Kullanım: python3 render.py --data data --out site"""
import argparse
import html
import json
import os
from datetime import datetime

T = {
    "en": {
        "title": "Hoxt status", "overall": {"operational": "All systems operational", "degraded": "Some systems are degraded", "outage": "Service disruption"},
        "status": {"operational": "Operational", "degraded": "Degraded", "outage": "Outage"}, "uptime": "90-day uptime", "since": "since", "updated": "Last checked",
        "incidents": "Incidents", "none": "No incidents reported.", "resolved": "Resolved", "ongoing": "Ongoing", "lang": "Türkçe", "lang_href": "tr/", "home": "../",
        "footer": "Independent monitoring, every 5 minutes. A status change needs two consecutive checks.",
    },
    "tr": {
        "title": "Hoxt durumu", "overall": {"operational": "Tüm sistemler çalışıyor", "degraded": "Bazı sistemlerde bozulma var", "outage": "Hizmet kesintisi"},
        "status": {"operational": "Çalışıyor", "degraded": "Bozulma", "outage": "Kesinti"}, "uptime": "90 günlük erişilebilirlik", "since": "şu zamandan beri", "updated": "Son kontrol",
        "incidents": "Olaylar", "none": "Bildirilen olay yok.", "resolved": "Çözüldü", "ongoing": "Sürüyor", "lang": "English", "lang_href": "../", "home": "../",
        "footer": "Bağımsız izleme, 5 dakikada bir. Durum değişimi art arda iki kontrol gerektirir.",
    },
}
COLORS = {"operational": "#1a7f4b", "degraded": "#b7791f", "outage": "#c0392b"}
CSS = """:root{--bg:#fff;--fg:#1c2128;--mut:#5b6573;--card:#f6f8fa;--bd:#d8dee4}@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b98a8;--card:#161b22;--bd:#30363d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px 48px}h1{font-size:1.4rem;margin:0 0 16px}.banner{padding:14px 16px;border-radius:10px;color:#fff;font-weight:600;margin-bottom:20px}
.row{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px 14px;background:var(--card);border:1px solid var(--bd);border-radius:10px;margin-bottom:8px}
.name{font-weight:600}.mut{color:var(--mut);font-size:.85rem}.badge{font-weight:600;white-space:nowrap}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
h2{font-size:1.1rem;margin:28px 0 10px}.inc{padding:12px 14px;border:1px solid var(--bd);border-radius:10px;margin-bottom:8px;background:var(--card)}a{color:inherit}
@media(max-width:480px){.row{flex-direction:column;align-items:flex-start}}"""


def e(s):
    return html.escape(str(s), quote=True)


def fmt(ts):
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ""


def page(lang, status, incidents):
    t = T[lang]
    overall = status["overall"]
    rows = []
    for c in status["components"]:
        up = c.get("uptime_90d")
        rows.append(
            '<div class="row"><div><div class="name">%s</div><div class="mut">%s %s · %s: %s</div></div><div class="badge"><span class="dot" style="background:%s"></span>%s</div></div>'
            % (e(c["name"]), e(t["since"]), e(fmt(c["since"])), e(t["uptime"]), e("—" if up is None else "%s%%" % up), COLORS[c["status"]], e(t["status"][c["status"]]))
        )
    inc = []
    for i in sorted(incidents, key=lambda x: x.get("started", ""), reverse=True)[:20]:
        title = (i.get("title") or {}).get(lang) or (i.get("title") or {}).get("en") or ""
        body = (i.get("body") or {}).get(lang) or (i.get("body") or {}).get("en") or ""
        state = t["resolved"] if i.get("resolved") else t["ongoing"]
        inc.append('<div class="inc"><div class="name">%s</div><div class="mut">%s · %s</div><p>%s</p></div>' % (e(title), e(fmt(i.get("started", ""))), e(state), e(body)))
    return """<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>%s</style></head><body><main>
<h1>%s</h1><div class="banner" style="background:%s">%s</div>%s
<h2>%s</h2>%s
<p class="mut">%s: %s · <a href="%s">%s</a></p><p class="mut">%s</p></main></body></html>
""" % (lang, e(t["title"]), CSS, e(t["title"]), COLORS[overall], e(t["overall"][overall]), "".join(rows), e(t["incidents"]), "".join(inc) or '<p class="mut">%s</p>' % e(t["none"]),
       e(t["updated"]), e(fmt(status["generated_at"])), e(t["lang_href"]), e(t["lang"]), e(t["footer"]))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    status = json.load(open(os.path.join(a.data, "status.json"), encoding="utf-8"))
    ip = os.path.join(a.data, "incidents.json")
    incidents = json.load(open(ip, encoding="utf-8")) if os.path.exists(ip) else []
    os.makedirs(os.path.join(a.out, "tr"), exist_ok=True)
    open(os.path.join(a.out, "index.html"), "w", encoding="utf-8", newline="\n").write(page("en", status, incidents))
    open(os.path.join(a.out, "tr", "index.html"), "w", encoding="utf-8", newline="\n").write(page("tr", status, incidents))
    # herkese açık makine okunur kopya (sır yok: yalnız bileşen durumu)
    open(os.path.join(a.out, "status.json"), "w", encoding="utf-8", newline="\n").write(json.dumps({"overall": status["overall"], "generated_at": status["generated_at"],
        "components": [{k: c.get(k) for k in ("id", "name", "status", "since", "uptime_90d")} for c in status["components"]]}, indent=2, ensure_ascii=False))
    print("RENDER ok")


if __name__ == "__main__":
    main()
