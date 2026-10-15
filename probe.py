#!/usr/bin/env python3
"""Hoxt durum izleyicisi (status.hoxt.net + DNS izleme; portal v1 aşama 7, D5).

Bağımsız bir gözlem noktasından (GitHub Actions, herkese açık depo `hoxt-status`) her 5 dakikada çalışır: HTTP uç noktaları, TLS sertifika süresi ve DNS kayıt tutarlılığı
(yetkili ad sunucuları + genel çözümleyiciler). Çıktı: `data/status.json` (herkese açık, SIR İÇERMEZ), `data/history.json` (90 gün), `index.html`. Durum DEĞİŞİMİNDE ntfy
bildirimi gider (konu adı `NTFY_TOPIC` ortam sırrından; ASLA yazdırılmaz/commit'lenmez). Yalnız standart kütüphane + `dig`.

Kullanım:  python3 probe.py --config checks.json --records expected-records.tsv --data data [--no-notify]
"""
import argparse
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

OK, DEGRADED, OUTAGE = "operational", "degraded", "outage"
SEVERITY = {OK: 0, DEGRADED: 1, OUTAGE: 2}
CONFIRM_TICKS = 2         # art arda bozuk tur (≈10 dk) → durum değişir (tek seferlik takılma alarm vermez)
HISTORY_DAYS = 90
REMIND_HOURS = 6          # kesinti sürerken hatırlatma aralığı


def now():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# ağ katmanı (testte değiştirilir)
# ---------------------------------------------------------------------------------------------------------------------------------------------
class Network:
    def http(self, url, timeout=15):
        """-> (status|None, body_text, seconds). Ağ hatasında status=None."""
        t0 = time.time()
        req = urllib.request.Request(url, headers={"User-Agent": "hoxt-status-probe/1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(65536).decode("utf-8", "replace"), time.time() - t0
        except urllib.error.HTTPError as e:
            return e.code, "", time.time() - t0
        except Exception:
            return None, "", time.time() - t0

    def cert_days(self, host, port=443, timeout=10):
        """-> sertifikanın bitmesine kalan gün (float) | None."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
                exp = ssl.cert_time_to_seconds(t.getpeercert()["notAfter"])
            return (exp - time.time()) / 86400
        except Exception:
            return None

    def dig(self, server, name, rtype, timeout=5):
        """-> normalize edilmiş yanıt kümesi (sıralı liste) | None (yanıt yok)."""
        cmd = ["dig", "+short", "+time=%d" % timeout, "+tries=1", name, rtype] if server is None else ["dig", "+short", "+time=%d" % timeout, "+tries=1", "@" + server, name, rtype]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 2 + 3)
        except Exception:
            return None
        if p.returncode != 0:
            return None
        lines = sorted({norm(l) for l in p.stdout.splitlines() if l.strip() and not l.startswith(";;")})
        return lines


def norm(v):
    """DNS yanıtını karşılaştırılabilir hâle getirir (küçük harf, sondaki nokta, TXT tırnakları, parçalı TXT birleştirme)."""
    v = v.strip()
    v = v.replace('" "', "")
    v = v.strip('"')
    return v.rstrip(".").lower()


def want(v):
    """Beklenen değer: `sha256:<hex>` ise tam değerin özeti (uzun/gizli olmayan ama gürültülü TXT'ler için), değilse düz değer."""
    return v.strip()


def matches(expected, answers):
    """Beklenen kümeyle gelen yanıt kümesi eşit mi? (`sha256:` ön ekli beklenen, gelen değerin SHA-256'sına karşı)"""
    if answers is None:
        return False
    exp = [e for e in expected]
    got = list(answers)
    if len(exp) != len(got):
        return False
    remaining = got[:]
    for e in exp:
        if e.startswith("sha256:"):
            hit = next((g for g in remaining if hashlib.sha256(g.encode()).hexdigest() == e[7:].lower()), None)
        else:
            hit = next((g for g in remaining if g == norm(e)), None)
        if hit is None:
            return False
        remaining.remove(hit)
    return True


# ---------------------------------------------------------------------------------------------------------------------------------------------
# kontroller
# ---------------------------------------------------------------------------------------------------------------------------------------------
def check_http(net, c):
    status, body, secs = net.http(c["url"], timeout=c.get("timeout", 15))
    expect = c.get("status", 200)
    if status is None:
        return OUTAGE, "unreachable"
    if status != expect:
        return OUTAGE, "http_%d" % status
    if c.get("contains") and c["contains"] not in body:
        return DEGRADED, "unexpected_body"
    if secs > c.get("slow_seconds", 8):
        return DEGRADED, "slow"
    return OK, "ok"


def check_tls(net, c):
    days = net.cert_days(c["host"], c.get("port", 443))
    if days is None:
        return OUTAGE, "tls_unreachable"
    if days < c.get("outage_days", 3):
        return OUTAGE, "cert_expires_%dd" % max(0, int(days))
    if days < c.get("warn_days", 14):
        return DEGRADED, "cert_expires_%dd" % int(days)
    return OK, "ok"


def check_dns(net, c, records, public, authoritative):
    """Tüm beklenen kayıtlar yetkili sunucularda VE genel çözümleyicilerde tutarlı mı?"""
    bad, silent = [], 0
    servers = [("auth:" + s, s) for s in authoritative] + [("pub:" + s, s) for s in public]
    for name, rtype, expected in records:
        for label, srv in servers:
            ans = net.dig(srv, name, rtype)
            if ans is None:
                silent += 1
            elif not matches(expected, ans):
                bad.append("%s %s@%s" % (name, rtype, label))
    total = len(records) * len(servers)
    if total and silent == total:
        return OUTAGE, "dns_no_answer"
    if bad:
        return (OUTAGE if len(bad) >= max(3, total // 2) else DEGRADED), "dns_mismatch:" + ",".join(sorted(set(bad))[:5])
    return OK, "ok"


def run_all(net, cfg, records):
    out = []
    for c in cfg["checks"]:
        if c.get("enabled", True) is False:
            continue
        if c["type"] == "http":
            st, detail = check_http(net, c)
        elif c["type"] == "tls":
            st, detail = check_tls(net, c)
        elif c["type"] == "dns":
            st, detail = check_dns(net, c, records, cfg.get("public_resolvers", ["8.8.8.8", "1.1.1.1"]), cfg.get("authoritative", []))
        else:
            continue
        out.append({"component": c["component"], "check": c["id"], "status": st, "detail": detail})
    return out


# ---------------------------------------------------------------------------------------------------------------------------------------------
# durum birleştirme / geçişler
# ---------------------------------------------------------------------------------------------------------------------------------------------
def merge(prev, results, cfg, t):
    """Önceki status.json + bu turun sonuçları -> yeni status + geçiş listesi. ALARM GÜRÜLTÜSÜ YOK: normalden bozuğa geçiş için art arda `CONFIRM_TICKS` bozuk tur gerekir
    (tek seferlik takılma durumu DEĞİŞTİRMEZ); bozuktan normale dönüş HEMEN yansır."""
    prev_c = {c["id"]: c for c in (prev or {}).get("components", [])}
    transitions = []
    comps = []
    for comp in cfg["components"]:
        mine = [r for r in results if r["component"] == comp["id"]]
        if not mine:
            continue
        worst = max(mine, key=lambda r: SEVERITY[r["status"]])
        p = prev_c.get(comp["id"], {})
        prev_status = p.get("status")
        streak = (p.get("consecutive_bad", 0) + 1) if worst["status"] != OK else 0
        if worst["status"] == OK:
            status = OK
        elif streak >= CONFIRM_TICKS or prev_status is None:
            status = worst["status"]
        else:
            status = prev_status          # henüz doğrulanmadı: önceki durum korunur
        detail = worst["detail"] if status != OK and worst["status"] != OK else "ok"
        entry = {"id": comp["id"], "name": comp["name"], "status": status, "detail": detail, "since": p.get("since") if prev_status == status else t.isoformat(),
                 "consecutive_bad": streak, "last_reminder": p.get("last_reminder")}
        if prev_status != status and not (prev_status is None and status == OK):   # ilk koşuda sağlıklı = sessiz; ilk koşuda bozuk = bir kez duyurulur
            kind = "recovered" if status == OK else ("outage" if status == OUTAGE else "degraded")
            transitions.append({"component": comp["id"], "name": comp["name"], "kind": kind, "from": prev_status or "unknown", "to": status, "detail": detail})
            entry["last_reminder"] = t.isoformat() if status == OUTAGE else None
        elif status == OUTAGE and (not p.get("last_reminder") or t - datetime.fromisoformat(p["last_reminder"]) >= timedelta(hours=REMIND_HOURS)):
            transitions.append({"component": comp["id"], "name": comp["name"], "kind": "reminder", "from": status, "to": status, "detail": detail})
            entry["last_reminder"] = t.isoformat()
        comps.append(entry)
    overall = max((SEVERITY[c["status"]] for c in comps), default=0)
    return {"generated_at": t.isoformat(), "overall": [OK, DEGRADED, OUTAGE][overall], "components": comps}, transitions


def update_history(hist, status, t):
    """Günlük sayaçlar: {bileşen: {YYYY-MM-DD: [ok_turlari, toplam_tur]}}; 90 günden eskisi atılır."""
    hist = hist or {}
    day = t.strftime("%Y-%m-%d")
    for c in status["components"]:
        h = hist.setdefault(c["id"], {})
        ok, total = h.get(day, [0, 0])
        h[day] = [ok + (1 if c["status"] == OK else 0), total + 1]
    cut = (t - timedelta(days=HISTORY_DAYS)).strftime("%Y-%m-%d")
    for cid in list(hist):
        hist[cid] = {d: v for d, v in hist[cid].items() if d >= cut}
    return hist


def uptime(hist, cid):
    days = hist.get(cid, {})
    ok = sum(v[0] for v in days.values())
    total = sum(v[1] for v in days.values())
    return None if total == 0 else round(100.0 * ok / total, 3)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# bildirim (ntfy) — konu adı sır: ortam değişkeninden, çıktıya/günlüğe ASLA girmez
# ---------------------------------------------------------------------------------------------------------------------------------------------
def notify(transitions, topic, post=None):
    if not transitions:
        return 0
    if not topic:
        print("ntfy: NTFY_TOPIC unset, %d notification(s) skipped" % len(transitions))
        return 0
    post = post or _post
    sent = 0
    for tr in transitions:
        title = {"outage": "Hoxt KESİNTİ", "degraded": "Hoxt bozulma", "recovered": "Hoxt düzeldi", "reminder": "Hoxt kesinti SÜRÜYOR"}[tr["kind"]]
        msg = "%s: %s (%s)" % (tr["name"], tr["to"], tr["detail"])
        prio = "5" if tr["kind"] in ("outage", "reminder") else ("3" if tr["kind"] == "recovered" else "4")
        tags = {"outage": "rotating_light", "reminder": "rotating_light", "degraded": "warning", "recovered": "white_check_mark"}[tr["kind"]]
        try:
            post("https://ntfy.sh/" + topic, msg, {"Title": title, "Priority": prio, "Tags": tags})
            sent += 1
        except Exception as e:  # noqa: BLE001 — ağ hatası izlemeyi düşürmez; konu adı mesaja girmez
            print("ntfy: send failed (%s)" % type(e).__name__)
    return sent


def _post(url, msg, headers):
    req = urllib.request.Request(url, data=msg.encode("utf-8"), headers={**headers, "Content-Type": "text/plain; charset=utf-8"}, method="POST")
    urllib.request.urlopen(req, timeout=15).read()


# ---------------------------------------------------------------------------------------------------------------------------------------------
def load_records(path):
    rows = {}
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        name, rtype, value = line.split("\t")[:3]
        rows.setdefault((name.lower(), rtype.upper()), []).append(value)
    return [(n, t, v) for (n, t), v in rows.items()]


def main(argv=None, net=None, t=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows/CI konsol kodlamasından bağımsız
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--records", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--no-notify", action="store_true")
    a = ap.parse_args(argv)
    cfg = json.load(open(a.config, encoding="utf-8"))
    records = load_records(a.records)
    t = t or now()
    net = net or Network()
    os.makedirs(a.data, exist_ok=True)
    sp, hp = os.path.join(a.data, "status.json"), os.path.join(a.data, "history.json")
    prev = json.load(open(sp, encoding="utf-8")) if os.path.exists(sp) else None
    hist = json.load(open(hp, encoding="utf-8")) if os.path.exists(hp) else {}

    status, transitions = merge(prev, run_all(net, cfg, records), cfg, t)
    hist = update_history(hist, status, t)
    for c in status["components"]:
        c["uptime_90d"] = uptime(hist, c["id"])
    for c in status["components"]:
        c.pop("detail", None)   # HATA AYRINTISI herkese açık depoya GİRMEZ (yalnız ntfy mesajında, özel kanalda)
    json.dump(status, open(sp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    json.dump(hist, open(hp, "w", encoding="utf-8"), indent=1, sort_keys=True)
    sent = 0 if a.no_notify else notify(transitions, os.environ.get("NTFY_TOPIC", ""))
    print("STATUS overall=%s components=%d transitions=%d notified=%d" % (status["overall"], len(status["components"]), len(transitions), sent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
