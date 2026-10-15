#!/usr/bin/env python3
"""Herkese acik durum deposu icin GIZLILIK KAPISI (Tolga sarti): public depoya/sayfaya sunucu IP'si, ic makine adi, hata ayrintisi veya log GIRMEZ;
yalniz hizmet adi + durum + zaman. Kullanim:
  python3 public_gate.py output <data_dir> <docs_dir>     # uretilen cikti: yapisal beyaz liste + IP/ic-ad/hata-ayrintisi desenleri (tum dosyalar)
  python3 public_gate.py source <dosya>...                # kaynak dosyalar: yalniz IP + ic-ad desenleri
Cikis 0 = temiz, 1 = ihlal (ihlaller dosya:satir + desen adiyla yazilir, EŞLEŞEN DEGER YAZILMAZ)."""
import json
import os
import re
import sys

ALLOWED_IPS = {"8.8.8.8", "1.1.1.1"}   # herkese acik cozumleyiciler (checks.json: public_resolvers)
STATUSES = {"operational", "degraded", "outage"}
TOP_KEYS = {"generated_at", "overall", "components"}
COMP_KEYS_DATA = {"id", "name", "status", "since", "consecutive_bad", "last_reminder", "uptime_90d"}
COMP_KEYS_DOCS = {"id", "name", "status", "since", "uptime_90d"}

IP_PATTERNS = [
    ("ipv4", re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")),
    ("ipv6", re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z])|(?<![0-9A-Za-z:])[0-9A-Fa-f:]*::[0-9A-Fa-f:]*(?![0-9A-Za-z:])")),
]
NAME_PATTERNS = [
    ("ic-ad-soneki", re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:internal|local|lan|corp|intranet|home|localdomain|lxd)\b", re.I)),
    ("localhost", re.compile(r"\blocalhost\b", re.I)),
    ("staging-adi", re.compile(r"\bstaging\b", re.I)),
    ("kullanici@host", re.compile(r"\b(?:root|admin|ubuntu|deploy)@[\w.-]+", re.I)),
]
DETAIL_PATTERNS = [
    ("yigin-izi", re.compile(r"Traceback|\bat line \d+|\bException\b|Errno|\bstack trace\b", re.I)),
    ("dosya-yolu", re.compile(r"(?:^|[\s\"'(])/(?:var|etc|root|home|usr|opt|tmp)/", re.I)),
    ("hata-ayrintisi", re.compile(r"\b(?:http_\d{3}|unreachable|tls_unreachable|dns_mismatch|dns_no_answer|cert_expires_\d+d|unexpected_body)\b")),
    ("sir-benzeri", re.compile(r"ntfy\.sh/[A-Za-z0-9_-]{8,}|sk_(?:live|test)_|\bre_[A-Za-z0-9]{16,}|whsec[_]|-----BEGIN")),
]


def _lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            yield n, line


def _scan_text(path, patterns, out):
    for n, line in _lines(path):
        for name, rx in patterns:
            for m in rx.finditer(line):
                if name == "ipv4" and m.group(0) in ALLOWED_IPS:
                    continue
                out.append("%s:%d: %s" % (path, n, name))


def _scan_status_json(path, comp_keys, out):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        out.append("%s: gecersiz-json" % path)
        return
    if set(data) - TOP_KEYS:
        out.append("%s: beklenmeyen-ust-anahtar" % path)
    if data.get("overall") not in STATUSES:
        out.append("%s: gecersiz-genel-durum" % path)
    for c in data.get("components", []):
        extra = set(c) - comp_keys
        if extra:
            out.append("%s: beklenmeyen-bilesen-anahtari(%s)" % (path, ",".join(sorted(extra))))
        if c.get("status") not in STATUSES:
            out.append("%s: gecersiz-durum" % path)


def _files(root):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d != ".git"]
        for f in fn:
            if f.lower().endswith((".json", ".html", ".txt", ".md", ".xml", ".csv", ".tsv")):
                yield os.path.join(dp, f)


def check_output(data_dir, docs_dir):
    out = []
    sj = os.path.join(data_dir, "status.json")
    if os.path.exists(sj):
        _scan_status_json(sj, COMP_KEYS_DATA, out)
    dj = os.path.join(docs_dir, "status.json")
    if os.path.exists(dj):
        _scan_status_json(dj, COMP_KEYS_DOCS, out)
    for root in (data_dir, docs_dir):
        if os.path.isdir(root):
            for p in _files(root):
                _scan_text(p, IP_PATTERNS + NAME_PATTERNS + DETAIL_PATTERNS, out)
    return out


def check_source(paths):
    out = []
    for p in paths:
        _scan_text(p, IP_PATTERNS + NAME_PATTERNS, out)
    return out


def main(argv):
    if len(argv) >= 4 and argv[1] == "output":
        bad = check_output(argv[2], argv[3])
    elif len(argv) >= 3 and argv[1] == "source":
        bad = check_source(argv[2:])
    else:
        print(__doc__)
        return 2
    for b in bad:
        print("IHLAL " + b)
    print("GATE: " + ("KIRMIZI (%d ihlal)" % len(bad) if bad else "TEMIZ"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
