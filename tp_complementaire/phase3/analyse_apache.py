#!/usr/bin/env python3
"""
Analyseur Apache access.log — Projet AEGIS Phase 3.3
Usage : sudo python3 analyse_apache.py [--log /chemin/access.log] [--output rapport.json]
"""

import re
import json
import argparse
import datetime
import os
import sys
from collections import defaultdict, Counter

# ─────────────────────────────────────────────────────────────
# FORMAT COMBINED APACHE
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/..."
# ─────────────────────────────────────────────────────────────
RE_ACCESS = re.compile(
    r'(?P<ip>[\d.]+)\s+'         # IP
    r'\S+\s+\S+\s+'              # ident, authuser
    r'\[(?P<date>[^\]]+)\]\s+'   # date
    r'"(?P<methode>\S+)\s+'      # méthode HTTP
    r'(?P<url>\S+)\s+'           # URL
    r'\S+"\s+'                   # protocole
    r'(?P<code>\d{3})\s+'        # code HTTP
    r'(?P<taille>\S+)\s+'        # taille
    r'"(?P<referer>[^"]*)"\s+'   # referer
    r'"(?P<ua>[^"]*)"'            # user-agent
)

# Patterns suspects dans les URLs
PATTERNS_SUSPECTS = [
    r'/etc/passwd',
    r'/proc/',
    r'\.\./\.\.',
    r'<script',
    r'SELECT\b',
    r'UNION\b',
    r'eval\(',
    r'base64_decode',
    r'system\(',
    r'phpinfo',
    r'shell\.php',
    r'cmd=',
    r'exec\(',
    r'\.\.%2[fF]',
    r'%3Cscript',
]
RE_SUSPECTS = re.compile('|'.join(PATTERNS_SUSPECTS), re.IGNORECASE)

def parse_apache_date(date_str: str):
    """Parse le format Apache : 10/Apr/2026:14:32:01 +0200"""
    try:
        date_str = date_str.split()[0]  # ignorer le timezone
        return datetime.datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None

def analyser_access_log(log_path: str):
    if not os.path.exists(log_path):
        print(f"[!] Fichier introuvable : {log_path}")
        sys.exit(1)

    erreurs_4xx5xx     = []
    requetes_suspectes = []
    user_agents        = Counter()
    codes_http         = Counter()
    ip_counter         = Counter()
    total              = 0

    with open(log_path, "r", errors="replace") as f:
        for ligne in f:
            m = RE_ACCESS.match(ligne.strip())
            if not m:
                continue

            total += 1
            ip      = m.group("ip")
            date    = m.group("date")
            url     = m.group("url")
            code    = int(m.group("code"))
            ua      = m.group("ua")
            methode = m.group("methode")
            taille  = m.group("taille")

            codes_http[code] += 1
            ip_counter[ip]   += 1
            user_agents[ua]  += 1

            dt = parse_apache_date(date)

            # ── Erreurs 4xx / 5xx ──
            if code >= 400:
                erreurs_4xx5xx.append({
                    "timestamp": dt.isoformat() if dt else date,
                    "ip": ip,
                    "methode": methode,
                    "url": url,
                    "code": code,
                    "ua": ua
                })

            # ── Patterns suspects ──
            if RE_SUSPECTS.search(url) or RE_SUSPECTS.search(ua):
                pattern_detecte = []
                for p in PATTERNS_SUSPECTS:
                    if re.search(p, url, re.IGNORECASE) or re.search(p, ua, re.IGNORECASE):
                        pattern_detecte.append(p.replace(r'\b', '').replace('\\', ''))

                requetes_suspectes.append({
                    "timestamp": dt.isoformat() if dt else date,
                    "ip": ip,
                    "methode": methode,
                    "url": url,
                    "code": code,
                    "ua": ua,
                    "patterns": pattern_detecte
                })

    # Top 5 User-Agents rares (les moins fréquents parmi les présents)
    ua_tries = user_agents.most_common()
    ua_rares = [
        {"user_agent": ua, "occurrences": count}
        for ua, count in reversed(ua_tries[-20:])  # 20 derniers = les plus rares
        if ua not in ("-", "")
    ][:5]

    return {
        "meta": {
            "fichier": log_path,
            "analyse_le": datetime.datetime.now().isoformat(),
            "total_requetes": total,
        },
        "codes_http": dict(codes_http.most_common()),
        "erreurs_4xx5xx": {
            "count": len(erreurs_4xx5xx),
            "details": erreurs_4xx5xx[:50]   # limité à 50 pour lisibilité
        },
        "requetes_suspectes": {
            "count": len(requetes_suspectes),
            "details": requetes_suspectes
        },
        "top5_user_agents_rares": ua_rares,
        "top10_ip": [
            {"ip": ip, "requetes": count}
            for ip, count in ip_counter.most_common(10)
        ],
        "resume": {
            "total_requetes": total,
            "erreurs_4xx5xx": len(erreurs_4xx5xx),
            "requetes_suspectes": len(requetes_suspectes),
            "ips_distinctes": len(ip_counter),
        }
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyseur access.log Apache — AEGIS")
    parser.add_argument("--log",    default="/var/log/apache2/access.log")
    parser.add_argument("--output", default="analyse_apache.json")
    args = parser.parse_args()

    print(f"\n🛡  AEGIS — Analyse Apache access.log")
    print(f"   Fichier : {args.log}\n")

    resultats = analyser_access_log(args.log)
    r = resultats["resume"]

    print(f"  Requêtes totales      : {r['total_requetes']}")
    print(f"  Erreurs 4xx/5xx       : {r['erreurs_4xx5xx']}")
    print(f"  Requêtes suspectes    : {r['requetes_suspectes']}")
    print(f"  IPs distinctes        : {r['ips_distinctes']}")

    if resultats["requetes_suspectes"]["count"] > 0:
        print("\n  ⚠  REQUÊTES SUSPECTES :")
        for req in resultats["requetes_suspectes"]["details"][:5]:
            print(f"    [{req['code']}] {req['ip']:15s} {req['url'][:60]}  patterns: {req['patterns']}")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Rapport exporté : {args.output}")
