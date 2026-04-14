#!/usr/bin/env python3
"""
Analyseur auth.log — Projet AEGIS Phase 3.2
Usage : sudo python3 analyse_auth.py [--hours N] [--log /chemin/auth.log]
"""

import re
import json
import argparse
import datetime
import sys
import os
from collections import defaultdict

# ─────────────────────────────────────────────────────────────
# PARSING DES DATES
# auth.log peut avoir deux formats selon la version :
#   - "Apr 13 14:32:01"           (syslog classique, sans année)
#   - "2026-04-13T14:32:01+02:00" (format ISO, systemd)
# ─────────────────────────────────────────────────────────────
CURRENT_YEAR = datetime.datetime.now().year

def parse_date(date_str: str):
    """Tente de parser une date depuis auth.log. Retourne un datetime ou None."""
    date_str = date_str.strip()

    # Format ISO (systemd)
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            return datetime.datetime.strptime(date_str, fmt).replace(tzinfo=None)
        except ValueError:
            pass

    # Format syslog classique (sans année)
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(date_str, fmt)
            return dt.replace(year=CURRENT_YEAR)
        except ValueError:
            pass

    return None


# ─────────────────────────────────────────────────────────────
# EXPRESSIONS RÉGULIÈRES
# ─────────────────────────────────────────────────────────────

# Syslog classique : "Apr 13 14:32:01 hostname sshd[1234]: ..."
RE_SYSLOG = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+?)\[?\d*\]?:\s+(.*)$'
)
# Journald ISO : "2026-04-13T14:32:01+02:00 hostname sshd[1234]: ..."
RE_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+\S+\s+(\S+?)\[?\d*\]?:\s+(.*)$'
)

RE_FAILED   = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)')
RE_ACCEPTED = re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)')
RE_SUDO     = re.compile(r'(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)')
RE_INVALID  = re.compile(r'Invalid user (\S+) from ([\d.]+)')


def parse_line(line: str):
    """Retourne (datetime, process, message) ou None."""
    for pattern in (RE_ISO, RE_SYSLOG):
        m = pattern.match(line)
        if m:
            dt = parse_date(m.group(1))
            return dt, m.group(2), m.group(3)
    return None


# ─────────────────────────────────────────────────────────────
# ANALYSE PRINCIPALE
# ─────────────────────────────────────────────────────────────
def analyser_auth_log(log_path: str, heures: int):

    if not os.path.exists(log_path):
        print(f"[!] Fichier introuvable : {log_path}")
        sys.exit(1)

    maintenant    = datetime.datetime.now()
    limite        = maintenant - datetime.timedelta(hours=heures)

    echecs        = defaultdict(list)   # ip → [(timestamp, user), ...]
    connexions    = defaultdict(list)   # user → [timestamp, ...]
    sudo_cmds     = []
    invalid_users = defaultdict(int)    # ip → count

    lignes_parsees = 0
    lignes_hors_periode = 0

    with open(log_path, "r", errors="replace") as f:
        for ligne in f:
            ligne = ligne.rstrip()
            parsed = parse_line(ligne)
            if not parsed:
                continue

            dt, process, message = parsed
            lignes_parsees += 1

            if dt and dt < limite:
                lignes_hors_periode += 1
                continue

            # Tentatives échouées SSH
            m = RE_FAILED.search(message)
            if m:
                echecs[m.group(2)].append({
                    "timestamp": dt.isoformat() if dt else "inconnu",
                    "user": m.group(1)
                })
                continue

            # Connexions réussies SSH
            m = RE_ACCEPTED.search(message)
            if m:
                connexions[m.group(1)].append({
                    "timestamp": dt.isoformat() if dt else "inconnu",
                    "ip": m.group(2)
                })
                continue

            # Commandes sudo
            m = RE_SUDO.search(message)
            if m:
                sudo_cmds.append({
                    "timestamp": dt.isoformat() if dt else "inconnu",
                    "user": m.group(1),
                    "as_user": m.group(2),
                    "commande": m.group(3).strip()
                })
                continue

            # Utilisateurs invalides
            m = RE_INVALID.search(message)
            if m:
                invalid_users[m.group(2)] += 1

    # IPs avec plus de 5 tentatives
    ip_suspectes = {
        ip: {
            "tentatives": len(events),
            "utilisateurs_cibles": list({e["user"] for e in events}),
            "premier": events[0]["timestamp"] if events else "",
            "dernier": events[-1]["timestamp"] if events else "",
        }
        for ip, events in echecs.items()
        if len(events) > 5
    }

    return {
        "meta": {
            "fichier": log_path,
            "periode_heures": heures,
            "analyse_le": maintenant.isoformat(),
            "lignes_parsees": lignes_parsees,
        },
        "echecs_par_ip": {
            ip: {"count": len(ev), "details": ev}
            for ip, ev in echecs.items()
        },
        "ip_suspectes_plus_5_tentatives": ip_suspectes,
        "connexions_reussies": dict(connexions),
        "commandes_sudo": sudo_cmds,
        "utilisateurs_invalides": dict(invalid_users),
        "resume": {
            "total_echecs": sum(len(v) for v in echecs.values()),
            "ip_uniques_echecs": len(echecs),
            "ip_suspectes": len(ip_suspectes),
            "connexions_reussies": sum(len(v) for v in connexions.values()),
            "commandes_sudo": len(sudo_cmds),
        }
    }


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyseur auth.log — AEGIS")
    parser.add_argument("--hours", type=int, default=24,
                        help="Analyser les N dernières heures (défaut: 24)")
    parser.add_argument("--log", type=str, default="/var/log/auth.log",
                        help="Chemin vers auth.log")
    parser.add_argument("--output", type=str, default="analyse_auth.json",
                        help="Fichier JSON de sortie")
    args = parser.parse_args()

    print(f"\n🛡  AEGIS — Analyse auth.log ({args.hours}h)")
    print(f"   Fichier : {args.log}\n")

    resultats = analyser_auth_log(args.log, args.hours)

    # Résumé console
    r = resultats["resume"]
    print(f"  Échecs SSH totaux     : {r['total_echecs']}")
    print(f"  IPs distinctes        : {r['ip_uniques_echecs']}")
    print(f"  IPs suspectes (>5)    : {r['ip_suspectes']}")
    print(f"  Connexions réussies   : {r['connexions_reussies']}")
    print(f"  Commandes sudo        : {r['commandes_sudo']}")

    if resultats["ip_suspectes_plus_5_tentatives"]:
        print("\n  ⚠  IPs SUSPECTES :")
        for ip, info in resultats["ip_suspectes_plus_5_tentatives"].items():
            print(f"    {ip:20s} — {info['tentatives']} tentatives — cibles: {', '.join(info['utilisateurs_cibles'])}")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Rapport exporté : {args.output}")
