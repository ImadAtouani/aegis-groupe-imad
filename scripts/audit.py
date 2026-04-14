#!/usr/bin/env python3
"""
Script d'audit de sécurité — Projet AEGIS
IPSSI BTC1 — TechSud fictif
"""

import subprocess
import socket
import json
import csv
import os
import sys
import datetime
import platform

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
PORTS_TO_CHECK = [21, 22, 23, 25, 80, 443, 445, 2222, 3306, 3389, 5001, 8080, 8443]
SCAN_TARGET = "127.0.0.1"
OUTPUT_JSON = "audit_result.json"
OUTPUT_CSV  = "audit_result.csv"

results = {
    "meta": {},
    "system": {},
    "network": {},
    "ports": [],
    "users": [],
    "services": [],
    "ssh_config": {},
    "ufw_status": "",
    "fail2ban_status": "",
    "vulnerabilities": []
}

# ─────────────────────────────────────────
def run(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)
        return out.strip()
    except:
        return ""

def check_port(host, port, timeout=1):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

# ─────────────────────────────────────────
# 1. METADATA
# ─────────────────────────────────────────
def collect_meta():
    print("[*] Collecte des métadonnées...")
    results["meta"] = {
        "date": datetime.datetime.now().isoformat(),
        "auditor": os.getenv("USER", "inconnu"),
        "hostname": socket.gethostname(),
        "script_version": "1.0"
    }

# ─────────────────────────────────────────
# 2. SYSTÈME
# ─────────────────────────────────────────
def collect_system():
    print("[*] Collecte des infos système...")
    results["system"] = {
        "os": platform.system(),
        "release": platform.release(),
        "version": run("lsb_release -d | cut -d: -f2"),
        "kernel": run("uname -r"),
        "uptime": run("uptime -p"),
        "last_update": run("stat -c %y /var/cache/apt/pkgcache.bin 2>/dev/null | cut -d' ' -f1"),
        "pending_updates": run("apt list --upgradable 2>/dev/null | grep -c upgradable") or "0",
    }

# ─────────────────────────────────────────
# 3. RÉSEAU
# ─────────────────────────────────────────
def collect_network():
    print("[*] Collecte des infos réseau...")
    results["network"] = {
        "interfaces": run("ip -brief addr"),
        "routes": run("ip route"),
        "listening_ports": run("ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null"),
    }

# ─────────────────────────────────────────
# 4. SCAN DE PORTS
# ─────────────────────────────────────────
def scan_ports():
    print(f"[*] Scan des ports sur {SCAN_TARGET}...")
    for port in PORTS_TO_CHECK:
        open_ = check_port(SCAN_TARGET, port)
        risk = "CRITIQUE" if port in [21,23,3306,3389,445] else \
               "ÉLEVÉ" if port in [22,80] else "FAIBLE"
        results["ports"].append({
            "port": port,
            "open": open_,
            "risk": risk if open_ else "N/A",
            "note": get_port_note(port) if open_ else ""
        })
        status = "OUVERT ⚠" if open_ else "fermé"
        print(f"    Port {port:5d} : {status}")

def get_port_note(port):
    notes = {
        21: "FTP — transfert non chiffré",
        22: "SSH — vérifier durcissement",
        23: "Telnet — NON CHIFFRÉ, désactiver",
        80: "HTTP — pas de HTTPS",
        445: "SMB — risque élevé si exposé WAN",
        3306: "MariaDB/MySQL — NE PAS exposer sur WAN",
        3389: "RDP — cible fréquente de bruteforce",
        2222: "SSH port custom — OK si durci",
        5001: "Synology DSM — accès admin NAS",
    }
    return notes.get(port, "")

# ─────────────────────────────────────────
# 5. UTILISATEURS
# ─────────────────────────────────────────
def collect_users():
    print("[*] Analyse des utilisateurs...")
    raw = run("cat /etc/passwd")
    for line in raw.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, uid, gid, _, home, shell = parts[:7]
        uid = int(uid)
        active = shell not in ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"]
        risk = ""
        if uid == 0 and username != "root":
            risk = "CRITIQUE — UID 0 non-root"
        elif active and uid >= 1000:
            risk = "VÉRIFIER"
        results["users"].append({
            "username": username,
            "uid": uid,
            "shell": shell,
            "active": active,
            "risk": risk
        })

# ─────────────────────────────────────────
# 6. SERVICES
# ─────────────────────────────────────────
def collect_services():
    print("[*] Collecte des services actifs...")
    raw = run("systemctl list-units --type=service --state=running --no-legend")
    for line in raw.splitlines():
        parts = line.split()
        if parts:
            results["services"].append(parts[0])

# ─────────────────────────────────────────
# 7. CONFIG SSH
# ─────────────────────────────────────────
def check_ssh():
    print("[*] Vérification configuration SSH...")
    checks = {
        "PermitRootLogin": ("no", "CRITIQUE"),
        "PasswordAuthentication": ("no", "ÉLEVÉ"),
        "Port": ("2222", "INFO"),
        "MaxAuthTries": ("3", "MOYEN"),
        "X11Forwarding": ("no", "FAIBLE"),
    }
    config_raw = run("sudo sshd -T 2>/dev/null")
    ssh_conf = {}
    for key, (expected, severity) in checks.items():
        val = run(f"echo '{config_raw}' | grep -i '^{key.lower()} ' | awk '{{print $2}}'")
        ok = val.lower() == expected.lower()
        ssh_conf[key] = {
            "value": val or "non trouvé",
            "expected": expected,
            "ok": ok,
            "severity": severity if not ok else "OK"
        }
        if not ok:
            results["vulnerabilities"].append({
                "id": f"SSH-{key}",
                "severity": severity,
                "description": f"SSH: {key} = '{val}' (attendu: '{expected}')",
                "recommendation": f"Modifier /etc/ssh/sshd_config : {key} {expected}"
            })
    results["ssh_config"] = ssh_conf

# ─────────────────────────────────────────
# 8. UFW
# ─────────────────────────────────────────
def check_ufw():
    print("[*] Vérification UFW...")
    status = run("sudo ufw status verbose 2>/dev/null")
    results["ufw_status"] = status
    if "inactive" in status.lower() or not status:
        results["vulnerabilities"].append({
            "id": "FW-001",
            "severity": "CRITIQUE",
            "description": "Pare-feu UFW inactif ou non configuré",
            "recommendation": "Activer ufw : sudo ufw enable"
        })

# ─────────────────────────────────────────
# 9. FAIL2BAN
# ─────────────────────────────────────────
def check_fail2ban():
    print("[*] Vérification fail2ban...")
    status = run("sudo fail2ban-client status 2>/dev/null")
    results["fail2ban_status"] = status
    if not status:
        results["vulnerabilities"].append({
            "id": "F2B-001",
            "severity": "ÉLEVÉ",
            "description": "fail2ban non actif",
            "recommendation": "Installer et démarrer fail2ban"
        })

# ─────────────────────────────────────────
# 10. EXPORT
# ─────────────────────────────────────────
def export_json():
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[+] Résultats exportés : {OUTPUT_JSON}")

def export_csv():
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Ouvert", "Risque", "Note"])
        for p in results["ports"]:
            writer.writerow([p["port"], p["open"], p["risk"], p["note"]])
    print(f"[+] Résultats CSV exportés : {OUTPUT_CSV}")

def print_summary():
    print("\n" + "="*50)
    print("  RÉSUMÉ DE L'AUDIT")
    print("="*50)
    open_ports = [p for p in results["ports"] if p["open"]]
    print(f"  Ports ouverts     : {len(open_ports)}/{len(PORTS_TO_CHECK)}")
    print(f"  Vulnérabilités    : {len(results['vulnerabilities'])}")
    critiques = [v for v in results["vulnerabilities"] if v["severity"] == "CRITIQUE"]
    print(f"  ⚠  Critiques       : {len(critiques)}")
    print()
    if results["vulnerabilities"]:
        print("  VULNÉRABILITÉS DÉTECTÉES :")
        for v in results["vulnerabilities"]:
            print(f"  [{v['severity']:8s}] {v['id']} — {v['description']}")
    print("="*50)

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("\n🛡  AEGIS — Script d'audit de sécurité")
    print(f"   Cible : {SCAN_TARGET}  |  {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}\n")

    collect_meta()
    collect_system()
    collect_network()
    scan_ports()
    collect_users()
    collect_services()
    check_ssh()
    check_ufw()
    check_fail2ban()
    export_json()
    export_csv()
    print_summary()
