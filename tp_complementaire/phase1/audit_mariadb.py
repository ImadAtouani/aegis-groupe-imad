#!/usr/bin/env python3
"""
Audit MariaDB — Projet AEGIS
Phase 1.5 — Vérifications de sécurité base de données
Les credentials sont lus depuis un fichier .env, jamais dans le code.
"""

import socket
import subprocess
import json
import os
import sys
import datetime

# ─────────────────────────────────────────────────────────────
# CHARGEMENT DES CREDENTIALS DEPUIS .env
# ─────────────────────────────────────────────────────────────
def load_env(path=".env"):
    """Charge les variables depuis un fichier .env simple."""
    env = {}
    if not os.path.exists(path):
        print(f"[!] Fichier {path} introuvable.")
        print("    Créez-le avec le contenu suivant :")
        print("    DB_AUDIT_USER=audituser")
        print("    DB_AUDIT_PASS=VotreMotDePasse")
        sys.exit(1)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

# ─────────────────────────────────────────────────────────────
# VÉRIFICATION PORT 3306 DEPUIS L'EXTÉRIEUR
# ─────────────────────────────────────────────────────────────
def get_external_ip():
    """Récupère l'IP de l'interface réseau principale (pas 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def check_port_3306_external(host="127.0.0.1", timeout=2):
    """
    Tente une connexion TCP sur 3306.
    En pratique, lancez ce check depuis une VM attaquante
    avec l'IP du serveur cible.
    """
    try:
        with socket.create_connection((host, 3306), timeout=timeout):
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False

# ─────────────────────────────────────────────────────────────
# VÉRIFICATIONS SQL (compte lecture seule)
# ─────────────────────────────────────────────────────────────
def run_sql_checks(user, password, host="127.0.0.1"):
    """
    Exécute les vérifications de sécurité MariaDB.
    Le compte utilisé n'a que les droits SELECT sur mysql.*
    """
    results = {}

    def sql(query):
        """Exécute une requête via mysql en ligne de commande."""
        cmd = [
            "mysql",
            f"-u{user}",
            f"-p{password}",
            f"-h{host}",
            "--batch",
            "--skip-column-names",
            "-e", query
        ]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            return out.strip()
        except subprocess.CalledProcessError:
            return None

    # 1. Root a-t-il un mot de passe ?
    root_check = sql(
        "SELECT COUNT(*) FROM mysql.user "
        "WHERE User='root' AND (authentication_string='' OR authentication_string IS NULL);"
    )
    results["root_sans_mot_de_passe"] = {
        "valeur": root_check == "1" if root_check is not None else "vérification impossible",
        "risque": "CRITIQUE" if root_check == "1" else "OK",
        "detail": "Le compte root MariaDB n'a pas de mot de passe" if root_check == "1"
                  else "Root a un mot de passe défini"
    }

    # 2. Comptes sans mot de passe
    no_pass = sql(
        "SELECT GROUP_CONCAT(User, '@', Host SEPARATOR ', ') FROM mysql.user "
        "WHERE (authentication_string='' OR authentication_string IS NULL) AND User NOT IN ('', 'mariadb.sys');"
    )
    results["comptes_sans_mot_de_passe"] = {
        "valeur": no_pass if no_pass else "aucun",
        "risque": "ÉLEVÉ" if no_pass and no_pass != "NULL" else "OK",
        "detail": f"Comptes sans mot de passe : {no_pass}" if no_pass else "Tous les comptes ont un mot de passe"
    }

    # 3. Base 'test' présente ?
    test_db = sql("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test';")
    results["base_test_presente"] = {
        "valeur": test_db == "1" if test_db is not None else "inconnu",
        "risque": "MOYEN" if test_db == "1" else "OK",
        "detail": "La base 'test' existe (à supprimer)" if test_db == "1"
                  else "Base 'test' absente — bien"
    }

    # 4. Bind-address (lecture du fichier de config)
    bind = "inconnu"
    for conf_path in ["/etc/mysql/mariadb.conf.d/50-server.cnf",
                      "/etc/mysql/mysql.conf.d/mysqld.cnf",
                      "/etc/mysql/my.cnf"]:
        if os.path.exists(conf_path):
            try:
                with open(conf_path) as f:
                    for line in f:
                        if line.strip().startswith("bind-address"):
                            bind = line.split("=")[1].strip()
                            break
            except PermissionError:
                bind = "permission refusée (relancer en sudo)"
            break
    results["bind_address"] = {
        "valeur": bind,
        "risque": "CRITIQUE" if bind == "0.0.0.0" else ("OK" if bind in ["127.0.0.1", "localhost"] else "VÉRIFIER"),
        "detail": "MariaDB écoute sur toutes les interfaces — exposé WAN !" if bind == "0.0.0.0"
                  else f"MariaDB écoute sur {bind}"
    }

    # 5. Comptes avec accès depuis n'importe quel hôte (wildcard %)
    wildcard = sql(
        "SELECT GROUP_CONCAT(User, '@', Host SEPARATOR ', ') FROM mysql.user WHERE Host='%';"
    )
    results["comptes_wildcard_host"] = {
        "valeur": wildcard if wildcard and wildcard != "NULL" else "aucun",
        "risque": "ÉLEVÉ" if wildcard and wildcard != "NULL" else "OK",
        "detail": f"Comptes accessibles depuis n'importe où : {wildcard}" if wildcard and wildcard != "NULL"
                  else "Aucun compte avec hôte wildcard '%'"
    }

    return results


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🛡  AEGIS — Audit MariaDB")
    print(f"   {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}\n")

    env = load_env(".env")
    db_user = env.get("DB_AUDIT_USER", "audituser")
    db_pass = env.get("DB_AUDIT_PASS", "")

    audit = {
        "meta": {
            "date": datetime.datetime.now().isoformat(),
            "module": "audit_mariadb"
        },
        "port_3306_accessible_localement": check_port_3306_external("127.0.0.1"),
	"port_3306_accessible_externe": check_port_3306_external(
    		os.environ.get("TARGET_IP", get_external_ip())
	),
        "verifications_sql": run_sql_checks(db_user, db_pass)
    }

    # Affichage résumé
    print("  RÉSULTATS :")
    print(f"  Port 3306 local       : {'OUVERT' if audit['port_3306_accessible_localement'] else 'fermé'}")
    print(f"  Port 3306 externe     : {'⚠ OUVERT' if audit['port_3306_accessible_externe'] else 'fermé (bien)'}")
    for k, v in audit["verifications_sql"].items():
        emoji = "✅" if v["risque"] == "OK" else "⚠️ "
        print(f"  {emoji} {k:35s}: [{v['risque']:8s}] {v['detail']}")

    # Export JSON
    output_file = "audit_mariadb.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Rapport exporté : {output_file}")
