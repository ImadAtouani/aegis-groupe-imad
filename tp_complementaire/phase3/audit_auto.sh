#!/bin/bash
# ─────────────────────────────────────────────────────────────
# audit_auto.sh — Projet AEGIS Phase 3.4
# Script d'audit de sécurité avec sortie colorée
# Tourne en cron toutes les heures
#
# Crontab (sudo crontab -e) :
#   0 * * * * /opt/aegis/audit_auto.sh >> /var/log/audit_auto.log 2>&1
# ─────────────────────────────────────────────────────────────

LOG_FILE="/var/log/audit_auto.log"
SSH_PORT_ATTENDU="2222"
PORTS_INATTENDUS_REFERENCE=(22 23 21 3389 5900 6379)

# ── Couleurs ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'   # No Color

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

FAIL_COUNT=0
bump_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  🛡  AEGIS — Audit automatique de sécurité${NC}"
echo -e "${BOLD}  $(date '+%d/%m/%Y %H:%M:%S')${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""

# ── 1. UFW actif ? ───────────────────────────────────────────
echo -e "${BOLD}[1] Pare-feu UFW${NC}"
if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    ok "UFW est actif"
else
    fail "UFW est INACTIF — aucun filtrage réseau !"
    bump_fail
fi
echo ""

# ── 2. fail2ban actif ? ─────────────────────────────────────
echo -e "${BOLD}[2] fail2ban${NC}"
if systemctl is-active --quiet fail2ban; then
    BANS=$(sudo fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    ok "fail2ban actif — IPs bannies (sshd) : ${BANS:-0}"
else
    fail "fail2ban est INACTIF"
    bump_fail
fi
echo ""

# ── 3. SSH pas sur le port 22 ? ─────────────────────────────
echo -e "${BOLD}[3] Port SSH${NC}"
SSH_PORT_ACTUEL=$(sudo sshd -T 2>/dev/null | grep "^port " | awk '{print $2}')
if [ "$SSH_PORT_ACTUEL" = "$SSH_PORT_ATTENDU" ]; then
    ok "SSH écoute sur le port custom $SSH_PORT_ATTENDU (pas sur 22)"
elif [ "$SSH_PORT_ACTUEL" = "22" ]; then
    fail "SSH écoute sur le port 22 (standard) — facile à scanner"
    bump_fail
else
    warn "SSH écoute sur le port $SSH_PORT_ACTUEL (attendu: $SSH_PORT_ATTENDU)"
fi
echo ""

# ── 4. Root SSH désactivé ? ─────────────────────────────────
echo -e "${BOLD}[4] Accès root SSH${NC}"
PERMIT_ROOT=$(sudo sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')
if [ "$PERMIT_ROOT" = "no" ]; then
    ok "PermitRootLogin = no"
else
    fail "PermitRootLogin = $PERMIT_ROOT — root peut se connecter en SSH !"
    bump_fail
fi
echo ""

# ── 5. MariaDB sur 127.0.0.1 uniquement ? ───────────────────
echo -e "${BOLD}[5] MariaDB bind-address${NC}"
if systemctl is-active --quiet mariadb 2>/dev/null || systemctl is-active --quiet mysql 2>/dev/null; then
    BIND=""
    for conf in /etc/mysql/mariadb.conf.d/50-server.cnf \
                /etc/mysql/mysql.conf.d/mysqld.cnf \
                /etc/mysql/my.cnf; do
        if [ -f "$conf" ]; then
            BIND=$(grep "^bind-address" "$conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
            break
        fi
    done
    if [ "$BIND" = "127.0.0.1" ] || [ "$BIND" = "localhost" ]; then
        ok "MariaDB écoute sur 127.0.0.1 uniquement"
    elif [ "$BIND" = "0.0.0.0" ]; then
        fail "MariaDB écoute sur 0.0.0.0 — exposé sur le réseau !"
        bump_fail
    elif [ -z "$BIND" ]; then
        warn "bind-address non trouvé dans la config (vérifier manuellement)"
    else
        warn "MariaDB bind-address = $BIND"
    fi
else
    info "MariaDB non installé ou inactif"
fi
echo ""

# ── 6. Mises à jour de sécurité disponibles ? ───────────────
echo -e "${BOLD}[6] Mises à jour de sécurité${NC}"
if command -v apt &>/dev/null; then
    apt-get update -qq 2>/dev/null
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -i "security" | wc -l)
    if [ "$UPDATES" -eq 0 ]; then
        ok "Aucune mise à jour de sécurité en attente"
    else
        warn "$UPDATES mise(s) à jour de sécurité disponible(s)"
        apt-get -s upgrade 2>/dev/null | grep -i "security" | awk '{print "           " $2}' | head -5
    fi
else
    info "apt non disponible"
fi
echo ""

# ── 7. Processus sur des ports inattendus ? ─────────────────
echo -e "${BOLD}[7] Ports en écoute inattendus${NC}"
PORTS_ACTIFS=$(ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | grep -oP ':\K\d+$' | sort -u)
SUSPECT_FOUND=0
for port in $PORTS_ACTIFS; do
    for ref in "${PORTS_INATTENDUS_REFERENCE[@]}"; do
        if [ "$port" = "$ref" ]; then
            fail "Port inattendu en écoute : $port"
            bump_fail
            SUSPECT_FOUND=1
        fi
    done
done
if [ "$SUSPECT_FOUND" -eq 0 ]; then
    ok "Aucun port inattendu détecté parmi les référentiels"
fi
info "Ports actifs : $(echo $PORTS_ACTIFS | tr '\n' ' ')"
echo ""

# ── 8. Fichiers modifiés dans /etc/ dans les 24h ────────────
echo -e "${BOLD}[8] Modifications récentes dans /etc/ (24h)${NC}"
MODIFS=$(find /etc -maxdepth 3 -newer /etc/passwd -type f 2>/dev/null \
    | grep -v "\.dpkg-" | grep -v "/etc/mtab" | grep -v "resolv.conf" \
    | head -20)
if [ -z "$MODIFS" ]; then
    ok "Aucune modification suspecte dans /etc/ dans les 24h"
else
    warn "Fichiers modifiés dans /etc/ :"
    echo "$MODIFS" | while read -r f; do
        echo -e "           ${YELLOW}$f${NC}"
    done
fi
echo ""

# ── RÉSUMÉ ──────────────────────────────────────────────────
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ✅  Audit terminé — Aucun problème critique détecté${NC}"
else
    echo -e "${RED}${BOLD}  ⚠   Audit terminé — $FAIL_COUNT problème(s) critique(s) détecté(s)${NC}"
fi
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo ""
