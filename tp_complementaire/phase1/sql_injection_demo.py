#!/usr/bin/env python3
"""
Démonstration injection SQL — Projet AEGIS
Phase 1.4 — Version vulnérable vs version sécurisée
"""

import mysql.connector
import sys

# ─────────────────────────────────────────────────────────────
# CONNEXION
# ─────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "appuser",
    "password": "AppUser@2026!",
    "database": "techsud_db"
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ─────────────────────────────────────────────────────────────
# VERSION VULNÉRABLE — concaténation de chaînes
# ─────────────────────────────────────────────────────────────
def chercher_client_vulnerable(nom_cherche: str):
    """
    ⚠️  DANGEREUX — Ne jamais faire ça en production.
    La valeur de nom_cherche est insérée telle quelle dans la requête SQL.
    Un attaquant peut y glisser du SQL arbitraire.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Requête construite par concaténation — VULNÉRABLE
    query = "SELECT id, nom, email FROM clients WHERE nom = '" + nom_cherche + "'"
    print(f"\n[VULNERABLE] Requête exécutée :\n  {query}")

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                print(f"  → Résultat : id={row[0]}, nom={row[1]}, email={row[2]}")
        else:
            print("  → Aucun résultat.")
    except mysql.connector.Error as e:
        print(f"  → Erreur SQL : {e}")
    finally:
        cursor.close()
        conn.close()


# ─────────────────────────────────────────────────────────────
# VERSION SÉCURISÉE — requêtes paramétrées
# ─────────────────────────────────────────────────────────────
def chercher_client_securise(nom_cherche: str):
    """
    ✅  SÉCURISÉ — Le connecteur MySQL échappe automatiquement
    la valeur avant de l'insérer. Le SQL injecté est traité
    comme une donnée, pas comme du code.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Requête paramétrée — le %s est un placeholder
    query = "SELECT id, nom, email FROM clients WHERE nom = %s"
    print(f"\n[SECURISE] Requête template :\n  {query}")
    print(f"  Paramètre transmis séparément : {repr(nom_cherche)}")

    try:
        cursor.execute(query, (nom_cherche,))
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                print(f"  → Résultat : id={row[0]}, nom={row[1]}, email={row[2]}")
        else:
            print("  → Aucun résultat (injection neutralisée).")
    except mysql.connector.Error as e:
        print(f"  → Erreur SQL : {e}")
    finally:
        cursor.close()
        conn.close()


# ─────────────────────────────────────────────────────────────
# DÉMONSTRATION
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  DÉMONSTRATION INJECTION SQL — AEGIS / TechSud")
    print("=" * 60)

    # ── Cas 1 : requête normale ──────────────────────────────
    print("\n━━━ CAS 1 : Recherche normale ━━━")
    chercher_client_vulnerable("Dupont")
    chercher_client_securise("Dupont")

    # ── Cas 2 : injection classique (dump toute la table) ────
    print("\n━━━ CAS 2 : Injection — dump toute la table ━━━")
    payload_dump = "' OR '1'='1"
    print(f"  Payload injecté : {payload_dump}")
    # La requête devient : WHERE nom = '' OR '1'='1'
    # → condition toujours vraie → tous les enregistrements retournés
    chercher_client_vulnerable(payload_dump)
    chercher_client_securise(payload_dump)   # Rien retourné : le payload est traité comme un nom

    # ── Cas 3 : injection UNION (exfiltration d'autres tables) ──
    print("\n━━━ CAS 3 : Injection UNION — lecture d'autres données ━━━")
    payload_union = "' UNION SELECT 1, user(), database() -- "
    print(f"  Payload injecté : {payload_union}")
    # La requête devient : WHERE nom = '' UNION SELECT 1, user(), database() --
    # → retourne l'utilisateur SQL courant et le nom de la base
    chercher_client_vulnerable(payload_union)
    chercher_client_securise(payload_union)

    # ── Cas 4 : injection avec commentaire (bypass filtre naïf) ──
    print("\n━━━ CAS 4 : Injection avec fermeture de guillemet ━━━")
    payload_comment = "Dupont' -- "
    print(f"  Payload injecté : {payload_comment}")
    chercher_client_vulnerable(payload_comment)
    chercher_client_securise(payload_comment)

    print("\n" + "=" * 60)
    print("  CONCLUSION")
    print("=" * 60)
    print("""
  Version vulnérable :
    - Le payload est concaténé directement dans la requête SQL.
    - L'attaquant contrôle la structure de la requête.
    - Il peut lire toute la base, contourner l'authentification,
      exfiltrer des données sensibles, voire exécuter des commandes
      système (via LOAD_FILE / INTO OUTFILE selon les droits).

  Version sécurisée (requêtes paramétrées) :
    - La requête SQL est compilée AVANT d'y injecter les données.
    - Le connecteur échappe les caractères spéciaux (', --, etc.).
    - Le payload est traité comme une simple chaîne de caractères,
      jamais comme du code SQL.
    - Aucun des payloads ci-dessus ne fonctionne.
""")
