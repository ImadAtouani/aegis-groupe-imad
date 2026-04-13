# Analyse des vecteurs d'attaque — TechSud

## Vecteurs probables
1. Webshell via formulaire de contact (upload sans validation MIME)
   - /var/www/html/upload/shell.php uploadé sur SRV-WEB-01
   - Porte d'entrée probable de l'attaquant

2. Compte "deploy" réactivé / mot de passe faible
   - Connexion SSH depuis 185.220.101.47 (Tor exit node)
   - Compte normalement désactivé

3. SSH exposé sur Internet sans restriction (ports 22 ouverts SRV-PROD-01 + SRV-WEB-01)

4. MariaDB potentiellement exposé sur WAN (port 3306)

5. Site en HTTP sans HTTPS — interception possible

6. Pas de logs centralisés — effacement facilité (auth.log partiellement effacé)

7. Cron malveillant : /etc/cron.d/sysupdate → exécute /tmp/.x11-unix/sshd_bak toutes les 5 min

8. Connexion C2 vers 45.142.212.10:4444 (probablement reverse shell / miner)
