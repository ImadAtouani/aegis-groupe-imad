<?php
/**
 * ⚠️  VERSION VULNÉRABLE — usage pédagogique uniquement
 * Projet AEGIS — Phase 2.2
 * Ce formulaire accepte n'importe quel fichier sans aucune vérification.
 * C'est exactement ce qui a permis l'upload du webshell sur TechSud.
 */

$upload_dir = __DIR__ . '/upload/';
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['fichier'])) {
    $nom_original = $_FILES['fichier']['name'];
    $destination  = $upload_dir . $nom_original;

    // ❌ Aucune vérification : ni extension, ni type MIME, ni taille
    if (move_uploaded_file($_FILES['fichier']['tmp_name'], $destination)) {
        $message = "Fichier uploadé : <a href='upload/$nom_original'>$nom_original</a>";
    } else {
        $message = "Échec de l'upload.";
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>TechSud — Formulaire de contact (VULNÉRABLE)</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 60px auto; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin-bottom: 20px; }
        .msg { background: #d4edda; padding: 10px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="warning">⚠️ VERSION VULNÉRABLE — Usage pédagogique AEGIS uniquement</div>
    <h2>Envoyer un fichier</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="fichier" required><br><br>
        <button type="submit">Envoyer</button>
    </form>
    <?php if ($message): ?>
        <div class="msg"><?= $message ?></div>
    <?php endif; ?>
</body>
</html>
