<?php
/**
 * ✅  VERSION SÉCURISÉE — Projet AEGIS Phase 2.3
 * Corrections appliquées :
 *   1. Vérification du type MIME avec finfo_file() côté serveur
 *   2. Seules les images sont acceptées
 *   3. Le fichier est renommé à l'arrivée (UUID + extension contrôlée)
 *   4. L'exécution PHP est désactivée dans /upload/ via .htaccess
 */

$upload_dir = __DIR__ . '/upload/';
$message    = '';
$erreur     = '';

// Types MIME autorisés (images uniquement)
const MIME_AUTORISES = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/gif'  => 'gif',
    'image/webp' => 'webp',
];

const TAILLE_MAX = 2 * 1024 * 1024; // 2 Mo

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['fichier'])) {

    $tmp  = $_FILES['fichier']['tmp_name'];
    $size = $_FILES['fichier']['size'];

    // ── 1. Vérification taille ───────────────────────────
    if ($size > TAILLE_MAX) {
        $erreur = "Fichier trop volumineux (max 2 Mo).";
    } else {
        // ── 2. Vérification MIME réelle (pas l'extension) ──
        $finfo     = new finfo(FILEINFO_MIME_TYPE);
        $mime_reel = $finfo->file($tmp);

        if (!array_key_exists($mime_reel, MIME_AUTORISES)) {
            $erreur = "Type de fichier refusé : $mime_reel. Seules les images JPEG/PNG/GIF/WebP sont acceptées.";
        } else {
            // ── 3. Renommage avec un nom aléatoire ────────
            $extension    = MIME_AUTORISES[$mime_reel];
            $nouveau_nom  = bin2hex(random_bytes(16)) . '.' . $extension;
            $destination  = $upload_dir . $nouveau_nom;

            if (move_uploaded_file($tmp, $destination)) {
                $message = "Image uploadée avec succès sous le nom : $nouveau_nom";
            } else {
                $erreur = "Échec de l'enregistrement du fichier.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>TechSud — Upload sécurisé</title>
    <style>
        body  { font-family: sans-serif; max-width: 600px; margin: 60px auto; }
        .ok   { background: #d4edda; border: 1px solid #28a745; padding: 10px; margin-top: 10px; }
        .err  { background: #f8d7da; border: 1px solid #dc3545; padding: 10px; margin-top: 10px; }
        .info { background: #d1ecf1; border: 1px solid #17a2b8; padding: 10px; margin-bottom: 20px; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="info">
        ✅ Version sécurisée — MIME vérifié côté serveur, fichier renommé, PHP désactivé dans /upload/
    </div>
    <h2>Envoyer une image</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="fichier" accept="image/*" required><br><br>
        <button type="submit">Envoyer</button>
    </form>
    <?php if ($message): ?><div class="ok"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($erreur):  ?><div class="err"><?= htmlspecialchars($erreur) ?></div><?php endif; ?>
</body>
</html>
