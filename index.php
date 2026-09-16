<?php
$site = [
    'name' => 'Dariel Rodriguez',
    'title' => 'Seguridad De La Información',
    'subtitle' => 'Página web de prueba HTTPS, puertos y servidor HTTP',
    'image' => 'assets/personal-photo.jpg',
    'image_alt' => 'Imagen De Perfil',
];
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($site['name']) ?> — <?= htmlspecialchars($site['title']) ?></title>
    <style>
        :root {
            --bg: #fafaf9;
            --text: #1c1c1c;
            --muted: #6b7280;
            --border: #e7e5e4;
            --radius: 12px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Inter, -apple-system, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }
        header {
            max-width: 1080px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }
        .brand {
            font-weight: 700;
            font-size: 1.125rem;
            letter-spacing: -0.01em;
        }
        main {
            max-width: 1080px;
            margin: 0 auto;
            padding: 3rem 1.5rem 5rem;
        }
        .hero {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 4rem;
            align-items: center;
        }
        .hero-text h1 {
            font-size: clamp(2rem, 4.5vw, 3.25rem);
            font-weight: 700;
            letter-spacing: -0.03em;
            line-height: 1.15;
            margin-bottom: 1.25rem;
        }
        .hero-text p {
            color: var(--muted);
            font-size: 1.125rem;
            max-width: 32rem;
            margin-bottom: 2rem;
        }
        .btn {
            display: inline-block;
            background: var(--text);
            color: var(--bg);
            text-decoration: none;
            font-weight: 500;
            font-size: 0.95rem;
            padding: 0.75rem 1.75rem;
            border-radius: var(--radius);
            transition: opacity 0.2s ease;
        }
        .btn:hover { opacity: 0.8; }
        .hero-image {
            width: 100%;
            aspect-ratio: 4 / 3;
            object-fit: cover;
            border-radius: var(--radius);
            border: 1px solid var(--border);
            display: block;
        }
        footer {
            max-width: 1080px;
            margin: 0 auto;
            padding: 2rem 1.5rem 3rem;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-size: 0.875rem;
        }
        @media (max-width: 768px) {
            .hero {
                grid-template-columns: 1fr;
                gap: 2.5rem;
            }
            .hero-image { order: -1; }
        }
    </style>
</head>
<body>
    <header>
        <div class="brand"><?= htmlspecialchars($site['name']) ?></div>
    </header>

    <main>
        <section class="hero">
            <div class="hero-text">
                <h1><?= htmlspecialchars($site['title']) ?></h1>
                <p><?= htmlspecialchars($site['subtitle']) ?></p>
                <a class="btn" href="usuarios.php">Ver usuarios</a>
            </div>
            <img class="hero-image"
                 src="<?= htmlspecialchars($site['image']) ?>"
                 alt="<?= htmlspecialchars($site['image_alt']) ?>">
        </section>
    </main>

</body>
</html>
