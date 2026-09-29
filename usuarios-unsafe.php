<?php
declare(strict_types=1);

/**
 * ============================================================================
 *  PÁGINA INTENCIONALMENTE VULNERABLE — SOLO LABORATORIO
 * ============================================================================
 *  Réplica de usuarios.php con vulnerabilidades deliberadas para demostración
 *  de clase (XSS + SQL Injection).
 *
 *  Índice de fallas (todas marcadas en el código con [VULNERABILIDAD]):
 *
 *  SQL Injection (usa DatabaseService::unsafeQuery / unsafeExec):
 *   1. Búsqueda q            -> concatenada en LIKE (ver buildWhereUnsafe)
 *   2. Filtro province       -> concatenado al WHERE (ver buildWhereUnsafe)
 *   3. sort / dir            -> concatenados al ORDER BY (ver consulta de listado)
 *   4. INSERT (guardar)      -> valores concatenados (ver POST action=save)
 *   5. UPDATE (guardar)      -> valores concatenados (ver POST action=save)
 *   6. DELETE / soft-delete  -> id concatenado (ver POST action=delete)
 *
 *  Cross Site Scripting:
 *   7. XSS reflejado   -> $search y $province impresos sin htmlspecialchars
 *                         (input de búsqueda, select de provincia y hidden "return")
 *   8. XSS almacenado  -> name/email/phone/province leídos de la BD e impresos
 *                         sin escape (celdas de la tabla y data-* del botón editar)
 *
 *  Lo que SÍ se conserva (no son parte de la demo): sesiones, flash, CSRF.
 * ============================================================================
 */

session_start();

require __DIR__ . '/services/DatabaseService.php';

const USERS_TABLE = 'users';
const PER_PAGE = 10;
const SORTABLE_COLUMNS = ['name', 'email', 'phone', 'province', 'created_at'];

function flash(string $type, string $message): void
{
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function pullFlash(): ?array
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);

    return is_array($flash) ? $flash : null;
}

function urlWith(array $params): string
{
    $params = array_filter($params, static fn ($value) => $value !== '' && $value !== null);

    return 'usuarios-unsafe.php' . ($params === [] ? '' : '?' . http_build_query($params));
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function csrfIsValid(): bool
{
    $token = $_POST['csrf_token'] ?? '';

    return is_string($token)
        && isset($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $token);
}

function formatDate(?string $value): string
{
    if ($value === null || $value === '') {
        return '—';
    }

    $timestamp = strtotime($value);

    return $timestamp === false ? $value : date('d/m/Y H:i', $timestamp);
}

/**
 * [VULNERABILIDAD - SQLi] A diferencia de la página segura, aquí el WHERE se
 * construye por concatenación directa de entrada del usuario.
 *
 *   1. $search  -> LIKE '%$search%'      (payload: ' OR 1=1 --)
 *   2. $province-> province = '$province' (payload: x' OR 1=1 --)
 *
 * La capa segura (DatabaseService::buildWhere) parametriza; aquí no.
 */
function buildWhereUnsafe(string $search, string $province): string
{
    $where = ' WHERE deleted_at IS NULL';

    if ($province !== '') {
        // [VULNERABILIDAD - SQLi #2] $province concatenado sin parametrizar ni escapar comillas.
        $where .= " AND province = '$province'";
    }

    if ($search !== '') {
        // [VULNERABILIDAD - SQLi #1] $search concatenado dentro de los LIKE.
        $where .= " AND (name LIKE '%$search%' OR email LIKE '%$search%' OR phone LIKE '%$search%')";
    }

    return $where;
}

function validateUser(DatabaseService $db, array $data, string $id): array
{
    $errors = [];

    if ($data['name'] === '') {
        $errors[] = 'El nombre es obligatorio.';
    } elseif (mb_strlen($data['name']) > 120) {
        $errors[] = 'El nombre no puede superar los 120 caracteres.';
    }

    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'El correo no es válido.';
    } elseif (mb_strlen($data['email']) > 160) {
        $errors[] = 'El correo no puede superar los 160 caracteres.';
    }

    if ($data['phone'] !== '' && preg_match('/^[0-9+\-\s().]{7,30}$/', $data['phone']) !== 1) {
        $errors[] = 'El teléfono no es válido.';
    }

    if (mb_strlen($data['province']) > 80) {
        $errors[] = 'La provincia no puede superar los 80 caracteres.';
    }

    if ($errors === [] && $data['email'] !== '') {
        $rows = $db->select(USERS_TABLE, ['email' => ['=', $data['email']]], [
            'columns' => ['id'],
            'withDeleted' => true,
        ]);

        foreach ($rows as $row) {
            if ($row['id'] !== $id) {
                $errors[] = 'El correo ya está registrado.';
                break;
            }
        }
    }

    return $errors;
}

/**
 * @return array<int, int|string>
 */
function pageItems(int $page, int $totalPages): array
{
    if ($totalPages <= 7) {
        return range(1, $totalPages);
    }

    if ($page <= 4) {
        return [1, 2, 3, 4, 5, '…', $totalPages];
    }

    if ($page >= $totalPages - 3) {
        return [
            1,
            '…',
            $totalPages - 4,
            $totalPages - 3,
            $totalPages - 2,
            $totalPages - 1,
            $totalPages,
        ];
    }

    return [1, '…', $page - 1, $page, $page + 1, '…', $totalPages];
}

$siteName = 'Dariel Rodriguez';
$db = new DatabaseService(require __DIR__ . '/config/database.php');
$csrfToken = csrfToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $returnTo = (string) ($_POST['return'] ?? '');

    if (!csrfIsValid()) {
        flash('error', 'La sesión expiró. Vuelve a intentarlo.');
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $id = trim((string) ($_POST['id'] ?? ''));

        try {
            if ($action === 'delete') {
                // [VULNERABILIDAD - SQLi #6] $id concatenado en el DELETE lógico.
                // Payload: id = x' OR '1'='1  -> elimina todos los registros.
                $deleted = $db->unsafeExec(
                    "UPDATE users SET deleted_at = NOW() WHERE id = '$id' AND deleted_at IS NULL"
                );

                if ($deleted === 0) {
                    flash('error', 'No se encontró el usuario que intentas eliminar.');
                } else {
                    flash('success', 'Usuario eliminado correctamente.');
                }
            } elseif ($action === 'save') {
                $data = [
                    'name' => trim((string) ($_POST['name'] ?? '')),
                    'email' => trim((string) ($_POST['email'] ?? '')),
                    'phone' => trim((string) ($_POST['phone'] ?? '')),
                    'province' => trim((string) ($_POST['province'] ?? '')),
                ];

                $errors = validateUser($db, $data, $id);

                if ($errors !== []) {
                    flash('error', implode(' ', $errors));
                } elseif ($id === '') {
                    $newId = DatabaseService::uuid();

                    // [VULNERABILIDAD - SQLi #4] INSERT con todos los valores concatenados.
                    // Payload en name:  a', 'x@x.com', '', '')--  -> rompe/inyecta la sentencia.
                    $db->unsafeExec(
                        "INSERT INTO users (id, name, email, phone, province) VALUES ('$newId', '{$data['name']}', '{$data['email']}', '{$data['phone']}', '{$data['province']}')"
                    );

                    flash('success', 'Usuario creado correctamente.');
                } else {
                    // [VULNERABILIDAD - SQLi #5] UPDATE con valores e id concatenados.
                    // Payload en name:  x', email = 'pwn@pwn.com  -> sobrescribe el correo.
                    $updated = $db->unsafeExec(
                        "UPDATE users SET name = '{$data['name']}', email = '{$data['email']}', phone = '{$data['phone']}', province = '{$data['province']}' WHERE id = '$id'"
                    );

                    if ($updated === 0 && $db->find(USERS_TABLE, $id) === null) {
                        flash('error', 'No se encontró el usuario que intentas actualizar.');
                    } else {
                        flash('success', 'Usuario actualizado correctamente.');
                    }
                }
            } else {
                flash('error', 'Acción no reconocida.');
            }
        } catch (Throwable $exception) {
            flash('error', 'Ocurrió un error al procesar la solicitud.');
        }
    }

    $location = 'usuarios-unsafe.php';
    if ($returnTo !== '' && preg_match('/^[A-Za-z0-9=&_%.\-+]*$/', $returnTo) === 1) {
        $location .= '?' . $returnTo;
    }

    header('Location: ' . $location);
    exit;
}

$search = trim((string) ($_GET['q'] ?? ''));
$province = trim((string) ($_GET['province'] ?? ''));

// [VULNERABILIDAD - SQLi #3] $sort sin whitelist: cualquier valor llega al ORDER BY.
// Payload: sort = (CASE WHEN 1=1 THEN name ELSE email END)
$sort = (string) ($_GET['sort'] ?? 'created_at');

// [VULNERABILIDAD - SQLi #3] $direction sin normalizar a ASC/DESC: valor crudo al ORDER BY.
$direction = strtoupper((string) ($_GET['dir'] ?? 'DESC'));

$page = max(1, (int) ($_GET['page'] ?? 1));

$where = buildWhereUnsafe($search, $province);

$countRows = $db->unsafeQuery("SELECT COUNT(*) AS total FROM users{$where}");
$total = (int) ($countRows[0]['total'] ?? 0);
$totalPages = max(1, (int) ceil($total / PER_PAGE));
$page = min($page, $totalPages);
$offset = ($page - 1) * PER_PAGE;

// [VULNERABILIDAD - SQLi #3] $sort y $direction concatenados sin whitelist ni escape.
$users = $db->unsafeQuery(
    "SELECT * FROM users{$where} ORDER BY {$sort} {$direction} LIMIT " . PER_PAGE . " OFFSET {$offset}"
);

$provinces = $db->distinct(USERS_TABLE, 'province');
$flash = pullFlash();
$currentQuery = (string) ($_SERVER['QUERY_STRING'] ?? '');
$baseParams = ['q' => $search, 'province' => $province, 'sort' => $sort, 'dir' => $direction];

function pageUrl(int $n): string
{
    global $baseParams;

    return urlWith(array_merge($baseParams, ['page' => $n]));
}

$sortLink = static function (string $column, string $label) use ($baseParams, $sort, $direction): string {
    $nextDirection = ($sort === $column && $direction === 'ASC') ? 'DESC' : 'ASC';
    $indicator = $sort === $column ? ($direction === 'ASC' ? ' ↑' : ' ↓') : '';
    $href = urlWith(array_merge($baseParams, ['sort' => $column, 'dir' => $nextDirection, 'page' => 1]));

    return '<a class="sort-link" href="' . $href . '">' . $label . $indicator . '</a>';
};

$prevUrl = urlWith(array_merge($baseParams, ['page' => max(1, $page - 1)]));
$nextUrl = urlWith(array_merge($baseParams, ['page' => min($totalPages, $page + 1)]));
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Usuarios (unsafe) — <?= $siteName ?></title>
    <style>
        :root {
            --bg: #fafaf9;
            --text: #1c1c1c;
            --muted: #6b7280;
            --border: #e7e5e4;
            --radius: 12px;
            --danger: #b91c1c;
            --success: #15803d;
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
            color: inherit;
            text-decoration: none;
        }
        main {
            max-width: 1080px;
            margin: 0 auto;
            padding: 1rem 1.5rem 5rem;
        }
        .page-title {
            font-size: clamp(1.5rem, 3vw, 2.25rem);
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 0.35rem;
        }
        .page-subtitle { color: var(--muted); margin-bottom: 2rem; }
        code {
            background: #f5f5f4;
            padding: 0.1rem 0.35rem;
            border-radius: 4px;
            font-size: 0.875em;
        }
        .btn {
            display: inline-block;
            background: var(--text);
            color: var(--bg);
            text-decoration: none;
            font-weight: 500;
            font-size: 0.95rem;
            font-family: inherit;
            padding: 0.75rem 1.75rem;
            border: 1px solid var(--text);
            border-radius: var(--radius);
            transition: opacity 0.2s ease;
            cursor: pointer;
        }
        .btn:hover { opacity: 0.8; }
        .btn-secondary { background: transparent; color: var(--text); }
        .toolbar {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }
        .toolbar form {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.75rem;
        }
        .input, .select {
            font: inherit;
            padding: 0.625rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: #fff;
            color: var(--text);
        }
        .input { min-width: 16rem; }
        .input:focus, .select:focus {
            outline: 2px solid var(--text);
            outline-offset: 1px;
        }
        .spacer { flex: 1 1 auto; }
        .alert {
            padding: 0.75rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: #fff;
            margin-bottom: 1.5rem;
            font-size: 0.9375rem;
        }
        .alert.success { border-color: #bbf7d0; background: #f0fdf4; color: var(--success); }
        .alert.error { border-color: #fecaca; background: #fef2f2; color: var(--danger); }
        .table-wrap {
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: #fff;
        }
        table { width: 100%; border-collapse: collapse; font-size: 0.9375rem; }
        th, td {
            text-align: left;
            padding: 0.875rem 1rem;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        th {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--muted);
            font-weight: 600;
            background: #fcfcfb;
        }
        tbody tr:last-child td { border-bottom: 0; }
        .sort-link { color: inherit; text-decoration: none; }
        .sort-link:hover { text-decoration: underline; text-underline-offset: 3px; }
        .actions { display: flex; align-items: center; gap: 1rem; }
        .action {
            background: none;
            border: 0;
            padding: 0;
            font: inherit;
            font-size: 0.9375rem;
            color: var(--text);
            cursor: pointer;
            text-decoration: underline;
            text-underline-offset: 3px;
        }
        .action:hover { opacity: 0.7; }
        .action.danger { color: var(--danger); }
        .inline { display: inline; }
        .empty { padding: 2.5rem 1rem; text-align: center; color: var(--muted); }
        .pagination {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 1rem;
            margin-top: 1.25rem;
            font-size: 0.9375rem;
            color: var(--muted);
        }
        .pagination .pages {
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }
        .pagination .page-link {
            min-width: 2rem;
            padding: 0.25rem 0.375rem;
            text-align: center;
        }
        .pagination .current {
            font-weight: 700;
            color: var(--text);
        }
        .pagination .ellipsis {
            color: var(--muted);
            padding: 0.25rem 0.125rem;
        }
        .pagination a { color: var(--text); text-decoration: none; }
        .pagination a:hover { text-decoration: underline; text-underline-offset: 3px; }
        .pagination .disabled { opacity: 0.35; pointer-events: none; }
        dialog.modal {
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.75rem;
            width: min(480px, calc(100vw - 2rem));
            color: var(--text);
        }
        dialog.modal::backdrop { background: rgba(28, 28, 28, 0.45); }
        dialog.modal h2 {
            font-size: 1.25rem;
            letter-spacing: -0.01em;
            margin-bottom: 1.25rem;
        }
        .field { display: flex; flex-direction: column; gap: 0.35rem; margin-bottom: 1rem; }
        .field label { font-size: 0.875rem; font-weight: 500; }
        .field input {
            font: inherit;
            padding: 0.625rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
        }
        .field input:focus { outline: 2px solid var(--text); outline-offset: 1px; }
        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 0.75rem;
            margin-top: 1.5rem;
        }
        .modal-actions .btn { padding: 0.625rem 1.25rem; }
        @media (max-width: 768px) {
            th, td { padding: 0.75rem 0.625rem; }
            .input { min-width: 100%; }
        }
    </style>
</head>
<body>
    <header>
        <a class="brand" href="index.php"><?= $siteName ?></a>
    </header>

    <main>
        <div class="alert error">⚠ Página intencionalmente vulnerable (SQL Injection + XSS) — solo para laboratorio. No usar en producción.</div>

        <h1 class="page-title">Usuarios (unsafe)</h1>
        <p class="page-subtitle">Versión vulnerable de la página <code>Usuarios</code>: misma funcionalidad, sin defensas.</p>

        <?php if ($flash !== null): ?>
            <div class="alert <?= $flash['type'] ?>"><?= $flash['message'] ?></div>
        <?php endif; ?>

        <div class="toolbar">
            <form method="get" action="usuarios-unsafe.php">
                <!-- [VULNERABILIDAD - XSS reflejado #7] $search impreso sin htmlspecialchars.
                     Payload: q=" onmouseover="alert(1)" x="  o  q=<script>alert(1)</script> -->
                <input class="input" type="search" name="q" placeholder="Buscar por nombre, correo o teléfono" value="<?= $search ?>">

                <!-- [VULNERABILIDAD - XSS reflejado #7] $province impreso sin escape. -->
                <select class="select" name="province">
                    <option value="">Todas las provincias</option>
                    <?php foreach ($provinces as $option): ?>
                        <!-- [VULNERABILIDAD - XSS almacenado #8] valores de BD (provincia) sin escape. -->
                        <option value="<?= $option ?>" <?= $option === $province ? 'selected' : '' ?>><?= $option ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="hidden" name="sort" value="<?= $sort ?>">
                <input type="hidden" name="dir" value="<?= $direction ?>">
                <button type="submit" class="btn btn-secondary">Buscar</button>
                <?php if ($search !== '' || $province !== ''): ?>
                    <a class="action" href="usuarios-unsafe.php">Limpiar</a>
                <?php endif; ?>
            </form>
            <span class="spacer"></span>
            <button type="button" class="btn" id="new-user">Nuevo usuario</button>
        </div>

        <div class="table-wrap">
            <?php if ($users === []): ?>
                <p class="empty">No se encontraron usuarios.</p>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th><?= $sortLink('name', 'Nombre') ?></th>
                            <th><?= $sortLink('email', 'Correo') ?></th>
                            <th><?= $sortLink('phone', 'Teléfono') ?></th>
                            <th><?= $sortLink('province', 'Provincia') ?></th>
                            <th><?= $sortLink('created_at', 'Creado') ?></th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <!-- [VULNERABILIDAD - XSS almacenado #8] datos de BD impresos sin escape.
                                     Crear un usuario con name = <script>alert(1)</script> ejecuta el script. -->
                                <td><?= $user['name'] ?></td>
                                <td><?= $user['email'] ?></td>
                                <td><?= $user['phone'] !== '' ? $user['phone'] : '—' ?></td>
                                <td><?= $user['province'] !== '' ? $user['province'] : '—' ?></td>
                                <td><?= formatDate($user['created_at']) ?></td>
                                <td>
                                    <div class="actions">
                                        <!-- [VULNERABILIDAD - XSS almacenado #8] data-* sin escape:
                                             el atributo se rompe y el navegador puede ejecutar handlers. -->
                                        <button type="button" class="action"
                                                data-edit
                                                data-id="<?= $user['id'] ?>"
                                                data-name="<?= $user['name'] ?>"
                                                data-email="<?= $user['email'] ?>"
                                                data-phone="<?= $user['phone'] ?>"
                                                data-province="<?= $user['province'] ?>">Editar</button>
                                        <form class="inline" method="post" action="usuarios-unsafe.php" onsubmit="return confirm('¿Eliminar este usuario?');">
                                            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="id" value="<?= $user['id'] ?>">
                                            <!-- [VULNERABILIDAD - XSS reflejado #7] QUERY_STRING crudo sin escape.
                                                 Payload: usuarios-unsafe.php?x="><script>alert(1)</script> -->
                                            <input type="hidden" name="return" value="<?= $currentQuery ?>">
                                            <button type="submit" class="action danger">Eliminar</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <div class="pagination">
            <?php if ($totalPages > 1): ?>
                <a class="<?= $page <= 1 ? 'disabled' : '' ?>" href="<?= $prevUrl ?>">Anterior</a>
                <span>Página <?= $page ?> de <?= $totalPages ?> (<?= $total ?> registros)</span>
                <div class="pages">
                    <?php foreach (pageItems($page, $totalPages) as $item): ?>
                        <?php if ($item === '…'): ?>
                            <span class="ellipsis">…</span>
                        <?php elseif ((int) $item === $page): ?>
                            <span class="current"><?= (int) $item ?></span>
                        <?php else: ?>
                            <a class="page-link" href="<?= pageUrl((int) $item) ?>"><?= (int) $item ?></a>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
                <a class="<?= $page >= $totalPages ? 'disabled' : '' ?>" href="<?= $nextUrl ?>">Siguiente</a>
            <?php else: ?>
                <span><?= $total ?> registros</span>
            <?php endif; ?>
        </div>
    </main>

    <dialog class="modal" id="user-dialog">
        <form method="post" action="usuarios-unsafe.php" id="user-form">
            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
            <input type="hidden" name="action" value="save">
            <input type="hidden" name="id" id="field-id" value="">
            <!-- [VULNERABILIDAD - XSS reflejado #7] QUERY_STRING crudo sin escape (mismo vector #7). -->
            <input type="hidden" name="return" value="<?= $currentQuery ?>">
            <h2 id="dialog-title">Nuevo usuario</h2>
            <div class="field">
                <label for="field-name">Nombre</label>
                <input id="field-name" name="name" type="text" maxlength="120" required>
            </div>
            <div class="field">
                <label for="field-email">Correo</label>
                <input id="field-email" name="email" type="email" maxlength="160" required>
            </div>
            <div class="field">
                <label for="field-phone">Teléfono</label>
                <input id="field-phone" name="phone" type="text" maxlength="30">
            </div>
            <div class="field">
                <label for="field-province">Provincia</label>
                <input id="field-province" name="province" type="text" maxlength="80" list="province-options">
                <datalist id="province-options">
                    <!-- [VULNERABILIDAD - XSS almacenado #8] valores de BD sin escape. -->
                    <?php foreach ($provinces as $option): ?>
                        <option value="<?= $option ?>"></option>
                    <?php endforeach; ?>
                </datalist>
            </div>
            <div class="modal-actions">
                <button type="button" class="btn btn-secondary" data-close>Cancelar</button>
                <button type="submit" class="btn">Guardar</button>
            </div>
        </form>
    </dialog>

    <script>
        const dialog = document.getElementById('user-dialog');
        const form = document.getElementById('user-form');
        const title = document.getElementById('dialog-title');
        const fields = {
            id: document.getElementById('field-id'),
            name: document.getElementById('field-name'),
            email: document.getElementById('field-email'),
            phone: document.getElementById('field-phone'),
            province: document.getElementById('field-province')
        };

        document.getElementById('new-user').addEventListener('click', () => {
            form.reset();
            fields.id.value = '';
            title.textContent = 'Nuevo usuario';
            dialog.showModal();
        });

        document.querySelectorAll('[data-edit]').forEach((button) => {
            button.addEventListener('click', () => {
                form.reset();
                fields.id.value = button.dataset.id;
                fields.name.value = button.dataset.name;
                fields.email.value = button.dataset.email;
                fields.phone.value = button.dataset.phone;
                fields.province.value = button.dataset.province;
                title.textContent = 'Editar usuario';
                dialog.showModal();
            });
        });

        document.querySelectorAll('[data-close]').forEach((button) => {
            button.addEventListener('click', () => dialog.close());
        });

        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) {
                dialog.close();
            }
        });
    </script>
</body>
</html>
