<?php
declare(strict_types=1);

$env = static function (string $key, string $default): string {
    $value = getenv($key);

    return $value === false ? $default : $value;
};

return [
    'host' => $env('DB_HOST', '127.0.0.1'),
    'port' => $env('DB_PORT', '3306'),
    'dbname' => $env('DB_NAME', 'security_landing_page'),
    'user' => $env('DB_USER', 'root'),
    'pass' => $env('DB_PASS', ''),
    'charset' => 'utf8mb4',
    'soft_delete_column' => 'deleted_at',
];
