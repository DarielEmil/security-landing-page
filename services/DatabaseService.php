<?php
declare(strict_types=1);

final class DatabaseService
{
    private const OPERATORS = ['=', '!=', '<>', '>', '<', '>=', '<=', 'LIKE', 'NOT LIKE'];

    private PDO $pdo;
    private string $softDeleteColumn;

    public function __construct(array $config)
    {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=%s',
            (string) ($config['host'] ?? '127.0.0.1'),
            (string) ($config['port'] ?? '3306'),
            (string) ($config['dbname'] ?? ''),
            (string) ($config['charset'] ?? 'utf8mb4')
        );

        $this->pdo = new PDO($dsn, (string) ($config['user'] ?? ''), (string) ($config['pass'] ?? ''), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        $this->softDeleteColumn = $this->identifier((string) ($config['soft_delete_column'] ?? 'deleted_at'));
    }

    public static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    public function select(string $table, array $filters = [], array $options = []): array
    {
        $table = $this->identifier($table);
        $columns = $this->columns($options['columns'] ?? ['*']);
        [$where, $params] = $this->buildWhere($filters, $options);

        $sql = sprintf('SELECT %s FROM %s%s', implode(', ', $columns), $table, $where);

        if (isset($options['orderBy'])) {
            $direction = strtoupper((string) ($options['direction'] ?? 'ASC')) === 'DESC' ? 'DESC' : 'ASC';
            $sql .= sprintf(' ORDER BY %s %s', $this->identifier((string) $options['orderBy']), $direction);
        }

        if (isset($options['limit'])) {
            $sql .= sprintf(
                ' LIMIT %d OFFSET %d',
                max(1, (int) $options['limit']),
                max(0, (int) ($options['offset'] ?? 0))
            );
        }

        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);

        return $statement->fetchAll();
    }

    public function find(string $table, string $id, string $primaryKey = 'id', bool $withDeleted = false): ?array
    {
        $rows = $this->select($table, [$primaryKey => ['=', $id]], [
            'limit' => 1,
            'withDeleted' => $withDeleted,
        ]);

        return $rows[0] ?? null;
    }

    public function count(string $table, array $filters = [], array $options = []): int
    {
        $table = $this->identifier($table);
        [$where, $params] = $this->buildWhere($filters, $options);

        $statement = $this->pdo->prepare(sprintf('SELECT COUNT(*) FROM %s%s', $table, $where));
        $statement->execute($params);

        return (int) $statement->fetchColumn();
    }

    public function insert(string $table, array $data): string
    {
        if ($data === []) {
            throw new InvalidArgumentException('No hay datos para insertar.');
        }

        $table = $this->identifier($table);
        $columns = $this->columns(array_keys($data));

        $sql = sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $table,
            implode(', ', $columns),
            implode(', ', array_fill(0, count($columns), '?'))
        );

        $statement = $this->pdo->prepare($sql);
        $statement->execute(array_values($data));

        return $this->pdo->lastInsertId();
    }

    public function update(string $table, string $id, array $data, string $primaryKey = 'id'): int
    {
        if ($data === []) {
            return 0;
        }

        $table = $this->identifier($table);
        $primaryKey = $this->identifier($primaryKey);
        $assignments = [];
        $params = [];

        foreach ($data as $column => $value) {
            $assignments[] = $this->identifier((string) $column) . ' = ?';
            $params[] = $value;
        }

        $params[] = $id;

        $sql = sprintf(
            'UPDATE %s SET %s WHERE %s = ?',
            $table,
            implode(', ', $assignments),
            $primaryKey
        );

        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);

        return $statement->rowCount();
    }

    public function delete(string $table, string $id, bool $soft = true, string $primaryKey = 'id'): int
    {
        $table = $this->identifier($table);
        $primaryKey = $this->identifier($primaryKey);

        $sql = $soft
            ? sprintf(
                'UPDATE %s SET %s = NOW() WHERE %s = ? AND %s IS NULL',
                $table,
                $this->softDeleteColumn,
                $primaryKey,
                $this->softDeleteColumn
            )
            : sprintf('DELETE FROM %s WHERE %s = ?', $table, $primaryKey);

        $statement = $this->pdo->prepare($sql);
        $statement->execute([$id]);

        return $statement->rowCount();
    }

    public function distinct(string $table, string $column, bool $withDeleted = false): array
    {
        $table = $this->identifier($table);
        $column = $this->identifier($column);
        [$where, $params] = $this->buildWhere([], ['withDeleted' => $withDeleted]);

        $sql = sprintf('SELECT DISTINCT %s FROM %s', $column, $table);
        $sql .= ($where === '' ? ' WHERE ' : $where . ' AND ') . sprintf('%s IS NOT NULL', $column);
        $sql .= sprintf(' ORDER BY %s ASC', $column);

        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);

        return array_map(static fn (array $row): string => (string) $row[$column], $statement->fetchAll());
    }

    private function buildWhere(array $filters, array $options): array
    {
        $conditions = [];
        $params = [];

        foreach ($filters as $column => $condition) {
            $column = $this->identifier((string) $column);
            $operator = '=';
            $value = $condition;

            if (is_array($condition)) {
                $operator = strtoupper(trim((string) ($condition[0] ?? '=')));
                $value = $condition[1] ?? null;
            }

            if (!in_array($operator, self::OPERATORS, true)) {
                throw new InvalidArgumentException(sprintf('Operador no permitido: "%s".', $operator));
            }

            $conditions[] = sprintf('%s %s ?', $column, $operator);
            $params[] = $value;
        }

        $search = $options['search'] ?? null;
        if (is_array($search)) {
            $searchClause = $this->buildSearch($search, $params);
            if ($searchClause !== null) {
                $conditions[] = $searchClause;
            }
        }

        if (!($options['withDeleted'] ?? false) && !array_key_exists($this->softDeleteColumn, $filters)) {
            $conditions[] = sprintf('%s IS NULL', $this->softDeleteColumn);
        }

        $where = $conditions === [] ? '' : ' WHERE ' . implode(' AND ', $conditions);

        return [$where, $params];
    }

    private function buildSearch(array $search, array &$params): ?string
    {
        $term = trim((string) ($search['term'] ?? ''));
        $columns = $search['columns'] ?? [];

        if ($term === '' || !is_array($columns) || $columns === []) {
            return null;
        }

        $parts = [];
        foreach ($columns as $column) {
            $parts[] = $this->identifier((string) $column) . ' LIKE ?';
            $params[] = '%' . $term . '%';
        }

        return '(' . implode(' OR ', $parts) . ')';
    }

    private function identifier(string $name): string
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $name) !== 1) {
            throw new InvalidArgumentException(sprintf('Identificador SQL no valido: "%s".', $name));
        }

        return $name;
    }

    private function columns(array $columns): array
    {
        $validated = [];

        foreach ($columns as $column) {
            $column = (string) $column;
            $validated[] = $column === '*' ? '*' : $this->identifier($column);
        }

        return $validated;
    }
}
