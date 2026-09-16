using System.Data;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using SecurityLandingPage.Configuration;

namespace SecurityLandingPage.Services;

public sealed record FilterCondition(string Operator, object? Value)
{
    public static FilterCondition Equal(object? value) => new("=", value);
}

public sealed class SearchOptions
{
    public string Term { get; init; } = string.Empty;

    public IReadOnlyList<string> Columns { get; init; } = Array.Empty<string>();
}

public sealed class SelectOptions
{
    public IReadOnlyList<string> Columns { get; init; } = new[] { "*" };

    public string? OrderBy { get; init; }

    public string Direction { get; init; } = "ASC";

    public int? Limit { get; init; }

    public int Offset { get; init; }

    public bool WithDeleted { get; init; }

    public SearchOptions? Search { get; init; }
}

public sealed class DatabaseService
{
    private static readonly string[] Operators = { "=", "!=", "<>", ">", "<", ">=", "<=", "LIKE", "NOT LIKE" };

    private static readonly Regex IdentifierPattern = new("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.Compiled);

    private readonly DatabaseOptions _options;

    private readonly string _softDeleteColumn;

    public DatabaseService(DatabaseOptions options)
    {
        _options = options;
        _softDeleteColumn = Identifier(options.SoftDeleteColumn);
    }

    public static string Uuid() => Guid.NewGuid().ToString();

    public async Task<List<Dictionary<string, object?>>> SelectAsync(
        string table,
        IReadOnlyDictionary<string, FilterCondition>? filters = null,
        SelectOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SelectOptions();

        table = Identifier(table);
        var columns = Columns(options.Columns);
        var parameters = new List<SqlParameter>();
        var where = BuildWhere(filters, options, parameters);

        var limit = options.Limit is null ? (int?)null : Math.Max(1, options.Limit.Value);
        var offset = Math.Max(0, options.Offset);
        var direction = NormalizeDirection(options.Direction);

        var sql = new StringBuilder("SELECT ");

        if (limit is not null && offset == 0)
        {
            sql.Append("TOP (@").Append(AddParameter(parameters, limit.Value)).Append(") ");
        }

        sql.Append(string.Join(", ", columns)).Append(" FROM ").Append(table).Append(where);

        if (limit is not null && offset > 0)
        {
            var orderBy = options.OrderBy is null ? "(SELECT NULL)" : Identifier(options.OrderBy);
            sql.Append(" ORDER BY ").Append(orderBy).Append(' ').Append(direction);
            sql.Append(" OFFSET @").Append(AddParameter(parameters, offset)).Append(" ROWS");
            sql.Append(" FETCH NEXT @").Append(AddParameter(parameters, limit.Value)).Append(" ROWS ONLY");
        }
        else if (options.OrderBy is not null)
        {
            sql.Append(" ORDER BY ").Append(Identifier(options.OrderBy)).Append(' ').Append(direction);
        }

        return await ExecuteReaderAsync(sql.ToString(), parameters, cancellationToken);
    }

    public async Task<Dictionary<string, object?>?> FindAsync(
        string table,
        string id,
        string primaryKey = "id",
        bool withDeleted = false,
        CancellationToken cancellationToken = default)
    {
        var rows = await SelectAsync(
            table,
            new Dictionary<string, FilterCondition> { [primaryKey] = FilterCondition.Equal(id) },
            new SelectOptions { Limit = 1, WithDeleted = withDeleted },
            cancellationToken);

        return rows.Count > 0 ? rows[0] : null;
    }

    public async Task<int> CountAsync(
        string table,
        IReadOnlyDictionary<string, FilterCondition>? filters = null,
        SelectOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SelectOptions();

        table = Identifier(table);
        var parameters = new List<SqlParameter>();
        var where = BuildWhere(filters, options, parameters);

        await using var connection = new SqlConnection(_options.BuildConnectionString());
        await connection.OpenAsync(cancellationToken);

        await using var command = new SqlCommand($"SELECT COUNT(*) FROM {table}{where}", connection);
        AddParameters(command, parameters);

        var result = await command.ExecuteScalarAsync(cancellationToken);

        return result is null or DBNull ? 0 : Convert.ToInt32(result);
    }

    public async Task<string> InsertAsync(
        string table,
        IReadOnlyDictionary<string, object?> data,
        CancellationToken cancellationToken = default)
    {
        if (data.Count == 0)
        {
            throw new ArgumentException("No hay datos para insertar.", nameof(data));
        }

        table = Identifier(table);
        var columns = Columns(data.Keys.ToList());
        var parameters = new List<SqlParameter>();

        foreach (var value in data.Values)
        {
            AddParameter(parameters, value);
        }

        var placeholders = parameters.Select(parameter => "@" + parameter.ParameterName);
        var sql = $"INSERT INTO {table} ({string.Join(", ", columns)}) VALUES ({string.Join(", ", placeholders)})";

        await using var connection = new SqlConnection(_options.BuildConnectionString());
        await connection.OpenAsync(cancellationToken);

        await using (var command = new SqlCommand(sql, connection))
        {
            AddParameters(command, parameters);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (data.TryGetValue("id", out var explicitId) && explicitId is not null)
        {
            return explicitId.ToString() ?? string.Empty;
        }

        await using var identityCommand = new SqlCommand("SELECT CAST(SCOPE_IDENTITY() AS nvarchar(50))", connection);
        var identity = await identityCommand.ExecuteScalarAsync(cancellationToken);

        return identity is null or DBNull ? string.Empty : (string)identity;
    }

    public async Task<int> UpdateAsync(
        string table,
        string id,
        IReadOnlyDictionary<string, object?> data,
        string primaryKey = "id",
        CancellationToken cancellationToken = default)
    {
        if (data.Count == 0)
        {
            return 0;
        }

        table = Identifier(table);
        primaryKey = Identifier(primaryKey);

        var assignments = new List<string>();
        var parameters = new List<SqlParameter>();

        foreach (var (column, value) in data)
        {
            assignments.Add($"{Identifier(column)} = @{AddParameter(parameters, value)}");
        }

        var idParameter = AddParameter(parameters, id);
        var sql = $"UPDATE {table} SET {string.Join(", ", assignments)} WHERE {primaryKey} = @{idParameter}";

        await using var connection = new SqlConnection(_options.BuildConnectionString());
        await connection.OpenAsync(cancellationToken);

        await using var command = new SqlCommand(sql, connection);
        AddParameters(command, parameters);

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<int> DeleteAsync(
        string table,
        string id,
        bool soft = true,
        string primaryKey = "id",
        CancellationToken cancellationToken = default)
    {
        table = Identifier(table);
        primaryKey = Identifier(primaryKey);

        var sql = soft
            ? $"UPDATE {table} SET {_softDeleteColumn} = SYSDATETIME() WHERE {primaryKey} = @p0 AND {_softDeleteColumn} IS NULL"
            : $"DELETE FROM {table} WHERE {primaryKey} = @p0";

        await using var connection = new SqlConnection(_options.BuildConnectionString());
        await connection.OpenAsync(cancellationToken);

        await using var command = new SqlCommand(sql, connection);
        command.Parameters.Add(CreateParameter("p0", id));

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<List<string>> DistinctAsync(
        string table,
        string column,
        bool withDeleted = false,
        CancellationToken cancellationToken = default)
    {
        table = Identifier(table);
        column = Identifier(column);

        var parameters = new List<SqlParameter>();
        var where = BuildWhere(null, new SelectOptions { WithDeleted = withDeleted }, parameters);

        var sql = new StringBuilder($"SELECT DISTINCT {column} FROM {table}");
        sql.Append(where.Length == 0 ? " WHERE " : where + " AND ");
        sql.Append(column).Append(" IS NOT NULL");
        sql.Append(" ORDER BY ").Append(column).Append(" ASC");

        var rows = await ExecuteReaderAsync(sql.ToString(), parameters, cancellationToken);

        return rows
            .Select(row => row.TryGetValue(column, out var value) ? value?.ToString() ?? string.Empty : string.Empty)
            .ToList();
    }

    private async Task<List<Dictionary<string, object?>>> ExecuteReaderAsync(
        string sql,
        List<SqlParameter> parameters,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(_options.BuildConnectionString());
        await connection.OpenAsync(cancellationToken);

        await using var command = new SqlCommand(sql, connection);
        AddParameters(command, parameters);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        var names = new string[reader.FieldCount];
        for (var index = 0; index < reader.FieldCount; index++)
        {
            names[index] = reader.GetName(index);
        }

        var rows = new List<Dictionary<string, object?>>();

        while (await reader.ReadAsync(cancellationToken))
        {
            var row = new Dictionary<string, object?>(reader.FieldCount, StringComparer.Ordinal);

            for (var index = 0; index < reader.FieldCount; index++)
            {
                row[names[index]] = await reader.IsDBNullAsync(index, cancellationToken)
                    ? null
                    : reader.GetValue(index);
            }

            rows.Add(row);
        }

        return rows;
    }

    private string BuildWhere(
        IReadOnlyDictionary<string, FilterCondition>? filters,
        SelectOptions options,
        List<SqlParameter> parameters)
    {
        var conditions = new List<string>();
        filters ??= new Dictionary<string, FilterCondition>();

        foreach (var (column, condition) in filters)
        {
            var name = Identifier(column);
            var op = (condition.Operator ?? "=").Trim().ToUpperInvariant();

            if (!Operators.Contains(op, StringComparer.Ordinal))
            {
                throw new ArgumentException($"Operador no permitido: \"{op}\".");
            }

            conditions.Add($"{name} {op} @{AddParameter(parameters, condition.Value)}");
        }

        if (options.Search is not null)
        {
            var searchClause = BuildSearch(options.Search, parameters);
            if (searchClause is not null)
            {
                conditions.Add(searchClause);
            }
        }

        if (!options.WithDeleted && !filters.ContainsKey(_softDeleteColumn))
        {
            conditions.Add($"{_softDeleteColumn} IS NULL");
        }

        return conditions.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", conditions);
    }

    private string? BuildSearch(SearchOptions search, List<SqlParameter> parameters)
    {
        var term = (search.Term ?? string.Empty).Trim();
        var columns = search.Columns ?? Array.Empty<string>();

        if (term.Length == 0 || columns.Count == 0)
        {
            return null;
        }

        var parts = new List<string>();

        foreach (var column in columns)
        {
            parts.Add($"{Identifier(column)} LIKE @{AddParameter(parameters, $"%{term}%")}");
        }

        return "(" + string.Join(" OR ", parts) + ")";
    }

    private static string Identifier(string name)
    {
        if (!IdentifierPattern.IsMatch(name))
        {
            throw new ArgumentException($"Identificador SQL no valido: \"{name}\".");
        }

        return name;
    }

    private static List<string> Columns(IReadOnlyList<string> columns)
    {
        var validated = new List<string>();

        foreach (var column in columns)
        {
            validated.Add(column == "*" ? "*" : Identifier(column));
        }

        return validated;
    }

    private static string NormalizeDirection(string direction)
    {
        return string.Equals(direction, "DESC", StringComparison.OrdinalIgnoreCase) ? "DESC" : "ASC";
    }

    private static void AddParameters(SqlCommand command, List<SqlParameter> parameters)
    {
        foreach (var parameter in parameters)
        {
            command.Parameters.Add(parameter);
        }
    }

    private static string AddParameter(List<SqlParameter> parameters, object? value)
    {
        var name = $"p{parameters.Count}";

        parameters.Add(CreateParameter(name, value));

        return name;
    }

    private static SqlParameter CreateParameter(string name, object? value)
    {
        var parameter = new SqlParameter { ParameterName = name };

        switch (value)
        {
            case null:
            case DBNull:
                parameter.SqlDbType = SqlDbType.NVarChar;
                parameter.Value = DBNull.Value;
                break;
            case string text:
                parameter.SqlDbType = SqlDbType.NVarChar;
                parameter.Size = text.Length == 0 ? 1 : text.Length;
                parameter.Value = text;
                break;
            case bool flag:
                parameter.SqlDbType = SqlDbType.Bit;
                parameter.Value = flag;
                break;
            case DateTime date:
                parameter.SqlDbType = SqlDbType.DateTime2;
                parameter.Value = date;
                break;
            default:
                parameter.Value = value;
                break;
        }

        return parameter;
    }
}
