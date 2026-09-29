using System.Globalization;
using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using SecurityLandingPage.Services;

namespace SecurityLandingPage.Pages;

// ============================================================================
//  PÁGINA INTENCIONALMENTE VULNERABLE — SOLO LABORATORIO
// ============================================================================
//  Réplica de Usuarios.cshtml.cs con vulnerabilidades deliberadas para
//  demostración de clase (SQL Injection). NO desplegar a producción.
//
//  Índice de fallas (todas marcadas con [VULNERABILIDAD]):
//
//  SQL Injection (usa DatabaseService.UnsafeQueryAsync / UnsafeExecuteAsync):
//   1. Búsqueda q        -> interpolada en LIKE (ver BuildWhereUnsafe)
//   2. Filtro province   -> interpolado al WHERE (ver BuildWhereUnsafe)
//   3. sort / dir        -> interpolados al ORDER BY (sin whitelist)
//   4. INSERT (guardar)  -> valores interpolados (ver OnPostAsync, action=save)
//   5. UPDATE (guardar)  -> valores interpolados (ver OnPostAsync, action=save)
//   6. DELETE            -> id interpolado (ver OnPostAsync, action=delete)
//
//  Las vulnerabilidades XSS de esta página viven en la vista UsuariosUnsafe.cshtml
//  (Html.Raw). Lo que SÍ se conserva: sesiones, flash y antiforgery.
// ============================================================================

[IgnoreAntiforgeryToken]
public sealed class UsuariosUnsafeModel : PageModel
{
    private const string UsersTable = "users";

    private const int PerPage = 10;

    private const string FlashTypeKey = "flash.type";

    private const string FlashMessageKey = "flash.message";

    private static readonly Regex PhonePattern = new("^[0-9+\\-\\s().]{7,30}$", RegexOptions.Compiled);

    private static readonly Regex ReturnPattern = new("^[A-Za-z0-9=&_%._+\\-]*$", RegexOptions.Compiled);

    private readonly DatabaseService _db;

    private readonly IAntiforgery _antiforgery;

    public UsuariosUnsafeModel(DatabaseService db, IAntiforgery antiforgery)
    {
        _db = db;
        _antiforgery = antiforgery;
    }

    public string SiteName { get; } = "Dariel Rodriguez";

    public string Search { get; private set; } = string.Empty;

    public string Province { get; private set; } = string.Empty;

    public string Sort { get; private set; } = "created_at";

    public string Direction { get; private set; } = "DESC";

    public int PageNumber { get; private set; } = 1;

    public int TotalPages { get; private set; } = 1;

    public int Total { get; private set; }

    public string PrevUrl { get; private set; } = string.Empty;

    public string NextUrl { get; private set; } = string.Empty;

    public string CurrentQuery { get; private set; } = string.Empty;

    public FlashMessage? Flash { get; private set; }

    public List<UserRow> Users { get; private set; } = new();

    public List<string> Provinces { get; private set; } = new();

    public IReadOnlyList<PageItem> PageItems { get; private set; } = new List<PageItem>();

    public async Task OnGetAsync(string? q, string? province, string? sort, string? dir, [FromQuery(Name = "page")] int page = 1, CancellationToken cancellationToken = default)
    {
        Search = (q ?? string.Empty).Trim();
        Province = (province ?? string.Empty).Trim();

        // [VULNERABILIDAD - SQLi #3] Sin whitelist de columnas ni normalización de dirección:
        // la página segura valida contra SortableColumns y fuerza ASC/DESC. Aquí el valor
        // crudo llega hasta el ORDER BY.
        Sort = sort ?? "created_at";
        Direction = (dir ?? "DESC").Trim().ToUpperInvariant();

        PageNumber = Math.Max(1, page);

        var where = BuildWhereUnsafe(Search, Province);

        var countRows = await _db.UnsafeQueryAsync($"SELECT COUNT(*) AS total FROM {UsersTable}{where}", cancellationToken);
        Total = countRows.Count > 0 && int.TryParse(countRows[0]["total"]?.ToString(), out var parsed) ? parsed : 0;
        TotalPages = Math.Max(1, (int)Math.Ceiling(Total / (double)PerPage));
        PageNumber = Math.Min(PageNumber, TotalPages);
        var offset = (PageNumber - 1) * PerPage;

        // [VULNERABILIDAD - SQLi #3] Sort y Direction interpolados sin validación.
        var usersSql = $"SELECT * FROM {UsersTable}{where} ORDER BY {Sort} {Direction} OFFSET {offset} ROWS FETCH NEXT {PerPage} ROWS ONLY";
        var rows = await _db.UnsafeQueryAsync(usersSql, cancellationToken);

        Users = rows.Select(UserRow.From).ToList();

        // Método seguro del service compartido (no forma parte de la demo).
        Provinces = await _db.DistinctAsync(UsersTable, "province", false, cancellationToken);
        Flash = PullFlash();

        var queryString = Request.QueryString.Value ?? string.Empty;
        CurrentQuery = queryString.StartsWith('?') ? queryString[1..] : queryString;

        PageItems = BuildPageItems(PageNumber, TotalPages);
        PrevUrl = BuildUrl(Search, Province, Sort, Direction, Math.Max(1, PageNumber - 1));
        NextUrl = BuildUrl(Search, Province, Sort, Direction, Math.Min(TotalPages, PageNumber + 1));
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        var returnTo = Request.Form["return"].ToString();

        if (!await _antiforgery.IsRequestValidAsync(HttpContext))
        {
            SetFlash("error", "La sesión expiró. Vuelve a intentarlo.");
        }
        else
        {
            var action = Request.Form["action"].ToString();
            var id = Request.Form["id"].ToString().Trim();

            try
            {
                if (action == "delete")
                {
                    // [VULNERABILIDAD - SQLi #6] id interpolado en el DELETE lógico.
                    // Payload: x' OR '1'='1  -> elimina todos los registros.
                    var deleted = await _db.UnsafeExecuteAsync(
                        $"UPDATE {UsersTable} SET deleted_at = SYSDATETIME() WHERE id = '{id}' AND deleted_at IS NULL",
                        cancellationToken);

                    if (deleted == 0)
                    {
                        SetFlash("error", "No se encontró el usuario que intentas eliminar.");
                    }
                    else
                    {
                        SetFlash("success", "Usuario eliminado correctamente.");
                    }
                }
                else if (action == "save")
                {
                    var data = new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["name"] = Request.Form["name"].ToString().Trim(),
                        ["email"] = Request.Form["email"].ToString().Trim(),
                        ["phone"] = Request.Form["phone"].ToString().Trim(),
                        ["province"] = Request.Form["province"].ToString().Trim(),
                    };

                    var errors = await ValidateUserAsync(data, id, cancellationToken);

                    if (errors.Count > 0)
                    {
                        SetFlash("error", string.Join(" ", errors));
                    }
                    else if (id.Length == 0)
                    {
                        var newId = DatabaseService.Uuid();

                        // [VULNERABILIDAD - SQLi #4] INSERT con valores interpolados.
                        // Payload en name:  a', 'x@x.com', '', '')--  -> rompe/inyecta la sentencia.
                        await _db.UnsafeExecuteAsync(
                            $"INSERT INTO {UsersTable} (id, name, email, phone, province) VALUES ('{newId}', '{data["name"]}', '{data["email"]}', '{data["phone"]}', '{data["province"]}')",
                            cancellationToken);

                        SetFlash("success", "Usuario creado correctamente.");
                    }
                    else
                    {
                        // [VULNERABILIDAD - SQLi #5] UPDATE con valores e id interpolados.
                        // Payload en name:  x', email = 'pwn@pwn.com  -> sobrescribe el correo.
                        var updated = await _db.UnsafeExecuteAsync(
                            $"UPDATE {UsersTable} SET name = '{data["name"]}', email = '{data["email"]}', phone = '{data["phone"]}', province = '{data["province"]}' WHERE id = '{id}'",
                            cancellationToken);

                        if (updated == 0 && await _db.FindAsync(UsersTable, id, "id", false, cancellationToken) is null)
                        {
                            SetFlash("error", "No se encontró el usuario que intentas actualizar.");
                        }
                        else
                        {
                            SetFlash("success", "Usuario actualizado correctamente.");
                        }
                    }
                }
                else
                {
                    SetFlash("error", "Acción no reconocida.");
                }
            }
            catch (Exception)
            {
                SetFlash("error", "Ocurrió un error al procesar la solicitud.");
            }
        }

        var location = Url.Page("/UsuariosUnsafe") ?? "/UsuariosUnsafe";

        if (returnTo.Length > 0 && ReturnPattern.IsMatch(returnTo))
        {
            location += "?" + returnTo;
        }

        return Redirect(location);
    }

    public string SortLink(string column, string label)
    {
        var nextDirection = Sort == column && Direction == "ASC" ? "DESC" : "ASC";
        var indicator = Sort == column ? (Direction == "ASC" ? " ↑" : " ↓") : string.Empty;
        var href = BuildUrl(Search, Province, column, nextDirection, 1);

        return $"<a class=\"sort-link\" href=\"{HtmlEncoder.Default.Encode(href)}\">{HtmlEncoder.Default.Encode(label)}{indicator}</a>";
    }

    public string PageUrl(int page)
        => BuildUrl(Search, Province, Sort, Direction, Math.Max(1, Math.Min(TotalPages, page)));

    public string FormatDate(object? value)
    {
        switch (value)
        {
            case null:
                return "—";
            case DateTime timestamp:
                return timestamp.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture);
            case string text when text.Length == 0:
                return "—";
            case string text when DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed):
                return parsed.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture);
            default:
                return value.ToString() ?? string.Empty;
        }
    }

    // [VULNERABILIDAD - SQLi #1 y #2] WHERE construido por interpolación:
    //   1. Search   -> LIKE '%{Search}%'
    //   2. Province -> province = '{Province}'
    // La página segura usa FilterCondition + SqlParameters; aquí nada se parametriza.
    private static string BuildWhereUnsafe(string search, string province)
    {
        var where = new StringBuilder(" WHERE deleted_at IS NULL");

        if (province.Length > 0)
        {
            where.Append($" AND province = '{province}'");
        }

        if (search.Length > 0)
        {
            where.Append($" AND (name LIKE '%{search}%' OR email LIKE '%{search}%' OR phone LIKE '%{search}%')");
        }

        return where.ToString();
    }

    private async Task<List<string>> ValidateUserAsync(Dictionary<string, object?> data, string id, CancellationToken cancellationToken)
    {
        var errors = new List<string>();

        var name = (string)(data["name"] ?? string.Empty);
        var email = (string)(data["email"] ?? string.Empty);
        var phone = (string)(data["phone"] ?? string.Empty);
        var province = (string)(data["province"] ?? string.Empty);

        if (name.Length == 0)
        {
            errors.Add("El nombre es obligatorio.");
        }
        else if (Length(name) > 120)
        {
            errors.Add("El nombre no puede superar los 120 caracteres.");
        }

        if (!IsValidEmail(email))
        {
            errors.Add("El correo no es válido.");
        }
        else if (Length(email) > 160)
        {
            errors.Add("El correo no puede superar los 160 caracteres.");
        }

        if (phone.Length > 0 && !PhonePattern.IsMatch(phone))
        {
            errors.Add("El teléfono no es válido.");
        }

        if (Length(province) > 80)
        {
            errors.Add("La provincia no puede superar los 80 caracteres.");
        }

        if (errors.Count == 0 && email.Length > 0)
        {
            var rows = await _db.SelectAsync(
                UsersTable,
                new Dictionary<string, FilterCondition>(StringComparer.Ordinal) { ["email"] = FilterCondition.Equal(email) },
                new SelectOptions { Columns = new[] { "id" }, WithDeleted = true },
                cancellationToken);

            foreach (var row in rows)
            {
                var existingId = row.TryGetValue("id", out var value)
                    ? value?.ToString() ?? string.Empty
                    : string.Empty;

                if (!string.Equals(existingId, id, StringComparison.OrdinalIgnoreCase))
                {
                    errors.Add("El correo ya está registrado.");
                    break;
                }
            }
        }

        return errors;
    }

    private string BuildUrl(string? search, string? province, string? sort, string? direction, int? page)
    {
        var query = new Dictionary<string, string?>(StringComparer.Ordinal);

        if (!string.IsNullOrEmpty(search))
        {
            query["q"] = search;
        }

        if (!string.IsNullOrEmpty(province))
        {
            query["province"] = province;
        }

        if (!string.IsNullOrEmpty(sort))
        {
            query["sort"] = sort;
        }

        if (!string.IsNullOrEmpty(direction))
        {
            query["dir"] = direction;
        }

        if (page is not null)
        {
            query["page"] = page.Value.ToString(CultureInfo.InvariantCulture);
        }

        var path = Url.Page("/UsuariosUnsafe") ?? "/UsuariosUnsafe";

        return query.Count == 0 ? path : QueryHelpers.AddQueryString(path, query);
    }

    private void SetFlash(string type, string message)
    {
        HttpContext.Session.SetString(FlashTypeKey, type);
        HttpContext.Session.SetString(FlashMessageKey, message);
    }

    private FlashMessage? PullFlash()
    {
        var type = HttpContext.Session.GetString(FlashTypeKey);
        var message = HttpContext.Session.GetString(FlashMessageKey);

        if (type is null || message is null)
        {
            return null;
        }

        HttpContext.Session.Remove(FlashTypeKey);
        HttpContext.Session.Remove(FlashMessageKey);

        return new FlashMessage(type, message);
    }

    private static bool IsValidEmail(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        try
        {
            var address = new MailAddress(value);

            if (!string.Equals(address.Address, value, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var host = address.Host;

            return host.Contains('.') && !host.StartsWith('.') && !host.EndsWith('.');
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static int Length(string value) => value.EnumerateRunes().Count();

    private static IReadOnlyList<PageItem> BuildPageItems(int page, int totalPages)
    {
        if (totalPages <= 7)
        {
            return Enumerable.Range(1, totalPages).Select(n => new PageItem(n)).ToList();
        }

        if (page <= 4)
        {
            return new List<PageItem>
            {
                new(1),
                new(2),
                new(3),
                new(4),
                new(5),
                PageItem.Ellipsis,
                new(totalPages),
            };
        }

        if (page >= totalPages - 3)
        {
            return new List<PageItem>
            {
                new(1),
                PageItem.Ellipsis,
                new(totalPages - 4),
                new(totalPages - 3),
                new(totalPages - 2),
                new(totalPages - 1),
                new(totalPages),
            };
        }

        return new List<PageItem>
        {
            new(1),
            PageItem.Ellipsis,
            new(page - 1),
            new(page),
            new(page + 1),
            PageItem.Ellipsis,
            new(totalPages),
        };
    }
}
