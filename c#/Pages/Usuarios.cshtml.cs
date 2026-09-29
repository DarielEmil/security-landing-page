using System.Globalization;
using System.Net.Mail;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using SecurityLandingPage.Services;

namespace SecurityLandingPage.Pages;

[IgnoreAntiforgeryToken]
public sealed class UsuariosModel : PageModel
{
    private const string UsersTable = "users";

    private const int PerPage = 10;

    private const string FlashTypeKey = "flash.type";

    private const string FlashMessageKey = "flash.message";

    private static readonly string[] SortableColumns = { "name", "email", "phone", "province", "created_at" };

    private static readonly Regex PhonePattern = new("^[0-9+\\-\\s().]{7,30}$", RegexOptions.Compiled);

    private static readonly Regex ReturnPattern = new("^[A-Za-z0-9=&_%._+\\-]*$", RegexOptions.Compiled);

    private readonly DatabaseService _db;

    private readonly IAntiforgery _antiforgery;

    public UsuariosModel(DatabaseService db, IAntiforgery antiforgery)
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
        Sort = sort ?? "created_at";
        Direction = string.Equals(dir, "ASC", StringComparison.OrdinalIgnoreCase) ? "ASC" : "DESC";
        PageNumber = Math.Max(1, page);

        if (!SortableColumns.Contains(Sort, StringComparer.Ordinal))
        {
            Sort = "created_at";
        }

        var filters = new Dictionary<string, FilterCondition>(StringComparer.Ordinal);
        if (Province.Length > 0)
        {
            filters["province"] = FilterCondition.Equal(Province);
        }

        var searchOptions = Search.Length == 0
            ? null
            : new SearchOptions { Columns = new[] { "name", "email", "phone" }, Term = Search };

        Total = await _db.CountAsync(UsersTable, filters, new SelectOptions { Search = searchOptions }, cancellationToken);
        TotalPages = Math.Max(1, (int)Math.Ceiling(Total / (double)PerPage));
        PageNumber = Math.Min(PageNumber, TotalPages);

        PageItems = BuildPageItems(PageNumber, TotalPages);

        var rows = await _db.SelectAsync(UsersTable, filters, new SelectOptions
        {
            OrderBy = Sort,
            Direction = Direction,
            Limit = PerPage,
            Offset = (PageNumber - 1) * PerPage,
            Search = searchOptions,
        }, cancellationToken);

        Users = rows.Select(UserRow.From).ToList();
        Provinces = await _db.DistinctAsync(UsersTable, "province", false, cancellationToken);
        Flash = PullFlash();

        var queryString = Request.QueryString.Value ?? string.Empty;
        CurrentQuery = queryString.StartsWith('?') ? queryString[1..] : queryString;

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
                    if (id.Length == 0 || !Guid.TryParse(id, out _) ||
                        await _db.DeleteAsync(UsersTable, id, true, "id", cancellationToken) == 0)
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
                        var insertData = new Dictionary<string, object?>(data, StringComparer.Ordinal)
                        {
                            ["id"] = DatabaseService.Uuid(),
                        };

                        await _db.InsertAsync(UsersTable, insertData, cancellationToken);
                        SetFlash("success", "Usuario creado correctamente.");
                    }
                    else if (!Guid.TryParse(id, out _))
                    {
                        SetFlash("error", "No se encontró el usuario que intentas actualizar.");
                    }
                    else
                    {
                        var updated = await _db.UpdateAsync(UsersTable, id, data, "id", cancellationToken);

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

        var location = Url.Page("/Usuarios") ?? "/Usuarios";

        if (returnTo.Length > 0 && ReturnPattern.IsMatch(returnTo))
        {
            location += "?" + returnTo;
        }

        return Redirect(location);
    }

    public string PageUrl(int page)
        => BuildUrl(Search, Province, Sort, Direction, Math.Max(1, Math.Min(TotalPages, page)));

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

    public string SortLink(string column, string label)
    {
        var nextDirection = Sort == column && Direction == "ASC" ? "DESC" : "ASC";
        var indicator = Sort == column ? (Direction == "ASC" ? " ↑" : " ↓") : string.Empty;
        var href = BuildUrl(Search, Province, column, nextDirection, 1);

        return $"<a class=\"sort-link\" href=\"{HtmlEncoder.Default.Encode(href)}\">{HtmlEncoder.Default.Encode(label)}{indicator}</a>";
    }

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

        var path = Url.Page("/Usuarios") ?? "/Usuarios";

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
}

public sealed record FlashMessage(string Type, string Message);

public sealed record PageItem(int? Number)
{
    public static PageItem Ellipsis { get; } = new(null);

    public bool IsEllipsis => Number is null;
}

public sealed record UserRow(string Id, string Name, string Email, string Phone, string Province, object? CreatedAt)
{
    public static UserRow From(Dictionary<string, object?> row) => new(
        Read(row, "id"),
        Read(row, "name"),
        Read(row, "email"),
        Read(row, "phone"),
        Read(row, "province"),
        row.TryGetValue("created_at", out var createdAt) ? createdAt : null);

    private static string Read(Dictionary<string, object?> row, string column)
        => row.TryGetValue(column, out var value) ? value?.ToString() ?? string.Empty : string.Empty;
}
