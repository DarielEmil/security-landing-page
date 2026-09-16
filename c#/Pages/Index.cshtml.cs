using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SecurityLandingPage.Pages;

public sealed class IndexModel : PageModel
{
    public SiteInfo Site { get; } = new(
        Name: "Dariel Rodriguez",
        Title: "Seguridad De La Información",
        Subtitle: "Página web de prueba HTTPS, puertos y servidor HTTP",
        Image: "assets/personal-photo.jpg",
        ImageAlt: "Imagen De Perfil");

    public void OnGet()
    {
    }
}

public sealed record SiteInfo(string Name, string Title, string Subtitle, string Image, string ImageAlt);
