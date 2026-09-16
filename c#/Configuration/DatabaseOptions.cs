using Microsoft.Data.SqlClient;

namespace SecurityLandingPage.Configuration;

public sealed class DatabaseOptions
{
    public string Host { get; set; } = "127.0.0.1";

    public string Port { get; set; } = "1433";

    public string Database { get; set; } = "security_landing_page";

    public string User { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string SoftDeleteColumn { get; set; } = "deleted_at";

    public bool IntegratedSecurity { get; set; } = true;

    public bool Encrypt { get; set; }

    public bool TrustServerCertificate { get; set; } = true;

    public string BuildConnectionString()
    {
        var builder = new SqlConnectionStringBuilder
        {
            DataSource = string.IsNullOrWhiteSpace(Port) ? Host : $"{Host},{Port}",
            InitialCatalog = Database,
            IntegratedSecurity = IntegratedSecurity,
            Encrypt = Encrypt,
            TrustServerCertificate = TrustServerCertificate,
            ApplicationName = "SecurityLandingPage",
        };

        if (!IntegratedSecurity)
        {
            builder.UserID = User;
            builder.Password = Password;
        }

        return builder.ConnectionString;
    }
}
