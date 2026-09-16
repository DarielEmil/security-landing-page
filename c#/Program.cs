using SecurityLandingPage.Configuration;
using SecurityLandingPage.Services;

var builder = WebApplication.CreateBuilder(args);

var database = builder.Configuration.GetSection("Database").Get<DatabaseOptions>() ?? new DatabaseOptions();

database.Host = Environment.GetEnvironmentVariable("DB_HOST") ?? database.Host;
database.Port = Environment.GetEnvironmentVariable("DB_PORT") ?? database.Port;
database.Database = Environment.GetEnvironmentVariable("DB_NAME") ?? database.Database;
database.User = Environment.GetEnvironmentVariable("DB_USER") ?? database.User;
database.Password = Environment.GetEnvironmentVariable("DB_PASS") ?? database.Password;

builder.Services.AddSingleton(database);
builder.Services.AddScoped<DatabaseService>();
builder.Services.AddRazorPages();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(2);
    options.Cookie.Name = ".SecurityLandingPage.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.MapRazorPages();

app.Run();
