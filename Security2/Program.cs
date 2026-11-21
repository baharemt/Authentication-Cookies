
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// 1. Configure Cookie Authentication
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "app_auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;

        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = false;

        // Return HTTP status codes instead of redirects
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode =
                StatusCodes.Status401Unauthorized;

            return Task.CompletedTask;
        };

        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode =
                StatusCodes.Status403Forbidden;

            return Task.CompletedTask;
        };
    });

// 2. Configure Authorization
builder.Services.AddAuthorization();

var app = builder.Build();

// 3. Authentication and Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// 4. Login
app.MapPost("/login", async (
    LoginRequest request,
    HttpContext http) =>
{
    // Demo only: replace with DB + password hashing
    if (request.Username != "user" ||
        request.Password != "password")
    {
        return Results.Unauthorized();
    }

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, "123"),
        new Claim(ClaimTypes.Name, request.Username),
        new Claim(ClaimTypes.Role, "User")
    };

    var identity = new ClaimsIdentity(
        claims,
        CookieAuthenticationDefaults.AuthenticationScheme);

    var principal = new ClaimsPrincipal(identity);

    await http.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        principal,
        new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30)
        });

    return Results.Ok(new
    {
        Message = "Login successful"
    });
});

// 5. Protected endpoint
app.MapGet("/secure-data", (ClaimsPrincipal user) =>
{
    var userId = user.FindFirstValue(
        ClaimTypes.NameIdentifier);

    var username = user.Identity?.Name;

    return Results.Ok(new
    {
        Message = "This is secure data",
        UserId = userId,
        Username = username
    });
})
.RequireAuthorization();

// 6. Logout
app.MapPost("/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(
        CookieAuthenticationDefaults.AuthenticationScheme);

    return Results.Ok(new
    {
        Message = "Logged out"
    });
})
.RequireAuthorization();

app.Run();

public record LoginRequest(
    string Username,
    string Password);
