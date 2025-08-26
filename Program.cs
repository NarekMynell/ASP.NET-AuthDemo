using AuthDemo.Configurations;
using AuthDemo.Data;
using AuthDemo.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

AddServices(builder.Services, builder.Configuration);
ConfigureServices(builder.Services, builder.Configuration);

var app = builder.Build();

ConfigureMiddleware(app);

app.Run();

void AddServices(IServiceCollection services, IConfiguration configuration)
{
    services.AddDbContext<AppDbContext>(options =>
        options.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));

    services.AddScoped<IEmailService, EmailService>();
    services.AddControllers();
    services.AddSwaggerGen();
}

void ConfigureServices(IServiceCollection services, IConfiguration configuration)
{
    services.Configure<EmailSettings>(configuration.GetSection("EmailSettings"));
    services.Configure<JwtSettings>(configuration.GetSection("JwtSettings"));
}

void ConfigureMiddleware(WebApplication app)
{
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();
    app.UseAuthorization();
    app.MapControllers();
}
