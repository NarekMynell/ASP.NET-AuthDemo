using AuthDemo.Data;
using AuthDemo.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// PostgreSQL-ի միացում
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Email Service ավելացնել DI container–ում
builder.Services.AddScoped<IEmailService, EmailService>();

// Controllers (API)
builder.Services.AddControllers();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Development միջավայրում Swagger
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
app.Run();
