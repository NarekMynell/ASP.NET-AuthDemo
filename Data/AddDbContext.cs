using AuthDemo.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthDemo.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<EmailConfirmationToken> EmailConfirmationTokens { get; set; }
    }
}