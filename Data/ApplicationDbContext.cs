using Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {

            modelBuilder.Entity<User>().HasData(
                new User { Id = 1, FullName = "Mahmud Ahmadov", Email = "zhmdff@gmail.com", PasswordHash = "$2a$12$t1TxFpRZaWTAVvpnTsG9JOQILUta3PKqFlJ3ILofcQhpIbD360/hK" }
            );

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => rt.Token)
                .IsUnique();
        }

    }
}
