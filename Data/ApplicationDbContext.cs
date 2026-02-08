using Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) {}

        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().HasData(
                new User
                {
                    Id = 1,
                    FullName = "Mahmud Ahmadov",
                    Email = "zhmdff@gmail.com",
                    PasswordHash = "$2a$12$t1TxFpRZaWTAVvpnTsG9JOQILUta3PKqFlJ3ILofcQhpIbD360/hK",
                    EmailVerified = false,
                    CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    FailedLoginAttempts = 0,
                    IsActive = true
                }
            );

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => rt.TokenHash);

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => rt.UserId);

            modelBuilder.Entity<AuditLog>()
                .HasIndex(a => a.UserId);

            modelBuilder.Entity<AuditLog>()
                .HasIndex(a => a.TimestampUtc);
        }
    }
}