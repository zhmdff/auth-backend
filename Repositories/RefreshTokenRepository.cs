using Auth.Data;
using Auth.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Repositories
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly ApplicationDbContext _context;

        public RefreshTokenRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task SaveRefreshToken(int userId, string token, DateTime expiresAt)
        {
            var tokenHash = HashToken(token);

            _context.RefreshTokens.Add(new RefreshToken
            {
                UserId = userId,
                TokenHash = tokenHash,
                ExpiresAt = expiresAt,
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            });

            await _context.SaveChangesAsync();
        }

        public async Task<RefreshToken?> GetRefreshToken(string token)
        {
            var tokenHash = HashToken(token);
            return await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash && !rt.IsRevoked);
        }

        public async Task RevokeRefreshToken(string token)
        {
            var tokenHash = HashToken(token);
            var refreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);

            if (refreshToken != null)
            {
                refreshToken.IsRevoked = true;
                await _context.SaveChangesAsync();
            }
        }

        public async Task<RefreshToken?> ValidateRefreshToken(string token)
        {
            var tokenHash = HashToken(token);
            var refreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash && !rt.IsRevoked);

            if (refreshToken == null || refreshToken.ExpiresAt < DateTime.UtcNow)
                return null;

            return refreshToken;
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(bytes);
        }
    }
}