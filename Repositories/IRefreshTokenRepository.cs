using Auth.Models;

namespace Auth.Repositories
{
    public interface IRefreshTokenRepository
    {
        Task SaveRefreshToken(int userId, string token, DateTime expiresAt);
        Task<RefreshToken?> GetRefreshToken(string token);
        Task RevokeRefreshToken(string token);
        Task<RefreshToken?> ValidateRefreshToken(string token);
    }
}
