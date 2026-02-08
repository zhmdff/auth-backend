using System.Security.Claims;

namespace Auth.Services
{
    public interface ITokenService
    {
        string GenerateAccessToken(int userId, string email, string fullName);
        string GenerateRefreshToken();
        ClaimsPrincipal ValidateToken(string token);
    }
}
