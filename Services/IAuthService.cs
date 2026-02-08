namespace Auth.Services
{
    public interface IAuthService
    {
        Task<(bool Success, string AccessToken, string RefreshToken, string ErrorMessage)> LoginAsync( string email, string password, string ipAddress, string userAgent, string country);
        Task<(bool Success, string AccessToken, string RefreshToken, string ErrorMessage)> RefreshTokenAsync( string refreshToken, string ipAddress, string userAgent, string country);
    }
}
