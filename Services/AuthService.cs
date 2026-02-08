using Auth.Models;
using Auth.Repositories;

namespace Auth.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepository;
        private readonly TokenService _tokenService;
        private readonly RefreshTokenRepository _tokenRepository;
        private readonly AuditLogRepository _auditRepository;

        public AuthService( IUserRepository userRepository, TokenService tokenService, RefreshTokenRepository tokenRepository, AuditLogRepository auditRepository)
        {
            _userRepository = userRepository;
            _tokenService = tokenService;
            _tokenRepository = tokenRepository;
            _auditRepository = auditRepository;
        }

        public async Task<(bool Success, string AccessToken, string RefreshToken, string ErrorMessage)> LoginAsync(
            string email,
            string password,
            string ipAddress,
            string userAgent,
            string country)
        {
            var user = await _userRepository.ValidateCredentials(email, password);

            if (user == null)
            {
                await _auditRepository.LogEvent(new AuditLog
                {
                    UserId = null,
                    EventType = "Login",
                    TimestampUtc = DateTime.UtcNow,
                    Success = false,
                    FailureReason = "Invalid credentials",
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    Country = country
                });

                return (false, null, null, "Invalid email or password.");
            }

            var accessToken = _tokenService.GenerateAccessToken(user.Id, user.Email, user.FullName);
            var refreshToken = _tokenService.GenerateRefreshToken();
            await _tokenRepository.SaveRefreshToken(user.Id, refreshToken, DateTime.UtcNow.AddDays(7));

            await _auditRepository.LogEvent(new AuditLog
            {
                UserId = user.Id,
                EventType = "Login",
                TimestampUtc = DateTime.UtcNow,
                Success = true,
                FailureReason = null,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                Country = country
            });

            return (true, accessToken, refreshToken, null);
        }

        public async Task<(bool Success, string AccessToken, string RefreshToken, string ErrorMessage)> RefreshTokenAsync(
            string refreshToken,
            string ipAddress,
            string userAgent,
            string country)
        {
            var storedToken = await _tokenRepository.ValidateRefreshToken(refreshToken);
            if (storedToken == null)
            {
                await _auditRepository.LogEvent(new AuditLog
                {
                    UserId = null,
                    EventType = "TokenRefresh",
                    TimestampUtc = DateTime.UtcNow,
                    Success = false,
                    FailureReason = "Invalid or expired refresh token",
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    Country = country
                });

                return (false, null, null, "Invalid or expired refresh token");
            }

            var user = await _userRepository.GetByIdAsync(storedToken.UserId);
            if (user == null)
            {
                await _auditRepository.LogEvent(new AuditLog
                {
                    UserId = storedToken.UserId,
                    EventType = "TokenRefresh",
                    TimestampUtc = DateTime.UtcNow,
                    Success = false,
                    FailureReason = "User not found",
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    Country = country
                });

                return (false, null, null, "User not found");
            }

            var newAccessToken = _tokenService.GenerateAccessToken(user.Id, user.Email, user.FullName);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            await _tokenRepository.RevokeRefreshToken(refreshToken);
            await _tokenRepository.SaveRefreshToken(user.Id, newRefreshToken, DateTime.UtcNow.AddDays(7));

            await _auditRepository.LogEvent(new AuditLog
            {
                UserId = user.Id,
                EventType = "TokenRefresh",
                TimestampUtc = DateTime.UtcNow,
                Success = true,
                FailureReason = null,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                Country = country
            });

            return (true, newAccessToken, newRefreshToken, null);
        }
    }
}