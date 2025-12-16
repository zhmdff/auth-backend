using Auth.Models;
using Auth.Repositories;
using Auth.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Auth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly TokenService _tokenService;
        private readonly IUserRepository _userRepository;
        private readonly RefreshTokenRepository _tokenRepository;

        public AuthController(TokenService tokenService, IUserRepository userRepository, RefreshTokenRepository tokenRepository)
        {
            _tokenService = tokenService;
            _userRepository = userRepository;
            _tokenRepository = tokenRepository;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] AuthRequest request)
        {
            Console.WriteLine($"[DEBUG] Login attempt: {request.Email}");

            var user = await _userRepository.ValidateCredentials(request.Email, request.Password);
            if (user == null)
            {
                Console.WriteLine("[DEBUG] Invalid credentials");
                return Unauthorized(new { message = "Invalid email or password." });
            }

            var accessToken = _tokenService.GenerateAccessToken(user.Id, user.Email);
            var refreshToken = _tokenService.GenerateRefreshToken();

            Console.WriteLine($"[DEBUG] Generated tokens. Access: {accessToken}, Refresh: {refreshToken}");

            await _tokenRepository.SaveRefreshToken(user.Id, refreshToken, DateTime.UtcNow.AddDays(7));

            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            });

            Console.WriteLine("[DEBUG] Refresh token cookie set");

            return Ok(new AuthResponse { AccessToken = accessToken });
        }


        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            if (!Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
                return Unauthorized(new { message = "Refresh token missing" });

            var storedToken = await _tokenRepository.ValidateRefreshToken(refreshToken);
            if (storedToken == null)
                return Unauthorized(new { message = "Invalid or expired refresh token" });

            var user = await _userRepository.GetByIdAsync(storedToken.UserId);
            var newAccessToken = _tokenService.GenerateAccessToken(user.Id, user.Email);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            await _tokenRepository.RevokeRefreshToken(refreshToken);
            await _tokenRepository.SaveRefreshToken(user.Id, newRefreshToken, DateTime.UtcNow.AddDays(7));

            Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            });

            Console.WriteLine("[DEBUG] Token refreshed");

            return Ok(new AuthResponse { AccessToken = newAccessToken });
        }

        [Authorize]
        [HttpGet("dashboard")]
        public IActionResult Dashboard()
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            var fullName = User.FindFirst("fullName")?.Value;

            return Ok(new
            {
                Email = email,
                FullName = fullName
            });
        }
    }
}
