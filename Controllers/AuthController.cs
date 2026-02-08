using Auth.Models;
using Auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Auth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] AuthRequest request)
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = Request.Headers["User-Agent"].ToString();
            var country = Request.Headers["CF-IPCountry"].FirstOrDefault() ?? "Unknown";

            var result = await _authService.LoginAsync(request.Email, request.Password, ipAddress, userAgent, country);

            if (!result.Success)
                return Unauthorized(new { message = result.ErrorMessage });

            Response.Cookies.Append("refreshToken", result.RefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            });

            return Ok(new { AccessToken = result.AccessToken });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            if (!Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
                return Unauthorized(new { message = "Refresh token missing" });

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = Request.Headers["User-Agent"].ToString();
            var country = Request.Headers["CF-IPCountry"].FirstOrDefault() ?? "Unknown";

            var result = await _authService.RefreshTokenAsync(refreshToken, ipAddress, userAgent, country);

            if (!result.Success)
                return Unauthorized(new { message = result.ErrorMessage });

            Response.Cookies.Append("refreshToken", result.RefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            });

            return Ok(new { AccessToken = result.AccessToken });
        }

        [Authorize]
        [HttpGet("dashboard")]
        public IActionResult Dashboard()
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            var fullName = User.FindFirstValue(ClaimTypes.Name);

            return Ok(new { Email = email, FullName = fullName });
        }
    }
}