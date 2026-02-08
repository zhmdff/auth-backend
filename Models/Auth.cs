using System.ComponentModel.DataAnnotations;

namespace Auth.Models
{
    public class AuthRequest
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [MaxLength(100)]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
        [MaxLength(100)]
        public string Password { get; set; }
    }

    public class AuthResponse
    {
        public string AccessToken { get; set; }
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresIn { get; set; } = 900;
    }

    public class JwtSettings
    {
        public string Secret { get; set; }
        public int AccessTokenExpirationMinutes { get; set; } = 15;
        public int RefreshTokenExpirtaionDays { get; set; } = 7;
    }

}
