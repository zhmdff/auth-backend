using System.ComponentModel.DataAnnotations;

namespace Auth.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }

        public int UserId { get; set; }

        [Required]
        [MaxLength(500)]
        public string TokenHash { get; set; }

        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public bool IsRevoked { get; set; } = false;
        public DateTime? RevokedAt { get; set; }

        public User User { get; set; }
    }
}
