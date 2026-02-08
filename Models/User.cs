using System.ComponentModel.DataAnnotations;

namespace Auth.Models
{
    public class User
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string FullName { get; set; }

        [Required]
        [MaxLength(100)]
        public string Email { get; set; }

        [Required]
        [MaxLength(500)]
        public string PasswordHash { get; set; }

        public bool EmailVerified { get; set; } = false;
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;
        public DateTime? LockoutEnd { get; set; }
        public bool IsActive { get; set; } = true;
    }
}
