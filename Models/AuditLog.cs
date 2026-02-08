using System.ComponentModel.DataAnnotations;

namespace Auth.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public int? UserId { get; set; }

        [Required]
        [MaxLength(50)]
        public string EventType { get; set; }

        public DateTime TimestampUtc { get; set; }
        public bool Success { get; set; }

        [MaxLength(500)]
        public string? FailureReason { get; set; }

        [MaxLength(45)]
        public string? IpAddress { get; set; }

        [MaxLength(500)]
        public string? UserAgent { get; set; }

        [MaxLength(100)]
        public string? Country { get; set; }
    }
}
