using Auth.Models;

namespace Auth.Repositories
{
    public interface IAuditLogRepository
    {
        Task LogEvent(AuditLog log);
    }
}
