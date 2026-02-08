using Auth.Models;

namespace Auth.Repositories
{
    public interface IUserRepository
    {
        Task<User?> GetByIdAsync(int id);
        Task<User?> GetByEmailAsync(string email);
        Task<User?> ValidateCredentials(string email, string password);
        Task UpdateAsync(User user);
    }
}
