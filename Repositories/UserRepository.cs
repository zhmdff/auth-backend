using Auth.Data;
using Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth.Repositories
{
    public sealed class UserRepository : IUserRepository
    {
        private readonly ApplicationDbContext _db;

        public UserRepository(ApplicationDbContext db)
        {
            _db = db;
        }

        public Task<User?> GetByIdAsync(int id) => _db.Users.FindAsync(id).AsTask();

        public async Task<User?> GetByEmailAsync(string email)
        {
            return await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
        }

        public async Task<User?> ValidateCredentials(string email, string password)
        {
            var user = await _db.Users.SingleOrDefaultAsync(u => u.Email == email);

            if (user == null) return null;

            return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash) ? user : null;

        }

        public async Task UpdateAsync(User user)
        {
            _db.Users.Update(user);
            await _db.SaveChangesAsync();
        }

    }
}
