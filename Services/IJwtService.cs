using AuthDemo.Entities;

namespace AuthDemo.Services
{
    public interface IJwtService
    {
        int AccessTokenExpiryMinutes { get; }
        int RefreshTokenExpiryDays { get; }
        string GenerateAccessToken(User user);
        string GenerateRefreshToken();
        bool ValidateAccessToken(string token);          
        int? GetUserIdFromToken(string token);
        Task<RefreshToken?> GetValidRefreshTokenAsync(string token);
        Task RevokeRefreshTokenAsync(string token);
        Task SaveRefreshTokenAsync(int userId, string token);
    }
}