using AuthDemo.Configurations;
using AuthDemo.Data;
using AuthDemo.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthDemo.Services
{
    /// <summary>
    /// JWT Token-ների կառավարման ծառայություն
    /// Պատասխանատու է access և refresh token-ների ստեղծման, ստուգման և կառավարման համար
    /// </summary>
    public class JwtService : IJwtService
    {
        private readonly AppDbContext _context;
        private readonly JwtSettings _jwtSettings;
        private readonly string _secretKey;

        public int AccessTokenExpiryMinutes => _jwtSettings.AccessTokenExpiryMinutes;
        public int RefreshTokenExpiryDays => _jwtSettings.RefreshTokenExpiryDays;

        public JwtService(AppDbContext context, IOptions<JwtSettings> options, IConfiguration configuration)
        {
            _context = context;
            _jwtSettings = options.Value;
            _secretKey = configuration["Jwt:Key"]
                ?? throw new InvalidOperationException("JWT Secret key not found in configuration.");
        }

        /// <summary>
        /// JWT Access Token ստեղծում տվյալ օգտատիրոջ համար
        /// Access Token-ը կարճաժամկետ է (15 րոպե) և պարունակում է օգտատիրոջ հիմնական տվյալները
        /// </summary>
        /// <param name="user">Օգտատեր, որի համար ստեղծվում է token-ը</param>
        /// <returns>JWT token որպես string</returns>
        public string GenerateAccessToken(User user)
        {
            // JWT Token-ի ստեղծման համար օբյեկտ
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // Secret Key-ը bytes array-ի վերածելը ստորագրության համար
            var key = Encoding.UTF8.GetBytes(_secretKey);
            
            // Token-ի բովանդակության նկարագրումը
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                // Claims - օգտատիրոջ մասին ինֆորմացիա, որը կպահվի token-ի մեջ
                Subject = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), // Standard claim - օգտատիրոջ ID
                    new Claim(ClaimTypes.Email, user.Email), // Standard claim - օգտատիրոջ email
                    new Claim(ClaimTypes.Name, $"{user.Name} {user.Surname}") // Standard claim - անուն ազգանուն
                ]),
                
                // Token-ի ժամկետը - հիմա + 15 րոպե (կամ ինչ որ կարգավորված է)
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
                
                // Token-ի issue անողը (մեր app-ը)
                Issuer = _jwtSettings.Issuer,
                
                // Token-ի audience-ը (ում համար է նախատեսված)
                Audience = _jwtSettings.Audience,

                // Ստորագրման տվյալները - HMAC SHA256 ալգորիթմով
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key), 
                    SecurityAlgorithms.HmacSha256Signature)
            };
            
            // Token-ի ստեղծումը և string-ի վերածումը
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// Refresh Token ստեղծում - պատահական 32 բայթի string
        /// Refresh Token-ը չի պարունակում ոչ մի ինֆորմացիա, պարզապես պատահական տվյալներ են
        /// </summary>
        /// <returns>Base64 encoded random string</returns>
        public string GenerateRefreshToken()
        {
            // 32 բայթի պատահական տվյալներ
            var randomBytes = new byte[32];
            
            // Cryptographically secure random number generator
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            
            // Base64 encoding - URL-safe string-ի համար
            return Convert.ToBase64String(randomBytes);
        }

        /// <summary>
        /// Access Token-ի վալիդության ստուգում
        /// Ստուգում է ստորագրությունը, ժամկետը և այլ պարամետրերը
        /// </summary>
        /// <param name="token">JWT token որպես string</param>
        /// <returns>true եթե վալիդ է, false եթե ոչ</returns>
        public bool ValidateAccessToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secretKey);
                
                // Token validation parameters - նույն պարամետրերը ինչ Program.cs-ում
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true, // Ստորագրության ստուգում
                    IssuerSigningKey = new SymmetricSecurityKey(key), // Մեր secret key-ով ստուգում
                    ValidateIssuer = true, // Issuer-ի ստուգում
                    ValidIssuer = _jwtSettings.Issuer,
                    ValidateAudience = true, // Audience-ի ստուգում
                    ValidAudience = _jwtSettings.Audience,
                    ValidateLifetime = true, // Ժամկետի ստուգում
                    ClockSkew = TimeSpan.Zero // Ժամի տարբերությունը 0 (ճիշտ ժամկետ)
                }, out SecurityToken validatedToken);
                
                return true; // Եթե exception չի նետվել, token-ը վալիդ է
            }
            catch
            {
                return false; // Ցանկացած error-ի դեպքում token-ը ոչ վալիդ է
            }
        }

        /// <summary>
        /// JWT Token-ից օգտատիրոջ ID-ի հանումը
        /// Token-ը decode անելով ստանալ userId claim-ը
        /// </summary>
        /// <param name="token">JWT token</param>
        /// <returns>User ID կամ null, եթե չի գտնվում</returns>
        public int? GetUserIdFromToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                
                // Token-ը decode անելը (առանց validation-ի)
                var jsonToken = tokenHandler.ReadJwtToken(token);

                // "userId" claim-ը գտնելը
                var userIdClaim = jsonToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
                
                // String-ը int-ի վերածելը
                if (userIdClaim != null && int.TryParse(userIdClaim.Value, out int userId))
                {
                    return userId;
                }
                return null;
            }
            catch
            {
                return null; // Error-ի դեպքում null վերադարձ
            }
        }

        /// <summary>
        /// Database-ից վալիդ Refresh Token-ի ստացումը
        /// Ստուգում է որ token-ը գոյություն ունի և ժամկետը չի լրացել
        /// </summary>
        /// <param name="token">Refresh token string</param>
        /// <returns>RefreshToken entity կամ null</returns>
        public async Task<RefreshToken?> GetValidRefreshTokenAsync(string token)
        {
            return await _context.RefreshTokens
                .Include(rt => rt.User) // User տվյալներն էլ բեռնելը
                .FirstOrDefaultAsync(rt => 
                    rt.Token == token && // Token-ը համընկնում է
                    rt.Expiration > DateTime.UtcNow); // Ժամկետը չի լրացել
        }

        /// <summary>
        /// Refresh Token-ի ջնջումը database-ից
        /// Logout-ի կամ security breach-ի ժամանակ օգտագործվում է
        /// </summary>
        /// <param name="token">Refresh token string</param>
        public async Task RevokeRefreshTokenAsync(string token)
        {
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == token);

            if (refreshToken != null)
            {
                // Token-ը ամբողջությամբ ջնջելը database-ից
                _context.RefreshTokens.Remove(refreshToken);
                await _context.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Նոր Refresh Token-ի պահումը database-ում
        /// Միաժամանակ հին token-ները ջնջելը security-ի համար
        /// </summary>
        /// <param name="userId">Օգտատիրոջ ID</param>
        /// <param name="token">Նոր refresh token</param>
        /// <returns>Ստեղծված RefreshToken entity</returns>
        public async Task SaveRefreshTokenAsync(int userId, string token)
        {
            // Հին token-ները ջնջելը (ըստ ցանկության)
            // Security հտարակությամբ յուրաքանչյուր օգտատեր կարող է ունենալ մի refresh token միայն
            var existingTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId)
                .ToListAsync();
            
            // Բոլոր հին token-ները ջնջելը
            _context.RefreshTokens.RemoveRange(existingTokens);

            // Նոր token-ի ստեղծումը
            var refreshToken = new RefreshToken
            {
                Token = token,
                UserId = userId,
                Expiration = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays)
            };

            // Database-ում պահելը
            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();
        }
    }
}