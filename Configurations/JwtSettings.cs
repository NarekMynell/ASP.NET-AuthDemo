namespace AuthDemo.Configurations
{
    public class JwtSettings
    {
        public required string Issuer { get; set; }
        public required string Audience { get; set; }
        public required int AccessTokenExpiryMinutes { get; set; }
        public required int RefreshTokenExpiryDays { get; set; }
    }
}