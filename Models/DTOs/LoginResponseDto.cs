namespace AuthDemo.Models.DTOs
{
    public class LoginResponseDto
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresInMinutes { get; set; }
        public UserInfoDto User { get; set; } = new();
    }
}