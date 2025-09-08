namespace AuthDemo.Models.DTOs
{
    public class UserInfoDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Surname { get; set; } = string.Empty;
        public int Age { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Sex { get; set; } = string.Empty;
        public DateTime Birthday { get; set; }
    }
}