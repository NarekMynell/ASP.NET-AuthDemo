using System.ComponentModel.DataAnnotations;

namespace AuthDemo.Entities
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public required int UserId { get; set; }
        public User? User { get; set; }
        public required string Token { get; set; }
        public required DateTime Expiration { get; set; }
    }
}