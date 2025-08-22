using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthDemo.Entities
{
    public class EmailConfirmationToken
    {
        [Key]
        public int Id { get; set; }
        public required int UserId { get; set; }
        [ForeignKey(nameof(UserId))]
        public User User { get; set; }
        public required string Token { get; set; }
        public required DateTime Expiration { get; set; }
    }
}