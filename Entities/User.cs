using System.ComponentModel.DataAnnotations;

namespace AuthDemo.Entities
{
    public class User 
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(50)] 
        public required string Name { get; set; }

        [MaxLength(50)] 
        public required string Surname { get; set; }

        [Range(0, 120)] 
        public int Age { get; set; }

        public DateTime Birthday { get; set; }

        [EmailAddress]
        public required string Email { get; set; }

        public required string PasswordHash { get; set; }
        
        public required string Sex { get; set; }

        public bool EmailConfirmed { get; set; } = false;
    }
}
