using System.ComponentModel.DataAnnotations;

namespace AuthDemo.Entities
{
    public class User 
    {
        [Key] // սա Primary Key-ն է
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

        public required string PasswordHash { get; set; } // մենք Password-ը չենք պահում PlainText-ով
        
        public required string Sex { get; set; } // "Male" / "Female" / "Other"

        public bool EmailConfirmed { get; set; } = false; // Email հաստատված է թե ոչ
    }
}
