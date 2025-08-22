using System.ComponentModel.DataAnnotations;

namespace AuthDemo.Models.DTOs
{
    public class RegisterDto
    {
        [Required(ErrorMessage = "Անունը պարտադիր է")]
        [MaxLength(50, ErrorMessage = "Անունը չի կարող գերազանցել 50 սիմվոլը")]
        public required string Name { get; set; }

        [Required(ErrorMessage = "Ազգանունը պարտադիր է")]
        [MaxLength(50)]
        public required string Surname { get; set; }

        [Range(0, 120, ErrorMessage = "Տարիքը պետք է լինի 0-120 միջակայքում")]
        public int Age { get; set; }

        [Required(ErrorMessage = "Ծննդյան օրը պարտադիր է")]
        public DateTime Birthday { get; set; }

        [Required(ErrorMessage = "Email-ը պարտադիր է")]
        [EmailAddress(ErrorMessage = "Սխալ email")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Գաղտնաբառը պարտադիր է")]
        [MinLength(6, ErrorMessage = "Գաղտնաբառը պետք է լինի առնվազն 6 սիմվոլ")]
        public required string Password { get; set; }

        [Required(ErrorMessage = "Սեռը պարտադիր է")]
        public required string Sex { get; set; }
    }
}
