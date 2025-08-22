using AuthDemo.Data;
using AuthDemo.Entities;
using AuthDemo.Models;
using AuthDemo.Models.DTOs;
using AuthDemo.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace AuthDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IEmailService _emailService;
        private readonly PasswordHasher<User> _passwordHasher;

        public AuthController(AppDbContext context, IEmailService emailService)
        {
            _context = context;
            _emailService = emailService;
            _passwordHasher = new PasswordHasher<User>();
        }

        // ─────────────── Register ───────────────
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
                return BadRequest(new { message = "Այս email-ով օգտատեր արդեն կա" });

            var user = new User
            {
                Name = request.Name,
                Surname = request.Surname,
                Age = request.Age,
                Birthday = request.Birthday,
                Email = request.Email,
                Sex = request.Sex,
                EmailConfirmed = false,
                PasswordHash = ""
            };

            user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            var token = Guid.NewGuid().ToString();

            var emailToken = new EmailConfirmationToken
            {
                UserId = user.Id,
                User = user,
                Token = token,
                Expiration = DateTime.UtcNow.AddHours(24)
            };
            _context.EmailConfirmationTokens.Add(emailToken);
            await _context.SaveChangesAsync();

            string confirmLink = $"{Request.Scheme}://{Request.Host}/api/auth/confirm?userId={user.Id}&token={token}";
            await _emailService.SendEmailAsync(user.Email, "Confirm your account",
                $"Սեղմեք հաստատման համար: <a href='{confirmLink}'>Confirm</a>");

            return Ok(new { message = "Գրանցումը հաջողվեց։ Ստուգեք email-ը հաստատման համար։" });
        }

        // ─────────────── Confirm Email ───────────────
        [HttpGet("confirm")]
        public async Task<IActionResult> ConfirmEmail(int userId, string token)
        {
            var emailToken = await _context.EmailConfirmationTokens
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.UserId == userId && t.Token == token);

            if (emailToken == null)
                return BadRequest("Սխալ թոկեն կամ userId");

            if (emailToken.Expiration < DateTime.UtcNow)
            {
                _context.EmailConfirmationTokens.Remove(emailToken);
                await _context.SaveChangesAsync();
                return BadRequest("Թոկենը լրացել է");
            }

            emailToken.User.EmailConfirmed = true;
            _context.EmailConfirmationTokens.Remove(emailToken);
            await _context.SaveChangesAsync();

            return Ok("Email-ը հաստատվեց։ Հիմա կարող եք login անել։");
        }

        // ─────────────── Login ───────────────
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user == null)
                return BadRequest("Սխալ email կամ password");

            if (!user.EmailConfirmed)
                return BadRequest("Email-ը հաստատված չէ։ Ստուգեք ձեր էլեկտրոնային հասցեն");

            var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (result == PasswordVerificationResult.Failed)
                return BadRequest("Սխալ email կամ password");

            return Ok(new { message = "Login հաջողվեց" });
        }
    }
}
