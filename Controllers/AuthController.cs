using AuthDemo.Data;
using AuthDemo.Entities;
using AuthDemo.Models;
using AuthDemo.Models.DTOs;
using AuthDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly PasswordHasher<User> _passwordHasher;
        private readonly IEmailService _emailService;
        private readonly IJwtService _jwtService;

        public AuthController(AppDbContext context, IEmailService emailService, IJwtService jwtService)
        {
            _context = context;
            _emailService = emailService;
            _passwordHasher = new PasswordHasher<User>();
            _jwtService = jwtService;
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

            if (emailToken.User == null)
            {
                return BadRequest("Օգտատերը գտնված չէ");
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

            // JWT tokens ստեղծում
            var accessToken = _jwtService.GenerateAccessToken(user);
            var refreshToken = _jwtService.GenerateRefreshToken();
            
            // Refresh token պահելը database-ում
            await _jwtService.SaveRefreshTokenAsync(user.Id, refreshToken);

            var response = new LoginResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                TokenType = "Bearer",
                ExpiresInMinutes = _jwtService.AccessTokenExpiryMinutes,
                User = new UserInfoDto
                {
                    Id = user.Id,
                    Name = user.Name,
                    Surname = user.Surname,
                    Age = user.Age,
                    Email = user.Email,
                    Sex = user.Sex,
                    Birthday = user.Birthday
                }
            };

            return Ok(response);
        }

        // ─────────────── Refresh Token ───────────────
        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] string refreshToken)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var storedRefreshToken = await _jwtService.GetValidRefreshTokenAsync(refreshToken);
            if (storedRefreshToken == null)
                return BadRequest("Սխալ կամ ժամկետն անցած refresh token");

            var user = storedRefreshToken.User!;

            // Նոր tokens ստեղծում
            var newAccessToken = _jwtService.GenerateAccessToken(user);
            var newRefreshToken = _jwtService.GenerateRefreshToken();

            // Հին refresh token-ը չեղարկելը և նորը պահելը
            await _jwtService.RevokeRefreshTokenAsync(refreshToken);
            await _jwtService.SaveRefreshTokenAsync(user.Id, newRefreshToken);

            var response = new LoginResponseDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                TokenType = "Bearer",
                ExpiresInMinutes = _jwtService.AccessTokenExpiryMinutes,
                User = new UserInfoDto
                {
                    Id = user.Id,
                    Name = user.Name,
                    Surname = user.Surname,
                    Age = user.Age,
                    Email = user.Email,
                    Sex = user.Sex,
                    Birthday = user.Birthday
                }
            };

            return Ok(response);
        }

        // ─────────────── Logout ───────────────
        [HttpPost("logout")]
        [Authorize] // Պետք է access token ունենալ
        public async Task<IActionResult> Logout([FromBody] string refreshToken)
        {
            // Refresh token-ը չեղարկելը
            await _jwtService.RevokeRefreshTokenAsync(refreshToken);

            return Ok(new { message = "Logout հաջողվեց" });
        }

        // ─────────────── Protected Route - User Profile ───────────────
        [HttpGet("profile")]
        [Authorize] // Միայն valid access token-ով կարելի է մուտք գործել
        public async Task<IActionResult> GetProfile()
        {
            // User ID-ն JWT token-ից վերցնելը
            var userIdClaim = User.FindFirst("userId")?.Value;
            if (userIdClaim == null || !int.TryParse(userIdClaim, out int userId))
                return Unauthorized("Սխալ token");

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                return NotFound("Օգտատերը գտնված չէ");

            var userInfo = new UserInfoDto
            {
                Id = user.Id,
                Name = user.Name,
                Surname = user.Surname,
                Age = user.Age,
                Email = user.Email,
                Sex = user.Sex,
                Birthday = user.Birthday
            };

            return Ok(userInfo);
        }

        // ─────────────── Test Protected Route ───────────────
        [HttpGet("test-protected")]
        [Authorize]
        public IActionResult TestProtected()
        {
            var userName = User.FindFirst(ClaimTypes.Name)?.Value;
            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            var userId = User.FindFirst("userId")?.Value;

            return Ok(new 
            { 
                message = "Դուք հաջողությամբ մուտք եք գործել protected route", 
                user = new { name = userName, email = userEmail, id = userId }
            });
        }
    }
}
