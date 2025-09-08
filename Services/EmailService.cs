using System.Net;
using System.Net.Mail;
using AuthDemo.Configurations;
using Microsoft.Extensions.Options;

namespace AuthDemo.Services
{
    // Email Service interface

    public interface IEmailService
    {
        Task SendEmailAsync(string to, string subject, string body);
    }

    public class EmailService : IEmailService
    {
        private readonly EmailSettings _settings;

        public EmailService(IOptions<EmailSettings> options)
        {
            _settings = options.Value;
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            using var client = new SmtpClient(_settings.Host, _settings.Port);
            client.Credentials = new NetworkCredential(_settings.Username, _settings.Password);
            client.EnableSsl = true;

            var mailMessage = new MailMessage(_settings.FromEmail, to, subject, body)
            {
                IsBodyHtml = true
            };

            await client.SendMailAsync(mailMessage);
        }
    }
}