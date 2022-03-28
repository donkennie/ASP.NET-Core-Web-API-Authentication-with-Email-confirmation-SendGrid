/*using MailKit.Net.Smtp;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;

using System.Text;
using System.Threading.Tasks;

namespace EmailService
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailConfiguration _emailConfig;

        public EmailSender(EmailConfiguration emailConfig)
        {
            _emailConfig = emailConfig;
        }




        public void SendEmail(Message message)
        {
            var emailMessage = new MimeMessage();
            Send(emailMessage);
        }

        private MimeMessage CreateEmailMessage(Message message)
        {

            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress(_emailConfig.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.From.Add(new MailboxAddress("ajeigbekehinde160@gmail.com", _emailConfig.From));
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text)
            {
                Text = message.Content
            };

            return emailMessage;
        }  
    

        private void Send(MimeMessage mailMessage)
        {
            using (var client = new SmtpClient())
            {
                try
                {
                    client.Connect(_emailConfig.SmtpServer, _emailConfig.Port, false);
                    client.AuthenticationMechanisms.Remove("XOAUTH2");
                    client.Authenticate(_emailConfig.Username, _emailConfig.Password);
                    
                    client.Send(mailMessage);
                }
                catch (Exception)
                {

                     throw;               
                }

                finally
                {
                    client.Disconnect(true);
                    client.Dispose();
                };
            }
        }
    }
}
*/