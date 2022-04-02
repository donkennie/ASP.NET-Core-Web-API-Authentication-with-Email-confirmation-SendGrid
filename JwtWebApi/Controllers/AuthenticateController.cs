using EmailService;
using JwtWebApi.IdentityAuth;
using JwtWebApi.Models;
using JwtWebApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
         private readonly UserManager<ApplicationUser> _userManager;

         private readonly RoleManager<IdentityRole> _roleManager;

         private readonly IConfiguration _configuration;

       // private readonly IEmailSender _emailSenderForMimeKit;

         private readonly IMailService _mailService;

         public AuthenticateController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration /*IEmailSender emailSenderForMimeKit*/, IMailService mailService)
         {
             _userManager = userManager;
             _roleManager = roleManager;
             _configuration = configuration;
          //  _emailSenderForMimeKit = emailSenderForMimeKit;      
             _mailService = mailService;
         }

        [HttpPost]
        [Route("register")]

        public async Task<IActionResult> Register([FromBody] RegisterModel model)
         {
             var userExists = await _userManager.FindByEmailAsync(model.Email);
             if (userExists!= null)
             {
                 return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "The Email is already being used!" });
             }

             ApplicationUser user = new()
             {
                 Email = model.Email,
                 SecurityStamp = Guid.NewGuid().ToString(),
                 UserName = model.Username
             };

             var result = await _userManager.CreateAsync(user, model.Password);
           
             if (result.Succeeded)
             {

                var confirmEmailToken = await this._userManager.GenerateEmailConfirmationTokenAsync(user);
                
               /* var message = new Message(new string[] { "ajeigbekehinde160@gmail.com" }, "Test Email", "This is content from our email.", "ajeigbekehinde160@gmail.com");
                _emailSender.SendEmail(message);*/

                var encodedEmailToken = Encoding.UTF8.GetBytes(confirmEmailToken);
                var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

                string url = $"{_configuration["AppUrl"]}/api/auth/confirmemail?userid={user.Id}&token={validEmailToken}";

                await _mailService.SendEmailAsync(user.Email, "Confirm your email", $"<h1>Welcome to Auth Demo</h1>" +
                    $"<p>Please confirm your email by <a href='{url}'>Clicking here</a></p>");

                return Ok(new Response { Status = "Success", Message = "User created successfully!" });
             }

                 var errors = new List<string>();

                 foreach (var error in result.Errors)
                 {
                     errors.Add(error.Description);
                 }
                 return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = string.Join(", ", errors) });
         }


         [HttpPost]
         [Route("register-admin")]
         public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
         {

             var userExists = await _userManager.FindByNameAsync(model.Username);

             if (userExists != null)
             {
                 return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
             }

             ApplicationUser user = new()
             {
                 Email = model.Email,
                 SecurityStamp = Guid.NewGuid().ToString(),
                 UserName = model.Username
             };

             var result = await _userManager.CreateAsync(user, model.Password);


             if (!result.Succeeded)
             {

                 var errors = new List<string>();

                 foreach (var error in result.Errors)
                 {
                     errors.Add(error.Description);
                 }

                 return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = string.Join(", ", errors) });
             }

             if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
             {
                 await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
             }

             if (!await _roleManager.RoleExistsAsync(UserRoles.User))
             {
                 await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
             }

             if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
             {
                 await _userManager.AddToRoleAsync(user, UserRoles.Admin);

             }

             return Ok(new Response { Status = "Success", Message = "User created successfully!" });
         }


        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
                return NotFound();

            var result = await _userManager.ConfirmEmailAsync(userId, token);

            if (result.IsSuccess)
            {
                return Redirect($"{_configuration["AppUrl"]}/ConfirmEmail.html");
            }

            return BadRequest(result);
        }




        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
         {
               var user = await _userManager.FindByEmailAsync(model.Email);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                 {
                     new Claim(ClaimTypes.Name, user.Email),
                     new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                      new Claim(ClaimTypes.NameIdentifier, user.Id),
                 };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT: ValidIssuer"],
                    audience: _configuration["JWT: ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );
                if (ModelState.IsValid)
                {
                    await _mailService.SendEmailAsync(model.Email, "New login", "<h1> Hey!, new login to your account noticed</h1><p>New login to your account at" + DateTime.Now + "</p> ");

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(token),
                        expiration = token.ValidTo
                    });

                }



            }
                 return Unauthorized("You're not recognised- Unauthorized!");
         }

        [HttpPost]
        [Route("Change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
           
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "User does not exist!" });

            }

            if (string.Compare(model.NewPassword, model.ConfirmNewPassword) != 0)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "The new Password and the Confirm new password are not match!" });


            }

            

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);

            if (!result.Succeeded)
            {
                var errors = new List<string>();

                foreach(var error in result.Errors)
                {
                    errors.Add(error.Description);
                }

                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = string.Join(", ", errors) });
            }

            return Ok(new Response { Status = "Success", Message = "Password sucessfully changed" });

        }

        //reset password for admin
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("reset-password-admin")]
        public async Task<IActionResult> ResetPasswordAdmin([FromBody] ResetPasswordAdminModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

                 if (user == null)
                    return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "User does not exist!" });

                if (string.Compare(model.NewPassword, model.ConfirmNewPassword) != 0)
                    return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "The new Password and the Confirm new password are not match!" });

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

            if (!result.Succeeded)
            {

                var errors = new List<string>();

                foreach (var error in result.Errors)
                {
                    errors.Add(error.Description);
                }

                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = string.Join(", ", errors) });
            }

            return Ok(new Response { Status = "Success", Message = "Password sucessfully reseted" });
        }


        //reset password for user
         [HttpPost]
         [Route("reset-password-token")]
         public async Task<IActionResult> ResetPasswordToken([FromBody] ResetPasswordTokenModel model)
         {
             var user = await _userManager.FindByNameAsync(model.Username);

             if (user == null)
                      return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "User does not exist!" });

             var token = await _userManager.GeneratePasswordResetTokenAsync(user);
             // here
             var encodedToken = Encoding.UTF8.GetBytes(token);
             var validToken = WebEncoders.Base64UrlEncode(encodedToken);

             //Best practice send token to your email and generate url, the following only for example

             return Ok(new { token = token });

         }


         [HttpPost]
         [Route("reset-password")]
         public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
         {

             var user = await _userManager.FindByNameAsync(model.Username);

             if (user == null)
                 return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "User does not exist!" });

             if (string.Compare(model.NewPassword, model.ConfirmNewPassword) != 0)
                 return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "The new Password and the Confirm new password are not match!" });

             if (string.IsNullOrEmpty(model.Token))
             {
                 return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "Invalid token!" });
             }

             var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

             if (!result.Succeeded)
             {

                 var errors = new List<string>();

                 foreach (var error in result.Errors)
                 {
                     errors.Add(error.Description);
                 }

                 return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = string.Join(", ", errors) });
             }

             return Ok(new Response { Status = "Success", Message = "Password sucessfully reseted" });
         }

       
    }
}
