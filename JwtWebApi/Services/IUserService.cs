using JwtWebApi.IdentityAuth;
using JwtWebApi.Models;
using JwtWebApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtWebApi
{
    public interface IUserService
    {
        
        Task<Response> RegisterUserAsync(RegisterModel model);
        Task<Response> LoginUserAsync(LoginModel model);
        Task<Response> ConfirmEmailAsync(string userId, string token);
    }

    public class UserService : IUserService
    {
        private  UserManager<ApplicationUser> _userManager;
        private IConfiguration _configuration { get; }
        private IMailService _mailService;
        public UserService(UserManager<ApplicationUser> userManager, IConfiguration configuration, IMailService mailService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _mailService = mailService;
        }


        public async Task<Response> RegisterUserAsync(RegisterModel model) 
        {
            if (model == null)
                throw new NullReferenceException("Register Model is null");

            //if (model.Password != model.Email)
            //    return new Response
            //    {
            //        Message = "Confirm password doesn't match the password",
            //        IsSuccess = false
            //    };

            var user= new ApplicationUser
            {
                Email = model.Email,
                //SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                var confirmEmailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                var encodedEmailToken = Encoding.UTF8.GetBytes(confirmEmailToken);
                var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

                string url = $"{_configuration["AppUrl"]}/api/auth/confirmemail?userid={user.Id}&token={validEmailToken}";

                await _mailService.SendEmailAsync(user.Email, "Confirm your email", $"<h1>Welcome to Auth Demo</h1>" +
                    $"<p>Please confirm your email by <a href='{url}'>Clicking here</a></p>");

                return new Response { IsSuccess = true, Message = "User created successfully!" };
            }

            var errors = new List<string>();

            foreach (var error in result.Errors)
            {
                errors.Add(error.Description);
            }
            return new Response { IsSuccess= false, Message = string.Join(", ", errors) };


        }



        public async Task<Response> LoginUserAsync(LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                return new Response
                {
                    Message = "There is no user with that Email address",
                    IsSuccess = false
                };
            }

            var result = await _userManager.CheckPasswordAsync(user, model.Password);

            if (!result)
                return new Response
                {
                    Message = "Invalid password",
                    IsSuccess = false
                };


            var authClaims = new List<Claim>
                {
                   // new Claim("Email", user.Email),
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                     new Claim(ClaimTypes.NameIdentifier, user.Id),
                };

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT: ValidIssuer"],
                audience: _configuration["JWT: ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            string tokenAsString = new JwtSecurityTokenHandler().WriteToken(token);

            return new Response
            {
                Message = tokenAsString,
                IsSuccess = true,
                ExpireDate = token.ValidTo
            };
        }

        public async Task<Response> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new Response
                {
                    IsSuccess = false,
                    Message = "User not found"
                };

            var decodedToken = WebEncoders.Base64UrlDecode(token);
            string normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ConfirmEmailAsync(user, normalToken);

            if (result.Succeeded)
                return new Response
                {
                    Message = "Email confirmed successfully!",
                    IsSuccess = true,
                };

            var errors = new List<string>();

            foreach (var error in result.Errors)
            {
                errors.Add(error.Description);
            }
            return new Response { IsSuccess = false, Message = string.Join(", ", errors) };
            //return new Response
            // {
            //     IsSuccess = false,
            //     Message = "Email did not confirm",
            //     Errors = result.Errors.Select(e => e.Description)
            // };
        }
    }

    }
