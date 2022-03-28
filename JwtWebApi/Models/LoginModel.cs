using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtWebApi.Models
{
    public class LoginModel
    {
        [EmailAddress]
        [StringLength(50)]
        [Required(ErrorMessage = "Email is a required field")]

        public string Email { get; set; }
        //[Required(ErrorMessage = "Username is required")]
        //public string Username { get; set; }

        [Required(ErrorMessage = "Password is a required field")]
        public string Password { get; set; }
    }
}
