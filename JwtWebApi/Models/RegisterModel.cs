using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtWebApi.Models
{
    public class RegisterModel
    {
        
        [Required(ErrorMessage = "Username is a required field")]
        public string Username { get; set; }

       //[DataType(DataType.EmailAddress)]
        [EmailAddress]
        [StringLength(50)]
        [Required(ErrorMessage = "Email is a required field")]
        public string Email { get; set; }

        //[StringLength(50, MinimumLength = 5)]
        [Required(ErrorMessage = "Password is a required field")]
        public string Password { get; set; }
    }
}
