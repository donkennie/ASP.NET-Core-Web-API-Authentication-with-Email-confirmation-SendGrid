using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtWebApi.Models
{
    public class ResetPasswordModel
    {
        /* [EmailAddress]
        [StringLength(50)]
        [Required(ErrorMessage = "Email is required")]

        public string Email { get; set; }*/


        [Required(ErrorMessage = "Username is a required field")]
        public string Username { get; set; }

        [Required(ErrorMessage = "New password is a required field")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Confirm new password is required")]
        public string ConfirmNewPassword { get; set; }

        public string Token { get; set; }
    }
}
