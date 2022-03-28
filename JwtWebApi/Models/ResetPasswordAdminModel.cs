using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JwtWebApi.Models
{
    public class ResetPasswordAdminModel
    {

        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; }
 
        [Required(ErrorMessage = "New password is required")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Confirm new password is required")]
        public string ConfirmNewPassword { get; set; }
    }
}
