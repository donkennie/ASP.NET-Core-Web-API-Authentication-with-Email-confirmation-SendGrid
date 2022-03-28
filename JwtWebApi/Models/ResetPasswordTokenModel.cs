using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtWebApi.Models
{
    public class ResetPasswordTokenModel
    {
        /*
         [EmailAddress]
        [StringLength(50)]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }*/
        public string Username { get; set; }
    }
}
