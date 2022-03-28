using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtWebApi.Models
{
    public class Response
    {

        public bool IsSuccess { get; set; }

        public string Status { get; set; }

        public string Message { get; set; }

        public DateTime? ExpireDate { get; set; }
    }
}
