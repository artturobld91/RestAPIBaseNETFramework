using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RestAPIBaseNETFramework.DTOs
{
    public class UserLoginDTO
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }

        public string Rol { get; set; }
    }
}