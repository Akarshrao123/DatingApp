using System;
using System.ComponentModel.DataAnnotations;

namespace API.DTOs;

public class LoginDto
{
   
   
   public required string username { get; set; }

   
   public required string password { get; set; }
}