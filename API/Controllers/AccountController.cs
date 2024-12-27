using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

#pragma warning disable CS9113 // Parameter is unread.
public class AccountController(DataContext context,ITokenService tokenService): BaseApiController
#pragma warning restore CS9113 // Parameter is unread.
{
    [HttpPost("register")] //Account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        using var hmac=new HMACSHA512();

        if(await UserExists(registerDto.username)) return BadRequest("Username is taken");

        var user = new AppUser
        {
            UserName=registerDto.username.ToLower(),
            PasswordHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
            PasswordSalt=hmac.Key
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();

        return new UserDto
        {
            UserName=user.UserName,
            Token= tokenService.CreateToken(user)
        };

    }

    [HttpPost("login")]    
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        var user= await context.Users.FirstOrDefaultAsync(x=>
        x.UserName==loginDto.username.ToLower());

        if(user==null) return Unauthorized("Invalid Username");

        using var hmac= new HMACSHA512(user.PasswordSalt);

        var computedHash= hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));

        for(int i=0;i<computedHash.Length;i++)
        {
            if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");

        }

         return new UserDto
        {
            UserName=user.UserName,
            Token= tokenService.CreateToken(user)
        };
        
    }

    private async Task<bool> UserExists(string username)
    {
        return await context.Users.AnyAsync(x=>x.UserName.ToLower()==username.ToLower());
    }

}
