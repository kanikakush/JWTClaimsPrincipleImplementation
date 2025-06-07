using JWTClaimsPrincipleImplementation.Data;
using JWTClaimsPrincipleImplementation.Entities;
using JWTClaimsPrincipleImplementation.Interface;
using JWTClaimsPrincipleImplementation.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTClaimsPrincipleImplementation.Services
{
    public class AuthService : IAuthService // Assuming IAuthService is defined in Interface/IAuthService.cs
    {
        private readonly IConfiguration configuration;
        private readonly MyDbContext context; // Assuming you have a DbContext for database operations
        public AuthService(IConfiguration configuration, MyDbContext context)
        {
            this.configuration = configuration;
            this.context = context;
        }
        public async Task<User?> RegisterAsync(UserDto request)
        {
            if(await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return null; // User already exists
            }
            var user = new User
            {
                Username = request.Username,
                PasswordHash = new PasswordHasher<User>()
                    .HashPassword(null, request.Password),// Hashing the password
                Role = request.Role ?? "Admin" // Default role if not specified
            };
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();
            return user;
        }
        public async Task<TokenResponseDto?> LoginAsync(UserDto request)
        {
            User? user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
                return null;
            //passswordHasher has proprty VerifyHashedPassword as we can't convert it in simple string
            var passwordVerificationResult = new PasswordHasher<User>()
                .VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                return null;
            }
            var token = new TokenResponseDto{
                AccessToken = CreateToken(user), // Create JWT token
                RefreshUser = await GenerateAndSaveRefreshToken(user) // Return the user information
            };
            //return Ok(new { Message = "Login successful", User = user });
            return token;
        }
        private async Task<string?> GenerateAndSaveRefreshToken(User user)
        {
            var randomNuber = new byte[32]; // Generate a random number for the refresh token
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNuber);
            var refreshToken = Convert.ToBase64String(randomNuber);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(1); // Set expiry time for the refresh token
            context.Users.Update(user);
            await context.SaveChangesAsync();
            return refreshToken;
        }
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role ?? "Admin") // Default role if not set
                // Add other claims as needed
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1), // Token expiration time
                signingCredentials: creds
                );
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            var user = await context.Users.FindAsync(request.UserId);
            if(user is null || user.RefreshToken != request.RefreshUser || user.RefreshTokenExpiryTime < DateTime.UtcNow)
            {
                return null; // Invalid or expired refresh token
            }
            var token = new TokenResponseDto
            {
                AccessToken = CreateToken(user), // Create a new JWT token
                RefreshUser = await GenerateAndSaveRefreshToken(user) // Generate and save a new refresh token
            };
            return token;
        }
    }
}
