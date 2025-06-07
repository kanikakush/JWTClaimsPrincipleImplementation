using JWTClaimsPrincipleImplementation.Entities;
using JWTClaimsPrincipleImplementation.Model;

namespace JWTClaimsPrincipleImplementation.Interface
{
    public interface IAuthService
    {
        public Task<User?> RegisterAsync(UserDto request);
        public Task<TokenResponseDto?> LoginAsync(UserDto request);
        public Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request);
    }
}
