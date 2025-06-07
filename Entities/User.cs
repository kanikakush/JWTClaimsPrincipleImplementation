namespace JWTClaimsPrincipleImplementation.Entities
{
    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string? Role { get; set; } = string.Empty;
        public string? RefreshToken { get; set; } = string.Empty; // Optional field for refresh token
        public DateTime? RefreshTokenExpiryTime { get; set; } = null; // Optional field for refresh token expiry time
    }
}
