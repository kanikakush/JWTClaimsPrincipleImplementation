namespace JWTClaimsPrincipleImplementation.Model
{
    public class RefreshTokenRequestDto
    {
        public Guid UserId { get; set; }
        public string RefreshUser { get; set; } = string.Empty;// The user information associated with the token
    }
}
