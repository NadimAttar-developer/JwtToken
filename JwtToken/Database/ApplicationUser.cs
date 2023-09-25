using Microsoft.AspNetCore.Identity;

// DONE BY ENG: NADIM ATTAR

namespace JwtToken.Database;

public class ApplicationUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}
