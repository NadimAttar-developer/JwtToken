using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

// DONE BY ENG: NADIM ATTAR

namespace JwtToken.Controllers;
[Authorize]
[Route("api/[controller]")]
[ApiController]
public class WeatherForecastController : ControllerBase
{
    [HttpGet(Name = "GetWeatherForecast")]
    public IActionResult GetWeatherForecast()
    {
        return Ok();
    }
}
