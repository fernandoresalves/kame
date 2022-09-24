using Microsoft.AspNetCore.Mvc;

namespace Kame.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PingController : Controller
    {
        [HttpGet]
        public string Get()
        {
            return DateTime.Now.ToString();
        }
    }
}
