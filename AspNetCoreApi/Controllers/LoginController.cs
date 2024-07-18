//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Mvc;

//namespace AspNetCoreApi.Controllers
//{
//    [Route("/login")]
//    [ApiController]
//    public class LoginController : ControllerBase
//    {
//        [HttpGet]
//        public IActionResult OnGet()
//        {
//            var html = "<p>Welcome to Code Maze2222</p>";
//            var html2 = @"
//<form method=""post"">
//    <input name=""username"" value=""bibi22"" />
//    <input name=""password"" value=""poulet33"" />

//    <button type=""submit"">Submit</button>
//</form>
//";
//            return new ContentResult
//            {
//                Content = html2,
//                ContentType = "text/html"
//            };
//        }

//        [HttpPost]
//        public IActionResult OnPost([FromForm] Credential credential)
//        {
//            return Ok();
//        }

//    }
//}
