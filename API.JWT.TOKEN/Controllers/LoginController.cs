using API.JWT.TOKEN.Models.entities;
using Microsoft.AspNetCore.Mvc;
using API.JWT.TOKEN.Repositories;
using API.JWT.TOKEN.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace API.JWT.TOKEN.Controllers
{
	[ApiController]
	[Route("v1")]
	public class LoginController : ControllerBase
	{
		[HttpPost]
		[Route("login")]
		public async Task<ActionResult<dynamic>> AuthenticateAsync([FromBody] User model)
		{
			//recuperar usuário
			var user = UserRepository.Get(model.Username, model.Password);

			//verifica se o usuário existe
			if (user == null)
			{
				return BadRequest(new { mensagem = "Usuário inválido" });
			}

			//Gerar token

			var token = TokenService.GenerateToken(user);
			var refleshToken = TokenService.GenerateRefleshToken();
			TokenService.SaveRefleshToken(user.Username, refleshToken);

			//ocutar password
			user.Password = "";


			return new
			{
				user = new { Id = user.Id, Username = User.Identity.Name, Role = user.Role },
				token = token,
				refleshToken = refleshToken
			};
		}

		[HttpPost]
		[Route("reflesh")]
		public IActionResult Reflesh(string token, string refleshToken)
		{
			var principal = TokenService.GetPrincipalFromExpiredToken(token);
			var username = principal.Identity.Name;
			var savedRefleshToken = TokenService.GetRefleshToken(username);

			if(savedRefleshToken != refleshToken)
			{
				throw new SecurityTokenException("Reflesh Token Inválido");
			}

			var newJwtToken = TokenService.GenerateToken(principal.Claims);
			var newRefleshToken = TokenService.GenerateRefleshToken();

			TokenService.DeleteRefleshToken(username, refleshToken);
			TokenService.SaveRefleshToken(username, newRefleshToken);

			return new ObjectResult(new
			{
				token = newJwtToken,
				refleshToken = newRefleshToken
			});
			
		}

		[HttpGet]
		[Route("login2")]
		[Authorize]
		public ActionResult<User> Login()
		{
			return Ok(new { mensagem = "Tudo certo"});

		}
	}
}
