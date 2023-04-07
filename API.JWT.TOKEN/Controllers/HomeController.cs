using API.JWT.TOKEN.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace API.JWT.TOKEN.Controllers
{
	[ApiController]
	public class HomeController : ControllerBase
	{
		[HttpGet]
		[Route("any")]
		public string Anonymous() => "Anônimo";


		[HttpGet]
		[Route("authenticated")]
		[Authorize]
		public string Authenticated() => $"Autenticado - {User.Identity.Name}";

		[HttpGet]
		[Route("employee")] // Regra de vizualização apenas para funcionario. 
		[Authorize(Roles ="employee,manager")]
		public string Employee() => $"Funcionario";

		[HttpGet]
		[Route("manager")] // Regra de vizualização apenas para funcionario. 
		[Authorize(Roles = "manager")]
		public string Manager() => "Gerente";
	}
}