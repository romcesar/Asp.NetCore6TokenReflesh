using API.JWT.TOKEN.Models.entities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace API.JWT.TOKEN.Service
{
	public static class TokenService
	{
		//Criando Token
		public static string GenerateToken(User user)
		{
			var tokenHandle = new JwtSecurityTokenHandler(); // Criar a instância para criar o token.

			var key = Encoding.ASCII.GetBytes(Settings.Secret); // Codifica em bytes o secret criado em Settings

			var obj = new { tok = "", exp = 0 };
			


			//Vai descrever tudo que o nosso token tem, o que precisa para nosso token funcionar.

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				//Mapear os Perfis dos usuários no caso aqui são as claims

				Subject = new ClaimsIdentity(new Claim[]
				{
					new Claim(ClaimTypes.Name, user.Username), // User.Identity.Name
					new Claim(ClaimTypes.Role, user.Role)// User.IsInRole
				}),

				Expires = DateTime.UtcNow.AddHours(8), // quanto tempo o token irá expirar. 
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature) // usado para cripta e descriptar o token

			};

			var ver = tokenDescriptor;


			var token = tokenHandle.CreateToken(tokenDescriptor); // criar a instância para criar o token.


			return tokenHandle.WriteToken(token) ; //WriteToken exibi em forma de string

		}

        //Capturar os Claims já gerados do token anterior.
		public static string GenerateToken(IEnumerable<Claim> claims)
		{
			var tokenHandle = new JwtSecurityTokenHandler();
			var key = Encoding.ASCII.GetBytes(Settings.Secret) ;
			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(claims),
				Expires = DateTime.UtcNow.AddHours(2),
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
			};
			var token = tokenHandle.CreateToken(tokenDescriptor) ;

			return tokenHandle.WriteToken(token) ;
		}

		//Criando o RefleshToken
		public static string GenerateRefleshToken()
		{
			var randomNumber = new byte[32];
			using var rng = RandomNumberGenerator.Create();
			rng.GetBytes(randomNumber);
			return Convert.ToBase64String(randomNumber);
		}

		public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
		{
			var tokenValidationParameters = new TokenValidationParameters
			{
				ValidateAudience = false,
				ValidateIssuer = false,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Settings.Secret)),
				ValidateLifetime = false,
			};

			var tokenHandle = new JwtSecurityTokenHandler();

			var principal = tokenHandle.ValidateToken(token, tokenValidationParameters, out var securityToken);

			if(securityToken is not JwtSecurityToken jwtSecurityToken ||  
				jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase)) 
			{
				throw new SecurityTokenException("Token Inválido");
			}

			return principal;
			
		}


		private static List<(string, string)> _refleshToken = new();

		//Abstração para salvar o reflesh toke. Tem que armazenar e pegar do banco
		public static void SaveRefleshToken(string username, string refleshToken)
		{
			_refleshToken.Add(new (username, refleshToken));
		}

		public static string GetRefleshToken(string username)
		{
			return _refleshToken.FirstOrDefault(x => x.Item1 == username).Item2;
		}

		public static void DeleteRefleshToken(string username, string refleshToken)
		{
			var item = _refleshToken.FirstOrDefault(x => x.Item1 == username && x.Item2 == refleshToken);
			_refleshToken.Remove(item);
		}
	}
	
}
