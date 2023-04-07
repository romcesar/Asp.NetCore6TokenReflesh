using API.JWT.TOKEN.Models.entities;
using System.Globalization;

namespace API.JWT.TOKEN.Repositories
{
	public static class UserRepository
	{
		public static User Get(string username, string password)
		{
			var users = new List<User>();

			users.Add( new User { Id =1, Username ="romulo.cesar",Password= "1234",Role = "employee" });
			users.Add(new User { Id = 1, Username = "maria.lima", Password = "4567", Role = "manager" });

			return users.FirstOrDefault(x => x.Username == username && x.Password == password);
		}
	}
}
