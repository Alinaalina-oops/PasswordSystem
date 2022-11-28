using Microsoft.EntityFrameworkCore;
using PasswordSystem.Models;

namespace PasswordSystem.Db
{
    public class MyDbContext : DbContext
    {
        public MyDbContext() : base()
        {
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured) 
            {
                optionsBuilder.UseSqlServer(@"Server=DESKTOP-RBPOQG7\SQLEXPRESS; Database=PasswordSystem; Trusted_Connection=True;");
            }
        }

        public DbSet<User> Users { get; set; }
    }
}
