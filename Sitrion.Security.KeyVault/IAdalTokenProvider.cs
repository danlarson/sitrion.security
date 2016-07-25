using System.Threading.Tasks;

namespace Sitrion.Security.KeyVault
{
    public interface IAdalTokenProvider
    {
        Task<string> GetToken(string authority, string resource, string scope);
    }
}