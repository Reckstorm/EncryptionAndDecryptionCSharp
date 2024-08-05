using System.Security.Cryptography;
using System.Text;
using Packt.Shared;

namespace CryptographyLib;

public static class Protector
{
    private static Dictionary<string, User> Users = new Dictionary<string, User>();
    private static readonly byte[] salt = Encoding.Unicode.GetBytes("7BANANAS");
    private static readonly int iterations = 2000;

    public static string Encrypt(string plainText, string password)
    {
        byte[] encryptedBytes;
        byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);

        var aes = Aes.Create();
        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);

        aes.Key = pbkdf2.GetBytes(32);
        aes.IV = pbkdf2.GetBytes(16);

        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(plainBytes, 0, plainBytes.Length);
            }
            encryptedBytes = ms.ToArray();
        }

        return Convert.ToBase64String(encryptedBytes);
    }

    public static string Decrypt(string cryptoText, string password)
    {
        byte[] plainBytes;
        byte[] encryptedBytes = Convert.FromBase64String(cryptoText);

        var aes = Aes.Create();
        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);

        aes.Key = pbkdf2.GetBytes(32);
        aes.IV = pbkdf2.GetBytes(16);

        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(encryptedBytes, 0, encryptedBytes.Length);
            }
            plainBytes = ms.ToArray();
        }

        return Encoding.Unicode.GetString(plainBytes);
    }

    public static User Register(string username, string password)
    {
        var rng = RandomNumberGenerator.Create();

        var saltBytes = new byte[16];

        rng.GetBytes(saltBytes);

        var saltText = Convert.ToBase64String(saltBytes);

        var saltedHashedPassord = SaltAndHashPassword(password, saltText);

        var User = new User { Name = username, Salt = saltText, SaltedHashedPassword = saltedHashedPassord };
        Users.Add(User.Name, User);

        return User;
    }

    private static string SaltAndHashPassword(string password, string saltText)
    {
        var sha = SHA256.Create();
        var saltedPassword = password+saltText;
        return Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));
    }

    public static bool CheckPassword(string username, string password)
    {
        if(!Users.ContainsKey(username)) return false;
        var user = Users[username];

        var saltedHashedPassword = SaltAndHashPassword(password, user.Salt);

        return saltedHashedPassword == user.SaltedHashedPassword;
    }
}
