using System;
using System.Security.Cryptography;
using System.Text;

namespace aes_generator
{
	class MainClass
	{
		public static Tuple<string, string> CreateKeyPair()
		{
			CspParameters cspParams = new CspParameters { ProviderType = 1 };

			RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(1024, cspParams);

			string publicKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(false));
			string privateKey = Convert.ToBase64String(rsaProvider.ExportCspBlob(true));

			return new Tuple<string, string>(privateKey, publicKey);
		}

		public static byte[] Encrypt(string publicKey, string data)
		{
			CspParameters cspParams = new CspParameters { ProviderType = 1 };
			RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams);

			rsaProvider.ImportCspBlob(Convert.FromBase64String(publicKey));

			byte[] plainBytes = Encoding.UTF8.GetBytes(data);
			byte[] encryptedBytes = rsaProvider.Encrypt(plainBytes, false);

			return encryptedBytes;
		}

		public static string Decrypt(string privateKey, byte[] encryptedBytes)
		{
			CspParameters cspParams = new CspParameters { ProviderType = 1 };

			RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams);

			var privateKeyByte = Convert.FromBase64String (privateKey);

			rsaProvider.ImportCspBlob(privateKeyByte);

			byte[] plainBytes = rsaProvider.Decrypt(encryptedBytes, false);

			string plainText = Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);

			return plainText;
		}

		#region main

		public static void Main (string[] args)
		{
			// http://stackoverflow.com/questions/18850030/aes-256-encryption-public-and-private-key-how-can-i-generate-and-use-it-net
			// https://msdn.microsoft.com/zh-tw/library/system.security.cryptography.cspparameters(v=vs.110).aspx

			var key = CreateKeyPair();
			var privateKey = key.Item1;
			var publicKey = key.Item2;
			var messages = "Hello World";
			Console.WriteLine ("PublicKey => " + publicKey);
			Console.WriteLine ("Private Key => " + privateKey);

			Console.WriteLine ("Original Message is " + messages);

			var encryptMessage = Convert.ToBase64String(Encrypt(publicKey, messages));
			Console.WriteLine ("Encrypt Message => " + encryptMessage);


			var decryptMessage = Decrypt (privateKey, Convert.FromBase64String (encryptMessage));
			Console.WriteLine ("Decrypt Message => " + decryptMessage);

		}

		#endregion
	}
}
