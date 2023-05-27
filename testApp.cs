using System;
using System.Timers;
using System.Text;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace HelloWorld
{
    class Hello {  

		// Registry...  
		static string keyName = @"HKEY_LOCAL_MACHINE\SOFTWARE";  
		static string subKey = @"GeneratedSalt";  
		static string valueName = "SaltData";  
		static System.Security.Cryptography.DataProtectionScope dpScope = DataProtectionScope.LocalMachine; 
	
		static void Main(string[] args)
		{
			while(true)
			{
				int i=0;
				System.Timers.Timer aTimer = new System.Timers.Timer();
				aTimer.Elapsed += new ElapsedEventHandler(OnTimedEvent);
				aTimer.Interval = 5000;
				aTimer.Enabled = true;
				Console.WriteLine("Press \'q\' to quit the sample.");
				while(Console.Read() != 'q');
				
			}
		}
		public static void StoreKey(string keyName, string subKey, string valueName, byte[] keyAsBytes, System.Security.Cryptography.DataProtectionScope dpScope)  
			{  
		 
				// Store key to protected byte array.  
				byte[] encryptedKeyPair = ProtectedData.Protect(keyAsBytes, null, dpScope);  

				// Create a security context.  
				string user = Environment.UserDomainName + "\\" + Environment.UserName; 
				Console.WriteLine("String is: {0}", user);
				RegistrySecurity security = new RegistrySecurity();  
				
				RegistryAccessRule rule = new RegistryAccessRule(user  
																, RegistryRights.FullControl  
																, InheritanceFlags.ContainerInherit  
																, PropagationFlags.None  
																, AccessControlType.Allow);  
				// Add rule to RegistrySecurity.  
				security.AddAccessRule(rule);  
				

				// Create registry key and apply security context   
				Registry.LocalMachine.CreateSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree);  

				// Write the encrypted connection string into the registry  
				Registry.SetValue(keyName + @"\" + subKey, valueName, encryptedKeyPair);  
			}  
		private static void checkDelete(string keyName)
		{
			
			using (RegistryKey key = Registry.CurrentUser.OpenSubKey(keyName, true))
			{
			if (key == null)
			{
				// Key doesn't exist. Do whatever you want to handle
				// add key with salt value in this case
			}
			else
			{
				key.DeleteValue("MyApp");
			}
			}
		}
		private static byte[] GenerateSalt ()
		{
			int saltLength = 32;
			byte[] salt = new byte[saltLength];
			var random = new RNGCryptoServiceProvider();
			
			random.GetNonZeroBytes(salt);
			
		   return salt;
	    }
		// Specify what you want to happen when the Elapsed event is raised.
		 private static void OnTimedEvent(object source, ElapsedEventArgs e)
		 {
			 Console.WriteLine("Generating Salt now!!");
			 byte[] salt = GenerateSalt();
			 string result = Encoding.Default.GetString(salt);
			 Console.WriteLine("String is: {0}", result);
			 StoreKey(keyName, subKey, valueName, salt, dpScope); 
		 }
	}
}