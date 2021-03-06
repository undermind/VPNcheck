﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Diagnostics;
//using System.Threading.Tasks;
using System.Security.Principal;
using System.Management;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;

using System.Net.Http;

namespace VPNcheck
{
    /*
    class OVpnConfig
    {
        public 
    }
    */
    class Program
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr tokenHandle, TokenInformationClass tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

        /// <summary>
        /// Passed to <see cref="GetTokenInformation"/> to specify what
        /// information about the token to return.
        /// </summary>
        enum TokenInformationClass
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUiAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        /// <summary>
        /// The elevation type for a user token.
        /// </summary>
        enum TokenElevationType
        {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        public enum IsUserAdministratorState { Err = -1, OrdinaryUser = 0, CanElevateAdmin = 1, Admin = 2 };
        public static IsUserAdministratorState IsUserAdministrator()
        {
            try
            {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator)) return IsUserAdministratorState.Admin;
                if (Environment.OSVersion.Platform != PlatformID.Win32NT || Environment.OSVersion.Version.Major < 6)
                {
                    // Operating system does not support UAC; skipping elevation check.
                    return 0;
                }
                int tokenInfLength = Marshal.SizeOf(typeof(int));
                IntPtr tokenInformation = Marshal.AllocHGlobal(tokenInfLength);

                try
                {
                    var token = user.Token;
                    var result = GetTokenInformation(token, TokenInformationClass.TokenElevationType, tokenInformation, tokenInfLength, out tokenInfLength);

                    if (!result)
                    {
                        var exception = Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error());
                        throw new InvalidOperationException("Couldn't get token information", exception);
                    }

                    var elevationType = (TokenElevationType)Marshal.ReadInt32(tokenInformation);

                    switch (elevationType)
                    {
                        case TokenElevationType.TokenElevationTypeDefault:
                            // TokenElevationTypeDefault - User is not using a split token, so they cannot elevate.
                            return IsUserAdministratorState.OrdinaryUser;
                        case TokenElevationType.TokenElevationTypeFull:
                            // TokenElevationTypeFull - User has a split token, and the process is running elevated. Assuming they're an administrator.
                            return IsUserAdministratorState.Admin;
                        case TokenElevationType.TokenElevationTypeLimited:
                            // TokenElevationTypeLimited - User has a split token, but the process is not running elevated. Assuming they're an administrator.
                            return IsUserAdministratorState.CanElevateAdmin;
                        default:
                            // Unknown token elevation type.
                            return IsUserAdministratorState.Err;
                    }
                }
                finally
                {
                    if (tokenInformation != IntPtr.Zero) Marshal.FreeHGlobal(tokenInformation);
                }

            }
            catch (Exception)
            {
                return IsUserAdministratorState.Err;
            }
        }

        private static readonly HttpClient HTTPClient = new HttpClient();
        private static readonly string HTTPRequest = "https://belyankin.ru/vpn.php";

        public static bool AntivirusInstalled()
        {

            string wmipathstr = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM AntivirusProduct");
                ManagementObjectCollection instances = searcher.Get();
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    /*var values = new Dictionary<string, string>
{
{ "displayName", queryObj["displayName"].ToString() },
{ "productState", int.Parse(queryObj["productState"].ToString()).ToString("X") }
};*/
                   

                    Console.WriteLine("displayName: {0}", queryObj["displayName"]);
                    ///Console.WriteLine("up2date: {0}", queryObj["productUptoDate"]);
                    ///Console.WriteLine("enabled: {0}", queryObj["onAccessScanningEnabled"]);
                    //Console.WriteLine("instanceGuid: {0}", queryObj["instanceGuid"]);
                    Console.WriteLine("pathToSignedProductExe: {0}", queryObj["pathToSignedProductExe"]);
                    Console.WriteLine("productState: {0}", int.Parse(queryObj["productState"].ToString()
                        ).ToString("X"));
                    HTTPClient.DefaultRequestHeaders.Add("av", queryObj["displayName"].ToString());
                    HTTPClient.DefaultRequestHeaders.Add("av-info", int.Parse(queryObj["productState"].ToString()).ToString("X"));



                }
                return instances.Count > 0;
            }

            catch (Exception e)
            {
                Console.WriteLine("# {0}", e.Message);
            }

            return false;
        }

        public static bool FirewallInstalled()
        {

            string wmipathstr = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM FirewallProduct");
                ManagementObjectCollection instances = searcher.Get();
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    Console.WriteLine("displayName: {0}", queryObj["displayName"]);
                    
                    //Console.WriteLine("instanceGuid: {0}", queryObj["instanceGuid"]);
                    Console.WriteLine("pathToSignedProductExe: {0}", queryObj["pathToSignedProductExe"]);
                    Console.WriteLine("productState: {0}", int.Parse(queryObj["productState"].ToString()
                        ).ToString("X"));
                    HTTPClient.DefaultRequestHeaders.Add("fw", queryObj["displayName"].ToString());
                    HTTPClient.DefaultRequestHeaders.Add("fw-info", int.Parse(queryObj["productState"].ToString()).ToString("X"));
                }
                return instances.Count > 0;
            }

            catch (Exception e)
            {
                Console.WriteLine("# {0}", e.Message);
            }

            return false;
        }


        public static bool AntiSpywareProductInstalled()
        {

            string wmipathstr = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM AntiSpywareProduct");
                ManagementObjectCollection instances = searcher.Get();
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    Console.WriteLine("displayName: {0}", queryObj["displayName"]);
                    //Console.WriteLine("instanceGuid: {0}", queryObj["instanceGuid"]);
                    Console.WriteLine("pathToSignedProductExe: {0}", queryObj["pathToSignedProductExe"]);
                    Console.WriteLine("productState: {0}", int.Parse(queryObj["productState"].ToString()
                        ).ToString("X"));
                    HTTPClient.DefaultRequestHeaders.Add("spy", queryObj["displayName"].ToString());
                    HTTPClient.DefaultRequestHeaders.Add("spy-info", int.Parse(queryObj["productState"].ToString()).ToString("X"));
                }
                return instances.Count > 0;
            }

            catch (Exception e)
            {
                Console.WriteLine("# {0}", e.Message);
            }

            return false;
        }
        public static bool CheckOpenVPNudp(string ip, int port)
        {
            IPEndPoint RemoteEndPoint = new IPEndPoint(IPAddress.Parse(ip), port);
            return CheckOpenVPNudp(RemoteEndPoint);
        }

        public static bool CheckOpenVPNudp(IPEndPoint RemoteEndPoint)
        {
            Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            byte[] data = { 56, 1, 0, 0, 0, 0, 0, 0, 0 }; //OpenVPN client welcome datagram
            server.SendTo(data, data.Length, SocketFlags.None, RemoteEndPoint);
            server.ReceiveTimeout = 15000; //15 seconds
            EndPoint Remote = (EndPoint)(RemoteEndPoint);
            try
            {
                byte[] answer = new byte[1024];
                int recv = server.ReceiveFrom(answer, ref Remote);
                //Console.WriteLine("Message received from {0}:", Remote.ToString());
                //Console.WriteLine(System.Text.Encoding.ASCII.GetString(answer, 0, recv));
                return true;

            }
            catch (Exception e)
            {
                Console.WriteLine("# {0}", e.Message);
                return false;
            }

        }

        public static bool CheckOpenVPNtcp(IPEndPoint target)
        {
            return CheckOpenVPNtcp(target.Address.ToString(), target.Port);
        }
        public static bool CheckOpenVPNtcp(string hostname, int port)
        {
            using (var tcpClient = new TcpClient())
            {
                try
                {
                    tcpClient.Connect(hostname, port);
                    return tcpClient.Connected;

                }
                catch (Exception e)
                {
                    Console.WriteLine("# {0}", e.Message);
                    return false;
                }
            }
        }

        static int CompareValueLong(KeyValuePair<string, long> a, KeyValuePair<string, long> b)
        {
            return a.Value.CompareTo(b.Value);
        }



        static void CheckOVPNconfig(string configfile)
        {
            try
            {
                bool client = false;
                ProtocolType proto = ProtocolType.Unspecified;
                IPEndPoint RemoteEndPoint = new IPEndPoint(0, 0);
                StringBuilder optconfig = new StringBuilder();
                var optremotes = new List<KeyValuePair<string, long>>();
                using (StreamReader conf = File.OpenText(configfile))
                {
                    string line = "";
                    do
                    {
                        line = conf.ReadLine();
                        //if (!line.StartsWith("#")) Console.WriteLine(line);
                        if ((!line.StartsWith("#")) && (!line.Contains("remote ")))
                        {
                            Console.WriteLine(line);
                            optconfig.AppendLine(line);
                        }
                        if (line.StartsWith("client")) client = true;
                        if (line.StartsWith("proto"))
                        {
                            proto = line.Contains("udp") ? ProtocolType.Udp : ProtocolType.Tcp;
                        }
                        if (line.StartsWith("remote "))
                        {
                            string host = line.Split(' ')[1];
                            int port = int.TryParse(line.Split(' ')[2], out port) ? int.Parse(line.Split(' ')[2]) : 1194;
                            UriHostNameType hnt = Uri.CheckHostName(host);

                            switch (hnt)
                            {
                                case UriHostNameType.Unknown:
                                    break;
                                case UriHostNameType.Basic:
                                    break;
                                case UriHostNameType.Dns:
                                    // TODO : Check all address from gethostentry
                                    RemoteEndPoint = new IPEndPoint(Dns.GetHostEntry(host).AddressList[0], port);
                                    break;
                                case UriHostNameType.IPv4:
                                    RemoteEndPoint = new IPEndPoint(IPAddress.Parse(host), port);
                                    break;
                                case UriHostNameType.IPv6:
                                    Console.WriteLine("IPv6!?");
                                    break;
                                default:
                                    break;
                            }

                            if (client && (RemoteEndPoint.Port != 0))
                            {
                                string tmpcaption = Console.Title;
                                Console.Title = string.Format("!!! connect to {0} ({2} {3}) via {1} !!!", RemoteEndPoint, proto, host, hnt);

                                /* Disable traceroute
                                 
                                IEnumerable<IPAddress> targettrace = GetTraceRoute(host);
                                Console.Write("# traceroute:");
                                int stepcount = 0;
                                foreach (IPAddress ipstep in targettrace)
                                {
                                    Console.Write(" {0} >", ipstep);stepcount++;
                                }
                                Console.WriteLine(" Total {0} hops", stepcount);
                                */

                                const int timeout = 10000;
                                const int maxTTL = 30;
                                const int bufferSize = 32;
                                Ping pingSender = new Ping();
                                PingOptions options = new PingOptions(maxTTL, true);

                                byte[] buffer = new byte[bufferSize];
                                new Random().NextBytes(buffer);
                                string pingrepl;
                                PingReply reply = pingSender.Send(host, timeout, buffer, options);
                                if (reply.Status == IPStatus.Success)
                                {
                                    pingrepl = string.Format("{0} {1} rtt:{2}ms rttl:{3}", reply.Address, reply.Status, reply.RoundtripTime, reply.Options.Ttl);
                                    /*
                                                    Console.WriteLine("Address: {0}", reply.Address.ToString());
                                                    Console.WriteLine("RoundTrip time: {0}", reply.RoundtripTime);
                                                    Console.WriteLine("Time to live: {0}", reply.Options.Ttl);
                                                    Console.WriteLine("Don't fragment: {0}", reply.Options.DontFragment);
                                                    Console.WriteLine("Buffer size: {0}", reply.Buffer.Length);
                                                */

                                    optremotes.Add(new KeyValuePair<string, long>(line, reply.RoundtripTime));
                                }
                                else
                                {
                                    pingrepl = string.Format("{0} {1}", reply.Address, reply.Status);
                                    optremotes.Add(new KeyValuePair<string, long>(line, long.MaxValue));
                                }

                                switch (proto)
                                {
                                    case ProtocolType.Tcp:
                                        Console.WriteLine("#{1} {0}#ping {3}\n{2}", CheckOpenVPNtcp(RemoteEndPoint) ? "OK" + Environment.NewLine : "FAILED" + Environment.NewLine + "#", RemoteEndPoint, line, pingrepl);
                                        break;
                                    case ProtocolType.Udp:
                                        Console.WriteLine("#{1} {0}#ping {3}\n{2} ", CheckOpenVPNudp(RemoteEndPoint) ? "OK" + Environment.NewLine : "FAILED" + Environment.NewLine + "#", RemoteEndPoint, line, pingrepl);
                                        break;
                                    default:
                                        break;
                                }
                                Console.Title = tmpcaption;
                            }
                        }
                    } while (!conf.EndOfStream);
                    //bring optimized togeter
                    optremotes.Sort(CompareValueLong);
                    foreach (KeyValuePair<string, long> orm in optremotes)
                    {
                        optconfig.AppendLine(string.Format("#ping {1}{2}{0}", orm.Key, orm.Value == long.MaxValue ? "TimeOut" : orm.Value.ToString(), Environment.NewLine));
                        //Console.WriteLine("{0} => {1}", orm.Key, orm.Value==long.MaxValue?"TimeOut":orm.Value.ToString());    
                    }
                    
                }



                Console.WriteLine("###########################################################");
                Console.WriteLine(optconfig.ToString());
                Console.WriteLine("###########################################################");
                Console.WriteLine("Write new version to file?");
                char answ;
                do
                {
                    answ = Console.ReadKey().KeyChar;
                } while (!char.IsLetter(answ));
                if (char.ToUpper(answ)== 'Y')
                {
                    //backups always made backups
                    Console.WriteLine("copy {0} to {1}", configfile, Path.ChangeExtension(configfile, ".old"));
                    try
                    {
                        System.IO.File.Copy(configfile, Path.ChangeExtension(configfile, ".old"));
                    }
                    catch (Exception e)
                    {

                        Console.WriteLine(e.Message);
                    }

                    using (StreamWriter sw = new StreamWriter(configfile, false))
                    {
                        sw.Write(optconfig.ToString()); sw.Close();
                    }
                    Console.WriteLine("Done");

                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
}

public static bool OpenVPNisInstalled()
{
    string ovpnver = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenVPN", "DisplayName", "Open VPN not installed");
    Console.WriteLine(ovpnver);

    RegistryKey ovpn = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenVPN-GUI", false); //old behavior
    if (ovpn == null) ovpn = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OpenVPN", false);
    if (ovpn == null) return false;
    string ovpnexe = (string)ovpn.GetValue("exe_path", null);
    bool result = System.IO.File.Exists(ovpnexe);
    if (result)
    {
        string confdir = (string)ovpn.GetValue("config_dir", null);
        string confext = (string)ovpn.GetValue("config_ext", null);
        foreach (string finf in System.IO.Directory.GetFiles(confdir, "*." + confext))
        {
            Console.WriteLine(finf);
            CheckOVPNconfig(finf);
        }
        string userfolder = System.Environment.GetEnvironmentVariable("USERPROFILE");
        Console.WriteLine("Trying user folder {0}", userfolder);
        bool isuserconfigexist = System.IO.Directory.Exists(userfolder + "\\OpenVPN\\config");
        if (isuserconfigexist)
        {
            foreach (string finf in System.IO.Directory.GetFiles(userfolder + "\\OpenVPN\\config", "*." + confext))
            {
                Console.WriteLine(finf);
                CheckOVPNconfig(finf);
            }

        }

    }

    return result;

}


public static IEnumerable<IPAddress> GetTraceRoute(string hostname)
{
    // following are the defaults for the "traceroute" command in unix.
    const int timeout = 10000;
    const int maxTTL = 30;
    const int bufferSize = 32;

    byte[] buffer = new byte[bufferSize];
    new Random().NextBytes(buffer);
    Ping pinger = new Ping();

    for (int ttl = 1; ttl <= maxTTL; ttl++)
    {
        PingOptions options = new PingOptions(ttl, true);
        PingReply reply = pinger.Send(hostname, timeout, buffer, options);

        if (reply.Status == IPStatus.TtlExpired)
        {
            // TtlExpired means we've found an address, but there are more addresses
            yield return reply.Address;
            continue;
        }
        if (reply.Status == IPStatus.TimedOut)
        {
            // TimedOut means this ttl is no good, we should continue searching
            Console.Write(" * > ");
            continue;
        }
        if (reply.Status == IPStatus.Success)
        {
            // Success means the tracert has completed
            yield return reply.Address;
        }

        // if we ever reach here, we're finished, so break
        break;
    }
}

static void Main(string[] args)
{
    IsUserAdministratorState admstate = IsUserAdministrator();
    Console.WriteLine(string.Format("***We are {0}***", admstate.ToString()));
    if (admstate != IsUserAdministratorState.Admin) Console.WriteLine("Warning!!!\nWe should have an Administrator rights to properly run OpenVPN");
    if (admstate.Equals(IsUserAdministratorState.CanElevateAdmin))
    {
        Console.WriteLine("Run OpenVPN as Administrator");
        ProcessStartInfo proc = new ProcessStartInfo();
        proc.UseShellExecute = true;
        proc.WorkingDirectory = Environment.CurrentDirectory;
        proc.FileName = Process.GetCurrentProcess().MainModule.FileName;
        proc.Verb = "runas";

        try
        {
            Process.Start(proc);
            return;
        }
        catch
        {
            // The user refused the elevation.
            // Do nothing and return directly ...
            //return;
            Console.WriteLine("Elevation failed!");
        }

        //return;  // Quit itself

    }
            HTTPClient.DefaultRequestHeaders.Add("username", Environment.UserName);
            HTTPClient.DefaultRequestHeaders.Add("hostname", Environment.MachineName);
            Console.WriteLine("***Antivirus:");
    AntivirusInstalled();
    Console.WriteLine("***Firewall:");
    FirewallInstalled();
    Console.WriteLine("***AntiSpywareProduct:");
    AntiSpywareProductInstalled();

            HTTPClient.PostAsync(HTTPRequest, new StringContent(""));
    Console.WriteLine("***OpenVPN");
    OpenVPNisInstalled();
    Console.Title = "[DONE] Hit Enter to exit";
    Console.ReadLine();
}
    }
}
/*
 * Examples of results that seem to prove the above logic:-
 Kasper
41000 вкл
42000 выкл


AVG Internet Security 2012 (from antivirusproduct WMI)

262144 (040000) = disabled and up to date

266240 (041000) = enabled and up to date

AVG Internet Security 2012 (from firewallproduct WMI)

266256 (041010) = firewall enabled - (last two blocks not relevant it seems for firewall)

262160 (040010) = firewall disabled - (last two blocks not relevant it seems for firewall)

Windows Defender

393472 (060100) = disabled and up to date

397584 (061110) = enabled and out of date

397568 (061100) = enabled and up to date

Microsoft Security Essentials

397312 (061000) = enabled and up to date

393216 (060000) = disabled and up to date


 */
