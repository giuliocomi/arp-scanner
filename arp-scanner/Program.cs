using System.Runtime.InteropServices;
using System.Net;
using System.Collections.Generic;
using System.Threading;
using System.IO;
using System;
using System.Text.RegularExpressions;
using System.Reflection;

namespace ArpScanner
{
    public class ARPScan
    {

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        static uint macAddrLen = (uint)new byte[6].Length;
        private const string separator = "|";
        private static List<string> macList = new List<string>();

        private static string MacAddresstoString(byte[] macAdrr)
        {
            string macString = BitConverter.ToString(macAdrr);
            return macString.ToUpper();
        }

        private static void ThreadedARPRequest(string ipString, ref List<Tuple<string, string, string>> result)
        {
            IPAddress ipAddress = new IPAddress(0);
            byte[] macAddr = new byte[6];
            string deviceInfo = "";

            try
            {
                ipAddress = IPAddress.Parse(ipString);
                SendARP((int)BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);
                if (MacAddresstoString(macAddr) != "00-00-00-00-00-00")
                {
                    string macString = MacAddresstoString(macAddr);
                    result.Add(new Tuple<string, string, string>(ipString, macString, GetDeviceInfoFromMac(macString)));
                }
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(string.Join(": ", "Invalid IP read from file", ipString));
                Console.ResetColor();
            }
        }

        private static string GetDeviceInfoFromMac(string mac)
        {
            string pattern = mac.Substring(0, 8) + ".*";

            try
            {
                foreach (var entry in macList)
                {
                    Match found = Regex.Match(entry, pattern);
                    if (found.Success)
                    {
                        return found.Value.Split(separator[0])[1];
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e); //TODO
            }

            return "Unknown";
        }

        public static List<Tuple<string, string, string>> CheckStatus(List<string> ipList, int timeout)
        {
            List<Tuple<string, string, string>> result = new List<Tuple<string, string, string>>();
            byte[] macAddr = new byte[6];

            try
            {
                foreach (string ipString in ipList)
                {
                    Thread threadARP = new Thread(() => ThreadedARPRequest(ipString, ref result));
                    threadARP.Start();
                }
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(e); //TODO
                Console.ResetColor();
            }

            Thread.Sleep(timeout);
            return result;
        }

        private static List<string> LoadListFromFile(string filename)
        {
            List<string> list = new List<string>();

            try
            {
                foreach (var ipAddress in File.ReadAllLines(filename))
                    list.Add(ipAddress.Trim());
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error reading file.");
                Console.ResetColor();
                return new List<string>();
            }
            return list;
        }

        public static void Main(string[] args)
        {
            string ipFile = "";
            int timeout = 4000;
            List<Tuple<string, string, string>> output = new List<Tuple<string, string, string>>();
            macList = LoadListFromFile("maclist.txt");

            if (args.Length > 0)
            {
                ipFile = args[0].ToString();
                if (args.Length > 1)
                {
                    try
                    {
                        timeout = (int.Parse(args[1]) > 0) ? int.Parse(args[1]) : timeout;
                    }
                    catch
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Cannot read timeout value.");
                    }
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("Starting ARP scan");
                Console.ResetColor();

                output = CheckStatus(LoadListFromFile(ipFile), timeout);

                Console.WriteLine(String.Format("{0,-20} | {1,-20} | {2,-20}", "IP", "MAC", "InterfaceDetails"));

                foreach (var entry in output)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(String.Format("{0,-20} | {1,-20} | {2,-20}", entry.Item1, entry.Item2, entry.Item3));
                    Console.ResetColor();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Please provide the text file containing the IP list for the ARP scan.");
                Console.WriteLine("Usage: arpscanner.exe [FILE_OF_IPv4_ADDRESSES] [TIMEOUT_IN_MILLISECONDS]");
                Console.ResetColor();
            }
            return;
        }
    }
}