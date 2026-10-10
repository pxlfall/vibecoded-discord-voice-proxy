using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace DiscordProxyInstaller
{
    internal class Discord
    {
        public static bool Exists()
        {
            return Directory.Exists(GetRootDirectory()) && File.Exists(Path.Join(GetAppDirectory(), "Discord.exe"));
        }

        public static bool IsX64()
        {
            using var reader = new BinaryReader(File.OpenRead(Path.Join(GetAppDirectory(), "Discord.exe")));
            if (reader.BaseStream.Length < 64 || reader.ReadUInt16() != 0x5A4D) return false;
            reader.BaseStream.Position = 60;
            var pe = reader.ReadInt32();
            if (pe < 0 || pe + 6L > reader.BaseStream.Length) return false;
            reader.BaseStream.Position = pe;
            return reader.ReadUInt32() == 0x00004550 && reader.ReadUInt16() == 0x8664;
        }

        public static string GetRootDirectory()
        {
            var customRoot = Environment.GetEnvironmentVariable("DISCORD_PROXY_ROOT");
            if (!string.IsNullOrWhiteSpace(customRoot)) return Path.GetFullPath(customRoot);
            return Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Discord");
        }

        public static string GetAppDirectory()
        {
            var root = GetRootDirectory();
            if (!Directory.Exists(root)) return "";
            var result = "";

            foreach (var item in Directory.GetDirectories(root))
            {
                var dir = Path.GetFileName(item);
                if (dir.StartsWith("app-"))
                {
                    var version = dir.Split("app-")[1];
                    if (Version.TryParse(version, out var parsed) && (result == "" || new Version(result).CompareTo(parsed) < 0))
                    {
                        result = version;
                    }
                }
            }

            return result == "" ? "" : Path.Join(root, "app-" + result);
        }

        public static void Install(string host, string port, string login = "", string password = "")
        {
            var appDir = GetAppDirectory();

            var backupDir = Path.Join(appDir, "discord-proxy-backup");
            if (!Directory.Exists(backupDir))
            {
                Directory.CreateDirectory(backupDir);
                foreach (var name in new[] { "DWrite.dll", "force-proxy.dll", "proxy.txt" })
                    if (File.Exists(Path.Join(appDir, name)))
                        File.Copy(Path.Join(appDir, name), Path.Join(backupDir, name));
            }

            WriteResourceToFile("DWrite.dll", Path.Join(appDir, "DWrite.dll"));
            WriteResourceToFile("force-proxy.dll", Path.Join(appDir, "force-proxy.dll"));

            var lines = new string[] {
                "SOCKS5_PROXY_ADDRESS=" + host,
                "SOCKS5_PROXY_PORT=" + port,
                "SOCKS5_PROXY_LOGIN=" + login,
                "SOCKS5_PROXY_PASSWORD=" + password,
                "SOCKS5_PROXY_DNS=1",
                "SOCKS5_DNS_LOG=1",
            };
            File.WriteAllLines(Path.Join(appDir, "proxy.txt"), lines);
        }

        public static void Run()
        {
            var appDir = GetAppDirectory();
            var exePath = Path.Combine(appDir, "Discord.exe");

            Process process = new Process();
            process.StartInfo.FileName = exePath;
            process.StartInfo.WorkingDirectory = appDir;
            process.Start();
        }

        public static void InstallAndRun(string host, string port, string login = "", string password = "")
        {
            Kill();
            Install(
              host,
              port,
              login,
              password
            );
            Run();
        }

        public static bool IsInstalled()
        {
            return File.Exists(Path.Join(GetAppDirectory(), "DWrite.dll"));
        }

        public static void Uninstall()
        {
            Kill();
            var appDir = GetAppDirectory();
            var backupDir = Path.Join(appDir, "discord-proxy-backup");
            foreach (var name in new[] { "DWrite.dll", "force-proxy.dll", "proxy.txt" })
            {
                File.Delete(Path.Join(appDir, name));
                if (File.Exists(Path.Join(backupDir, name)))
                    File.Copy(Path.Join(backupDir, name), Path.Join(appDir, name));
            }
            if (Directory.Exists(backupDir)) Directory.Delete(backupDir, true);
        }

        public static void Kill()
        {
            foreach (var process in Process.GetProcessesByName("Discord"))
            {
                process.Kill();
                process.WaitForExit(10000);
            }

            Thread.Sleep(1000);
        }

        private static void WriteResourceToFile(string resourceName, string fileName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (var resource = assembly.GetManifestResourceStream(assembly.GetName().Name + "." + resourceName)
                ?? throw new InvalidOperationException("Missing installer resource: " + resourceName))
            {
                using (var file = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    resource.CopyTo(file);
                }
            }
        }
    }
}
