using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace FIME
{
    internal static class Injector
    {
        private static class NativeMethods
        {
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr FindWindow(string ZeroOnly, string lpWindowName);

            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool IsWow64Process([In] IntPtr processHandle, [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hHandle);

            [DllImport("kernel32.dll", ExactSpelling = true)]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

            [DllImport("kernel32.dll")]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

            [DllImport("kernel32.dll")]
            public static extern IntPtr WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

            [DllImport("kernel32.dll", ExactSpelling = true)]
            public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, FreeType dwFreeType);

            [DllImport("kernel32.dll")]
            public static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitCode);

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VirtualMemoryOperation = 0x00000008,
                VirtualMemoryRead = 0x00000010,
                VirtualMemoryWrite = 0x00000020,
                DuplicateHandle = 0x00000040,
                CreateProcess = 0x000000080,
                SetQuota = 0x00000100,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x00001000,
                Synchronize = 0x00100000
            }

            [Flags]
            public enum AllocationType
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
                Reset = 0x80000,
                Physical = 0x400000,
                TopDown = 0x100000,
                WriteWatch = 0x200000,
                LargePages = 0x20000000
            }

            [Flags]
            public enum MemoryProtection
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                ReadOnly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }

            [Flags]
            public enum FreeType
            {
                Decommit = 0x4000,
                Release = 0x8000,
            }
        }

        private static bool IsX86(IntPtr processHandle)
        {
            if (IntPtr.Size != 8)
                return true;

            bool isWow64;
            return NativeMethods.IsWow64Process(processHandle, out isWow64) && isWow64;
        }

        public static bool Inject()
        {
            var ffxiv = NativeMethods.FindWindow("FFXIVGAME", null);
            if (ffxiv == IntPtr.Zero)
                return false;
            
            int pid;
            if (NativeMethods.GetWindowThreadProcessId(ffxiv, out pid) == 0)
                return false;

            var hProc = IntPtr.Zero;
            try
            {
            	hProc = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryInformation, false, pid);

                if (hProc == IntPtr.Zero)
                {
                    hProc = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryLimitedInformation, false, pid);
                    if (hProc == IntPtr.Zero)
                        return false;
                }
            }
            finally
            {
                if (hProc != IntPtr.Zero)
                    NativeMethods.CloseHandle(hProc);
            }

            var x86 = IsX86(hProc);

            var dllPath = Path.Combine(Path.GetTempPath(), x86 ? "FIME32.dll" : "FIME64.dll");
            try
            {
            	File.WriteAllBytes(dllPath, x86 ? Properties.Resources.FIME32 : Properties.Resources.FIME64);
            }
            catch
            {
            }

            if (!File.Exists(dllPath))
                return false;

            var hKernel32 = NativeMethods.GetModuleHandle("kernel32.dll");
            if (hKernel32 == IntPtr.Zero)
                return false;

            var lpLoadLibrary = NativeMethods.GetProcAddress(hKernel32, "LoadLibraryW");
            if (lpLoadLibrary == IntPtr.Zero)
                return false;

            var hProcess = IntPtr.Zero;
            var hVAlloc = IntPtr.Zero;
            var hThread = IntPtr.Zero;
            try
            {
                hProcess = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.All, false, pid);
                if (hProcess == IntPtr.Zero)
                    return false;
                
                dllPath += "\0";
                int buffSize = Encoding.Unicode.GetByteCount(dllPath);
                var buff = Encoding.Unicode.GetBytes(dllPath);

                hVAlloc = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, new IntPtr(buffSize), NativeMethods.AllocationType.Commit, NativeMethods.MemoryProtection.ReadWrite);
                if (hVAlloc != IntPtr.Zero)
                {
                    IntPtr lpNumberOfBytesWritten;
                    if (NativeMethods.WriteProcessMemory(hProcess, hVAlloc, buff, buffSize, out lpNumberOfBytesWritten))
                    {
                        IntPtr lpThreadId;
                        hThread = NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, 0, lpLoadLibrary, hVAlloc, 0, out lpThreadId);
                        if (hThread != IntPtr.Zero)
                        {
                            NativeMethods.WaitForSingleObject(hThread, 0xFFFFFFFF);

                            int exitCode;
                            return NativeMethods.GetExitCodeThread(hThread, out exitCode) && exitCode != 0;
                        }
                    }
                }
            }
            catch
            {
                if (hThread != IntPtr.Zero)
                    NativeMethods.CloseHandle(hThread);

                if (hVAlloc != IntPtr.Zero)
                    NativeMethods.VirtualFreeEx(hProcess, hVAlloc, 0, NativeMethods.FreeType.Release);

                if (hProcess != IntPtr.Zero)
                    NativeMethods.CloseHandle(hProcess);
            }

            return false;
        }
    }
}
