# Adding reference of standard .NET assemblies 
$Refs = @("C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.XML.Dll",
"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\v3.5\System.Data.Entity.dll",
"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\v3.0\System.Runtime.Serialization.dll",
"C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Runtime.Remoting.dll",
"C:\Windows\Microsoft.NET\Framework\v2.0.50727\System.Windows.Forms.dll")

$Source = @"
using System;
using System.Collections.Generic;
using System.Runtime.Remoting;
using System.Text;
using System.IO;
using EasyHook;
using System.Windows.Forms;

namespace FileMon
{
    public class FileMonInterface : MarshalByRefObject
    {
        public void IsInstalled(Int32 InClientPID)
        {
            Console.WriteLine("FileMon has been installed in target {0}.\r\n", InClientPID);
        }

        public void OnCreateFile(Int32 InClientPID, String[] InFileNames)
        {
            for (int i = 0; i < InFileNames.Length; i++)
            {
                Console.WriteLine(InFileNames[i]);
            }
        }

        public void ReportException(Exception InInfo)
        {
            Console.WriteLine("The target process has reported an error:\r\n" + InInfo.ToString());
        }

        public void Ping()
        {
        }
    }

    class Program
    {
        static String ChannelName = null;

        static void Main(string[] args)
        {
            Int32 TargetPID = 0;
            string targetExe = null;

            // Load the parameter
            while ((args.Length != 1) || !Int32.TryParse(args[0], out TargetPID) || !File.Exists(args[0]))
            {
                if (TargetPID > 0)
                {
                    break;
                }
                if (args.Length != 1 || !File.Exists(args[0]))
                {
                    Console.WriteLine();
                    Console.WriteLine("Usage: FileMon %PID%");
                    Console.WriteLine("   or: FileMon PathToExecutable");
                    Console.WriteLine();
                    Console.Write("Please enter a process Id or path to executable: ");

                    args = new string[] { Console.ReadLine() };

                    if (String.IsNullOrEmpty(args[0])) return;
                }
                else
                {
                    targetExe = args[0];
                    break;
                }
            }

            try
            {
                RemoteHooking.IpcCreateServer<FileMonInterface>(ref ChannelName, WellKnownObjectMode.SingleCall);

                string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "FileMonInject.dll");
                if (String.IsNullOrEmpty(targetExe))
                {
                    RemoteHooking.Inject(
                        TargetPID,
                        injectionLibrary,
                        injectionLibrary,
                        ChannelName);

                    Console.WriteLine("Injected to process {0}", TargetPID);
                }
                else
                {
                    RemoteHooking.CreateAndInject(targetExe, "", 0, InjectionOptions.DoNotRequireStrongName, injectionLibrary, injectionLibrary, out TargetPID, ChannelName);
                    Console.WriteLine("Created and injected process {0}", TargetPID);
                }
                Console.WriteLine("<Press any key to exit>");
                Console.ReadKey();
            }
            catch (Exception ExtInfo)
            {
                Console.WriteLine("There was an error while connecting to target:\r\n{0}", ExtInfo.ToString());
                Console.WriteLine("<Press any key to exit>");
                Console.ReadKey();
            }
        }
    }
}
"@

 $dllpath = "c:\users\public\deploy\netfx3.5\EasyHook.dll"
 $easy = [System.Reflection.Assembly]::LoadFrom($dllpath)
 $Refs = $Refs + $easy
$filemon = Add-Type -ReferencedAssemblies $Refs -TypeDefinition $Source -Language CSharp -OutputAssembly "C:\users\public\deploy\netfx3.5\filemon.exe"



$Source2 = @"
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using EasyHook;

namespace FileMonInject
{
    public class Main : EasyHook.IEntryPoint
    {

        // The CharSet must match the CharSet of the corresponding PInvoke signature
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        FileMon.FileMonInterface Interface;
        LocalHook CreateFileHook;
        LocalHook LstrcmpHook;
        LocalHook FindNextFileHook;
        Stack<String> Queue = new Stack<String>();
        Stack<String> FFFQueue = new Stack<String>();

        public Main(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // connect to host...
            Interface = RemoteHooking.IpcConnectClient<FileMon.FileMonInterface>(InChannelName);

            Interface.Ping();
        }

        public void Run(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // install hook...
            try
            {

                CreateFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                    new DCreateFile(CreateFile_Hooked),
                    this);

                CreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

                LstrcmpHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "lstrcmpW"),
                    new DLstrcmp(Lstrcmp_Hooked),
                    this);

                LstrcmpHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

                // FindNextFile
                FindNextFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "FindNextFileW"),
                    new DFindNextFile(FindNextFile_Hooked),
                    this);

                FindNextFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });


            }
            catch (Exception ExtInfo)
            {
                Interface.ReportException(ExtInfo);

                return;
            }

            Interface.IsInstalled(RemoteHooking.GetCurrentProcessId());

            RemoteHooking.WakeUpProcess();

            // wait for host process termination...
            try
            {
                while (true)
                {
                    Thread.Sleep(500);



                    // transmit newly monitored file accesses...
                    if (Queue.Count > 0)
                    {
                        String[] Package = null;

                        lock (Queue)
                        {
                            Package = Queue.ToArray();

                            Queue.Clear();
                        }

                        Interface.OnCreateFile(RemoteHooking.GetCurrentProcessId(), Package);
                    }
                    else
                        Interface.Ping();

                }
            }
            catch
            {
                // Ping() will raise an exception if host is unreachable
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DCreateFile(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFile(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile);

        // this is where we are intercepting all file accesses!
        static IntPtr CreateFile_Hooked(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile)
        {
            
            try
            {
                Main This = (Main)HookRuntimeInfo.Callback;

                lock (This.Queue)
                {
                    This.Queue.Push("[" + RemoteHooking.GetCurrentProcessId() + ":" + 
                        RemoteHooking.GetCurrentThreadId() +  "]: \"" + InFileName + "\"");
                }
            }
            catch
            {
            }

            // call original API...
            return CreateFile(
                InFileName,
                InDesiredAccess,
                InShareMode,
                InSecurityAttributes,
                InCreationDisposition,
                InFlagsAndAttributes,
                InTemplateFile);
        }

        // FindNextFileStuff
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
        CharSet = CharSet.Unicode,
        SetLastError = true)]
        delegate bool DFindNextFile(
            IntPtr hFindFIle,
            out WIN32_FIND_DATA lpFindFileData);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA
           lpFindFileData);

        // this is where we are intercepting all file accesses!
        static bool FindNextFile_Hooked(
            IntPtr hFindFile,
            out WIN32_FIND_DATA lpFindFileData)
        {

            try
            {
                Main This = (Main)HookRuntimeInfo.Callback;
                lock (This.FFFQueue)
                {
                    This.FFFQueue.Push("[" + RemoteHooking.GetCurrentProcessId() + ":" +
                        RemoteHooking.GetCurrentThreadId() + "]: \"" + "Intercepted dir!\"");
                }

            }
            catch
            {
            }

            // call original API...
            bool File = FindNextFile(hFindFile, out lpFindFileData);
            if (lstrcmp(lpFindFileData.cFileName, "secret.txt") == 0)                     // FindNextFile will stop when it encounters secret.txt.
            {
                // Act like nothing happened.
                bool NextFile = FindNextFile(hFindFile, out lpFindFileData);
                File = NextFile;
            }
            return File;

        }

        // DLstrcmp stuff
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
        CharSet = CharSet.Unicode,
        SetLastError = true)]
        delegate int DLstrcmp(string lpString1, string lpString2);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern int lstrcmp(string lpString1, string lpString2);

        // this is where we are intercepting all file accesses!
        static int Lstrcmp_Hooked(string lpString1, string lpString2)
        {

            try
            {
                Main This = (Main)HookRuntimeInfo.Callback;
            }
            catch
            {
            }

                // call original API...
                return lstrcmp(lpString1, lpString2);
        }

    }
}


"@

 $dllpath =  "C:\users\public\deploy\netfx3.5\filemon.exe"
 $filemon = [System.Reflection.Assembly]::LoadFrom($dllpath)
 $Refs = $Refs + $filemon
Add-Type -ReferencedAssemblies $Refs -TypeDefinition $Source2 -Language CSharp -OutputAssembly "c:\users\public\deploy\netfx3.5\filemoninject.dll"