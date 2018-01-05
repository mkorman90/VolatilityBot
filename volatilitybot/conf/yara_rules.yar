rule Winsock__WSA : Sockets Winsock {
    meta:
        weight = 1
    strings:
        $WSASocket ="WSASocket"
        $WSASend ="WSASend"
        $WSARecv ="WSARecv"
        $WSAConnect ="WSAConnect"
        $WSAIoctl ="WSAIoctl"
    condition:
        any of them
}

rule Winsock__Generic : Sockets Winsock {
    meta:
        weight = 1
    strings:
        $ ="socket"
        $ ="send"
        $ ="recv"
        $ ="connect"
        $ ="ioctlsocket"
        $ ="closesocket"
    condition:
        any of them
}

rule HostQuery__Peer : Sockets HostQuery {
    meta:
        weight = 1
    strings:
        $ ="getpeername"
    condition:
        any of them
}

rule HostQuery__ByName : Sockets HostQuery {
    meta:
        weight = 1
    strings:
        $ ="gethostbyname"
    condition:
        any of them
}

rule HostQuery__ByAddr : Sockets HostQuery {
    meta:
        weight = 1
    strings:
        $ ="gethostbyaddr"
    condition:
        any of them
}

rule SocketCalls__Winsock_Address_Conversion : Sockets SocketCalls {
    meta:
        weight = 1
    strings:
        $ ="inet_addr"
        $ ="inet_ntoa"
        $ ="htons"
        $ ="htonl"
    condition:
        any of them
}

rule SocketCalls__Advanced_WSA_Winsock : Sockets SocketCalls {
    meta:
        weight = 1
    strings:
        $ ="WSAEnumNetworkEvents"
        $ ="WSAAsync"
        $ ="WSAEnumNameSpaceProviders"
    condition:
        any of them
}
rule DebuggerCheck__API : AntiDebug DebuggerCheck {
    meta:
        weight = 1
    strings:
        $ ="IsDebuggerPresent"
    condition:
        any of them
}

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
    meta:
        weight = 1
    strings:
        $ ="IsDebugged"
    condition:
        any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
    meta:
        weight = 1
    strings:
        $ ="NtGlobalFlags"
    condition:
        any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
    meta:
        weight = 1
    strings:
        $ ="QueryInformationProcess"
    condition:
        any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
    meta:
        weight = 1
    strings:
        $ ="CheckRemoteDebuggerPresent"
    condition:
        any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
    meta:
        weight = 1
    strings:
        $ ="SetInformationThread"
    condition:
        any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
    meta:
        weight = 1
    strings:
        $ ="DebugActiveProcess"
    condition:
        any of them
}

rule DebuggerTiming__PerformanceCounter : AntiDebug DebuggerTiming {
    meta:
        weight = 1
    strings:
        $ ="QueryPerformanceCounter"
    condition:
        any of them
}

rule DebuggerTiming__Ticks : AntiDebug DebuggerTiming {
    meta:
        weight = 1
    strings:
        $ ="GetTickCount"
    condition:
        any of them
}

rule DebuggerOutput__String : AntiDebug DebuggerOutput {
    meta:
        weight = 1
    strings:
        $ ="OutputDebugString"
    condition:
        any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerException__UnhandledFilter : AntiDebug DebuggerException {
    meta:
        weight = 1
    strings:
        $ ="SetUnhandledExceptionFilter"
    condition:
        any of them
}

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
    meta:
        weight = 1
    strings:
        $ ="GenerateConsoleCtrlEvent"
    condition:
        any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
    meta:
        weight = 1
    strings:
        $ ="SetConsoleCtrlHandler"
    condition:
        any of them
}

///////////////////////////////////////////////////////////////////////////////
rule ThreadControl__Context : AntiDebug ThreadControl {
    meta:
        weight = 1
    strings:
        $ ="SetThreadContext"
    condition:
        any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
    meta:
        weight = 1
    strings:
        $ ="__invoke__watson"
    condition:
        any of them
}

rule SEH__v3 : AntiDebug SEH {
    meta:
        weight = 1
    strings:
        $ = "____except__handler3"
        $ = "____local__unwind3"
    condition:
        any of them
}

rule SEH__v4 : AntiDebug SEH {
    // VS 8.0+
    meta:
        weight = 1
    strings:
        $ = "____except__handler4"
        $ = "____local__unwind4"
        $ = "__XcptFilter"
    condition:
        any of them
}

rule SEH__vba : AntiDebug SEH {
    meta:
        weight = 1
    strings:
        $ = "vbaExceptHandler"
    condition:
        any of them
}

rule SEH__vectored : AntiDebug SEH {
    meta:
        weight = 1
    strings:
        $ = "AddVectoredExceptionHandler"
        $ = "RemoveVectoredExceptionHandler"
    condition:
        any of them
}

///////////////////////////////////////////////////////////////////////////////
// Patterns
rule DebuggerPattern__RDTSC : AntiDebug DebuggerPattern {
    meta:
        weight = 1
    strings:
        $ = {0F 31}
    condition:
        any of them
}

rule DebuggerPattern__CPUID : AntiDebug DebuggerPattern {
    meta:
        weight = 1
    strings:
        $ = {0F A2}
    condition:
        any of them
}

rule DebuggerPattern__SEH_Saves : AntiDebug DebuggerPattern {
    meta:
        weight = 1
    strings:
        $ = {64 ff 35 00 00 00 00}
    condition:
        any of them
}

rule DebuggerPattern__SEH_Inits : AntiDebug DebuggerPattern {
    meta:
        weight = 1
    strings:
        $ = {64 89 25 00 00 00 00}
    condition:
        any of them
}
rule RTTI__enabled : Compiler RTTI {
    meta:
        weight = 1
    strings:
        $ ="run-time check failure #" nocase
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_5_0 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ ="msvbvm50"
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_6_0 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ ="msvbvm60"
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_4_0_16bit : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ ="vb0016.dll"
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_4_0_32bit : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ ="vb0032.dll"
    condition:
        any of them
}

// TODO Line 50, Unknown how to match paths for pdb file and such

rule CompilerVersion__Delphi : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ ="this program must be run under win32" nocase
        $ ="SOFTWARE\\Borland\\Delphi\\RTL" nocase
    condition:
        any of them
}

// TODO Line 80, Unknown how to match regexes... lots of them

// Line 168
rule CompilerVersion__Microsoft_Visual_Cpp_4_2 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ = /MSVBVM(A|D).DLL/ nocase
    condition:
        any of them
}

// TODO skipping check at line 175
// TODO Should identify when it's the debug build vs release
rule CompilerVersion__Microsoft_Visual_Cpp_5_0 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ =/MSVC(P|R)50(A|D).DLL/ nocase
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_6_0 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ =/MSVC(P|R)60(A|D).DLL/ nocase
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2002 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ =/MSVC(P|R)70(A|D).DLL/ nocase
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2003 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ =/MSVC(P|R)71(A|D).DLL/ nocase
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2005 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ =/MSVC(P|R)80(A|D).DLL/ nocase
    condition:
        any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2008 : Compiler CompilerVersion {
    meta:
        weight = 1
    strings:
        $ =/MSVC(P|R)90(A|D).DLL/ nocase
    condition:
        any of them
}

// TODO add check for VS2010

rule CompilerPattern__BufferSecurityChecks : AntiDebug CompilerPattern {
    meta:
        weight = 1
    strings:
        $ = {8B 4D FC 33 CD E8}
    condition:
        any of them
}

rule CompilerPattern__FPO_Count : AntiDebug CompilerPattern {
    meta:
        weight = 1
    strings:
        $ = {C7 44 24 ?? 00 00 00 00}
    condition:
        any of them
}
rule CompressionUsed__LZ_Compression : Compression CompressionUsed {
    meta:
        weight = 1
    strings:
        $ ="LZOpenFile" nocase
        $ ="LZClose" nocase
        $ ="LZCopy" nocase
        $ ="LZRead" nocase
        $ ="LZInit" nocase
        $ ="LZSeek" nocase
    condition:
        any of them
}

rule CompressionUsed__UPX_Packing : Compression CompressionUsed {
    meta:
        weight = 1
    strings:
        $ ="UPX0" nocase
        $ ="UPX1" nocase
    condition:
        any of them
}

// Originally, I had regexes, but that was slow (made the program run in over a second,
// instead of under half a second)... so I'm using strings
rule DataConversion__ansi : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atoi" nocase
        $ = "atol" nocase
        $ = "atof" nocase
        $ = "atodb" nocase
    condition:
        any of them
}


rule DataConversion__wide : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "wtoi" nocase
        $ = "wtol" nocase
        $ = "wtof" nocase
        $ = "wtodb" nocase
    condition:
        any of them
}


rule DataConversion__64bit : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atoi64" nocase
        $ = "wtoi64" nocase
        $ = "atol64" nocase
        $ = "wtol64" nocase
        $ = "atof64" nocase
        $ = "wtof64" nocase
        $ = "atodb64" nocase
        $ = "wtodb64" nocase
    condition:
        any of them
}


rule DataConversion__locale : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atoi_l" nocase
        $ = "wtoi_l" nocase
        $ = "atoi64_l" nocase
        $ = "wtoi64_l" nocase
        
        $ = "atol_l" nocase
        $ = "wtol_l" nocase
        $ = "atol64_l" nocase
        $ = "wtol64_l" nocase
        
        $ = "atof_l" nocase
        $ = "wtof_l" nocase
        $ = "atof64_l" nocase
        $ = "wtof64_l" nocase
        
        $ = "atodb_l" nocase
        $ = "wtodb_l" nocase
        $ = "atodb64_l" nocase
        $ = "wtodb64_l" nocase
    condition:
        any of them
}


rule DataConversion__int : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atoi" nocase
        $ = "wtoi" nocase
    condition:
        any of them
}


rule DataConversion__long : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atol" nocase
        $ = "wtol" nocase
    condition:
        any of them
}

rule DataConversion__float : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atof" nocase
        $ = "wtof" nocase
    condition:
        any of them
}

rule DataConversion__double : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atodb" nocase
        $ = "wtodb" nocase
    condition:
        any of them
}

rule DataConversion__longdouble : IntegerParsing DataConversion {
    meta:
        weight = 1
    strings:
        $ = "atodbl" nocase
        $ = "wtodbl" nocase
    condition:
        any of them
}
// TODO get xvid codex version
rule LibsUsed__xvid_codex : Libs LibsUsed {
    meta:
        weight = 1
    strings:
        $ = "xvid codex " nocase
    condition:
        any of them
}

rule LibsUsed__libpng : Libs LibsUsed {
    meta:
        weight = 1
    strings:
        $ = "MNG features are not allowed in a PNG datastream" nocase
    condition:
        any of them
}

// TODO get inflate library version
rule LibsUsed__Inflate_Library : Libs LibsUsed {
    meta:
        weight = 1
    strings:
        $ = /inflate [0-9\\.]+ Copyright 1995/ 
    condition:
        any of them
}

rule LibsUsed__Lex_Yacc : Libs LibsUsed {
    meta:
        weight = 1
    strings:
        $ = "yy_create_buffer" nocase
    condition:
        any of them
}

rule LibsUsed__STL_new : Libs LibsUsed {
    meta:
        weight = 1
    strings:
        $ = "AVbad_alloc"
    condition:
        any of them
}
rule Functionality__Windows_GDI_Common_Controls : Microsoft Functionality {
    meta:
        weight = 1
    strings:
        $ ="comctl32.dll" nocase
        $ ="gdi32.dll" nocase
    condition:
        any of them
}

rule Functionality__Windows_Multimedia : Microsoft Functionality {
    meta:
        weight = 1
    strings:
        $ ="winmm.dll" nocase
    condition:
        any of them
}

rule Functionality__Windows_socket_library : Microsoft Functionality {
    meta:
        weight = 1
    strings:
        $ ="wsock32.dll" nocase
        $ ="ws2_32.dll" nocase
    condition:
        any of them
}

rule Functionality__Windows_Internet_API : Microsoft Functionality {
    meta:
        weight = 1
    strings:
        $ ="wininet.dll" nocase
    condition:
        any of them
}

rule Functionality__Windows_HTML_Help_Control : Microsoft Functionality {
    meta:
        weight = 1
    strings:
        $ ="hhctrl.dll" nocase
    condition:
        any of them
}

rule Functionality__Windows_Video_For_Windows : Microsoft Functionality {
    meta:
        weight = 1
    strings:
        $ ="msvfw32.dll" nocase
    condition:
        any of them
}

rule Copyright__faked : Microsoft Copyright {
    meta:
        weight = 1
    strings:
        $ ="Microsoft (c)"
    condition:
        any of them
}
