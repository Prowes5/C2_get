// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <stdio.h>
#include <wininet.h>
#include <winsock2.h>
#include <atlconv.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)

typedef HINTERNET(*FUNADDR2)(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
    );

HINTERNET new_internetconnectA(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
);

typedef int (*FUNADDR)(
    SOCKET s,
    const struct sockaddr* name,
    int namelen
    );

int WSAAPI new_WSAConnect(
    SOCKET s,
    const struct sockaddr* name,
    int namelen
);

void InstallHook(DWORD32 old_func, DWORD32 new_func);
void UnstallHook();

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    HMODULE hMod;
    FUNADDR2 pInternetConnectA;
    FUNADDR pconnect;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, TEXT("hh"), TEXT("DLLMain"), MB_OK);
        hMod = LoadLibraryA("wininet.dll");
        if (hMod == NULL) {
            printf("load dll error!\n");
            return 0;
        }

        pInternetConnectA = (FUNADDR2)GetProcAddress(hMod, "InternetConnectA");

        hMod = LoadLibraryA("ws2_32.dll");
        if (hMod == NULL) {
            printf("load dll error!\n");
            return 0;
        }

        pconnect = (FUNADDR)GetProcAddress(hMod, "connect");
        InstallHook((DWORD32)pInternetConnectA, (DWORD32)new_internetconnectA);
        InstallHook((DWORD32)pconnect, (DWORD32)new_WSAConnect);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

HINTERNET new_internetconnectA(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
) {
    MessageBox(NULL, TEXT("new_internetconnectA"), TEXT("CALL"), MB_OK);
    HMODULE hMod = LoadLibraryA("wininet.dll");
    FILE* fp;
    FUNADDR2 pInternetConnectA = (FUNADDR2)GetProcAddress(hMod, "InternetConnectA");
    HINTERNET hCon;
    char host[29];
    hCon = ((FUNADDR2)((DWORD64)pInternetConnectA - 5))(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    //HINTERNET hCon = InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    sprintf(host, "host: %s:%d\n", lpszServerName, nServerPort);
    printf("host: %s:%d\n", lpszServerName, nServerPort);
    //MessageBox(NULL, T2W((LPTSTR)lpszServerName), TEXT("host"), MB_OK);
    fopen_s(&fp, "host.txt", "a");
    fprintf(fp, host);
    fclose(fp);
    return hCon;
}

void InstallHook(DWORD32 old_func, DWORD32 new_func) {
    DWORD OldProtect = 0;

    MessageBox(NULL, TEXT("hook"), TEXT("Install"), MB_OK);
    if (VirtualProtect((LPVOID)(old_func - 5), 10, PAGE_EXECUTE_READWRITE, &OldProtect) == NULL) {
        printf("change protect fail\n");
        return;
    }

    /*
    InternetConnectA函数指令填充
    */
    //函数原来的指令
    /* push ebp */
    *(BYTE*)(old_func - 5) = 0x55;
    /* mov ebp, esp */
    *(WORD*)(old_func - 4) = 0xec8b;
    /* jmp eip+5 */
    *(WORD*)(old_func - 2) = 0x05EB;
    // hook的指令
    /* jmp new_func */
    *(BYTE*)old_func = 0xe9;
    *(DWORD*)(old_func + 1) = new_func - old_func - 5;
    if (VirtualProtect((LPVOID)(old_func - 5), 8, PAGE_EXECUTE_READ, &OldProtect) == NULL) {
        printf("change protect fail\n");
        return;
    }
}


int WSAAPI new_WSAConnect(
    SOCKET s,
    const struct sockaddr* name,
    int namelen
) {
    MessageBox(NULL, TEXT("new_WSAConnect"), TEXT("CALL"), MB_OK);

    
    FILE* fp;
    int ret;
    struct sockaddr_in *new_sock;
    unsigned short port;
    char host[29];

    HMODULE hMod = LoadLibraryA("ws2_32.dll");
    FUNADDR pconnect = (FUNADDR)GetProcAddress(hMod, "connect");

    ret = ((FUNADDR)((DWORD32)pconnect - 5))(s, name, namelen);
    new_sock = (struct sockaddr_in*)name;

    port = ntohs(new_sock->sin_port);
    sprintf(host, "host: %s:%d\n", inet_ntoa(new_sock->sin_addr), port);

    fopen_s(&fp, "host.txt", "a");
    fprintf(fp, host);
    fclose(fp);
    return ret;
}