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

void InstallHook(DWORD64 old_func, DWORD64 new_func);
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

        InstallHook((DWORD64)pInternetConnectA, (DWORD64)new_internetconnectA);
        InstallHook((DWORD64)pconnect+3, (DWORD64)new_WSAConnect);

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
    MessageBox(NULL, TEXT("hook_after"), TEXT("CALL"), MB_OK);
    HMODULE hMod = LoadLibraryA("wininet.dll");
    FILE* fp;
    FUNADDR2 pInternetConnectA = (FUNADDR2)GetProcAddress(hMod, "InternetConnectA");
    HINTERNET hCon;
    char host[29];
    hCon = ((FUNADDR2)((DWORD64)pInternetConnectA - 17))(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    //HINTERNET hCon = InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
    sprintf(host, "host: %s:%d\n", lpszServerName, nServerPort);
    printf("host: %s:%d\n", lpszServerName, nServerPort);
    //MessageBox(NULL, T2W((LPTSTR)lpszServerName), TEXT("host"), MB_OK);
    fopen_s(&fp, "host.txt", "a");
    fprintf(fp, host);
    fclose(fp);
    return hCon;
}

void InstallHook(DWORD64 old_func, DWORD64 new_func) {
    BYTE code[5];
    DWORD64 jmpAddr;
    DWORD OldProtect = 0;

    jmpAddr = old_func - new_func;
    MessageBox(NULL, TEXT("hook"), TEXT("Install"), MB_OK);
    if (VirtualProtect((LPVOID)(old_func - 17), 29, PAGE_EXECUTE_READWRITE, &OldProtect) == NULL) {
        printf("change protect fail\n");
        return;
    }

    /*
    InternetConnectA函数指令填充

    ///函数原来的指令
    mov qword ptr ss:[rsp+8], rbx
    mov qword ptr ss:[rsp+10], rbp
    mov qword ptr ss:[rsp+18], rsi

    ///此处InternetConnectA+4代表跳转到InternetConnectA函数的第四条指令处
    jmp InternetConnectA+4


    ///跳转到new_func
    mov rax, new_func
    jmp rax
    */
    * (DWORD64*)(old_func - 17) = 0x6c894808245c8948;
    *(DWORD64*)(old_func - 9) = 0xeb18247489481024;
    *(BYTE*)(old_func - 1) = 0x0f;
    *(WORD*)old_func = 0xb848;
    *(DWORD64*)(old_func + 2) = new_func;
    *(WORD*)(old_func + 10) = 0xe0ff;
    printf("%p\n", jmpAddr);
    if (VirtualProtect((LPVOID)(old_func - 17), 29, PAGE_EXECUTE_READ, &OldProtect) == NULL) {
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
    struct sockaddr_in* new_sock;
    unsigned short port;
    char host[29];

    HMODULE hMod = LoadLibraryA("ws2_32.dll");
    FUNADDR pconnect = (FUNADDR)GetProcAddress(hMod, "connect");

    ret = ((FUNADDR)((DWORD64)pconnect - 17))(s, name, namelen);
    new_sock = (struct sockaddr_in*)name;

    port = ntohs(new_sock->sin_port);
    sprintf(host, "host: %s:%d\n", inet_ntoa(new_sock->sin_addr), port);

    fopen_s(&fp, "host.txt", "a");
    fprintf(fp, host);
    fclose(fp);
    return ret;
}