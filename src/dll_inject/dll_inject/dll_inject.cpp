// dll_inject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<stdio.h>
#include<windows.h>
#include<wininet.h>
#include<tlhelp32.h>
#pragma comment(lib, "wininet.lib")
#pragma warning(disable:4996)

#define MAX_LEN 50


typedef HMODULE(*fcLoadLibrary)(
	LPCSTR lpLibFilename
	);

int GetProcessID(const char* pName);

int main(int argc, char** argv)
{
	HMODULE hMod;
	DWORD pid;
	HANDLE hProcess, hThread;

	int len;
	DWORD nWritten = 0;

	static CHAR hdrs[] = "Content-Type: application/x-www-form-urlencoded";
	static CHAR frmdata[] = "test";

	static CHAR path[] = "internet.dll";
	char* processname;

	if ((argc < 3) || (!strcmp(argv[1], "-h")) || (strcmp(argv[1], "install"))) {
		printf("将internet.dll Hook到指定的进程中并记录通信的IP和端口\n");
		printf("Usage: \n");
		printf("    dll_inject.exe [install|-h] [processname]\n");
		printf("    -h\t\t显示帮助\n");
		printf("    install\t指定进程名做hook\n");
		return 0;
	}

	processname = (char*)malloc(strlen(argv[2]));
	memset(processname, 0, strlen(argv[2])+1);
	strncpy(processname, argv[2], strlen(argv[2]));

	while (GetProcessID(processname) == -1);

	pid = GetProcessID(processname);
	printf("[+] 获取目标进程pid： %d\n", pid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProcess) {
		printf("[+] open process fail\n");
		return 0;
	}

	fcLoadLibrary pLoadLibrary = (fcLoadLibrary)GetProcAddress(GetModuleHandle((LPCSTR)"kernel32.dll"), "LoadLibraryA");
	if (pLoadLibrary == NULL) {
		printf("[+] GetProcAddr Fail\n");
		return 0;
	}
	LPVOID lpRemoteMemory = VirtualAllocEx(hProcess, 0, MAX_LEN, MEM_COMMIT, PAGE_READWRITE);

	len = strlen(path);
	BOOL bRet = WriteProcessMemory(hProcess, lpRemoteMemory, path, len, 0);
	if (bRet == NULL) {
		printf("[+] Write Process Memory Fail\n");
		return 0;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, lpRemoteMemory, 0, NULL);

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
    return 0;
}



int GetProcessID(const char* pName) {
	PROCESSENTRY32 pe;
	DWORD id = -1;
	HANDLE hSnapshot;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe))
		return 0;

	while (1) {
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32Next(hSnapshot, &pe) == FALSE) {
			break;
		}
		if (strcmp(pe.szExeFile, pName) == 0) {
			id = pe.th32ProcessID;
			break;
		}
	}

	CloseHandle(hSnapshot);
	return id;
}