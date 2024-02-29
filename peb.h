#pragma once
#include <Windows.h>
#include <stdio.h>

// 定义用于 NtQueryInformationProcess 函数的 PROCESSINFOCLASS 类型
typedef LONG PROCESSINFOCLASS;

// 定义 NtQueryInformationProcess 函数指针类型
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

// 定义 PEB（Process Environment Block）结构体指针类型
typedef struct _PEB* PPEB;

// 定义包含进程基本信息的结构体
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

// 查询进程信息的函数
PVOID QueryProcessInformation(
    IN HANDLE Process,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN DWORD ProcessInformationLength
) 
{
    PROCESS_BASIC_INFORMATION* pProcessInformation = NULL;
    pfnNtQueryInformationProcess gNtQueryInformationProcess;
    ULONG ReturnLength = 0;
    NTSTATUS Status;
    HMODULE hNtDll;

    // 加载 ntdll.dll 库
    if (!(hNtDll = LoadLibraryA("ntdll.dll"))) {
        wprintf(L"Cannot load ntdll.dll.\n");
        return NULL;
    }

    // 获取 NtQueryInformationProcess 函数的地址
    if (!(gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess"))) {
        wprintf(L"Cannot load NtQueryInformationProcess.\n");
        return NULL;
    }

    // 为请求的结构体分配内存
    if ((pProcessInformation = (PROCESS_BASIC_INFORMATION*)malloc(ProcessInformationLength)) == NULL) {
        wprintf(L"ExAllocatePoolWithTag failed.\n");
        return NULL;
    }

    // 填充请求的结构体
    if ((Status = gNtQueryInformationProcess(Process, ProcessInformationClass, pProcessInformation, ProcessInformationLength, &ReturnLength))) {
        wprintf(L"NtQueryInformationProcess should return NT_SUCCESS (Status = %#x).\n", Status);
        free(pProcessInformation);
        return NULL;
    }

    // 检查 NtQueryInformationProcess 返回的结构体大小是否与请求的大小一致
    if (ReturnLength != ProcessInformationLength) {
        wprintf(L"Warning : NtQueryInformationProcess ReturnLength is different than ProcessInformationLength\n");
        return NULL;
    }

    return pProcessInformation;
}
