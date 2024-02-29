#pragma once
#include <Windows.h>
#include <stdio.h>

// �������� NtQueryInformationProcess ������ PROCESSINFOCLASS ����
typedef LONG PROCESSINFOCLASS;

// ���� NtQueryInformationProcess ����ָ������
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

// ���� PEB��Process Environment Block���ṹ��ָ������
typedef struct _PEB* PPEB;

// ����������̻�����Ϣ�Ľṹ��
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

// ��ѯ������Ϣ�ĺ���
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

    // ���� ntdll.dll ��
    if (!(hNtDll = LoadLibraryA("ntdll.dll"))) {
        wprintf(L"Cannot load ntdll.dll.\n");
        return NULL;
    }

    // ��ȡ NtQueryInformationProcess �����ĵ�ַ
    if (!(gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess"))) {
        wprintf(L"Cannot load NtQueryInformationProcess.\n");
        return NULL;
    }

    // Ϊ����Ľṹ������ڴ�
    if ((pProcessInformation = (PROCESS_BASIC_INFORMATION*)malloc(ProcessInformationLength)) == NULL) {
        wprintf(L"ExAllocatePoolWithTag failed.\n");
        return NULL;
    }

    // �������Ľṹ��
    if ((Status = gNtQueryInformationProcess(Process, ProcessInformationClass, pProcessInformation, ProcessInformationLength, &ReturnLength))) {
        wprintf(L"NtQueryInformationProcess should return NT_SUCCESS (Status = %#x).\n", Status);
        free(pProcessInformation);
        return NULL;
    }

    // ��� NtQueryInformationProcess ���صĽṹ���С�Ƿ�������Ĵ�Сһ��
    if (ReturnLength != ProcessInformationLength) {
        wprintf(L"Warning : NtQueryInformationProcess ReturnLength is different than ProcessInformationLength\n");
        return NULL;
    }

    return pProcessInformation;
}
