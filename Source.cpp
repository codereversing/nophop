#include <cstdlib>
#include <ctime>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

#include "BeaEngine.h"

#define BOOLIFY(x) !!(x)

#define NOP 0x90

using ModuleName = std::wstring;
using AddressRange = std::pair<DWORD_PTR, DWORD_PTR>;
using ExecutableRegionsList = std::vector<AddressRange>;
using InstructionList = std::vector<DWORD_PTR>;
using NopRange = std::vector<AddressRange>;
using NopRangeList = std::vector<NopRange>;

using ModuleMap = std::map<ModuleName, AddressRange>;
using ExecutableMap = std::map<ModuleName, ExecutableRegionsList>;

using pDisasmFnc = int (__stdcall *)(DISASM *pMonDisasm);
pDisasmFnc DisasmFnc = nullptr;

const InstructionList GetInstructionList(const unsigned char * const pBytes, const size_t ulSize, const DWORD_PTR dwOffset,
    const bool bNopsOnly = false)
{
    InstructionList instructionList;

    DISASM disasm = { 0 };
#ifdef _M_IX86
    //Do nothing
#elif defined(_M_AMD64)
    disasm.Archi = 64;
#else
#error "Unsupported architecture"
#endif

    disasm.EIP = (UIntPtr)pBytes;
    int iLength = 0;
    int iLengthTotal = 0;
    do
    {
        iLength = DisasmFnc(&disasm);
        if (iLength != UNKNOWN_OPCODE)
        {
            const DWORD_PTR dwInstructionStart = (DWORD_PTR)(disasm.EIP);
            if (bNopsOnly)
            {
                if (disasm.Instruction.Opcode == NOP)
                {
                    instructionList.push_back(dwInstructionStart + dwOffset);
                }
            }
            else
            {
                instructionList.push_back(dwInstructionStart + dwOffset);
            }

            iLengthTotal += iLength;
            disasm.EIP += iLength;
        }
        else
        {
            ++iLengthTotal;
            ++disasm.EIP;
        }
    } while (iLengthTotal < ulSize);

    return instructionList;
}

const InstructionList GetNopList(const unsigned char * const pBytes, const size_t ulSize, const DWORD_PTR dwOffset)
{
    return GetInstructionList(pBytes, ulSize, dwOffset, true);
}

const NopRange FindNops(const unsigned char * const pBytes, const size_t ulSize, const DWORD_PTR dwOffset)
{
    //Find all NOPs in the code
    const InstructionList nopList = GetNopList(pBytes, ulSize, dwOffset);

    //Merge continuous NOPs into an address range
    NopRange nopListMerged;
    if (nopList.size() > 1)
    {
        auto firstElem = nopList.begin();
        auto nextElem = ++firstElem;
        --firstElem;
        nopListMerged.push_back(std::make_pair(*firstElem, *firstElem));

        while (nextElem != nopList.end())
        {
            if (*nextElem == ((*firstElem) + 1))
            {
                auto elem = nopListMerged.back();
                const DWORD_PTR dwRangeStart = elem.first;
                const DWORD_PTR dwRangeEnd = *nextElem;
                nopListMerged.pop_back();
                nopListMerged.push_back(std::make_pair(dwRangeStart, dwRangeEnd));
            }
            else
            {
                nopListMerged.push_back(std::make_pair(*nextElem, *nextElem));
            }

            ++firstElem;
            ++nextElem;
        }
    }

    //Toss out address ranges that are too small
    NopRange nopListTrimmed;
    const int iMinNops = 20;
    for (auto &nopRange : nopListMerged)
    {
        const DWORD_PTR dwRangeStart = nopRange.first;
        const DWORD_PTR dwRangeEnd = nopRange.second;

        if ((dwRangeEnd - dwRangeStart) > iMinNops)
        {
            nopListTrimmed.push_back(std::make_pair(dwRangeStart, dwRangeEnd));
        }
    }

    return nopListTrimmed;
}

const NopRangeList FindNopRanges(const HANDLE hProcess, const ExecutableMap &executableRegions, const size_t ulSize)
{
    NopRangeList nopRangeList;

    for (auto &executableRegion : executableRegions)
    {
        for (auto &executableAddressRange : executableRegion.second)
        {
            const DWORD_PTR dwLowerAddress = executableAddressRange.first;
            const DWORD_PTR dwHigherAddress = executableAddressRange.second;
            const DWORD_PTR dwRangeSize = dwHigherAddress - dwLowerAddress;

            if (dwRangeSize > ulSize)
            {
                std::unique_ptr<unsigned char> pLocalBytes(new unsigned char[dwRangeSize]);
                SIZE_T ulBytesRead = 0;
                const bool bSuccess = BOOLIFY(ReadProcessMemory(hProcess, (LPCVOID)dwLowerAddress,
                    pLocalBytes.get(), dwRangeSize, &ulBytesRead));
                if (bSuccess && ulBytesRead == dwRangeSize)
                {
                    const DWORD_PTR dwOffset = dwLowerAddress - (DWORD_PTR)pLocalBytes.get();

                    NopRange nopRange = FindNops(pLocalBytes.get(), dwRangeSize, dwOffset);
                    if (nopRange.size() > 0)
                    {
                        nopRangeList.emplace_back(nopRange);
                    }
                }
                else
                {
                    fprintf(stderr, "Could not read from 0x%X. Error = %X\n",
                        executableAddressRange.first, GetLastError());
                }
            }
        }
    }

    return nopRangeList;
}

InstructionList SelectRegions(const HANDLE hProcess, const NopRangeList &nopRangeList, InstructionList &writeInstructions)
{
    InstructionList writtenList;

    auto firstElem = writeInstructions.begin();
    auto nextElem = ++firstElem;
    --firstElem;
    while(nextElem != writeInstructions.end())
    {
        bool bContinueSearching = true;
        do
        {
            const size_t ulCurrentIndexModule = std::rand() % nopRangeList.size();
            const size_t ulCurrentIndexAddressRange = std::rand() % nopRangeList[ulCurrentIndexModule].size();

            const DWORD_PTR dwBaseWriteAddress = nopRangeList[ulCurrentIndexModule][ulCurrentIndexAddressRange].first;
            if(std::find(writtenList.begin(), writtenList.end(), dwBaseWriteAddress) == writtenList.end())
            {
                writtenList.push_back(dwBaseWriteAddress);
                bContinueSearching = false;
            }
        } while (bContinueSearching);

        ++firstElem;
        ++nextElem;
    }

    return writtenList;
}

const bool WriteJumps(const HANDLE hProcess, const InstructionList &writeInstructions, const InstructionList &selectedRegions)
{
#ifdef _M_IX86
#elif defined (_M_AMD64)
    unsigned char jmpBytes[] =
    {
        0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, /*mov rax, 0xBBBBBBBBBBBBBBBB*/
        0xFF, 0xE0													/*jmp rax*/
    };
#else
#error "Unsupported architecture"
#endif

    auto firstElem = selectedRegions.begin();
    auto nextElem = ++firstElem;
    --firstElem;

    int i = 0;
    while (nextElem != selectedRegions.end())
    {
        const DWORD_PTR dwInstructionSize = writeInstructions[i + 1] - writeInstructions[i];
        DWORD dwOldProtect = 0;
        bool bSuccess = BOOLIFY(VirtualProtectEx(hProcess, (LPVOID)*firstElem, dwInstructionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect));
        if (bSuccess)
        {
            size_t ulBytesWritten = 0;
            bSuccess = BOOLIFY(WriteProcessMemory(hProcess, (LPVOID)*firstElem, (LPCVOID)writeInstructions[i++], dwInstructionSize,
                &ulBytesWritten));

            DWORD_PTR dwNextAddress = *nextElem;
            memcpy(&jmpBytes[2], &dwNextAddress, sizeof(DWORD_PTR));
            
            bSuccess = BOOLIFY(WriteProcessMemory(hProcess, (LPVOID)(*firstElem + dwInstructionSize), jmpBytes, sizeof(jmpBytes),
                &ulBytesWritten));

            bSuccess = BOOLIFY(VirtualProtectEx(hProcess, (LPVOID)*firstElem, dwInstructionSize, dwOldProtect, &dwOldProtect));
            if (!bSuccess)
            {
                fprintf(stderr, "Could not put permissions back on address 0x%X. Error = %X\n",
                    *firstElem, GetLastError());
                return false;
            }

        }
        else
        {
            fprintf(stderr, "Could not change permissions on address 0x%X. Error = %X\n",
                *firstElem, GetLastError());
            return false;
        }

        ++firstElem;
        ++nextElem;
    }

    return true;
}

const HANDLE WriteCodeToRegions(const HANDLE hProcess, const ExecutableMap &executableRegions,
    const unsigned char * const pBytes, const size_t ulSize)
{
    const NopRangeList nopRangeList = FindNopRanges(hProcess, executableRegions, ulSize);
    InstructionList writeInstructions = GetInstructionList(pBytes, ulSize, 0);

    InstructionList selectedRegions = SelectRegions(hProcess, nopRangeList, writeInstructions);

    if (WriteJumps(hProcess, writeInstructions, selectedRegions))
    {
        DWORD dwThreadId = 0;
        DWORD_PTR dwStartAddress = selectedRegions[0];
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)dwStartAddress, nullptr, 0, &dwThreadId);
        return hThread;
    }

    return nullptr;
}

const HANDLE LoadProcess(const DWORD dwProcessId)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME |
        PROCESS_CREATE_THREAD | PROCESS_SET_INFORMATION,
        FALSE, dwProcessId);
    if (hProcess == nullptr)
    {
        fprintf(stderr, "Could not open process. Error = %X.\n",
            GetLastError());
        exit(-1);
    }

    return hProcess;
}

const ExecutableMap GetExecutableRegions(const HANDLE hProcess, const ModuleMap &mapModules)
{
    ExecutableMap mapExecutableRegions;
    ExecutableRegionsList lstExecutableRegions;

    for (auto &module : mapModules)
    {
        MEMORY_BASIC_INFORMATION memBasicInfo = { 0 };
        DWORD_PTR dwBaseAddress = module.second.first;
        const DWORD_PTR dwEndAddress = module.second.second;

        while (dwBaseAddress <= dwEndAddress)
        {
            const SIZE_T ulReadSize = VirtualQueryEx(hProcess, (LPCVOID)dwBaseAddress,
                &memBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
            if (ulReadSize > 0)
            {
                if ((memBasicInfo.State & MEM_COMMIT) &&
                    ((memBasicInfo.Protect & PAGE_EXECUTE_READWRITE) || (memBasicInfo.Protect & PAGE_EXECUTE_READ)))
                {
                    const DWORD_PTR dwRegionStart = (DWORD_PTR)memBasicInfo.AllocationBase;
                    const DWORD_PTR dwRegionEnd = dwRegionStart + (DWORD_PTR)memBasicInfo.RegionSize;
                    lstExecutableRegions.emplace_back(std::make_pair(dwRegionStart, dwRegionEnd));
                }
                dwBaseAddress += memBasicInfo.RegionSize;
            }
        }

        if (lstExecutableRegions.size() > 0)
        {
            mapExecutableRegions[module.first] = lstExecutableRegions;
            lstExecutableRegions.clear();
        }
    }

    if (mapExecutableRegions.size() == 0)
    {
        fprintf(stderr, "Could not find any executable regions.\n");
        exit(-1);
    }

    return mapExecutableRegions;
}

const ModuleMap GetModules(const DWORD dwProcessId)
{
    ModuleMap mapModules;

    const HANDLE hToolhelp32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    MODULEENTRY32 moduleEntry = { 0 };
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    const BOOL bSuccess = Module32First(hToolhelp32, &moduleEntry);
    if (!bSuccess)
    {
        fprintf(stderr, "Could not enumeate modules. Error = %X.\n",
            GetLastError());
        exit(-1);
    }

    do
    {
        const DWORD_PTR dwBase = (DWORD_PTR)moduleEntry.modBaseAddr;
        const DWORD_PTR dwEnd = dwBase + moduleEntry.modBaseSize;

        mapModules[std::wstring(moduleEntry.szModule)] = std::make_pair(dwBase, dwEnd);

    } while (Module32Next(hToolhelp32, &moduleEntry));

    CloseHandle(hToolhelp32);

    return mapModules;
}

int main(int argc, char *argv[])
{
    /*
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <Process Id>", argv[0]);
        exit(-1);
    }
    */

    std::srand((unsigned int)std::time(0));

#ifdef _M_IX86
#elif defined(_M_AMD64)
    const HMODULE hBeaEngine = LoadLibrary(L"BeaEngine64.dll");
#else
#error "Unsupported architecture"
#endif
    DisasmFnc = (pDisasmFnc)GetProcAddress(hBeaEngine, "Disasm");
    if (DisasmFnc == nullptr)
    {
        fprintf(stderr, "Could not get Disasm function from BeaEngine.\n");
        exit(-1);
    }

    auto handle = LoadProcess(GetCurrentProcessId());//atoi(argv[1]));
    auto modules = GetModules(GetCurrentProcessId());//atoi(argv[1]));
    auto executableRegions = GetExecutableRegions(handle, modules);

    HMODULE hModule = LoadLibrary(L"user32.dll");
    DWORD_PTR dwTargetAddress = (DWORD_PTR)GetProcAddress(hModule, "MessageBoxA");

#ifdef _M_IX86
#elif defined(_M_AMD64)
    DWORD dwHigh = (dwTargetAddress >> 32) & 0xFFFFFFFF;
    DWORD dwLow = (dwTargetAddress) & 0xFFFFFFFF;

    unsigned char pBytes[] =
    {
        0x45, 0x33, 0xC9,                               /*xor r9d, r9d*/
        0x45, 0x33, 0xC0,                               /*xor r8d, r8d*/
        0x33, 0xD2,                                     /*xor edx, edx*/
        0x33, 0xC9,                                     /*xor ecx, ecx*/
        0x68, 0x11, 0x11, 0x11, 0x11,                   /*push 0x11111111*/
        0xC7, 0x44, 0x24, 0x04, 0xDD, 0xCC, 0xBB, 0xAA, /*mov [rsp+4], 0AABBCCDD*/
        0xC3,                                           /*ret*/
        0xC3, 0xC3, 0xC3                                /*dummy*/
    };

    memcpy(&pBytes[11], &dwLow, sizeof(DWORD));
    memcpy(&pBytes[19], &dwHigh, sizeof(DWORD));

#else
#error "Unsupported platform"
#endif

    auto thread = WriteCodeToRegions(handle, executableRegions, pBytes, sizeof(pBytes) - 1);

    CloseHandle(handle);

    return 0;
}