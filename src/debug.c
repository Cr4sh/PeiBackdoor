#include <PiPei.h>

#include "../config.h"

#include "serial.h"
#include "printf.h"
#include "debug.h"
#include "ovmf.h"
#include "PeiBackdoor.h"
//--------------------------------------------------------------------------------------
#if defined(BACKDOOR_DEBUG)
//--------------------------------------------------------------------------------------
static char *NameFromPath(char *lpszPath)
{
    int sep = -1;
    unsigned int i = 0;

    for (i = 0; i < strlen(lpszPath); i += 1)
    {
        if (lpszPath[i] == '\\' || lpszPath[i] == '/')
        {
            sep = i;
        }
    }

    if (sep >= 0)
    {
        return lpszPath + sep + 1;
    }

    return lpszPath;
}
//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    va_list arglist;
    char szBuff[MAX_STR_LEN], szMessage[MAX_STR_LEN];    
    unsigned int i = 0;

#if defined(BACKDOOR_DEBUG_MEM)

    // get debug messages buffer info
    char *lpszMessages = BackdoorInfo()->Messages;
    size_t SpaceLeft = BACKDOOR_INFO_SIZE - sizeof(BACKDOOR_INFO) - strlen(lpszMessages) - 1;

#endif

    szBuff[MAX_STR_LEN - 1] = '\0';

    va_start(arglist, lpszMsg);    
    tfp_vsnprintf(szBuff, MAX_STR_LEN - 1, lpszMsg, arglist);
    va_end(arglist);

    lpszFile = NameFromPath(lpszFile);

    szMessage[MAX_STR_LEN - 1] = '\0';

    // build debug message string
    tfp_snprintf(szMessage, MAX_STR_LEN - 1, "%s(%d) : %s", lpszFile, Line, szBuff);

#if defined(BACKDOOR_DEBUG_MEM)

    if (SpaceLeft >= strlen(szMessage))
    {
        // save debug message into the BACKDOOR_INFO structure
        strcat(lpszMessages, szMessage);
    }

#endif

    for (i = 0; i < strlen(szMessage); i += 1)
    {

#if defined(BACKDOOR_DEBUG_OVMF)

        // send single byte to OVMF debug port
        __outbyte(OVMF_DEBUG_PORT, szMessage[i]);        

#elif defined(BACKDOOR_DEBUG_SERIAL)

        // send single byte via serial port
        SerialPortWrite(SERIAL_PORT_NUM, szMessage[i]);

#endif

    }
}
//--------------------------------------------------------------------------------------
#endif // BACKDOOR_DEBUG
//--------------------------------------------------------------------------------------
// EoF
