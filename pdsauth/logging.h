#ifndef PDSAuth_Logging_H
#define PDSAuth_Logging_H

#include "atlrx.h"
#include "messages.h"

#define LOG_MSG_SIZE		400
#define EVENTLOG_REG_KEY	"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\PDSAuth"
#define EVENTLOG_DLL_LOC	"%SystemRoot%\\SysWOW64\\inetsrv\\PDSAuth.dll"

/**
* Writes an event to the system application log.
* 
* @param the pds log type (see messages.h)
* @param message part one (optional)
* @param message part two (optional)
*/
void LogEvent(DWORD dwLogType, char* szMsg1, char* szMsg2);

/**
* Creates the necessary entries in the Registry to write and look up event log entries.
*/
bool AddEventSource();

#endif
