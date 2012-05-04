#include "Logging.h"

void LogEvent(DWORD dwLogType, char* szMsg1, char* szMsg2 ) {
	HANDLE h;
	char* ppszMsg[2];
	DWORD dwError;
	WORD wEventLogType;

	ppszMsg[0] = szMsg1;
	ppszMsg[1] = szMsg2;

	// Set the Event Log Error Type based on the Error
	switch (dwLogType) 
	{
		case PDS_ERROR:
			wEventLogType = EVENTLOG_ERROR_TYPE;
			break;
		case PDS_WARN:
			wEventLogType = EVENTLOG_WARNING_TYPE;
			break;
		default:
			wEventLogType = EVENTLOG_INFORMATION_TYPE;
			break;
	}

	// Report the Event into the Event Log
	h = RegisterEventSource(NULL, TEXT("PDSAuth"));
	if( h == NULL ) return;
	if( ! ReportEvent( h, wEventLogType, 0, dwLogType, NULL, 2, 0, (const char**)ppszMsg, NULL ) ) {
		dwError = GetLastError();
	}
	DeregisterEventSource(h);
	
}

bool AddEventSource()
{
    HKEY hk; 
    DWORD dwData; 

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,EVENTLOG_REG_KEY,0,KEY_READ,&hk) == ERROR_SUCCESS)
	{
		RegCloseKey(hk);
        return true;
	}
    if (RegCreateKey(HKEY_LOCAL_MACHINE,EVENTLOG_REG_KEY,&hk)) 
	{
        return false;
	}
	if (RegSetValueEx(hk,"EventMessageFile",0,REG_EXPAND_SZ,(const BYTE *)EVENTLOG_DLL_LOC,(DWORD)strlen(EVENTLOG_DLL_LOC) + 1))
	{
		RegCloseKey(hk);
        return false;
	}
    dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE; 
    if (RegSetValueEx(hk,"TypesSupported",0,REG_DWORD,(LPBYTE)&dwData,sizeof(DWORD)))
	{
		RegCloseKey(hk);
        return false;
	}
    RegCloseKey(hk);
	return true;
}