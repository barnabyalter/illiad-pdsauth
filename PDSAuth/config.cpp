#include "Config.h"

bool LoadConfig() 
{
	HKEY hk;

	// Open the PDSAuth Registry Key
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,PDSAUTH_REGISTRY_KEY,0,KEY_QUERY_VALUE,&hk) != ERROR_SUCCESS)
	{
		LogEvent(PDS_ERROR,"LoadConfig: The PDSAuth configuration registry key could not be read, please verify that the key exists and is set correctly",PDSAUTH_REGISTRY_KEY);
		return false;
	}

	// Load Required Registry Settings
	pszLoginURL  = LoadRegistryString("LoginURL",hk);
	if (pszLoginURL == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","LoginURL");
		RegCloseKey(hk);
		return false;
	}
	pszValidateURL  = LoadRegistryString("ValidateURL",hk);
	if (pszValidateURL == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","ValidateURL");
		RegCloseKey(hk);
		return false;
	}
	pszPDSCookie  = LoadRegistryString("PDSCookie",hk);
	if (pszPDSCookie == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","PDSCookie");
		RegCloseKey(hk);
		return false;
	}
	pszAccessDenied  = LoadRegistryString("AccessDenied",hk);
	if (pszAccessDenied == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","AccessDenied");
		RegCloseKey(hk);
		return false;
	}
	pszApplicationPath  = LoadRegistryString("ApplicationPath",hk);
	if (pszApplicationPath == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","ApplicationPath");
		RegCloseKey(hk);
		return false;
	}
	if (!LoadRegistryDWORD(&dwCookieTimeout,"CookieTimeout",hk)) 
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","CookieTimeout");
		RegCloseKey(hk);
		return false;
	}
	pszCookieName  = LoadRegistryString("CookieName",hk);
	if (pszCookieName == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","CookieName");
		RegCloseKey(hk);
		return false;
	}
	pszCookieDomain  = LoadRegistryString("CookieDomain",hk);
	if (pszCookieDomain == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","CookieDomain");
		RegCloseKey(hk);
		return false;
	}
	pszCookiePath  = LoadRegistryString("CookiePath",hk);
	if (pszCookiePath == NULL)
	{
		LogEvent(PDS_ERROR,"LoadConfig: A PDSAuth registry configuration value is missing or null, please set a valid value for","CookiePath");
		RegCloseKey(hk);
		return false;
	}
	
	//Load Optional Registry Settings
	pszServiceURL = LoadRegistryString("ServiceURL",hk);

	RegCloseKey(hk);
	return LoadPatronStatuses();
}

bool LoadPatronStatuses() 
{
	HKEY hk;
	
	// Open the PDSAuth\PatronStatuses Registry Key
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,PDSAUTH_PATRON_STATUS_KEY,0,KEY_QUERY_VALUE,&hk) == ERROR_SUCCESS)
	{
		char  szName[1000];
		DWORD dwKeyIdx=0, dwURLIdx=0, dwNameSize, dwBufferSize, dwType;

		// Loop over the values in they key, getting the buffer size and type
		while (
			RegEnumValue(hk,dwKeyIdx,szName,&dwNameSize,NULL,&dwType,NULL,&dwBufferSize) == ERROR_SUCCESS)
		{
			// Ensure the key is a non-null string ( set to one to eliminate "" terminated strings)
			if (dwType == REG_SZ && dwBufferSize > 1 )
			{
				// Allocate the string buffer and query the value into the patron statuses string array
				dwNameSize=sizeof(szName); //must always reset before calling RegEnumValue
				ppszPatronStatuses[dwURLIdx] = new char[dwBufferSize];
				RegEnumValue(hk,dwKeyIdx,szName,&dwNameSize,NULL,NULL,(LPBYTE)ppszPatronStatuses[dwURLIdx],&dwBufferSize);
				dwURLIdx++;  //Increment the number of loaded URLs
			}
			dwKeyIdx++;
			dwNameSize=sizeof(szName); //must always reset before calling RegEnumValue
		}

		RegCloseKey(hk);
		// At least one status must be parsed for a valid configuration
		if (dwURLIdx > 0) 
		{
			return true;
		}
	}
	LogEvent(PDS_ERROR,"LoadPatronStatuses: The PDSAuth PatronStatuses registry key could not be read or does not have any status values defined, please set up one or more patron statuses in",PDSAUTH_PATRON_STATUS_KEY);
	return false;
}

void FreeConfig()
{
	if( pszLoginURL != NULL)
		delete pszLoginURL;
	if( pszValidateURL != NULL)
		delete pszValidateURL;
	if( pszPDSCookie != NULL)
		delete pszPDSCookie;
	if( pszAccessDenied != NULL)
		delete pszAccessDenied;
	if( pszApplicationPath != NULL)
		delete pszApplicationPath;
	if( pszServiceURL != NULL)
		delete pszServiceURL;
	if( pszCookieDomain != NULL)
		delete pszCookieDomain;
	if( pszCookieName != NULL)
		delete pszCookieName;
	if( pszCookiePath != NULL)
		delete pszCookiePath;
	
	int i = 0;
	while(ppszPatronStatuses[i] != NULL)
	{
		if (ppszPatronStatuses[i] != NULL)
			delete ppszPatronStatuses[i];
		i++;
	}

}

char* LoadRegistryString(char* pszKey, HKEY hk) 
{
	DWORD dwBufferSize,dwType;
	char* pszBuf;

	// Open the key to get its size and type
	if (RegQueryValueEx(hk,TEXT(pszKey),NULL,&dwType,NULL,&dwBufferSize) == ERROR_SUCCESS )
	{
		// Ensure the key is a string type and not null (set to one to eliminate "" terminated strings)
		if (dwType == REG_SZ && dwBufferSize > 1)
		{
			// Allocate the string buffer and query the value into the buffer
			pszBuf = new char[dwBufferSize];
			RegQueryValueEx(hk,TEXT(pszKey),NULL,NULL,(LPBYTE)pszBuf,&dwBufferSize);
			return pszBuf;
		}
	}

	return NULL;
}

bool LoadRegistryDWORD(DWORD* dwDest, char* pszKey, HKEY hk) 
{
	DWORD dwLen,dwType;

	// Open the key to get its type
	if (RegQueryValueEx(hk,TEXT(pszKey),NULL,&dwType,NULL,NULL) == ERROR_SUCCESS )
	{
		// Ensure the dword type and query the value into the destination dword
		if (dwType == REG_DWORD && 
			RegQueryValueEx(hk,TEXT(pszKey),NULL,NULL,(LPBYTE)dwDest,&dwLen) == ERROR_SUCCESS )
		{
			return true;
		}
	}

	return false;
}