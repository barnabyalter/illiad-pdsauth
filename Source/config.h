#ifndef PDSAuth_Config_H
#define PDSAuth_Config_H

#include "atlrx.h"
#include "Logging.h"

// Windows 64-bit automatically installs 32-bit applications with the WOW6432Node Registry path
#define PDSAUTH_REGISTRY_KEY			"SOFTWARE\\Wow6432Node\\PDSAuth"
#define PDSAUTH_PATRON_STATUS_KEY		"SOFTWARE\\Wow6432Node\\PDSAuth\\PatronStatuses"

/*
#define PDSAUTH_REGISTRY_KEY			"SOFTWARE\\PDSAuth"
#define PDSAUTH_PATRON_STATUS_KEY		"SOFTWAREde\\PDSAuth\\PatronStatuses"
*/

extern char* pszLoginURL;
extern char* pszValidateURL;
extern char* pszPDSCookie;
extern char* pszAccessDenied;
extern char* pszServiceURL;
extern char* pszApplicationPath;
extern DWORD dwCookieTimeout;
extern char* pszCookieName;
extern char* pszCookieDomain;
extern char* pszCookiePath;
extern char* ppszPatronStatuses[];

/**
* Loads the filter configuration from the system registry
*/
bool LoadConfig();

/**
* Loads the patron status configuration from the system registry
*/
bool LoadPatronStatuses();

/**
* Frees the memory allocated to the config variables
*/
void FreeConfig();

/**
* Loads a registry value into a destination string
*
* @param the name of the registry key value to retrieve
* @param a handle to the open registry key
*/
char* LoadRegistryString(char* pszKey, HKEY hk);

/**
* Loads a registry value into a destination dword
*
* @param a destination dword
* @param the name of the registry key value to retrieve
* @param a handle to the open registry key
*/
bool LoadRegistryDWORD(DWORD* dwDest, char* pszKey, HKEY hk);

#endif
