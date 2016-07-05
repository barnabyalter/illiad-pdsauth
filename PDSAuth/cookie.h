#ifndef PDSAuth_Cookie_H
#define PDSAuth_Cookie_H

#include "atlrx.h"
#include <atlenc.h>
#include <strsafe.h>
#include <time.h>
#include "Logging.h"

#define MAX_BUFFER_SIZE		4096		//the maximum buffer size

extern HCRYPTPROV	hCryptProv;		// Handle to the encryption provider context
extern HCRYPTKEY	hCryptKey;		// Handle to the encryption key
extern char*		pszCookieSecret;//the secret check value for the local authentication cookie

/**
* Initializes the cookie encryption parameters
*/
bool InitializeEncryption();

/**
* Releases the cookie encryption parameters
*/
void FreeEncryption();

/**
* Generates an encrypted local authentication cookie
* 
* @param the user id to store in the encrypted string
* @return a pointer to a dynamically allocated string
*/
char* GenerateCookie(char* pszUser);

/**
* Validates an encrypted local authentication cookie
* 
* @param the cookie string to be validated
* @return a pointer to a dynamically allocated string
*/
char* ValidateCookie(char* pszCookie);

#endif