#include "Cookie.h"

bool InitializeEncryption()
{
	char	szSecret[MAX_BUFFER_SIZE];
	DWORD	cbSecret;
	HRESULT hr;

	// Attempt to acquire a handle to the default key container.
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
			// Some sort of error occured, create default key container.
			if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				LogEvent(PDS_ERROR,"InitializeEncryption: The PDSAuth filter could not acquire an encryption context.",NULL);
				return false;
			}
	}

	// Create an RC2 encryption key
	if (!CryptGenKey(hCryptProv, CALG_RC4, CRYPT_EXPORTABLE, &hCryptKey))
	{
		// Error during CryptGenKey!
		LogEvent(PDS_ERROR,"InitializeEncryption: The PDSAuth filter could not generate an encryption key.",NULL);
		CryptReleaseContext(hCryptProv, 0);
		return false;
	}

	// Set the Cookie Encryption secret used to check for validity
	// turn the rand number into a string and copy into the CookieSecret
	srand( (unsigned)time( NULL ) );
	_itoa_s(rand(), szSecret, 10);

	cbSecret = strlen(szSecret) + 1;
	pszCookieSecret = new char[cbSecret];

	hr = StringCchCopyEx(pszCookieSecret,cbSecret,szSecret,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);

	if( FAILED( hr ) )
		return false;
	return true;
}

void FreeEncryption()
{
	if(hCryptKey != NULL)
		CryptDestroyKey(hCryptKey);
	if(hCryptProv != NULL)
		CryptReleaseContext(hCryptProv, 0);
}

char* GenerateCookie(char* pszUser)
{
	unsigned char*	pszEncrypted;
	char*			pszCookie = NULL;
	DWORD			cbEncrypted, cbCookie;

	// Create the byte buffer to recieve encryption
	cbEncrypted = (DWORD)strlen(pszUser) + 1 + (DWORD)strlen(pszCookieSecret) + 1;
	
	if(cbEncrypted > MAX_BUFFER_SIZE)
		return NULL;

	pszEncrypted = new unsigned char[cbEncrypted];
	StringCchPrintfEx((char*)pszEncrypted,cbEncrypted,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
		"%s+%s",pszUser,pszCookieSecret);

	// Encrypt the buffer
	if (!CryptEncrypt(hCryptKey, 0, TRUE, 0, pszEncrypted, &cbEncrypted, cbEncrypted))
	{
		LogEvent(PDS_ERROR,"GenerateCookie: The PDSAuth filter failed while trying to encrypt the cookie for the following user",pszUser);
		delete pszEncrypted;
		return NULL;
	}

	cbCookie = AtlHexEncodeGetRequiredLength(cbEncrypted);
	if(cbCookie > MAX_BUFFER_SIZE)
	{
		delete pszEncrypted;
		return NULL;
	}
	pszCookie = new char[cbCookie];

	// Convert to hex for storage in the cookie
	if(!AtlHexEncode(pszEncrypted,cbEncrypted,pszCookie,(int*)&cbCookie))
	{
		LogEvent(PDS_ERROR,"GenerateCookie: The PDSAuth filter failed while trying to hex encode the cookie for the following user",pszUser);
		delete pszEncrypted;
		delete pszCookie;
		return NULL;
	}
	//set the last character of the string to null
	pszCookie[cbCookie] = '\0';

	delete pszEncrypted;

	return pszCookie;
}


char* ValidateCookie(char* pszCookie)
{
	char* pszEncrypted = NULL;
	char* pszUser = NULL;
	char* pszContents = NULL;
	char* pszSecret = NULL;
	unsigned char*	pszDecrypted = NULL;
	DWORD cbEncrypted, cbUser, cbContents, cbDecrypted;

	// extract the cookie value from the cookie string
	pszEncrypted = strrchr(pszCookie,'=');

	// advance the string pointer past the =
	pszEncrypted++;

	if(pszEncrypted != NULL)
	{
		
		// size and create the decryption buffer
		cbEncrypted = (DWORD)strlen(pszEncrypted);
		cbDecrypted = AtlHexDecodeGetRequiredLength(cbEncrypted);
		if(cbDecrypted > MAX_BUFFER_SIZE)
			return NULL;
		pszDecrypted = new unsigned char[cbDecrypted];

		// unencode the value
		if(!AtlHexDecode(pszEncrypted,cbEncrypted,pszDecrypted,(int*)&cbDecrypted))
		{
			LogEvent(PDS_ERROR,"ValidateCookie: The PDSAuth filter failed while trying to hex-decode the cookie",pszEncrypted);
			delete pszDecrypted;
			return NULL;
		}
		//set the last character of the string to null
		pszDecrypted[cbDecrypted] = '\0';

		// decrypt it
		if (!CryptDecrypt(hCryptKey, 0, TRUE, 0, pszDecrypted, &cbDecrypted))
		{
			LogEvent(PDS_ERROR,"ValidateCookie: The PDSAuth filter failed while trying to decrypt the cookie",(char*)pszDecrypted);
			delete pszDecrypted;
			return NULL;
		}

		// we now should have a byte buffer with the user id and secret, copy into a char buffer
		cbContents = cbDecrypted+1;
		if(cbContents > MAX_BUFFER_SIZE)
		{
			delete pszDecrypted;
			return NULL;
		}
		pszContents = new char[cbContents];
		StringCchCopyEx(pszContents,cbContents,(char*)pszDecrypted,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);

		delete pszDecrypted;

		// now check the second value to see if it matches the secret
		pszSecret =  strstr(pszContents,"+");
		if ( pszSecret != NULL )
		{
			pszSecret++;
			if( strcmp(pszCookieSecret,pszSecret) == 0 )
			{
				// we have a valid secret, so grab the user id
				cbUser = (DWORD)strlen(pszContents) - (DWORD)strlen(pszSecret);			
				pszUser = new char[cbUser];
				StringCchCopyEx(pszUser,cbUser,pszContents,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
			}
		}
		delete pszContents;
	}
	
	return pszUser;
}