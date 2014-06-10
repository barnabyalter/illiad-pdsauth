#include "PDSAuth.h"
//12-08, emh: added atlstr for string conversion
#include <atlstr.h>
#include <string.h>


BOOL WINAPI DllMain(HINSTANCE hInst, ULONG ulReason, LPVOID lpReserved)
{
	BOOL bReturn = true;

	switch (ulReason)
	{
		case DLL_PROCESS_ATTACH:
			// Setup the registry for Event Logging, if necessary
			if ( !AddEventSource() )
				return false;

			// Load the Configuration parameters
			if ( !LoadConfig() ) 
				return false;

			//Initialize Cookie Encryption
			if(!InitializeEncryption())
				return false;

			// Log the successful startup
			LogEvent(PDS_START,NULL,NULL);
			break;
		case DLL_PROCESS_DETACH:
			// Free the configuration variables
			FreeConfig();

			// Free the encryption service
			FreeEncryption();

			// Log the successful stop
			LogEvent(PDS_STOP,NULL,NULL);
			break;
		default:
			break;

	}
	return (bReturn);
}

BOOL WINAPI GetFilterVersion(HTTP_FILTER_VERSION * pVer)
{
	pVer->dwFilterVersion = MAKELONG( 1, 0 );   // Version 1.0

	//  Specify the types and order of notification
	pVer->dwFlags = (SF_NOTIFY_PREPROC_HEADERS | SF_NOTIFY_ORDER_HIGH);
	StringCchCopy(pVer->lpszFilterDesc,SF_MAX_FILTER_DESC_LEN+1,"PDSAuth, Version 1.0");

	return TRUE;
}


DWORD WINAPI HttpFilterProc(HTTP_FILTER_CONTEXT* pCtxt, DWORD NotificationType, VOID* pvData)
{
   DWORD dwRet;

   //  Send this notification to the right function
   switch ( NotificationType )
   {	
		case SF_NOTIFY_PREPROC_HEADERS:
			dwRet = OnPreprocHeaders(pCtxt,(PHTTP_FILTER_PREPROC_HEADERS) pvData);
			break;
		default:
			dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;
			break;
   }
   return dwRet;
}

DWORD OnPreprocHeaders(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH)
{
	DWORD dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;

	char  szURL[URL_BUFFER_SIZE];
	char* pszURL = szURL;
	DWORD cbURL = URL_BUFFER_SIZE;
	//12-08, emh: added var for converting string
	CString urlString(szURL);

	// determine if the requested URL is a protected url
	if(!pPPH->GetHeader( pCtxt, "url", pszURL, &cbURL ))
	{
		LogEvent(PDS_WARN,"The PDSAuth ISAPI could not read the url from the headers.",NULL);	
		return SF_STATUS_REQ_ERROR;
	}

	// do a string match of the (still) encoded url and the protected path listing
	// we're having to accomplish case-insensitivity by string lowering
	if ( strstr( _strlwr( pszURL ), _strlwr(pszApplicationPath) ) )
	{

	char*	pszPDSSession = NULL;
	char*	pszPDSHandle = NULL;
	char*	pszRedirectURL = NULL;
	char*	pszEncryptedCookie = NULL;
	char*	pszCookie = NULL;

	// retrieve local auth cookie
	pszCookie = GetLocalAuthCookie(pCtxt,pPPH);

	// retrieve the last requested service to redirect after authentication
	pszRedirectURL = GetRedirectUrl(pCtxt,pPPH);

	// retrieve the valid pds session cookie value
	// for use with the validation call 
	pszPDSHandle = GetPDSCookie(pCtxt,pPPH);

	// find out if the user cookie already exists
	if(pszCookie != NULL)
	{

		// decrypt the local authentication cookie
		char* pszUser = ValidateCookie(pszCookie);

		// if the username was retrieved from the cookie
		if (pszUser != NULL)
		{		
			// success:  redirect to the service URL with the user cookie
			dwRet = SetAuthHeader(pCtxt,pPPH,pszUser);
			delete pszUser;
		}
		// if we got here, the local cookie user is null
		else
		{
			// delete cookie and try authenticating against PDS again
			dwRet = RedirectWithCookieDeleted(pCtxt, pszRedirectURL);
			#ifdef _DEBUG
				LogEvent(PDS_DEBUG,"We will redirect and delete the cookie: ",pszRedirectURL);
			#endif
		}

	}
	// if PDS session returned non-NULL, we have a valid session and username
	// but a NULL local user cookie.. so attempt to set one
	else if (pszPDSHandle != NULL) 
	{		
		char pszPDSValURL[URL_BUFFER_SIZE];

		// create validation URL for PDS call
		StringCchPrintfEx(pszPDSValURL,URL_BUFFER_SIZE,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
			"%s%s",pszValidateURL,pszPDSHandle);

		char* pszUser = NULL;
		char* pszStatus = NULL;
		char* pszIllPermission = NULL;

		// send the validation http requests and parse the response
		// will return username is valid session and NULL if invalid
		PDSValidateSession(pszPDSValURL,&pszUser,&pszStatus,&pszIllPermission);

		#ifdef _DEBUG
			LogEvent(PDS_DEBUG,"Retrieved Username:",pszUser);
			LogEvent(PDS_DEBUG,"Retrieved Borrower Status:",pszStatus);
			LogEvent(PDS_DEBUG,"Retrieved ILL Permissions Flag:",pszIllPermission);
		#endif

		// if the user has been successfully retrieved
		if (pszUser != NULL) {

			//determine if current user's patron status has access to the system
			int i = 0;
			bool validPatron = false;
			while(ppszPatronStatuses[i] != NULL)
			{
				if ( pszStatus != NULL && 
					strstr( _strlwr( pszStatus ), _strlwr(ppszPatronStatuses[i]) ) )
				{
					validPatron = true;
					break;
				}
				i++;
			}

			// determine if user's ILL permissions flag is true or false
			// if false, reject user
			if ( pszIllPermission == NULL ||
					strstr( pszIllPermission, "N" ) )
			{
				validPatron = false;
			}

			// only proceed with authorization decision if the patron has a valid status
			// and an ILL permissions flag set to Y
			if (validPatron) {

			// success:  redirect to the previously requested URL with the user cookie
			pszEncryptedCookie = GenerateCookie(pszUser);

				if(pszEncryptedCookie != NULL)
				{
				// this should create another call to this ISAPI filter where the first conditional is true
				dwRet = RedirectWithCookie(pCtxt,pszRedirectURL,pszEncryptedCookie);
				}
				else
				{
					// unable to generate the encrypted cookie
					LogEvent(PDS_ERROR,"PDSAuth: The filter was unable to set an authentication cookie for the user:",pszUser);
					if (pszUser != NULL)
						delete pszUser;
					if (pszStatus != NULL)
						delete pszStatus;
					if (pszIllPermission != NULL)
						delete pszIllPermission;
					return SF_STATUS_REQ_ERROR;
				}

				if (pszEncryptedCookie != NULL)
					delete pszEncryptedCookie;

			} 
			else 
			{
				//the patron is not valid and should be redirected to an access denied page
				dwRet = RedirectToAccessDenied(pCtxt, pszAccessDenied);
				#ifdef _DEBUG
					LogEvent(PDS_DEBUG,"Redirecting to Access Denied page:",pszAccessDenied);
				#endif
			}

		} else {
			// there is a PDS handle, but it is invalid
			// Redirect to login to get a valid cookie
			dwRet = RedirectToLogin(pCtxt,pszRedirectURL);
			#ifdef _DEBUG
				LogEvent(PDS_DEBUG,"There is an invalid PDS handle; redirecting to login with redirect url:",pszRedirectURL);
			#endif
		}

		if (pszUser != NULL)
			delete pszUser;
		if (pszStatus != NULL)
			delete pszStatus;
		if (pszIllPermission != NULL)
			delete pszIllPermission;
		
	}
	else
	{
		// no cookie or pds session - first time auth
		// failure: assemble and redirect to the PDS login URL
		dwRet = RedirectToLogin(pCtxt,pszRedirectURL);
		#ifdef _DEBUG
			LogEvent(PDS_DEBUG,"There is no PDS handle or local auth cookie; redirecting to login with redirect url:",pszRedirectURL);
		#endif
	}

	}

	return dwRet;
}


char* GetRedirectUrl(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH)
{

	char	szBuf[URL_BUFFER_SIZE];
	char*	pszBuf =	szBuf;
	DWORD	cbBuf =		URL_BUFFER_SIZE;
	char*	pszRet =	NULL;
	char*	pszTicket = NULL;
	bool	br =		false;
	HRESULT	hr;
	DWORD	dwReserved = 0;

	//12-08, emh: added var for string-char conversion
	CString urlString(szBuf);

	// if we have set the Service URL in the registry, use that 
	//2011-12, NYU: this section wasn't directing to Finished, it was being ignored.
	//Commented out. not currently working. will revisit
	/*
	if( pszServiceURL != NULL )
	{
		// allocated the service URL buffer
		if( strlen(pszServiceURL)+1 > MAX_BUFFER_SIZE)
			goto Finished;
		else {
			pszRet = (char*)pCtxt->AllocMem(pCtxt,strlen(pszServiceURL)+1,dwReserved);
			// and set the service URL
			hr = StringCchCopyEx(pszRet,strlen(pszServiceURL)+1,pszServiceURL,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
			pszRet[strlen(pszServiceURL)]='\0';
		}
		if( pszRet != NULL || FAILED( hr ) )
			goto Finished;
	}*/
	
	// set the buffer to the max url size

	//2011-12, NYU: changed new char[] allocation method to AllocMem which automatically deallocates at end of session
	pszRet = (char*)pCtxt->AllocMem(pCtxt,URL_BUFFER_SIZE,dwReserved);

	// determine if the request is https or not
	if( !pCtxt->GetServerVariable( pCtxt, "HTTPS", pszBuf, &cbBuf ) )
		goto Finished;

	if( strcmp( _strlwr("on"), _strlwr(pszBuf) ) == 0 )
	{
		hr = StringCchCopyEx(pszRet,URL_BUFFER_SIZE,"https://",NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
		if( FAILED( hr ) )
			goto Finished;
	}
	else
	{
		hr = StringCchCopyEx(pszRet,URL_BUFFER_SIZE,"http://",NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
		if( FAILED( hr ) )
			goto Finished;
	}

	// append the server name
	cbBuf = URL_BUFFER_SIZE;
	if( !pCtxt->GetServerVariable( pCtxt, "SERVER_NAME", pszBuf, &cbBuf ) )
		goto Finished;
	hr = StringCchCatEx(pszRet,URL_BUFFER_SIZE,pszBuf,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
	if( FAILED( hr ) )
		goto Finished;

	// parse the URL (changed for IIS 5.0 preproc headers behavior)
	cbBuf = URL_BUFFER_SIZE;
	if(!pPPH->GetHeader( pCtxt, "url", pszBuf, &cbBuf ))
		goto Finished;

	// append the url after the server name
	hr = StringCchCatNEx(pszRet,URL_BUFFER_SIZE,pszBuf,cbBuf,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
	if( FAILED( hr ) )
		goto Finished;

	//12-08, emh: add - ENCODE pszRet since it will be the url parameter
	urlString = pszRet;
	//2011-12, NYU: make sure urlString is null terminated, otherwise buffer overload
	urlString.AppendChar('\0');
	if (urlString.Find("?") !=-1)
	{
		urlString.Replace("?","%3F");
		urlString.Replace("=","%3D");
		urlString.Replace("&","%26");
		urlString.Replace("/","%2F");
		urlString.Replace(":","%3A");
		//2011-12, NYU: removed intermediary variables for memory sake and used CString specific size and buffer methods
		if(urlString.GetLength() < URL_BUFFER_SIZE) {
			hr = StringCchCopyEx(pszRet,urlString.GetLength(),urlString.GetBuffer(),NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
			//2011-12, NYU: make sure pszRet is null terminated
			pszRet[urlString.GetLength()]='\0';
		} else {
			goto Finished;
		}

		if( FAILED( hr ) )
			goto Finished;
	}
	//12-08, emh: end ENCODE
		
	// if we have made it this far, we are okay on the GetServerVariable calls
	br = true;

Finished:
	if( !br || FAILED( hr ) )
	{
		LogEvent(PDS_ERROR,"GetRedirectUrl: The PDSAuth filter was unable to assemble a redirect url for the request: ",pszRet);
		pszRet = NULL;
	}

			
	return pszRet;
}

char* GetPDSCookie(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH)
{
	char	szBuf[URL_BUFFER_SIZE];
	char*	pszBuf = szBuf;
	DWORD	cbBuf = URL_BUFFER_SIZE;
	char*	pszCookie = NULL;
	char*	pszRet = NULL;
	DWORD	dwReserved = 0;

	//check for a querystring
	if( !pPPH->GetHeader(pCtxt, "Cookie:", pszBuf, &cbBuf) )
		return NULL;

	// parse out the local auth cookie if it exists in the cookie header
	pszCookie = strstr(pszBuf,pszPDSCookie);
	
	if(pszCookie != NULL)
	{
		// find the end of the cookie
		char* pszCookieEnd = NULL;
		DWORD cbCookie;

		// default the cookie length to the string length
		cbCookie = (DWORD)strlen(pszCookie)+1;

		pszCookieEnd = strstr(pszCookie,";");
		if(pszCookieEnd != NULL)
		{
			cbCookie = (DWORD)strlen(pszCookie)+1 - (DWORD)strlen(pszCookieEnd);
		}

		//2011-12, NYU: changed new char[] allocation method to AllocMem which automatically deallocates at end of session 
		pszRet = (char*)pCtxt->AllocMem(pCtxt, cbCookie, dwReserved);
		if( FAILED( StringCchCopyNEx(pszRet,cbCookie,pszCookie+strlen(pszPDSCookie)+1,cbCookie-(strlen(pszPDSCookie)+1)-1,NULL,NULL,STRSAFE_FILL_BEHIND_NULL) ) )
		{
			pszRet = NULL;
		}
	}

	return pszRet;
}

char* GetLocalAuthCookie(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH)
{
	char	szBuf[URL_BUFFER_SIZE];
	char*	pszBuf = szBuf;
	DWORD	cbBuf = URL_BUFFER_SIZE;
	char*	pszCookie = NULL;
	char*	pszRet = NULL;
	DWORD	dwReserved = 0;

	// check for a querystring
	if( !pPPH->GetHeader(pCtxt, "Cookie:", pszBuf, &cbBuf) )
		return NULL;

	// parse out the local auth cookie if it exists in the cookie header
	pszCookie = strstr(pszBuf,pszCookieName);
	
	if(pszCookie != NULL)
	{
		// find the end of the cookie
		char* pszCookieEnd = NULL;
		DWORD cbCookie;

		// default the cookie length to the string length
		cbCookie = (DWORD)strlen(pszCookie)+1;

		pszCookieEnd = strstr(pszCookie,";");
		if(pszCookieEnd != NULL)
		{
			cbCookie = (DWORD)strlen(pszCookie)+1 - (DWORD)strlen(pszCookieEnd);
		}

		//2011-12, NYU: changed new char[] allocation method to AllocMem which automatically deallocates at end of session 
		pszRet = (char*)pCtxt->AllocMem(pCtxt,cbCookie,dwReserved);
		if( FAILED( StringCchCopyNEx(pszRet,cbCookie,pszCookie,cbCookie-1,NULL,NULL,STRSAFE_FILL_BEHIND_NULL) ) )
		{
			pszRet = NULL;
		}
	}

	return pszRet;
}

DWORD RedirectToLogin(HTTP_FILTER_CONTEXT* pCtxt, char* pszRedirectURL)
{
	//12-08, emh: this routine redirects the user to login - is called
	//			  upon first authentication and also if a userid/netid isn't returned
	//			  from PDS
	char  szRedirectHeader[MAX_BUFFER_SIZE];

	// assemble the login redirection header
	StringCchPrintfEx(szRedirectHeader,MAX_BUFFER_SIZE,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
						"Location: %s%s\r\n",pszLoginURL,pszRedirectURL);

	// send a 302 redirect header to the client with the login url
	if(!pCtxt->ServerSupportFunction( pCtxt, SF_REQ_SEND_RESPONSE_HEADER, (PVOID)"302 Redirection", (DWORD)szRedirectHeader, 0 ))
	{
		LogEvent(PDS_ERROR,"RedirectToLogin: The PDSAuth filter was unable to send a login redirection header to the browser.",NULL);
		return SF_STATUS_REQ_ERROR;		
	}
	return SF_STATUS_REQ_FINISHED_KEEP_CONN;
}

DWORD RedirectToAccessDenied(HTTP_FILTER_CONTEXT* pCtxt, char* accessDeniedURL)
{
	char  szRedirectHeader[MAX_BUFFER_SIZE];

	// assemble the redirection header 
	StringCchPrintfEx(szRedirectHeader,MAX_BUFFER_SIZE,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
						"Location: %s\r\n",accessDeniedURL);

	// send a 302 redirect header to the client with the url
	if(!pCtxt->ServerSupportFunction( pCtxt, SF_REQ_SEND_RESPONSE_HEADER, (PVOID)"302 Redirection", (DWORD)szRedirectHeader, 0 ))
	{
		LogEvent(PDS_ERROR,"RedirectToAccessDenied: The PDSAuth filter was unable to send an access denied redirection header to the browser.",NULL);
		return SF_STATUS_REQ_ERROR;		
	}
	return SF_STATUS_REQ_FINISHED_KEEP_CONN;
}

DWORD RedirectWithCookie(HTTP_FILTER_CONTEXT* pCtxt, char* pszRedirectURL, char* pszCookie)
{
	char  szRedirectHeader[MAX_BUFFER_SIZE];
	char  szExpires[MAX_BUFFER_SIZE];
	__time64_t ltime;
	struct tm *gmt;

	//12-08, emh: UNESCAPE the pszRedirectURL just for this kind of redirect
	UrlUnescapeInPlace(pszRedirectURL,URL_DONT_UNESCAPE_EXTRA_INFO);

	// set an expires parameter for the cookie if the Cookie Timeout is > 0
	if(dwCookieTimeout > 0){
		// Create the timeout time from the current time + the Cookie Timeout 
		_time64(&ltime);
		ltime += dwCookieTimeout;
		gmt = _gmtime64( &ltime );
		// Format the expiration time string
		strftime(szExpires,MAX_BUFFER_SIZE,"%a, %m-%d-%Y %H:%M:%S GMT",gmt);

		// assemble the redirection header (with expiration), including the cookie
		StringCchPrintfEx(szRedirectHeader,MAX_BUFFER_SIZE,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
			"Location: %s\r\nSet-Cookie: %s=%s;expires=%s;path=%s;domain=%s\r\n",
			pszRedirectURL,pszCookieName,pszCookie,szExpires,pszCookiePath,pszCookieDomain);
	}
	else
	{
		// assemble the redirection header (no expiration), including the cookie
		StringCchPrintfEx(szRedirectHeader,MAX_BUFFER_SIZE,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
			"Location: %s\r\nSet-Cookie: %s=%s;path=%s;domain=%s\r\n",
			pszRedirectURL,pszCookieName,pszCookie,pszCookiePath,pszCookieDomain);
	}

	// send a 302 redirect header to the client with the login url
	if(!pCtxt->ServerSupportFunction( pCtxt, SF_REQ_SEND_RESPONSE_HEADER, (PVOID)"302 Redirection", (DWORD)szRedirectHeader, 0 ))
	{
		LogEvent(PDS_ERROR,"RedirectWithCookie: The PDSAuth filter was unable to send a cookie redirection header to the browser.",NULL);
		return SF_STATUS_REQ_ERROR;		
	}
	return SF_STATUS_REQ_FINISHED_KEEP_CONN;
}

DWORD RedirectWithCookieDeleted(HTTP_FILTER_CONTEXT* pCtxt, char* pszRedirectURL)
{
	char  szRedirectHeader[MAX_BUFFER_SIZE];
	char  szExpires[MAX_BUFFER_SIZE];

	//12-08, emh: UNESCAPE the pszRedirectURL just for this kind of redirect
	UrlUnescapeInPlace(pszRedirectURL,URL_DONT_UNESCAPE_EXTRA_INFO);

	//expires always in the past
	StringCchPrintfEx(szExpires,URL_BUFFER_SIZE,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
					"Thu, 01-Jan-1970 00:00:01 GMT");

	// assemble the redirection header (with expiration), including the cookie
	StringCchPrintfEx(szRedirectHeader,MAX_BUFFER_SIZE,NULL,NULL,STRSAFE_FILL_BEHIND_NULL,
		"Location: %s%s\r\nSet-Cookie: %s=%s;expires=%s;path=%s;domain=%s\r\n",
		pszLoginURL,pszRedirectURL,pszCookieName,'\0',szExpires,pszCookiePath,pszCookieDomain);

	// send a 302 redirect header to the client with the login url
	if(!pCtxt->ServerSupportFunction( pCtxt, SF_REQ_SEND_RESPONSE_HEADER, (PVOID)"302 Redirection", (DWORD)szRedirectHeader, 0 ))
	{
		LogEvent(PDS_ERROR,"RedirectWithCookieDeleted: The PDSAuth filter was unable to send a cookie redirection header to the browser.",NULL);
		return SF_STATUS_REQ_ERROR;		
	}
	return SF_STATUS_REQ_FINISHED_KEEP_CONN;
}

DWORD SetAuthHeader(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH, char* pszUser)
{

	char	szBuf[URL_BUFFER_SIZE];
	char*	pszBuf = szBuf;
	DWORD	cbBuf = URL_BUFFER_SIZE;
	char*	pszHeaderName = NULL;
	DWORD	cbHeaderName = URL_BUFFER_SIZE;

	// first check to see if we already have the header set
	if( !pPPH->GetHeader(pCtxt, PDS_AUTH_HEADER, pszBuf, &cbBuf) )
	{
	// set the auth header value
		if(!pPPH->AddHeader(pCtxt, PDS_AUTH_HEADER, pszUser))
		{
			LogEvent(PDS_ERROR,"SetAuthHeader: The PDSAuth filter was unable to set the PDSIlliadUser authentication header.",NULL);
			return SF_STATUS_REQ_ERROR;		
		} else {
			#ifdef _DEBUG
				LogEvent(PDS_DEBUG, "SetAuthHeader: The PDSAuth filter added the header successfully and will return SF_STATUS_REQ_NEXT_NOTIFICATION.",NULL);
			#endif
		}
	} else {
		#ifdef _DEBUG
			LogEvent(PDS_DEBUG, "SetAuthHeader: The PDSAuth filter found the PDSIlliadUser authentication header.",NULL);
		#endif
	}

	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}