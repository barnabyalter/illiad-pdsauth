#ifndef PDSAuth_h
#define PDSAuth_h

#include "atlrx.h"
#include <httpfilt.h>
#include <stdio.h>
#include <time.h>
#include <strsafe.h>

#include "Logging.h"
#include "Config.h"
#include "PDS.h"
#include "Cookie.h"

/**
*	Constant Definitions
*	These definitions should be the same across either all instances, or all client instances 
*	for an installation.
*/
#define APP_PARAM_NAME		"illiad"	//the expected name of the application url parameter
#define SERVICE_PARAM_NAME	"url"		//the expected name of the service url parameter
#define PDS_AUTH_HEADER		"PDSIlliadUser:"	//the name of the authentication header variable
#define	HTTP_TIMEOUT		30			//the default timeout for an http transation (in seconds)
#define DEFAULT_BUFFER_SIZE 64			//the default buffer size
#define URL_BUFFER_SIZE		4096		//the maximum buffer size for urls (originally 2048)
#define MAX_BUFFER_SIZE		4096		//the maximum buffer size
/**
*	Static Definitions
*	These variables will be set on Initialization and will be the same across all threads.
*/
char* pszLoginURL;						//Url of the PDS login page
char* pszValidateURL;					//Url of the PDS validation page w/query string params
char* pszPDSCookie;						//Name of the PDS Cookie
char* pszCookieDomain;					//Domain of the local cookie that's created
char* pszCookieName;					//Name of the local cookie that's created 
char* pszCookiePath;					//Path of the local cookie that's created 
char* pszAccessDenied;					//The URL to redirect unauthorized users to
char* pszServiceURL;					//service url of the application (defaults to the requested url)
char* pszApplicationPath;				//The root of the application
DWORD dwCookieTimeout;					//the timeout interval of the local authentication cookie
char* pszCookieSecret;					//the secret check value for the local authentication cookie
HCRYPTPROV hCryptProv;					// Handle to the encryption provider context
HCRYPTKEY  hCryptKey;					// Handle to the encryption key
char* ppszPatronStatuses[DEFAULT_BUFFER_SIZE];	//Array of patron statuses to match for protection

/**
* Header preprocessing handling.
* 
* @param a handle to the filter context
* @param the raw headers of the request
*/
DWORD OnPreprocHeaders(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH);

/**
* Retrieves the redirect URL from the configuration or URL parameters.
* 
* @param a handle to the filter context
* @return a pointer to a dynamically allocated string
*/
char* GetRedirectUrl(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH);

/**
* Retrieves the PDS cookie from the headers.
* 
* @param a handle to the filter context
* @return a pointer to a dynamically allocated string
*/
char* GetPDSCookie(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH);

/**
* Retrieves the local cookie from the request header
* 
* @param a handle to the filter context
* @return a pointer to a dynamically allocated string
*/
char* GetLocalAuthCookie(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH);

/**
* Assembles a redirection url and header and modifies the request to perform
* a redirection.
* 
* @param a handle to the filter context
* @param a pointer to a dynamically allocated string with the service id
* @return a response status code
*/
DWORD RedirectToLogin(HTTP_FILTER_CONTEXT* pCtxt, char* pszServiceID);

/**
* Assembles an access denied redirection url and header and modifies the request to perform
* a redirection.
* 
* @param a handle to the filter context
* @param a pointer to a dynamically allocated string with the access denied URL
* @return a response status code
*/
DWORD RedirectToAccessDenied(HTTP_FILTER_CONTEXT* pCtxt, char* accessDeniedURL);

/**
* Assembles a redirection url and header and modifies the request to perform
* a redirection.  It also attaches the local authenticated user cookie.
* 
* @param a handle to the filter context
* @param a pointer to a dynamically allocated string with the service id
* @param a pointer to a dynamically allocated string with the encrypted cookie value
* @return a response status code
*/
DWORD RedirectWithCookie(HTTP_FILTER_CONTEXT* pCtxt, char* pszServiceID, char* pszEncryptedCookie);

/**
* Assembles a redirection url and header and modifies the request to perform
* a redirection.  It also deletes the local authenticated user cookie.
* 
* @param a handle to the filter context
* @param a pointer to a dynamically allocated string with the service id
* @return a response status code
*/
DWORD RedirectWithCookieDeleted(HTTP_FILTER_CONTEXT* pCtxt, char* pszServiceID);

/**
* Attaches the authenticated user id to the header and allows the request to continue.
* 
* @param a handle to the filter context
* @param a pointer to a dynamically allocated string with the user id
* @return a response status code
*/
DWORD SetAuthHeader(HTTP_FILTER_CONTEXT* pCtxt, HTTP_FILTER_PREPROC_HEADERS* pPPH, char* pszUser);

#endif
