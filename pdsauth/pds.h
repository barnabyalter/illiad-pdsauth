#ifndef PDSAuth_PDS_H
#define PDSAuth_PDS_H

#include "atlrx.h"
#include <strsafe.h>
#import <msxml4.dll>

#include "Logging.h"

#define MAX_BUFFER_SIZE		4096		//the maximum buffer size

/**
* Validates a PDS cookie
* 
* @param the validation URL for PDS
* @return a pointer to a dynamically allocated string
*/
void PDSValidateSession(char* pszPDSValidateURL, char** pszUser, char** pszStatus, char** pszIllPermission);

/**
* Validates a PDS XML response and retrieves User Name
* 
* @param a pointer to the returned XML document
* @return a pointer to a dynamically allocated string
*/
char* PDSValidateUserXML(CComPtr<MSXML2::IXMLDOMDocument2> pXMLDoc);

/**
* Validates a PDS XML response and retrieves Borrower Status
* 
* @param a pointer to the returned XML document
* @return a pointer to a dynamically allocated string
*/
char* PDSValidateStatusXML(CComPtr<MSXML2::IXMLDOMDocument2> pXMLDoc);

/**
* Validates a PDS XML response and retrieves ILL Permissions Flag
* 
* @param a pointer to the returned XML document
* @return a pointer to a dynamically allocated string
*/
char* PDSValidatePermissionFlagXML(CComPtr<MSXML2::IXMLDOMDocument2> pXMLDoc);

#endif