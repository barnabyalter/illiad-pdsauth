#include "PDS.h"

void PDSValidateSession(char* pszPDSValidateURL,char** pszUser,char** pszStatus,char** pszIllPermission)
{

	if ( FAILED(CoInitialize(NULL)) )
	{
		LogEvent(PDS_ERROR,"PDSValidateSession: The PDSAuth ISAPI filter was unable to initialize COM",NULL);
		//return NULL;
	}

	CComPtr<MSXML2::IXMLHTTPRequest> pXMLRequest = 0;

	// using XMLHTTPRequest so we can get the string of a PDS response (non valid XML)
	if(SUCCEEDED( pXMLRequest.CoCreateInstance(__uuidof(XMLHTTPRequest)) ) )
	{

		// open and send the request which populates the responseText member
		if(SUCCEEDED( pXMLRequest->open("GET", pszPDSValidateURL, false) )
			&& SUCCEEDED( pXMLRequest->send() ) )
		{
			CComPtr<MSXML2::IXMLDOMDocument2> pXMLDoc = 0;
			//try to load the response as XML
			if (SUCCEEDED( pXMLDoc.CoCreateInstance(__uuidof(MSXML2::DOMDocument30)) ))
			{
				if (VARIANT_TRUE == pXMLDoc->loadXML(pXMLRequest->responseText) )
				{
					//valid XML response
					*pszUser = PDSValidateUserXML(pXMLDoc);
					*pszStatus = PDSValidateStatusXML(pXMLDoc);
					*pszIllPermission = PDSValidatePermissionFlagXML(pXMLDoc);
				}
				else
				{
					LogEvent(PDS_ERROR,"PDSValidateSession: The PDSAuth ISAPI filter was unable to load XML response ",NULL);
				}
			}
			else
				LogEvent(PDS_ERROR,"PDSValidateSession: The PDSAuth ISAPI filter was unable to create an XML Document Instance ",pXMLRequest->responseText);
		}
		else
			LogEvent(PDS_ERROR,"PDSValidateSession: The PDSAuth ISAPI filter was unable to load the Validation URL XML Document",pszPDSValidateURL);
	}
	else
		LogEvent(PDS_ERROR,"PDSValidateSession: The PDSAuth ISAPI filter was unable to create an XML Instance ",NULL);

	CoUninitialize();

	//return pszUser;
}

char* PDSValidateUserXML(CComPtr<MSXML2::IXMLDOMDocument2> pXMLDoc)
{
	char* pszUser = NULL;
	CComPtr<MSXML2::IXMLDOMNode> pXMLNode = 0;

	// Look for the authentication succes node
	pXMLNode = pXMLDoc->selectSingleNode(_bstr_t("//bor-info"));
	if (pXMLNode != NULL)
	{
		// Retrieve the user name node and value
		pXMLNode = pXMLDoc->selectSingleNode("//bor-info/id");
		if (pXMLNode != NULL)
		{
			DWORD cbBuf;				

			cbBuf = (DWORD)strlen((char*)pXMLNode->text) + 1;
			if(cbBuf < MAX_BUFFER_SIZE)
			{
				pszUser = new char[ cbBuf ];
				StringCchCopyEx(pszUser,cbBuf,pXMLNode->text,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
				#ifdef _DEBUG
					LogEvent(PDS_DEBUG,"The PDSAuth ISAPI filter successfully PDS authenticated user",pszUser);
				#endif
			}
			else
				LogEvent(PDS_ERROR,"PDSValidateUserXML: The PDSAuth ISAPI filter was unable to parse an extended validated user name because it was too large",_bstr_t(pXMLDoc->xml));
		}
		else
			LogEvent(PDS_ERROR,"PDSValidateUserXML: The PDSAuth ISAPI filter was unable to parse an extended validation Authentication response",_bstr_t(pXMLDoc->xml));

	}
	else
	{
		// we don't have a success response, check for a failure response
		pXMLNode = pXMLDoc->selectSingleNode("//pds/error");

		if (pXMLNode != NULL)
		{
			#ifdef _DEBUG
				LogEvent(PDS_DEBUG,"The PDSAuth ISAPI filter recieved a PDS Authentication Failure response",_bstr_t(pXMLDoc->xml));
			#endif
		}
		else
			LogEvent(PDS_ERROR,"PDSValidateUserXML: The PDSAuth ISAPI filter was unable to parse an extended validation Authentication response",_bstr_t(pXMLDoc->xml));
	}

	return pszUser;
}

char* PDSValidateStatusXML(CComPtr<MSXML2::IXMLDOMDocument2> pXMLDoc)
{
	char* pszUser = NULL;
	CComPtr<MSXML2::IXMLDOMNode> pXMLNode = 0;

	// Look for the authentication succes node
	pXMLNode = pXMLDoc->selectSingleNode(_bstr_t("//bor-info"));
	if (pXMLNode != NULL)
	{
		// Retrieve the borrower status node and value
		pXMLNode = pXMLDoc->selectSingleNode("//bor-info/bor-status");
		if (pXMLNode != NULL)
		{
			DWORD cbBuf;				

			cbBuf = (DWORD)strlen((char*)pXMLNode->text) + 1;
			if(cbBuf < MAX_BUFFER_SIZE)
			{
				pszUser = new char[ cbBuf ];
				StringCchCopyEx(pszUser,cbBuf,pXMLNode->text,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
				#ifdef _DEBUG
					LogEvent(PDS_DEBUG,"The PDSAuth ISAPI filter successfully retrieved borrower status",pszUser);
				#endif
			}
			else
				LogEvent(PDS_ERROR,"PDSValidateStatusXML: The PDSAuth ISAPI filter was unable to parse an extended validated borrower status because it was too large",_bstr_t(pXMLDoc->xml));
		}
		else
			LogEvent(PDS_ERROR,"PDSValidateStatusXML: The PDSAuth ISAPI filter was unable to parse an extended validation Authentication response",_bstr_t(pXMLDoc->xml));

	}
	else
	{
		// we don't have a success response, check for a failure response
		pXMLNode = pXMLDoc->selectSingleNode("//pds/error");

		if (pXMLNode != NULL)
		{
			#ifdef _DEBUG
				LogEvent(PDS_DEBUG,"The PDSAuth ISAPI filter recieved a PDS Authentication Failure response",_bstr_t(pXMLDoc->xml));
			#endif
		}
		else
			LogEvent(PDS_ERROR,"PDSValidateStatusXML: The PDSAuth ISAPI filter was unable to parse an extended validation Authentication response",_bstr_t(pXMLDoc->xml));
	}

	return pszUser;
}

char* PDSValidatePermissionFlagXML(CComPtr<MSXML2::IXMLDOMDocument2> pXMLDoc)
{
	char* pszUser = NULL;
	CComPtr<MSXML2::IXMLDOMNode> pXMLNode = 0;

	// Look for the authentication succes node
	pXMLNode = pXMLDoc->selectSingleNode(_bstr_t("//bor-info"));
	if (pXMLNode != NULL)
	{
		// Retrieve the ill-permission node and value
		pXMLNode = pXMLDoc->selectSingleNode("//bor-info/ill-permission");
		if (pXMLNode != NULL)
		{
			DWORD cbBuf;				

			cbBuf = (DWORD)strlen((char*)pXMLNode->text) + 1;
			if(cbBuf < MAX_BUFFER_SIZE)
			{
				pszUser = new char[ cbBuf ];
				StringCchCopyEx(pszUser,cbBuf,pXMLNode->text,NULL,NULL,STRSAFE_FILL_BEHIND_NULL);
				#ifdef _DEBUG
					LogEvent(PDS_DEBUG,"The PDSAuth ISAPI filter successfully retrieved borrower ILL permission",pszUser);
				#endif
			}
			else
				LogEvent(PDS_ERROR,"PDSValidatePermissionFlagXML: The PDSAuth ISAPI filter was unable to parse an extended validated borrower status because it was too large",_bstr_t(pXMLDoc->xml));
		}
		else
			LogEvent(PDS_ERROR,"PDSValidatePermissionFlagXML: The PDSAuth ISAPI filter was unable to parse an extended validation Authentication response",_bstr_t(pXMLDoc->xml));

	}
	else
	{
		// we don't have a success response, check for a failure response
		pXMLNode = pXMLDoc->selectSingleNode("//pds/error");

		if (pXMLNode != NULL)
		{
			#ifdef _DEBUG
				LogEvent(PDS_DEBUG,"The PDSAuth ISAPI filter recieved a PDS Authentication Failure response",_bstr_t(pXMLDoc->xml));
			#endif
		}
		else
			LogEvent(PDS_ERROR,"PDSValidatePermissionFlagXML: The PDSAuth ISAPI filter was unable to parse an extended validation Authentication response",_bstr_t(pXMLDoc->xml));
	}

	return pszUser;
}