/*
 * IP*Works! SSH V9 C++ Edition - Demo Application
 *
 * Copyright (c) 2014 /n software inc. - All rights reserved. - www.nsoftware.com
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../../include/ipworksssh.h"

#define LINE_LEN 80

class MyPSClient : public PSClient
{
public:
	virtual int FireSSHServerAuthentication(PSClientSSHServerAuthenticationEventParams *e)
	{
		e->Accept = true;
		return 0;
	}
};

int main(int argc, char **argv)
{

	MyPSClient psclient;
	char buffer[LINE_LEN];
	int ret_code = 0;

	printf("Remote Host: ");
	fgets(buffer,LINE_LEN,stdin);
	buffer[strlen(buffer)-1] = '\0';
	psclient.SetSSHHost(buffer);

	printf ("User (DOMAIN\\Username): " );
	fgets( buffer,LINE_LEN,stdin);
	buffer[strlen(buffer)-1] = '\0';
	psclient.SetSSHUser(buffer);

	printf ("Password: " );
	fgets( buffer,LINE_LEN,stdin);
	buffer[strlen(buffer)-1] = '\0';
	psclient.SetSSHPassword(buffer);

	printf("\nRetrieving information...");

	ret_code = psclient.Execute("get-process");

	if(ret_code)
	{
		printf("Error: %s\n", psclient.GetLastError());
	}
	else
	{
		printf("\n\nProcess     \t\tId\t\tHandles\t\tVirtual Mem\n\n");

		char processName[LINE_LEN];
		char processId[LINE_LEN];
		char handleCount[LINE_LEN];
		char virtualMem[LINE_LEN];

		for(int i=0; i<psclient.GetPSObjectCount(); i++)
		{
			psclient.SetPSObjectIndex(i);

			for(int j =0; j<psclient.GetPSObjectPropertyCount(); j++)
			{
				if(!strcmp(psclient.GetPSObjectPropertyName(j),"ProcessName"))
				{
					strcpy(processName,psclient.GetPSObjectPropertyValue(j));
				}

				if(!strcmp(psclient.GetPSObjectPropertyName(j),"Id"))
				{
					strcpy(processId,psclient.GetPSObjectPropertyValue(j));
				}

				if(!strcmp(psclient.GetPSObjectPropertyName(j),"HandleCount"))
				{
					strcpy(handleCount,psclient.GetPSObjectPropertyValue(j));
				}

				if(!strcmp(psclient.GetPSObjectPropertyName(j),"VirtualMemorySize"))
				{
					strcpy(virtualMem,psclient.GetPSObjectPropertyValue(j));
				}
			}
			printf("%-12.12s\t\t%s\t\t%s\t\t%s\n",processName,processId,handleCount,virtualMem);
		}
	}

	fprintf(stderr, "\npress <return> to continue...\n");
	getchar();
	exit(ret_code);
	return 0;
}






