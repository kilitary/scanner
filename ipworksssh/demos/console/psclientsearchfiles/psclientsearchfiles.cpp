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
	char searchPath[LINE_LEN];
	char searchFilter[LINE_LEN];
	char searchTerm[LINE_LEN];
	char command[200];

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

	printf("Search Path [C:\\]: ");
	fgets(searchPath,LINE_LEN,stdin);
	searchPath[strlen(searchPath) -1] = '\0';
	if(!strcmp(searchPath,""))
		strcpy(searchPath,"C:\\");

	printf("Search Filter [*.txt]: ");
	fgets(searchFilter,LINE_LEN,stdin);
	searchFilter[strlen(searchFilter) -1] = '\0';
	if(!strcmp(searchFilter,""))
		strcpy(searchFilter,"*.txt");

	printf("Search Term [test]: ");
	fgets(searchTerm,LINE_LEN,stdin);
	searchTerm[strlen(searchTerm) -1] = '\0';
	if(!strcmp(searchTerm,""))
		strcpy(searchTerm,"test");

	printf("Recurse (y/n)?: ");
	fgets(buffer,LINE_LEN,stdin);
	buffer[strlen(buffer)-1] = '\0';

	if(!strcmp(buffer,"Y") || !strcmp(buffer,"y"))
	{
		strcpy(command,"gci -recurse -path \"");
		strcat(command,searchPath);
		strcat(command,"\" -include ");
		strcat(command,searchFilter);
	}
	else
	{
		strcpy(command,"gci -path \"");
		strcat(command,searchPath);
		strcat(command,"\\");
		strcat(command,searchFilter);
		strcat(command,"\"");
	}

	strcat(command," | select-string \"");
	strcat(command,searchTerm);
	strcat(command,"\"");

	printf("\n\nSearching ...\n\n");

	ret_code = psclient.Execute(command);

	if(ret_code)
	{
		printf("Error: %s\n", psclient.GetLastError());
	}
	else
	{
		printf("%-20.20s  %-8.8s  %-30.30s\n","Path","Line Num","Line Text");

		char filePath[LINE_LEN];
		char lineNum[LINE_LEN];
		char lineText[LINE_LEN];

		for(int i=0; i<psclient.GetPSObjectCount(); i++)
		{
			psclient.SetPSObjectIndex(i);

			for(int j =0; j<psclient.GetPSObjectPropertyCount(); j++)
			{
				if(!strcmp(psclient.GetPSObjectPropertyName(j),"LineNumber"))
				{
					strcpy(lineNum,psclient.GetPSObjectPropertyValue(j));
				}

				if(!strcmp(psclient.GetPSObjectPropertyName(j),"Line"))
				{
					strncpy(lineText,psclient.GetPSObjectPropertyValue(j),LINE_LEN);
				}

				if(!strcmp(psclient.GetPSObjectPropertyName(j),"Path"))
				{
					strcpy(filePath,psclient.GetPSObjectPropertyValue(j));
				}
			}
			printf("%-20.20s  %-8.8s  %-30.30s\n",filePath,lineNum,lineText);
		}
	}

	fprintf(stderr, "\npress <return> to continue...\n");
	getchar();
	exit(ret_code);
	return 0;
}









