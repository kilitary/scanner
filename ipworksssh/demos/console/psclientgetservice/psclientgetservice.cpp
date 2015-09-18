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

#define LINE_LEN 120

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
	int ret_code = 0;
	char buffer[LINE_LEN];

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

	ret_code = psclient.SSHLogon(psclient.GetSSHHost(), 22);
	if (ret_code != 0)
	{
		exit(0);
		return 0;
	}

	while(true)
	{
		printf("Select an action. \n0) Quit\n1) List Services\n2) Start Service\n3) Stop Service\n4) Restart Service\n");
		fgets(buffer,LINE_LEN,stdin);
		buffer[strlen(buffer)-1] = '\0';
		if (strcmp("0", buffer) == 0)
		{
			exit(0);
			return 0;
		}
		else if (strcmp("1", buffer) == 0)
		{
			printf("\nRetrieving information...\n\n");
			ret_code = psclient.Execute("get-service");

			if(ret_code)
			{
				printf("Error: %s\n", psclient.GetLastError());
			}
			else
			{
				char serviceName[LINE_LEN];
				char displayName[LINE_LEN];
				char state[LINE_LEN];

				for(int i=0; i<psclient.GetPSObjectCount(); i++)
				{
					psclient.SetPSObjectIndex(i);

					for(int j =0; j<psclient.GetPSObjectPropertyCount(); j++)
					{
						if(!strcmp(psclient.GetPSObjectPropertyName(j),"ServiceName"))
						{
							strcpy(serviceName,psclient.GetPSObjectPropertyValue(j));
						}

						if(!strcmp(psclient.GetPSObjectPropertyName(j),"DisplayName"))
						{
							strcpy(displayName,psclient.GetPSObjectPropertyValue(j));
						}

						if(!strcmp(psclient.GetPSObjectPropertyName(j),"Status"))
						{
							strcpy(state,psclient.GetPSObjectPropertyValue(j));
						}
					}

					if (strcmp("1", state))
					{
						printf("%-20.20s %-50.50s %-7.7s\n",serviceName,displayName,"Running");
					}
					else if (strcmp("4", state))
					{
						printf("%-20.20s %-50.50s %-7.7s\n",serviceName,displayName,"Stopped");
					}
					else
					{
						printf("%-20.20s %-50.50s %-7.7s\n",serviceName,displayName, state);
					}
				}
			}
		}
		else if (strcmp("2", buffer) == 0)
		{
			char buffer[LINE_LEN];
			printf("What service do you want to start? ");
			fgets(buffer,LINE_LEN,stdin);
			buffer[strlen(buffer)-1] = '\0';
			char command[LINE_LEN*2];
			strcpy(command, "start-service -name ");
			strcpy(command + 20, buffer);
			ret_code = psclient.Execute(command);
			if(ret_code)
			{
				printf("Error: %s\n", psclient.GetLastError());
			}
			else
			{
				printf("%s started \n", buffer);
			}
		}
		else if (strcmp("3", buffer) == 0)
		{
			char buffer[LINE_LEN];
			printf("What service do you want to stop? ");
			fgets(buffer,LINE_LEN,stdin);
			buffer[strlen(buffer)-1] = '\0';
			char command[LINE_LEN*2];
			strcpy(command, "stop-service -name ");
			strcpy(command + 19, buffer);
			ret_code = psclient.Execute(command);
			if(ret_code)
			{
				printf("Error: %s\n", psclient.GetLastError());
			}
			else
			{
				printf("%s stopped \n", buffer);
			}
		}
		else if (strcmp("4", buffer) == 0)
		{
			char buffer[LINE_LEN];
			printf("What service do you want to restart? ");
			fgets(buffer,LINE_LEN,stdin);
			buffer[strlen(buffer)-1] = '\0';
			char command[LINE_LEN*2];
			strcpy(command, "restart-service -name ");
			strcpy(command + 22, buffer);
			ret_code = psclient.Execute(command);
			if(ret_code)
			{
				printf("Error: %s\n", psclient.GetLastError());
			}
			else
			{
				printf("%s restarted \n", buffer);
			}
		}
	}
}






