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

class MySCP : public SCP
{
public:

	MySCP()
	{
	}

	virtual int FireSSHServerAuthentication(SCPSSHServerAuthenticationEventParams *e)
	{
		if (e->Accept) return 0;
		printf("\nServer provided the following fingerprint:\n %s\n",
		       e->Fingerprint);
		printf("Would you like to continue? [y/n] ");
		char command[LINE_LEN];
		fgets(command,LINE_LEN,stdin);
		command[strlen(command)-1] = '\0';
		if (!strcmp(command, "y")) e->Accept = true;
		else exit(0);
		return 0;
	}

	virtual int FireStartTransfer(SCPStartTransferEventParams *e)
	{
		if (e->Direction == 0) //client
			printf( "Upload Started\n");
		else if (e->Direction == 1) //server
			printf( "Download Started\n");
		return 0;
	}

	virtual int FireTransfer(SCPTransferEventParams *e)
	{
		if (e->Direction == 0) //client
			printf( "%d%% uploaded\n",  e->PercentDone);
		else if (e->Direction == 1) //server
			printf( "%d%% downloaded\n",  e->PercentDone);

		return 0;
	}

	virtual int FireSSHStatus(SCPSSHStatusEventParams *e)
	{
		printf( "%s\n", e->Message );
		return 0;
	}

	virtual int FireError( SCPErrorEventParams *e )
	{
		printf("Error %i: %s\n", e->ErrorCode, e->Description);
		return 0;
	}


};

class MySExec : public SExec
{
public:
	bool stdoutFired;

	MySExec()
	{
		stdoutFired = false;
	}

	virtual int FireStdout( SExecStdoutEventParams *e )
	{
		printf("%s", e->Text);
		stdoutFired = true;
		return 0;
	}

	virtual int FireSSHServerAuthentication(SExecSSHServerAuthenticationEventParams *e)
	{
		e->Accept = true; //if application got here the certificate was accepted
		return 0;
	}
};

int main(int argc, char **argv)
{

	MySCP scp;                  // SCP object
	MySExec sexec;				// SExec object used for listing directories
	char command[LINE_LEN];     // user's command
	char *argument;             // arguments to the user's command
	char *argument2;            // arguments to the user's command
	int ret_code=0;
	int ret_code2=0;

	printf ("This demo shows how to use the SCP component to securely copy files to and from a "
			"remote server. The SExec component is used here to list the specified remote directory.\n\n");

	//  If at least three arguments follow "scp" at the command line,
	//   read them and log the user into a server.
	if (argc >= 4)
	{
		scp.SetSSHUser(argv[2]);
		scp.SetSSHPassword(argv[3]);
		ret_code = scp.SSHLogon(argv[1], 22);
	}
	else
	{
		printf ("SSH Server: " );
		fgets(command,LINE_LEN,stdin);
		command[strlen(command)-1] = '\0';
		scp.SetSSHHost( command );
		sexec.SetSSHHost( command );
		printf ("User: " );
		fgets(command,LINE_LEN,stdin);
		command[strlen(command)-1] = '\0';
		scp.SetSSHUser( command );
		sexec.SetSSHUser( command );
		printf("Password: ");
		fgets(command,LINE_LEN,stdin);
		command[strlen(command)-1] = '\0';
		scp.SetSSHPassword( command );
		sexec.SetSSHPassword( command );
		ret_code = scp.SSHLogon(scp.GetSSHHost(), 22);
		ret_code2 = sexec.SSHLogon(scp.GetSSHHost(), 22);
	}
	if (ret_code || ret_code2) goto done;

	printf("\nThe commands for this demo are as follows:\n");
	printf( "?          exit      help     ls\n"
			"put        get\n");

	while (1)
	{

		scp.SetRemoteFile("");
		printf( "\nscp> " );
		fgets(command,LINE_LEN,stdin);
		command[strlen(command)-1] = '\0';
		argument = strtok( command, " \t\n" );

		if ( ! strcmp(command, "?") )
		{
			printf( "?          exit      help     ls\n"
			        "put        get\n");
		}

		else if ( ! strcmp(command, "exit") )
		{
			ret_code = scp.SSHLogoff();
			ret_code2 = sexec.SSHLogoff();
			break;
		}

		else if ( ! strcmp(command, "ls") )
		{
			char cmd[LINE_LEN];
			strcpy(cmd, "ls -p ");
			if ( argument = strtok( NULL, " \t\n" ) )
			{
				strcat(cmd, argument);
				ret_code2 = sexec.Execute(cmd);
			}
			else
			{
				ret_code2 = sexec.Execute(cmd);
			}

			while (!sexec.stdoutFired) sexec.DoEvents();

			sexec.stdoutFired = false;
		}

		else if ( ! strcmp(command, "get") )
		{
			argument = strtok( NULL, " \t\n" ); //get the local file from the first argument
			argument2 = strtok( NULL, " \t\n" );//get the remote file from the second argument

			if (!argument || !argument2)
			{
				printf("Invalid command!\n\nThe expected format is \"put <RemoteFile> <LocalFile>\"\n");
			}
			else
			{
				scp.SetLocalFile(argument2);
				scp.SetRemoteFile(argument);
				ret_code = scp.Download();
				printf(  "Download complete.\n");
			}
		}

		else if ( ! strcmp(command, "help") )
		{
			printf( "?          exit      help     ls\n"
			        "put        get\n");
		}
		else if ( ! strcmp(command, "put") )
		{
			argument = strtok( NULL, " \t\n" ); //get the remote file from the first argument
			argument2 = strtok( NULL, " \t\n" );//get the local file from the second argument

			if (!argument || !argument2)
			{
				printf("Invalid command!\n\nThe expected format is \"put <RemoteFile> <LocalFile>\"\n");
			}
			else
			{
				scp.SetLocalFile(argument);
				scp.SetRemoteFile(argument2);
				ret_code = scp.Upload();
				printf(  "Upload complete.\n");
			}
		}
		else if ( ! strcmp(command, "") )
		{
			// Do nothing
		}
		else
		{
			printf( "Bad command / Not implemented in demo.\n" );
		} // end of command checking
		if (ret_code)     // Got an error.  The user is done.
		{
			printf("\nError: %d", ret_code);
			if (scp.GetLastError())
			{
				printf( " \"%s\"\n", scp.GetLastError() );
			}
		}
		
		if (ret_code2)
		{
			printf( "\nError: %d", ret_code );
			if (sexec.GetLastError())
			{
				printf( " \"%s\"\n", scp.GetLastError() );
			}
		}
		ret_code = 0;    // flush out error
		ret_code2 = 0;   // flush out error

		//fire any events that still need to be fired
		scp.DoEvents();
		sexec.DoEvents();
	}  // end of main while loop

done:
	if (ret_code)     // Got an error.  The user is done.
	{
		printf( "\nError: %d", ret_code );
		if (scp.GetLastError())
		{
			printf( " \"%s\"\n", scp.GetLastError() );
		}
		printf("Press any key to continue...");
		getchar();
		exit(ret_code);
	}
	if (ret_code2)
	{
		printf( "\nError: %d", ret_code );
		if (sexec.GetLastError())
		{
			printf( " \"%s\"\n", scp.GetLastError() );
		}
		printf("Press any key to continue...");
		getchar();
		exit(ret_code2);
	}
	return 0;
}
