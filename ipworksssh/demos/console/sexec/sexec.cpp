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
#define LINE_LEN 100

class MySexec : public SExec
{
public:
	int FireStderr(SExecStderrEventParams *e)
	{
		fwrite(e->Text, 1, e->lenText, stderr);
		return 0;
	}
	int FireStdout(SExecStdoutEventParams *e)
	{
		fwrite(e->Text, 1, e->lenText, stdout);
		return 0;
	}

	int FireSSHServerAuthentication(SExecSSHServerAuthenticationEventParams *e)
	{
		e->Accept = true;
		return 0;
	}
};

int main(int argc, char **argv)
{

	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <host> <user> <password> <command>\n", argv[0]);
		fprintf(stderr, "\npress <return> to continue...\n");
		getchar();
		exit(1);
	}

	MySexec sexec;
	
	int ret_code = sexec.SetTimeout(60);
	if (ret_code) goto done;

	ret_code = sexec.SetSSHUser(argv[2]);
	if (ret_code) goto done;

	ret_code = sexec.SetSSHPassword(argv[3]);
	if (ret_code) goto done;

	ret_code = sexec.SSHLogon(argv[1],22);
	if (ret_code) goto done;

	ret_code = sexec.Execute(argv[4]);
	if (ret_code) goto done;

done:
	if (ret_code)
	{
		fprintf(stderr, "error: %d", ret_code);
		if (sexec.GetLastError())
			fprintf(stderr, " (%s)", sexec.GetLastError());
		fprintf(stderr, "\nexiting...\n");
		exit(1);
	}
	fprintf(stderr, "\npress <return> to continue...\n");
	getchar();
	return 0;
}
