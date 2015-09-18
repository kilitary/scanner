/*
 * IP*Works! SSH V9 C++ Edition - Demo Application
 *
 * Copyright (c) 2014 /n software inc. - All rights reserved. - www.nsoftware.com
 *
 */

#include "../../../include/ipworksssh.h"
#include <stdio.h>
#include <stdlib.h>
#define LINE_LEN 100

class MyCertMgr : public CertMgr
{
	//overwrite events here if needed
public:
	virtual int FireCertList(CertMgrCertListEventParams *e)
	{
		printf("%s\n", e->CertSubject);
		return 0;
	}
};

int main(int argc, char **argv)
{
	char * certStore;
	int certStoreSize;
	MyCertMgr certmgr;

	if (argv[1])
	{
		certmgr.SetCertStore(argv[1], sizeof(argv[1]));
	}
	else
	{
		certmgr.SetCertStore("MY", 2);
	}
	certmgr.GetCertStore(certStore, certStoreSize);
	printf("Listing all certificates in store %s:\n\n", certStore);

	certmgr.ListStoreCertificates();

	if (certmgr.GetLastErrorCode())
		printf("%d (%s)", certmgr.GetLastErrorCode(), certmgr.GetLastError());
	printf("\npress <return> to continue...\n");
	getchar();
	return 0;
}



