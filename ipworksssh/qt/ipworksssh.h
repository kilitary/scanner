// IP*Works! SSH V9 C++ Edition - C++ Interface
//
// Copyright (c) 2014 /n software inc. - All rights reserved.
//

#ifndef _IPWORKSSSH_H_
#define _IPWORKSSSH_H_
  
#ifdef WIN32
#define IPWORKSSSH_CALL __stdcall
#else //UNIX
#define IPWORKSSSH_CALL
#endif

#if defined(_MSC_VER) || defined(__BORLANDC__)
  typedef __int64 ns_int64;
  typedef unsigned __int64 ns_uint64;
#else
  typedef long long int ns_int64;
  typedef unsigned long long int ns_uint64;
#endif


#ifdef UNIX
#if defined(__LP64__) || defined(__x86_64__) || defined(__ia64__) || defined(__amd64__) || defined(__ppc64__)
#ifndef UNIX64
#define UNIX64
#endif
#endif
#endif

#ifndef UNIX64
#define IPH64CAST
#else
#define IPH64CAST (ns_int64)
#endif

typedef int (IPWORKSSSH_CALL *PIPWORKSSSH_CALLBACK)
  (void *lpObj, int event_id, int cparam, void *param[], int cbparam[]);

#ifdef WIN32

#include "certmgr.h"
#include "psclient.h"
#include "scp.h"
#include "sexec.h"
#include "sftp.h"
#include "sshclient.h"
#include "sshdaemon.h"
#include "sshell.h"
#include "sshreversetunnel.h"
#include "sshtunnel.h"


#else //UNIX

#include "certmgr.h"
#include "psclient.h"
#include "scp.h"
#include "sexec.h"
#include "sftp.h"
#include "sshclient.h"
#include "sshdaemon.h"
#include "sshell.h"
#include "sshreversetunnel.h"
#include "sshtunnel.h"


#endif

#endif //_IPWORKSSSH_H_


