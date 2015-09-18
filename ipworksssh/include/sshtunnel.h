/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHTUNNEL_H_
#define _IPWORKSSSH_SSHTUNNEL_H_

#define IPWORKSSSH_ONLY_TYPES
#include "ipworksssh.h"
#include "ipworksssh.key"

//FirewallTypes
#define FW_NONE                                            0
#define FW_TUNNEL                                          1
#define FW_SOCKS4                                          2
#define FW_SOCKS5                                          3

//SSHAuthModes
#define AM_NONE                                            0
#define AM_MULTI_FACTOR                                    1
#define AM_PASSWORD                                        2
#define AM_PUBLIC_KEY                                      3
#define AM_KEYBOARD_INTERACTIVE                            4
#define AM_GSSAPIWITH_MIC                                  5
#define AM_CUSTOM                                          6

//CertStoreTypes
#define CST_USER                                           0
#define CST_MACHINE                                        1
#define CST_PFXFILE                                        2
#define CST_PFXBLOB                                        3
#define CST_JKSFILE                                        4
#define CST_JKSBLOB                                        5
#define CST_PEMKEY_FILE                                    6
#define CST_PEMKEY_BLOB                                    7
#define CST_PUBLIC_KEY_FILE                                8
#define CST_PUBLIC_KEY_BLOB                                9
#define CST_SSHPUBLIC_KEY_BLOB                             10
#define CST_P7BFILE                                        11
#define CST_P7BBLOB                                        12
#define CST_SSHPUBLIC_KEY_FILE                             13
#define CST_PPKFILE                                        14
#define CST_PPKBLOB                                        15
#define CST_XMLFILE                                        16
#define CST_XMLBLOB                                        17


extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_StaticInit(void *hInst);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_StaticDestroy();

#ifdef WIN32
#include <windows.h>
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

typedef struct {
  int ConnectionId;
  int StatusCode;
  const char* Description;
  int reserved;
} SSHTunnelConnectedEventParams;

typedef struct {
  const char* Address;
  int Port;
  int Accept;
  int reserved;
} SSHTunnelConnectionRequestEventParams;

typedef struct {
  int ConnectionId;
  const char* Text;
  int EOL;
  int lenText;
  int reserved;
} SSHTunnelDataInEventParams;

typedef struct {
  int ConnectionId;
  int StatusCode;
  const char* Description;
  int reserved;
} SSHTunnelDisconnectedEventParams;

typedef struct {
  int ConnectionId;
  int ErrorCode;
  const char* Description;
  int reserved;
} SSHTunnelErrorEventParams;

typedef struct {
  const char* Packet;
  int reserved;
} SSHTunnelSSHCustomAuthEventParams;

typedef struct {
  const char* Name;
  const char* Instructions;
  const char* Prompt;
  const char* Response;
  int EchoResponse;
  int reserved;
} SSHTunnelSSHKeyboardInteractiveEventParams;

typedef struct {
  const char* HostKey;
  const char* Fingerprint;
  const char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SSHTunnelSSHServerAuthenticationEventParams;

typedef struct {
  const char* Message;
  int reserved;
} SSHTunnelSSHStatusEventParams;



class SSHTunnel {
  
  public: //events
  
    virtual int FireConnected(SSHTunnelConnectedEventParams *e) {return 0;}
    virtual int FireConnectionRequest(SSHTunnelConnectionRequestEventParams *e) {return 0;}
    virtual int FireDataIn(SSHTunnelDataInEventParams *e) {return 0;}
    virtual int FireDisconnected(SSHTunnelDisconnectedEventParams *e) {return 0;}
    virtual int FireError(SSHTunnelErrorEventParams *e) {return 0;}
    virtual int FireSSHCustomAuth(SSHTunnelSSHCustomAuthEventParams *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SSHTunnelSSHKeyboardInteractiveEventParams *e) {return 0;}
    virtual int FireSSHServerAuthentication(SSHTunnelSSHServerAuthenticationEventParams *e) {return 0;}
    virtual int FireSSHStatus(SSHTunnelSSHStatusEventParams *e) {return 0;}


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SSHTunnelEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      if (event_id > 10000) return ((SSHTunnel*)lpObj)->SSHTunnelEventSinkW(event_id - 10000, cparam, param, cbparam);
      switch (event_id) {
         case 1: {
            SSHTunnelConnectedEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SSHTunnelConnectionRequestEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireConnectionRequest(&e);
            param[2] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 3: {
            SSHTunnelDataInEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[1]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireDataIn(&e);
            break;
         }
         case 4: {
            SSHTunnelDisconnectedEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 5: {
            SSHTunnelErrorEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireError(&e);
            break;
         }
         case 6: {
            SSHTunnelSSHCustomAuthEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)IPH64CAST(e.Packet);
            break;
         }
         case 7: {
            SSHTunnelSSHKeyboardInteractiveEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)IPH64CAST(e.Response);
            break;
         }
         case 8: {
            SSHTunnelSSHServerAuthenticationEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 9: {
            SSHTunnelSSHStatusEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }

    virtual int SSHTunnelEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {return 0;}

  public:

    SSHTunnel(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_81) {
      m_pObj = IPWorksSSH_SSHTunnel_Create(SSHTunnelEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~SSHTunnel() {
      IPWorksSSH_SSHTunnel_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_SSHTunnel_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_SSHTunnel_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline int GetConnected() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 1, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)IPH64CAST(bConnected);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 1, 0, val, 0);
    }
    inline int GetConnectionBacklog() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnectionBacklog(int iConnectionBacklog) {
      void* val = (void*)IPH64CAST(iConnectionBacklog);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 2, 0, val, 0);
    }
    inline int GetClientCount() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 3, 0, 0);
      return (int)(long)val;
    }

    inline int GetClientAcceptData(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 4, iClientId, 0);
      return (int)(long)val;
    }
    inline int SetClientAcceptData(int iClientId, int bClientAcceptData) {
      void* val = (void*)IPH64CAST(bClientAcceptData);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 4, iClientId, val, 0);
    }
    inline int GetClientBytesSent(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 5, iClientId, 0);
      return (int)(long)val;
    }

    inline int GetClientConnected(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 6, iClientId, 0);
      return (int)(long)val;
    }
    inline int SetClientConnected(int iClientId, int bClientConnected) {
      void* val = (void*)IPH64CAST(bClientConnected);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 6, iClientId, val, 0);
    }
    inline char* GetClientConnectionId(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 7, iClientId, 0);
      return (char*)val;
    }



    inline int SetClientDataToSend(int iClientId, const char *lpClientDataToSend, int lenClientDataToSend) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 8, iClientId, (void*)lpClientDataToSend, lenClientDataToSend);
    }

    inline int GetClientEOL(int iClientId, char *&lpClientEOL, int &lenClientEOL) {
      lpClientEOL = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 9, iClientId, &lenClientEOL);
      return lpClientEOL ? 0 : lenClientEOL;
    }

    inline int SetClientEOL(int iClientId, const char *lpClientEOL, int lenClientEOL) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 9, iClientId, (void*)lpClientEOL, lenClientEOL);
    }

    inline char* GetClientLocalAddress(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 10, iClientId, 0);
      return (char*)val;
    }


    inline char* GetClientRemoteHost(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 11, iClientId, 0);
      return (char*)val;
    }


    inline int GetClientRemotePort(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 12, iClientId, 0);
      return (int)(long)val;
    }

    inline int GetClientSingleLineMode(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 13, iClientId, 0);
      return (int)(long)val;
    }
    inline int SetClientSingleLineMode(int iClientId, int bClientSingleLineMode) {
      void* val = (void*)IPH64CAST(bClientSingleLineMode);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 13, iClientId, val, 0);
    }
    inline int GetClientTimeout(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 14, iClientId, 0);
      return (int)(long)val;
    }
    inline int SetClientTimeout(int iClientId, int iClientTimeout) {
      void* val = (void*)IPH64CAST(iClientTimeout);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 14, iClientId, val, 0);
    }
    inline int GetDefaultEOL(char *&lpDefaultEOL, int &lenDefaultEOL) {
      lpDefaultEOL = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 15, 0, &lenDefaultEOL);
      return lpDefaultEOL ? 0 : lenDefaultEOL;
    }

    inline int SetDefaultEOL(const char *lpDefaultEOL, int lenDefaultEOL) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 15, 0, (void*)lpDefaultEOL, lenDefaultEOL);
    }

    inline int GetDefaultSingleLineMode() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 16, 0, 0);
      return (int)(long)val;
    }
    inline int SetDefaultSingleLineMode(int bDefaultSingleLineMode) {
      void* val = (void*)IPH64CAST(bDefaultSingleLineMode);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 16, 0, val, 0);
    }
    inline int GetDefaultTimeout() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 17, 0, 0);
      return (int)(long)val;
    }
    inline int SetDefaultTimeout(int iDefaultTimeout) {
      void* val = (void*)IPH64CAST(iDefaultTimeout);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 17, 0, val, 0);
    }
    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 18, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)IPH64CAST(bFirewallAutoDetect);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 18, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 19, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)IPH64CAST(iFirewallType);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 19, 0, val, 0);
    }
    inline char* GetFirewallHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 20, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallHost(const char *lpFirewallHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 20, 0, (void*)lpFirewallHost, 0);
    }

    inline char* GetFirewallPassword() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 21, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallPassword(const char *lpFirewallPassword) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 21, 0, (void*)lpFirewallPassword, 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 22, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)IPH64CAST(lFirewallPort);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 22, 0, val, 0);
    }
    inline char* GetFirewallUser() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 23, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallUser(const char *lpFirewallUser) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 23, 0, (void*)lpFirewallUser, 0);
    }

    inline int GetKeepAlive() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 24, 0, 0);
      return (int)(long)val;
    }
    inline int SetKeepAlive(int bKeepAlive) {
      void* val = (void*)IPH64CAST(bKeepAlive);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 24, 0, val, 0);
    }
    inline int GetLinger() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 25, 0, 0);
      return (int)(long)val;
    }
    inline int SetLinger(int bLinger) {
      void* val = (void*)IPH64CAST(bLinger);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 25, 0, val, 0);
    }
    inline int GetListening() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetListening(int bListening) {
      void* val = (void*)IPH64CAST(bListening);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 26, 0, val, 0);
    }
    inline char* GetLocalHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 27, 0, 0);
      return (char*)val;
    }

    inline int SetLocalHost(const char *lpLocalHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 27, 0, (void*)lpLocalHost, 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 28, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)IPH64CAST(lLocalPort);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 28, 0, val, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncoded(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 29, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 29, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 30, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)IPH64CAST(iSSHAuthMode);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 30, 0, val, 0);
    }
    inline int GetSSHCertEncoded(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 31, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }

    inline int SetSSHCertEncoded(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 31, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int GetSSHCertStore(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 32, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }

    inline int SetSSHCertStore(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 32, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }

    inline char* GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 33, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertStorePassword(const char *lpSSHCertStorePassword) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 33, 0, (void*)lpSSHCertStorePassword, 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 34, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)IPH64CAST(iSSHCertStoreType);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 34, 0, val, 0);
    }
    inline char* GetSSHCertSubject() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 35, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertSubject(const char *lpSSHCertSubject) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 35, 0, (void*)lpSSHCertSubject, 0);
    }

    inline char* GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 36, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCompressionAlgorithms(const char *lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 36, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline char* GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 37, 0, 0);
      return (char*)val;
    }

    inline int SetSSHEncryptionAlgorithms(const char *lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 37, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline char* GetSSHForwardHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 38, 0, 0);
      return (char*)val;
    }

    inline int SetSSHForwardHost(const char *lpSSHForwardHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 38, 0, (void*)lpSSHForwardHost, 0);
    }

    inline int GetSSHForwardPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 39, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHForwardPort(int lSSHForwardPort) {
      void* val = (void*)IPH64CAST(lSSHForwardPort);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 39, 0, val, 0);
    }
    inline char* GetSSHHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 40, 0, 0);
      return (char*)val;
    }

    inline int SetSSHHost(const char *lpSSHHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 40, 0, (void*)lpSSHHost, 0);
    }

    inline char* GetSSHPassword() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 41, 0, 0);
      return (char*)val;
    }

    inline int SetSSHPassword(const char *lpSSHPassword) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 41, 0, (void*)lpSSHPassword, 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 42, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)IPH64CAST(lSSHPort);
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 42, 0, val, 0);
    }
    inline char* GetSSHUser() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 43, 0, 0);
      return (char*)val;
    }

    inline int SetSSHUser(const char *lpSSHUser) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 43, 0, (void*)lpSSHUser, 0);
    }


  public: //methods

    inline char* Config(const char* lpszConfigurationString) {
      void *param[1+1] = {(void*)IPH64CAST(lpszConfigurationString), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 2, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* DecodePacket(const char* lpszEncodedPacket, int *lpSize = 0) {
      void *param[1+1] = {(void*)IPH64CAST(lpszEncodedPacket), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 3, 1, param, cbparam);
      if (lpSize) *lpSize = cbparam[1];
      return (char*)IPH64CAST(param[1]);
    }
    inline int Disconnect(int iConnectionId) {
      void *param[1+1] = {(void*)IPH64CAST(iConnectionId), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 4, 1, param, cbparam);
      
      
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 5, 0, param, cbparam);
      
      
    }
    inline char* EncodePacket(const char* lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)IPH64CAST(lpPacket), 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 6, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* GetSSHParam(const char* lpPayload, int lenPayload, const char* lpszField) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 7, 2, param, cbparam);
      
      return (char*)IPH64CAST(param[2]);
    }
    inline char* GetSSHParamBytes(const char* lpPayload, int lenPayload, const char* lpszField, int *lpSize = 0) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 8, 2, param, cbparam);
      if (lpSize) *lpSize = cbparam[2];
      return (char*)IPH64CAST(param[2]);
    }
    inline char* SetSSHParam(const char* lpPayload, int lenPayload, const char* lpszFieldType, const char* lpszFieldValue, int *lpSize = 0) {
      void *param[3+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszFieldType), (void*)IPH64CAST(lpszFieldValue), 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 9, 3, param, cbparam);
      if (lpSize) *lpSize = cbparam[3];
      return (char*)IPH64CAST(param[3]);
    }
    inline int Shutdown() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 10, 0, param, cbparam);
      
      
    }

};


#ifdef WIN32 //UNICODE

typedef struct {
  int ConnectionId;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SSHTunnelConnectedEventParamsW;

typedef struct {
  LPWSTR Address;
  int Port;
  int Accept;
  int reserved;
} SSHTunnelConnectionRequestEventParamsW;

typedef struct {
  int ConnectionId;
  LPWSTR Text;
  int EOL;
  int lenText;
  int reserved;
} SSHTunnelDataInEventParamsW;

typedef struct {
  int ConnectionId;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SSHTunnelDisconnectedEventParamsW;

typedef struct {
  int ConnectionId;
  int ErrorCode;
  LPWSTR Description;
  int reserved;
} SSHTunnelErrorEventParamsW;

typedef struct {
  LPWSTR Packet;
  int reserved;
} SSHTunnelSSHCustomAuthEventParamsW;

typedef struct {
  LPWSTR Name;
  LPWSTR Instructions;
  LPWSTR Prompt;
  LPWSTR Response;
  int EchoResponse;
  int reserved;
} SSHTunnelSSHKeyboardInteractiveEventParamsW;

typedef struct {
  LPWSTR HostKey;
  LPWSTR Fingerprint;
  LPWSTR KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SSHTunnelSSHServerAuthenticationEventParamsW;

typedef struct {
  LPWSTR Message;
  int reserved;
} SSHTunnelSSHStatusEventParamsW;



class SSHTunnelW : public SSHTunnel {

  public: //properties
  












    inline LPWSTR GetClientConnectionId(int iClientId) {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+7, iClientId, 0);
    }





    inline int SetClientDataToSend(int iClientId, LPWSTR lpClientDataToSend) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+8, iClientId, (void*)lpClientDataToSend, 0);
    }

    inline int SetClientDataToSendB(int iClientId, const char *lpClientDataToSend, int lenClientDataToSend) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 8, iClientId, (void*)lpClientDataToSend, lenClientDataToSend);
    }
    inline LPWSTR GetClientEOL(int iClientId) {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+9, iClientId, 0);
    }

    inline int SetClientEOL(int iClientId, LPWSTR lpClientEOL) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+9, iClientId, (void*)lpClientEOL, 0);
    }
    inline int GetClientEOLB(int iClientId, char *&lpClientEOL, int &lenClientEOL) {
      lpClientEOL = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 9, iClientId, &lenClientEOL);
      return lpClientEOL ? 0 : lenClientEOL;
    }
    inline int SetClientEOLB(int iClientId, const char *lpClientEOL, int lenClientEOL) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 9, iClientId, (void*)lpClientEOL, lenClientEOL);
    }
    inline LPWSTR GetClientLocalAddress(int iClientId) {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+10, iClientId, 0);
    }



    inline LPWSTR GetClientRemoteHost(int iClientId) {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+11, iClientId, 0);
    }









    inline LPWSTR GetDefaultEOL() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+15, 0, 0);
    }

    inline int SetDefaultEOL(LPWSTR lpDefaultEOL) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+15, 0, (void*)lpDefaultEOL, 0);
    }
    inline int GetDefaultEOLB(char *&lpDefaultEOL, int &lenDefaultEOL) {
      lpDefaultEOL = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 15, 0, &lenDefaultEOL);
      return lpDefaultEOL ? 0 : lenDefaultEOL;
    }
    inline int SetDefaultEOLB(const char *lpDefaultEOL, int lenDefaultEOL) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 15, 0, (void*)lpDefaultEOL, lenDefaultEOL);
    }








    inline LPWSTR GetFirewallHost() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+20, 0, 0);
    }

    inline int SetFirewallHost(LPWSTR lpFirewallHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+20, 0, (void*)lpFirewallHost, 0);
    }

    inline LPWSTR GetFirewallPassword() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+21, 0, 0);
    }

    inline int SetFirewallPassword(LPWSTR lpFirewallPassword) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+21, 0, (void*)lpFirewallPassword, 0);
    }



    inline LPWSTR GetFirewallUser() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+23, 0, 0);
    }

    inline int SetFirewallUser(LPWSTR lpFirewallUser) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+23, 0, (void*)lpFirewallUser, 0);
    }







    inline LPWSTR GetLocalHost() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+27, 0, 0);
    }

    inline int SetLocalHost(LPWSTR lpLocalHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+27, 0, (void*)lpLocalHost, 0);
    }



    inline LPWSTR GetSSHAcceptServerHostKeyEncoded() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+29, 0, 0);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(LPWSTR lpSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+29, 0, (void*)lpSSHAcceptServerHostKeyEncoded, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncodedB(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 29, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }
    inline int SetSSHAcceptServerHostKeyEncodedB(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 29, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }


    inline LPWSTR GetSSHCertEncoded() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+31, 0, 0);
    }

    inline int SetSSHCertEncoded(LPWSTR lpSSHCertEncoded) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+31, 0, (void*)lpSSHCertEncoded, 0);
    }
    inline int GetSSHCertEncodedB(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 31, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }
    inline int SetSSHCertEncodedB(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 31, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }
    inline LPWSTR GetSSHCertStore() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+32, 0, 0);
    }

    inline int SetSSHCertStore(LPWSTR lpSSHCertStore) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+32, 0, (void*)lpSSHCertStore, 0);
    }
    inline int GetSSHCertStoreB(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 32, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }
    inline int SetSSHCertStoreB(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 32, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }
    inline LPWSTR GetSSHCertStorePassword() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+33, 0, 0);
    }

    inline int SetSSHCertStorePassword(LPWSTR lpSSHCertStorePassword) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+33, 0, (void*)lpSSHCertStorePassword, 0);
    }



    inline LPWSTR GetSSHCertSubject() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+35, 0, 0);
    }

    inline int SetSSHCertSubject(LPWSTR lpSSHCertSubject) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+35, 0, (void*)lpSSHCertSubject, 0);
    }

    inline LPWSTR GetSSHCompressionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+36, 0, 0);
    }

    inline int SetSSHCompressionAlgorithms(LPWSTR lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+36, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline LPWSTR GetSSHEncryptionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+37, 0, 0);
    }

    inline int SetSSHEncryptionAlgorithms(LPWSTR lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+37, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline LPWSTR GetSSHForwardHost() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+38, 0, 0);
    }

    inline int SetSSHForwardHost(LPWSTR lpSSHForwardHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+38, 0, (void*)lpSSHForwardHost, 0);
    }



    inline LPWSTR GetSSHHost() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+40, 0, 0);
    }

    inline int SetSSHHost(LPWSTR lpSSHHost) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+40, 0, (void*)lpSSHHost, 0);
    }

    inline LPWSTR GetSSHPassword() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+41, 0, 0);
    }

    inline int SetSSHPassword(LPWSTR lpSSHPassword) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+41, 0, (void*)lpSSHPassword, 0);
    }



    inline LPWSTR GetSSHUser() {
      return (LPWSTR)IPWorksSSH_SSHTunnel_Get(m_pObj, 10000+43, 0, 0);
    }

    inline int SetSSHUser(LPWSTR lpSSHUser) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 10000+43, 0, (void*)lpSSHUser, 0);
    }



  public: //events
  
    virtual int FireConnected(SSHTunnelConnectedEventParamsW *e) {return 0;}
    virtual int FireConnectionRequest(SSHTunnelConnectionRequestEventParamsW *e) {return 0;}
    virtual int FireDataIn(SSHTunnelDataInEventParamsW *e) {return 0;}
    virtual int FireDisconnected(SSHTunnelDisconnectedEventParamsW *e) {return 0;}
    virtual int FireError(SSHTunnelErrorEventParamsW *e) {return 0;}
    virtual int FireSSHCustomAuth(SSHTunnelSSHCustomAuthEventParamsW *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SSHTunnelSSHKeyboardInteractiveEventParamsW *e) {return 0;}
    virtual int FireSSHServerAuthentication(SSHTunnelSSHServerAuthenticationEventParamsW *e) {return 0;}
    virtual int FireSSHStatus(SSHTunnelSSHStatusEventParamsW *e) {return 0;}


  protected:
  
    virtual int SSHTunnelEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {
    	int ret_code = 0;
      switch (event_id) {
         case 1: {
            SSHTunnelConnectedEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireConnected(&e);
            break;
         }
         case 2: {
            SSHTunnelConnectionRequestEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = FireConnectionRequest(&e);
            param[2] = (void*)(e.Accept);
            break;
         }
         case 3: {
            SSHTunnelDataInEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (int)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[1]),  0};
            ret_code = FireDataIn(&e);
            break;
         }
         case 4: {
            SSHTunnelDisconnectedEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireDisconnected(&e);
            break;
         }
         case 5: {
            SSHTunnelErrorEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireError(&e);
            break;
         }
         case 6: {
            SSHTunnelSSHCustomAuthEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 7: {
            SSHTunnelSSHKeyboardInteractiveEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 8: {
            SSHTunnelSSHServerAuthenticationEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 9: {
            SSHTunnelSSHStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }
  
  public: //event overrides

    virtual int FireConnected(SSHTunnelConnectedEventParams *e) {return -10000;}
    virtual int FireConnectionRequest(SSHTunnelConnectionRequestEventParams *e) {return -10000;}
    virtual int FireDataIn(SSHTunnelDataInEventParams *e) {return -10000;}
    virtual int FireDisconnected(SSHTunnelDisconnectedEventParams *e) {return -10000;}
    virtual int FireError(SSHTunnelErrorEventParams *e) {return -10000;}
    virtual int FireSSHCustomAuth(SSHTunnelSSHCustomAuthEventParams *e) {return -10000;}
    virtual int FireSSHKeyboardInteractive(SSHTunnelSSHKeyboardInteractiveEventParams *e) {return -10000;}
    virtual int FireSSHServerAuthentication(SSHTunnelSSHServerAuthenticationEventParams *e) {return -10000;}
    virtual int FireSSHStatus(SSHTunnelSSHStatusEventParams *e) {return -10000;}

  public: //methods

    inline LPWSTR Config(LPWSTR lpszConfigurationString) {
      void *param[1+1] = {(void*)lpszConfigurationString, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+2, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR DecodePacket(LPWSTR lpszEncodedPacket) {
      void *param[1+1] = {(void*)lpszEncodedPacket, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+3, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int Disconnect(int iConnectionId) {
      void *param[1+1] = {(void*)iConnectionId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+4, 1, param, cbparam);
      
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+5, 0, param, cbparam);
      
    }
    inline LPWSTR EncodePacket(LPWSTR lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)lpPacket, 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+6, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR GetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+7, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR GetSSHParamBytes(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+8, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR SetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszFieldType, LPWSTR lpszFieldValue) {
      void *param[3+1] = {(void*)lpPayload, (void*)lpszFieldType, (void*)lpszFieldValue, 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+9, 3, param, cbparam);
      return (LPWSTR)IPH64CAST(param[3]);
    }
    inline int Shutdown() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 10000+10, 0, param, cbparam);
      
    }

};

#endif //WIN32

#endif //_IPWORKSSSH_SSHTUNNEL_H_




