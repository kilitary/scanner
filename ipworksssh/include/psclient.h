/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_PSCLIENT_H_
#define _IPWORKSSSH_PSCLIENT_H_

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


extern "C" void* IPWORKSSSH_CALL IPWorksSSH_PSClient_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_PSClient_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_PSClient_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_PSClient_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_PSClient_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_PSClient_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_PSClient_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_PSClient_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_PSClient_StaticInit(void *hInst);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_PSClient_StaticDestroy();

#ifdef WIN32
#include <windows.h>
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} PSClientConnectedEventParams;

typedef struct {
  const char* ConnectionEvent;
  int StatusCode;
  const char* Description;
  int reserved;
} PSClientConnectionStatusEventParams;

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} PSClientDisconnectedEventParams;

typedef struct {
  int ErrorCode;
  const char* Description;
  int reserved;
} PSClientErrorEventParams;

typedef struct {
  const char* BaseType;
  const char* Value;
  int reserved;
} PSClientPSObjectEventParams;

typedef struct {
  const char* Name;
  const char* Instructions;
  const char* Prompt;
  const char* Response;
  int EchoResponse;
  int reserved;
} PSClientSSHKeyboardInteractiveEventParams;

typedef struct {
  const char* HostKey;
  const char* Fingerprint;
  const char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} PSClientSSHServerAuthenticationEventParams;

typedef struct {
  const char* Message;
  int reserved;
} PSClientSSHStatusEventParams;



class PSClient {
  
  public: //events
  
    virtual int FireConnected(PSClientConnectedEventParams *e) {return 0;}
    virtual int FireConnectionStatus(PSClientConnectionStatusEventParams *e) {return 0;}
    virtual int FireDisconnected(PSClientDisconnectedEventParams *e) {return 0;}
    virtual int FireError(PSClientErrorEventParams *e) {return 0;}
    virtual int FirePSObject(PSClientPSObjectEventParams *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(PSClientSSHKeyboardInteractiveEventParams *e) {return 0;}
    virtual int FireSSHServerAuthentication(PSClientSSHServerAuthenticationEventParams *e) {return 0;}
    virtual int FireSSHStatus(PSClientSSHStatusEventParams *e) {return 0;}


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL PSClientEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      if (event_id > 10000) return ((PSClient*)lpObj)->PSClientEventSinkW(event_id - 10000, cparam, param, cbparam);
      switch (event_id) {
         case 1: {
            PSClientConnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            PSClientConnectionStatusEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((PSClient*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            PSClientDisconnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            PSClientErrorEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            PSClientPSObjectEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FirePSObject(&e);
            break;
         }
         case 6: {
            PSClientSSHKeyboardInteractiveEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((PSClient*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)IPH64CAST(e.Response);
            break;
         }
         case 7: {
            PSClientSSHServerAuthenticationEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((PSClient*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 8: {
            PSClientSSHStatusEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((PSClient*)lpObj)->FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }

    virtual int PSClientEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {return 0;}

  public:

    PSClient(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_11) {
      m_pObj = IPWorksSSH_PSClient_Create(PSClientEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~PSClient() {
      IPWorksSSH_PSClient_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_PSClient_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_PSClient_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_PSClient_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline int GetConnected() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 1, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)IPH64CAST(bConnected);
      return IPWorksSSH_PSClient_Set(m_pObj, 1, 0, val, 0);
    }
    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)IPH64CAST(bFirewallAutoDetect);
      return IPWorksSSH_PSClient_Set(m_pObj, 2, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 3, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)IPH64CAST(iFirewallType);
      return IPWorksSSH_PSClient_Set(m_pObj, 3, 0, val, 0);
    }
    inline char* GetFirewallHost() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 4, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallHost(const char *lpFirewallHost) {
      return IPWorksSSH_PSClient_Set(m_pObj, 4, 0, (void*)lpFirewallHost, 0);
    }

    inline char* GetFirewallPassword() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 5, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallPassword(const char *lpFirewallPassword) {
      return IPWorksSSH_PSClient_Set(m_pObj, 5, 0, (void*)lpFirewallPassword, 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 6, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)IPH64CAST(lFirewallPort);
      return IPWorksSSH_PSClient_Set(m_pObj, 6, 0, val, 0);
    }
    inline char* GetFirewallUser() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 7, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallUser(const char *lpFirewallUser) {
      return IPWorksSSH_PSClient_Set(m_pObj, 7, 0, (void*)lpFirewallUser, 0);
    }

    inline char* GetLocalHost() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 8, 0, 0);
      return (char*)val;
    }

    inline int SetLocalHost(const char *lpLocalHost) {
      return IPWorksSSH_PSClient_Set(m_pObj, 8, 0, (void*)lpLocalHost, 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 9, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)IPH64CAST(lLocalPort);
      return IPWorksSSH_PSClient_Set(m_pObj, 9, 0, val, 0);
    }
    inline int GetPSObjectPropertyCount() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 10, 0, 0);
      return (int)(long)val;
    }

    inline char* GetPSObjectPropertyDataType(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 11, iPSObjectPropertyIndex, 0);
      return (char*)val;
    }


    inline int GetPSObjectPropertyIsNull(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 12, iPSObjectPropertyIndex, 0);
      return (int)(long)val;
    }

    inline char* GetPSObjectPropertyName(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 13, iPSObjectPropertyIndex, 0);
      return (char*)val;
    }


    inline char* GetPSObjectPropertyValue(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 14, iPSObjectPropertyIndex, 0);
      return (char*)val;
    }


    inline char* GetPSObjectBaseType() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 15, 0, 0);
      return (char*)val;
    }


    inline int GetPSObjectCount() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 16, 0, 0);
      return (int)(long)val;
    }

    inline int GetPSObjectIndex() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 17, 0, 0);
      return (int)(long)val;
    }
    inline int SetPSObjectIndex(int lPSObjectIndex) {
      void* val = (void*)IPH64CAST(lPSObjectIndex);
      return IPWorksSSH_PSClient_Set(m_pObj, 17, 0, val, 0);
    }
    inline char* GetPSObjectValue() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 18, 0, 0);
      return (char*)val;
    }


    inline int GetSSHAcceptServerHostKeyEncoded(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_PSClient_Get(m_pObj, 19, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_PSClient_Set(m_pObj, 19, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 20, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)IPH64CAST(iSSHAuthMode);
      return IPWorksSSH_PSClient_Set(m_pObj, 20, 0, val, 0);
    }
    inline int GetSSHCertEncoded(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_PSClient_Get(m_pObj, 21, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }

    inline int SetSSHCertEncoded(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_PSClient_Set(m_pObj, 21, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int GetSSHCertStore(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_PSClient_Get(m_pObj, 22, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }

    inline int SetSSHCertStore(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_PSClient_Set(m_pObj, 22, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }

    inline char* GetSSHCertStorePassword() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 23, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertStorePassword(const char *lpSSHCertStorePassword) {
      return IPWorksSSH_PSClient_Set(m_pObj, 23, 0, (void*)lpSSHCertStorePassword, 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 24, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)IPH64CAST(iSSHCertStoreType);
      return IPWorksSSH_PSClient_Set(m_pObj, 24, 0, val, 0);
    }
    inline char* GetSSHCertSubject() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 25, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertSubject(const char *lpSSHCertSubject) {
      return IPWorksSSH_PSClient_Set(m_pObj, 25, 0, (void*)lpSSHCertSubject, 0);
    }

    inline char* GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 26, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCompressionAlgorithms(const char *lpSSHCompressionAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 26, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline char* GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 27, 0, 0);
      return (char*)val;
    }

    inline int SetSSHEncryptionAlgorithms(const char *lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 27, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline char* GetSSHHost() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 28, 0, 0);
      return (char*)val;
    }

    inline int SetSSHHost(const char *lpSSHHost) {
      return IPWorksSSH_PSClient_Set(m_pObj, 28, 0, (void*)lpSSHHost, 0);
    }

    inline char* GetSSHKeyExchangeAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 29, 0, 0);
      return (char*)val;
    }

    inline int SetSSHKeyExchangeAlgorithms(const char *lpSSHKeyExchangeAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 29, 0, (void*)lpSSHKeyExchangeAlgorithms, 0);
    }

    inline char* GetSSHMacAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 30, 0, 0);
      return (char*)val;
    }

    inline int SetSSHMacAlgorithms(const char *lpSSHMacAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 30, 0, (void*)lpSSHMacAlgorithms, 0);
    }

    inline char* GetSSHPassword() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 31, 0, 0);
      return (char*)val;
    }

    inline int SetSSHPassword(const char *lpSSHPassword) {
      return IPWorksSSH_PSClient_Set(m_pObj, 31, 0, (void*)lpSSHPassword, 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 32, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)IPH64CAST(lSSHPort);
      return IPWorksSSH_PSClient_Set(m_pObj, 32, 0, val, 0);
    }
    inline char* GetSSHPublicKeyAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 33, 0, 0);
      return (char*)val;
    }

    inline int SetSSHPublicKeyAlgorithms(const char *lpSSHPublicKeyAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 33, 0, (void*)lpSSHPublicKeyAlgorithms, 0);
    }

    inline char* GetSSHUser() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 34, 0, 0);
      return (char*)val;
    }

    inline int SetSSHUser(const char *lpSSHUser) {
      return IPWorksSSH_PSClient_Set(m_pObj, 34, 0, (void*)lpSSHUser, 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 35, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)IPH64CAST(iTimeout);
      return IPWorksSSH_PSClient_Set(m_pObj, 35, 0, val, 0);
    }

  public: //methods

    inline int ClearOutput() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 2, 0, param, cbparam);
      
      
    }
    inline char* Config(const char* lpszConfigurationString) {
      void *param[1+1] = {(void*)IPH64CAST(lpszConfigurationString), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_PSClient_Do(m_pObj, 3, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 4, 0, param, cbparam);
      
      
    }
    inline int Execute(const char* lpszCommand) {
      void *param[1+1] = {(void*)IPH64CAST(lpszCommand), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_PSClient_Do(m_pObj, 5, 1, param, cbparam);
      
      
    }
    inline char* GetPropertyValue(const char* lpszName) {
      void *param[1+1] = {(void*)IPH64CAST(lpszName), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_PSClient_Do(m_pObj, 6, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline int Interrupt() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 7, 0, param, cbparam);
      
      
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 8, 0, param, cbparam);
      
      
    }
    inline int SSHLogon(const char* lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)IPH64CAST(lpszSSHHost), (void*)IPH64CAST(lSSHPort), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_PSClient_Do(m_pObj, 9, 2, param, cbparam);
      
      
    }

};


#ifdef WIN32 //UNICODE

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} PSClientConnectedEventParamsW;

typedef struct {
  LPWSTR ConnectionEvent;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} PSClientConnectionStatusEventParamsW;

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} PSClientDisconnectedEventParamsW;

typedef struct {
  int ErrorCode;
  LPWSTR Description;
  int reserved;
} PSClientErrorEventParamsW;

typedef struct {
  LPWSTR BaseType;
  LPWSTR Value;
  int reserved;
} PSClientPSObjectEventParamsW;

typedef struct {
  LPWSTR Name;
  LPWSTR Instructions;
  LPWSTR Prompt;
  LPWSTR Response;
  int EchoResponse;
  int reserved;
} PSClientSSHKeyboardInteractiveEventParamsW;

typedef struct {
  LPWSTR HostKey;
  LPWSTR Fingerprint;
  LPWSTR KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} PSClientSSHServerAuthenticationEventParamsW;

typedef struct {
  LPWSTR Message;
  int reserved;
} PSClientSSHStatusEventParamsW;



class PSClientW : public PSClient {

  public: //properties
  






    inline LPWSTR GetFirewallHost() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+4, 0, 0);
    }

    inline int SetFirewallHost(LPWSTR lpFirewallHost) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+4, 0, (void*)lpFirewallHost, 0);
    }

    inline LPWSTR GetFirewallPassword() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+5, 0, 0);
    }

    inline int SetFirewallPassword(LPWSTR lpFirewallPassword) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+5, 0, (void*)lpFirewallPassword, 0);
    }



    inline LPWSTR GetFirewallUser() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+7, 0, 0);
    }

    inline int SetFirewallUser(LPWSTR lpFirewallUser) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+7, 0, (void*)lpFirewallUser, 0);
    }

    inline LPWSTR GetLocalHost() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+8, 0, 0);
    }

    inline int SetLocalHost(LPWSTR lpLocalHost) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+8, 0, (void*)lpLocalHost, 0);
    }





    inline LPWSTR GetPSObjectPropertyDataType(int iPSObjectPropertyIndex) {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+11, iPSObjectPropertyIndex, 0);
    }





    inline LPWSTR GetPSObjectPropertyName(int iPSObjectPropertyIndex) {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+13, iPSObjectPropertyIndex, 0);
    }



    inline LPWSTR GetPSObjectPropertyValue(int iPSObjectPropertyIndex) {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+14, iPSObjectPropertyIndex, 0);
    }



    inline LPWSTR GetPSObjectBaseType() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+15, 0, 0);
    }







    inline LPWSTR GetPSObjectValue() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+18, 0, 0);
    }



    inline LPWSTR GetSSHAcceptServerHostKeyEncoded() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+19, 0, 0);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(LPWSTR lpSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+19, 0, (void*)lpSSHAcceptServerHostKeyEncoded, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncodedB(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_PSClient_Get(m_pObj, 19, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }
    inline int SetSSHAcceptServerHostKeyEncodedB(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_PSClient_Set(m_pObj, 19, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }


    inline LPWSTR GetSSHCertEncoded() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+21, 0, 0);
    }

    inline int SetSSHCertEncoded(LPWSTR lpSSHCertEncoded) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+21, 0, (void*)lpSSHCertEncoded, 0);
    }
    inline int GetSSHCertEncodedB(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_PSClient_Get(m_pObj, 21, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }
    inline int SetSSHCertEncodedB(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_PSClient_Set(m_pObj, 21, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }
    inline LPWSTR GetSSHCertStore() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+22, 0, 0);
    }

    inline int SetSSHCertStore(LPWSTR lpSSHCertStore) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+22, 0, (void*)lpSSHCertStore, 0);
    }
    inline int GetSSHCertStoreB(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_PSClient_Get(m_pObj, 22, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }
    inline int SetSSHCertStoreB(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_PSClient_Set(m_pObj, 22, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }
    inline LPWSTR GetSSHCertStorePassword() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+23, 0, 0);
    }

    inline int SetSSHCertStorePassword(LPWSTR lpSSHCertStorePassword) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+23, 0, (void*)lpSSHCertStorePassword, 0);
    }



    inline LPWSTR GetSSHCertSubject() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+25, 0, 0);
    }

    inline int SetSSHCertSubject(LPWSTR lpSSHCertSubject) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+25, 0, (void*)lpSSHCertSubject, 0);
    }

    inline LPWSTR GetSSHCompressionAlgorithms() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+26, 0, 0);
    }

    inline int SetSSHCompressionAlgorithms(LPWSTR lpSSHCompressionAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+26, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline LPWSTR GetSSHEncryptionAlgorithms() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+27, 0, 0);
    }

    inline int SetSSHEncryptionAlgorithms(LPWSTR lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+27, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline LPWSTR GetSSHHost() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+28, 0, 0);
    }

    inline int SetSSHHost(LPWSTR lpSSHHost) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+28, 0, (void*)lpSSHHost, 0);
    }

    inline LPWSTR GetSSHKeyExchangeAlgorithms() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+29, 0, 0);
    }

    inline int SetSSHKeyExchangeAlgorithms(LPWSTR lpSSHKeyExchangeAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+29, 0, (void*)lpSSHKeyExchangeAlgorithms, 0);
    }

    inline LPWSTR GetSSHMacAlgorithms() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+30, 0, 0);
    }

    inline int SetSSHMacAlgorithms(LPWSTR lpSSHMacAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+30, 0, (void*)lpSSHMacAlgorithms, 0);
    }

    inline LPWSTR GetSSHPassword() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+31, 0, 0);
    }

    inline int SetSSHPassword(LPWSTR lpSSHPassword) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+31, 0, (void*)lpSSHPassword, 0);
    }



    inline LPWSTR GetSSHPublicKeyAlgorithms() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+33, 0, 0);
    }

    inline int SetSSHPublicKeyAlgorithms(LPWSTR lpSSHPublicKeyAlgorithms) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+33, 0, (void*)lpSSHPublicKeyAlgorithms, 0);
    }

    inline LPWSTR GetSSHUser() {
      return (LPWSTR)IPWorksSSH_PSClient_Get(m_pObj, 10000+34, 0, 0);
    }

    inline int SetSSHUser(LPWSTR lpSSHUser) {
      return IPWorksSSH_PSClient_Set(m_pObj, 10000+34, 0, (void*)lpSSHUser, 0);
    }





  public: //events
  
    virtual int FireConnected(PSClientConnectedEventParamsW *e) {return 0;}
    virtual int FireConnectionStatus(PSClientConnectionStatusEventParamsW *e) {return 0;}
    virtual int FireDisconnected(PSClientDisconnectedEventParamsW *e) {return 0;}
    virtual int FireError(PSClientErrorEventParamsW *e) {return 0;}
    virtual int FirePSObject(PSClientPSObjectEventParamsW *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(PSClientSSHKeyboardInteractiveEventParamsW *e) {return 0;}
    virtual int FireSSHServerAuthentication(PSClientSSHServerAuthenticationEventParamsW *e) {return 0;}
    virtual int FireSSHStatus(PSClientSSHStatusEventParamsW *e) {return 0;}


  protected:
  
    virtual int PSClientEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {
    	int ret_code = 0;
      switch (event_id) {
         case 1: {
            PSClientConnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireConnected(&e);
            break;
         }
         case 2: {
            PSClientConnectionStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireConnectionStatus(&e);
            break;
         }
         case 3: {
            PSClientDisconnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireDisconnected(&e);
            break;
         }
         case 4: {
            PSClientErrorEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireError(&e);
            break;
         }
         case 5: {
            PSClientPSObjectEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FirePSObject(&e);
            break;
         }
         case 6: {
            PSClientSSHKeyboardInteractiveEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 7: {
            PSClientSSHServerAuthenticationEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 8: {
            PSClientSSHStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }
  
  public: //event overrides

    virtual int FireConnected(PSClientConnectedEventParams *e) {return -10000;}
    virtual int FireConnectionStatus(PSClientConnectionStatusEventParams *e) {return -10000;}
    virtual int FireDisconnected(PSClientDisconnectedEventParams *e) {return -10000;}
    virtual int FireError(PSClientErrorEventParams *e) {return -10000;}
    virtual int FirePSObject(PSClientPSObjectEventParams *e) {return -10000;}
    virtual int FireSSHKeyboardInteractive(PSClientSSHKeyboardInteractiveEventParams *e) {return -10000;}
    virtual int FireSSHServerAuthentication(PSClientSSHServerAuthenticationEventParams *e) {return -10000;}
    virtual int FireSSHStatus(PSClientSSHStatusEventParams *e) {return -10000;}

  public: //methods

    inline int ClearOutput() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 10000+2, 0, param, cbparam);
      
    }
    inline LPWSTR Config(LPWSTR lpszConfigurationString) {
      void *param[1+1] = {(void*)lpszConfigurationString, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_PSClient_Do(m_pObj, 10000+3, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 10000+4, 0, param, cbparam);
      
    }
    inline int Execute(LPWSTR lpszCommand) {
      void *param[1+1] = {(void*)lpszCommand, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_PSClient_Do(m_pObj, 10000+5, 1, param, cbparam);
      
    }
    inline LPWSTR GetPropertyValue(LPWSTR lpszName) {
      void *param[1+1] = {(void*)lpszName, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_PSClient_Do(m_pObj, 10000+6, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int Interrupt() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 10000+7, 0, param, cbparam);
      
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 10000+8, 0, param, cbparam);
      
    }
    inline int SSHLogon(LPWSTR lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)lpszSSHHost, (void*)lSSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_PSClient_Do(m_pObj, 10000+9, 2, param, cbparam);
      
    }

};

#endif //WIN32

#endif //_IPWORKSSSH_PSCLIENT_H_




