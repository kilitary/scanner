/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHELL_H_
#define _IPWORKSSSH_SSHELL_H_

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


extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SShell_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SShell_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SShell_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_StaticInit(void *hInst);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_StaticDestroy();

#ifdef WIN32
#include <windows.h>
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SShellConnectedEventParams;

typedef struct {
  const char* ConnectionEvent;
  int StatusCode;
  const char* Description;
  int reserved;
} SShellConnectionStatusEventParams;

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SShellDisconnectedEventParams;

typedef struct {
  int ErrorCode;
  const char* Description;
  int reserved;
} SShellErrorEventParams;

typedef struct {
  const char* Packet;
  int reserved;
} SShellSSHCustomAuthEventParams;

typedef struct {
  const char* Name;
  const char* Instructions;
  const char* Prompt;
  const char* Response;
  int EchoResponse;
  int reserved;
} SShellSSHKeyboardInteractiveEventParams;

typedef struct {
  const char* HostKey;
  const char* Fingerprint;
  const char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SShellSSHServerAuthenticationEventParams;

typedef struct {
  const char* Message;
  int reserved;
} SShellSSHStatusEventParams;

typedef struct {
  const char* Text;
  int lenText;
  int reserved;
} SShellStderrEventParams;

typedef struct {
  const char* Text;
  int lenText;
  int reserved;
} SShellStdoutEventParams;



class SShell {
  
  public: //events
  
    virtual int FireConnected(SShellConnectedEventParams *e) {return 0;}
    virtual int FireConnectionStatus(SShellConnectionStatusEventParams *e) {return 0;}
    virtual int FireDisconnected(SShellDisconnectedEventParams *e) {return 0;}
    virtual int FireError(SShellErrorEventParams *e) {return 0;}
    virtual int FireSSHCustomAuth(SShellSSHCustomAuthEventParams *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SShellSSHKeyboardInteractiveEventParams *e) {return 0;}
    virtual int FireSSHServerAuthentication(SShellSSHServerAuthenticationEventParams *e) {return 0;}
    virtual int FireSSHStatus(SShellSSHStatusEventParams *e) {return 0;}
    virtual int FireStderr(SShellStderrEventParams *e) {return 0;}
    virtual int FireStdout(SShellStdoutEventParams *e) {return 0;}


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SShellEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      if (event_id > 10000) return ((SShell*)lpObj)->SShellEventSinkW(event_id - 10000, cparam, param, cbparam);
      switch (event_id) {
         case 1: {
            SShellConnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SShell*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SShellConnectionStatusEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SShell*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SShellDisconnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SShell*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SShellErrorEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SShell*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            SShellSSHCustomAuthEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)IPH64CAST(e.Packet);
            break;
         }
         case 6: {
            SShellSSHKeyboardInteractiveEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)IPH64CAST(e.Response);
            break;
         }
         case 7: {
            SShellSSHServerAuthenticationEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 8: {
            SShellSSHStatusEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 9: {
            SShellStderrEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SShell*)lpObj)->FireStderr(&e);
            break;
         }
         case 10: {
            SShellStdoutEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SShell*)lpObj)->FireStdout(&e);
            break;
         }

      }
      return ret_code;
    }

    virtual int SShellEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {return 0;}

  public:

    SShell(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_63) {
      m_pObj = IPWorksSSH_SShell_Create(SShellEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~SShell() {
      IPWorksSSH_SShell_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_SShell_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_SShell_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_SShell_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline char* GetCommand() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 1, 0, 0);
      return (char*)val;
    }

    inline int SetCommand(const char *lpCommand) {
      return IPWorksSSH_SShell_Set(m_pObj, 1, 0, (void*)lpCommand, 0);
    }

    inline int GetConnected() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)IPH64CAST(bConnected);
      return IPWorksSSH_SShell_Set(m_pObj, 2, 0, val, 0);
    }
    inline char* GetErrorMessage() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 3, 0, 0);
      return (char*)val;
    }


    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 4, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)IPH64CAST(bFirewallAutoDetect);
      return IPWorksSSH_SShell_Set(m_pObj, 4, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 5, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)IPH64CAST(iFirewallType);
      return IPWorksSSH_SShell_Set(m_pObj, 5, 0, val, 0);
    }
    inline char* GetFirewallHost() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 6, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallHost(const char *lpFirewallHost) {
      return IPWorksSSH_SShell_Set(m_pObj, 6, 0, (void*)lpFirewallHost, 0);
    }

    inline char* GetFirewallPassword() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 7, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallPassword(const char *lpFirewallPassword) {
      return IPWorksSSH_SShell_Set(m_pObj, 7, 0, (void*)lpFirewallPassword, 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 8, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)IPH64CAST(lFirewallPort);
      return IPWorksSSH_SShell_Set(m_pObj, 8, 0, val, 0);
    }
    inline char* GetFirewallUser() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 9, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallUser(const char *lpFirewallUser) {
      return IPWorksSSH_SShell_Set(m_pObj, 9, 0, (void*)lpFirewallUser, 0);
    }

    inline char* GetLocalHost() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 10, 0, 0);
      return (char*)val;
    }

    inline int SetLocalHost(const char *lpLocalHost) {
      return IPWorksSSH_SShell_Set(m_pObj, 10, 0, (void*)lpLocalHost, 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 11, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)IPH64CAST(lLocalPort);
      return IPWorksSSH_SShell_Set(m_pObj, 11, 0, val, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncoded(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SShell_Get(m_pObj, 12, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SShell_Set(m_pObj, 12, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)IPH64CAST(iSSHAuthMode);
      return IPWorksSSH_SShell_Set(m_pObj, 13, 0, val, 0);
    }
    inline int GetSSHCertEncoded(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SShell_Get(m_pObj, 14, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }

    inline int SetSSHCertEncoded(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SShell_Set(m_pObj, 14, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int GetSSHCertStore(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SShell_Get(m_pObj, 15, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }

    inline int SetSSHCertStore(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SShell_Set(m_pObj, 15, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }

    inline char* GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 16, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertStorePassword(const char *lpSSHCertStorePassword) {
      return IPWorksSSH_SShell_Set(m_pObj, 16, 0, (void*)lpSSHCertStorePassword, 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 17, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)IPH64CAST(iSSHCertStoreType);
      return IPWorksSSH_SShell_Set(m_pObj, 17, 0, val, 0);
    }
    inline char* GetSSHCertSubject() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 18, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertSubject(const char *lpSSHCertSubject) {
      return IPWorksSSH_SShell_Set(m_pObj, 18, 0, (void*)lpSSHCertSubject, 0);
    }

    inline char* GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 19, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCompressionAlgorithms(const char *lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SShell_Set(m_pObj, 19, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline char* GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 20, 0, 0);
      return (char*)val;
    }

    inline int SetSSHEncryptionAlgorithms(const char *lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SShell_Set(m_pObj, 20, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline char* GetSSHHost() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 21, 0, 0);
      return (char*)val;
    }

    inline int SetSSHHost(const char *lpSSHHost) {
      return IPWorksSSH_SShell_Set(m_pObj, 21, 0, (void*)lpSSHHost, 0);
    }

    inline char* GetSSHPassword() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 22, 0, 0);
      return (char*)val;
    }

    inline int SetSSHPassword(const char *lpSSHPassword) {
      return IPWorksSSH_SShell_Set(m_pObj, 22, 0, (void*)lpSSHPassword, 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 23, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)IPH64CAST(lSSHPort);
      return IPWorksSSH_SShell_Set(m_pObj, 23, 0, val, 0);
    }
    inline char* GetSSHUser() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 24, 0, 0);
      return (char*)val;
    }

    inline int SetSSHUser(const char *lpSSHUser) {
      return IPWorksSSH_SShell_Set(m_pObj, 24, 0, (void*)lpSSHUser, 0);
    }


    inline int SetStdin(const char *lpStdin, int lenStdin) {
      return IPWorksSSH_SShell_Set(m_pObj, 25, 0, (void*)lpStdin, lenStdin);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)IPH64CAST(iTimeout);
      return IPWorksSSH_SShell_Set(m_pObj, 26, 0, val, 0);
    }

  public: //methods

    inline char* Config(const char* lpszConfigurationString) {
      void *param[1+1] = {(void*)IPH64CAST(lpszConfigurationString), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 2, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* DecodePacket(const char* lpszEncodedPacket, int *lpSize = 0) {
      void *param[1+1] = {(void*)IPH64CAST(lpszEncodedPacket), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 3, 1, param, cbparam);
      if (lpSize) *lpSize = cbparam[1];
      return (char*)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 4, 0, param, cbparam);
      
      
    }
    inline char* EncodePacket(const char* lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)IPH64CAST(lpPacket), 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SShell_Do(m_pObj, 5, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline int Execute(const char* lpszCommand) {
      void *param[1+1] = {(void*)IPH64CAST(lpszCommand), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 6, 1, param, cbparam);
      
      
    }
    inline char* GetSSHParam(const char* lpPayload, int lenPayload, const char* lpszField) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 7, 2, param, cbparam);
      
      return (char*)IPH64CAST(param[2]);
    }
    inline char* GetSSHParamBytes(const char* lpPayload, int lenPayload, const char* lpszField, int *lpSize = 0) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 8, 2, param, cbparam);
      if (lpSize) *lpSize = cbparam[2];
      return (char*)IPH64CAST(param[2]);
    }
    inline int Interrupt() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 9, 0, param, cbparam);
      
      
    }
    inline int Send(const char* lpText, int lenText) {
      void *param[1+1] = {(void*)IPH64CAST(lpText), 0};
      int cbparam[1+1] = {lenText, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 10, 1, param, cbparam);
      
      
    }
    inline char* SetSSHParam(const char* lpPayload, int lenPayload, const char* lpszFieldType, const char* lpszFieldValue, int *lpSize = 0) {
      void *param[3+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszFieldType), (void*)IPH64CAST(lpszFieldValue), 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 11, 3, param, cbparam);
      if (lpSize) *lpSize = cbparam[3];
      return (char*)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 12, 0, param, cbparam);
      
      
    }
    inline int SSHLogon(const char* lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)IPH64CAST(lpszSSHHost), (void*)IPH64CAST(lSSHPort), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 13, 2, param, cbparam);
      
      
    }

};


#ifdef WIN32 //UNICODE

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SShellConnectedEventParamsW;

typedef struct {
  LPWSTR ConnectionEvent;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SShellConnectionStatusEventParamsW;

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SShellDisconnectedEventParamsW;

typedef struct {
  int ErrorCode;
  LPWSTR Description;
  int reserved;
} SShellErrorEventParamsW;

typedef struct {
  LPWSTR Packet;
  int reserved;
} SShellSSHCustomAuthEventParamsW;

typedef struct {
  LPWSTR Name;
  LPWSTR Instructions;
  LPWSTR Prompt;
  LPWSTR Response;
  int EchoResponse;
  int reserved;
} SShellSSHKeyboardInteractiveEventParamsW;

typedef struct {
  LPWSTR HostKey;
  LPWSTR Fingerprint;
  LPWSTR KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SShellSSHServerAuthenticationEventParamsW;

typedef struct {
  LPWSTR Message;
  int reserved;
} SShellSSHStatusEventParamsW;

typedef struct {
  LPWSTR Text;
  int lenText;
  int reserved;
} SShellStderrEventParamsW;

typedef struct {
  LPWSTR Text;
  int lenText;
  int reserved;
} SShellStdoutEventParamsW;



class SShellW : public SShell {

  public: //properties
  
    inline LPWSTR GetCommand() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+1, 0, 0);
    }

    inline int SetCommand(LPWSTR lpCommand) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+1, 0, (void*)lpCommand, 0);
    }



    inline LPWSTR GetErrorMessage() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+3, 0, 0);
    }







    inline LPWSTR GetFirewallHost() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+6, 0, 0);
    }

    inline int SetFirewallHost(LPWSTR lpFirewallHost) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+6, 0, (void*)lpFirewallHost, 0);
    }

    inline LPWSTR GetFirewallPassword() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+7, 0, 0);
    }

    inline int SetFirewallPassword(LPWSTR lpFirewallPassword) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+7, 0, (void*)lpFirewallPassword, 0);
    }



    inline LPWSTR GetFirewallUser() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+9, 0, 0);
    }

    inline int SetFirewallUser(LPWSTR lpFirewallUser) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+9, 0, (void*)lpFirewallUser, 0);
    }

    inline LPWSTR GetLocalHost() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+10, 0, 0);
    }

    inline int SetLocalHost(LPWSTR lpLocalHost) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+10, 0, (void*)lpLocalHost, 0);
    }



    inline LPWSTR GetSSHAcceptServerHostKeyEncoded() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+12, 0, 0);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(LPWSTR lpSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+12, 0, (void*)lpSSHAcceptServerHostKeyEncoded, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncodedB(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SShell_Get(m_pObj, 12, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }
    inline int SetSSHAcceptServerHostKeyEncodedB(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SShell_Set(m_pObj, 12, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }


    inline LPWSTR GetSSHCertEncoded() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+14, 0, 0);
    }

    inline int SetSSHCertEncoded(LPWSTR lpSSHCertEncoded) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+14, 0, (void*)lpSSHCertEncoded, 0);
    }
    inline int GetSSHCertEncodedB(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SShell_Get(m_pObj, 14, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }
    inline int SetSSHCertEncodedB(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SShell_Set(m_pObj, 14, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }
    inline LPWSTR GetSSHCertStore() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+15, 0, 0);
    }

    inline int SetSSHCertStore(LPWSTR lpSSHCertStore) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+15, 0, (void*)lpSSHCertStore, 0);
    }
    inline int GetSSHCertStoreB(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SShell_Get(m_pObj, 15, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }
    inline int SetSSHCertStoreB(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SShell_Set(m_pObj, 15, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }
    inline LPWSTR GetSSHCertStorePassword() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+16, 0, 0);
    }

    inline int SetSSHCertStorePassword(LPWSTR lpSSHCertStorePassword) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+16, 0, (void*)lpSSHCertStorePassword, 0);
    }



    inline LPWSTR GetSSHCertSubject() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+18, 0, 0);
    }

    inline int SetSSHCertSubject(LPWSTR lpSSHCertSubject) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+18, 0, (void*)lpSSHCertSubject, 0);
    }

    inline LPWSTR GetSSHCompressionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+19, 0, 0);
    }

    inline int SetSSHCompressionAlgorithms(LPWSTR lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+19, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline LPWSTR GetSSHEncryptionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+20, 0, 0);
    }

    inline int SetSSHEncryptionAlgorithms(LPWSTR lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+20, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline LPWSTR GetSSHHost() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+21, 0, 0);
    }

    inline int SetSSHHost(LPWSTR lpSSHHost) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+21, 0, (void*)lpSSHHost, 0);
    }

    inline LPWSTR GetSSHPassword() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+22, 0, 0);
    }

    inline int SetSSHPassword(LPWSTR lpSSHPassword) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+22, 0, (void*)lpSSHPassword, 0);
    }



    inline LPWSTR GetSSHUser() {
      return (LPWSTR)IPWorksSSH_SShell_Get(m_pObj, 10000+24, 0, 0);
    }

    inline int SetSSHUser(LPWSTR lpSSHUser) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+24, 0, (void*)lpSSHUser, 0);
    }



    inline int SetStdin(LPWSTR lpStdin) {
      return IPWorksSSH_SShell_Set(m_pObj, 10000+25, 0, (void*)lpStdin, 0);
    }

    inline int SetStdinB(const char *lpStdin, int lenStdin) {
      return IPWorksSSH_SShell_Set(m_pObj, 25, 0, (void*)lpStdin, lenStdin);
    }




  public: //events
  
    virtual int FireConnected(SShellConnectedEventParamsW *e) {return 0;}
    virtual int FireConnectionStatus(SShellConnectionStatusEventParamsW *e) {return 0;}
    virtual int FireDisconnected(SShellDisconnectedEventParamsW *e) {return 0;}
    virtual int FireError(SShellErrorEventParamsW *e) {return 0;}
    virtual int FireSSHCustomAuth(SShellSSHCustomAuthEventParamsW *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SShellSSHKeyboardInteractiveEventParamsW *e) {return 0;}
    virtual int FireSSHServerAuthentication(SShellSSHServerAuthenticationEventParamsW *e) {return 0;}
    virtual int FireSSHStatus(SShellSSHStatusEventParamsW *e) {return 0;}
    virtual int FireStderr(SShellStderrEventParamsW *e) {return 0;}
    virtual int FireStdout(SShellStdoutEventParamsW *e) {return 0;}


  protected:
  
    virtual int SShellEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {
    	int ret_code = 0;
      switch (event_id) {
         case 1: {
            SShellConnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireConnected(&e);
            break;
         }
         case 2: {
            SShellConnectionStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SShellDisconnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireDisconnected(&e);
            break;
         }
         case 4: {
            SShellErrorEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireError(&e);
            break;
         }
         case 5: {
            SShellSSHCustomAuthEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 6: {
            SShellSSHKeyboardInteractiveEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 7: {
            SShellSSHServerAuthenticationEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 8: {
            SShellSSHStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHStatus(&e);
            break;
         }
         case 9: {
            SShellStderrEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireStderr(&e);
            break;
         }
         case 10: {
            SShellStdoutEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireStdout(&e);
            break;
         }

      }
      return ret_code;
    }
  
  public: //event overrides

    virtual int FireConnected(SShellConnectedEventParams *e) {return -10000;}
    virtual int FireConnectionStatus(SShellConnectionStatusEventParams *e) {return -10000;}
    virtual int FireDisconnected(SShellDisconnectedEventParams *e) {return -10000;}
    virtual int FireError(SShellErrorEventParams *e) {return -10000;}
    virtual int FireSSHCustomAuth(SShellSSHCustomAuthEventParams *e) {return -10000;}
    virtual int FireSSHKeyboardInteractive(SShellSSHKeyboardInteractiveEventParams *e) {return -10000;}
    virtual int FireSSHServerAuthentication(SShellSSHServerAuthenticationEventParams *e) {return -10000;}
    virtual int FireSSHStatus(SShellSSHStatusEventParams *e) {return -10000;}
    virtual int FireStderr(SShellStderrEventParams *e) {return -10000;}
    virtual int FireStdout(SShellStdoutEventParams *e) {return -10000;}

  public: //methods

    inline LPWSTR Config(LPWSTR lpszConfigurationString) {
      void *param[1+1] = {(void*)lpszConfigurationString, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 10000+2, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR DecodePacket(LPWSTR lpszEncodedPacket) {
      void *param[1+1] = {(void*)lpszEncodedPacket, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 10000+3, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 10000+4, 0, param, cbparam);
      
    }
    inline LPWSTR EncodePacket(LPWSTR lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)lpPacket, 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SShell_Do(m_pObj, 10000+5, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int Execute(LPWSTR lpszCommand) {
      void *param[1+1] = {(void*)lpszCommand, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 10000+6, 1, param, cbparam);
      
    }
    inline LPWSTR GetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 10000+7, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR GetSSHParamBytes(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 10000+8, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline int Interrupt() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 10000+9, 0, param, cbparam);
      
    }
    inline int Send(LPWSTR lpText, int lenText) {
      void *param[1+1] = {(void*)lpText, 0};
      int cbparam[1+1] = {lenText, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 10000+10, 1, param, cbparam);
      
    }
    inline LPWSTR SetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszFieldType, LPWSTR lpszFieldValue) {
      void *param[3+1] = {(void*)lpPayload, (void*)lpszFieldType, (void*)lpszFieldValue, 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 10000+11, 3, param, cbparam);
      return (LPWSTR)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 10000+12, 0, param, cbparam);
      
    }
    inline int SSHLogon(LPWSTR lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)lpszSSHHost, (void*)lSSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 10000+13, 2, param, cbparam);
      
    }

};

#endif //WIN32

#endif //_IPWORKSSSH_SSHELL_H_




