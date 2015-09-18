/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SCP_H_
#define _IPWORKSSSH_SCP_H_

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


extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SCP_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SCP_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SCP_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_StaticInit(void *hInst);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_StaticDestroy();

#ifdef WIN32
#include <windows.h>
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SCPConnectedEventParams;

typedef struct {
  const char* ConnectionEvent;
  int StatusCode;
  const char* Description;
  int reserved;
} SCPConnectionStatusEventParams;

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SCPDisconnectedEventParams;

typedef struct {
  int Direction;
  const char* LocalFile;
  const char* RemoteFile;
  const char* RemotePath;
  int reserved;
} SCPEndTransferEventParams;

typedef struct {
  int ErrorCode;
  const char* Description;
  const char* LocalFile;
  const char* RemoteFile;
  const char* RemotePath;
  int reserved;
} SCPErrorEventParams;

typedef struct {
  const char* Packet;
  int reserved;
} SCPSSHCustomAuthEventParams;

typedef struct {
  const char* Name;
  const char* Instructions;
  const char* Prompt;
  const char* Response;
  int EchoResponse;
  int reserved;
} SCPSSHKeyboardInteractiveEventParams;

typedef struct {
  const char* HostKey;
  const char* Fingerprint;
  const char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SCPSSHServerAuthenticationEventParams;

typedef struct {
  const char* Message;
  int reserved;
} SCPSSHStatusEventParams;

typedef struct {
  int Direction;
  const char* LocalFile;
  const char* RemoteFile;
  const char* RemotePath;
  const char* FilePermissions;
  int reserved;
} SCPStartTransferEventParams;

typedef struct {
  int Direction;
  const char* LocalFile;
  const char* RemoteFile;
  const char* RemotePath;
  ns_int64 *pBytesTransferred;
  int PercentDone;
  const char* Text;
  int lenText;
  int reserved;
} SCPTransferEventParams;



class SCP {
  
  public: //events
  
    virtual int FireConnected(SCPConnectedEventParams *e) {return 0;}
    virtual int FireConnectionStatus(SCPConnectionStatusEventParams *e) {return 0;}
    virtual int FireDisconnected(SCPDisconnectedEventParams *e) {return 0;}
    virtual int FireEndTransfer(SCPEndTransferEventParams *e) {return 0;}
    virtual int FireError(SCPErrorEventParams *e) {return 0;}
    virtual int FireSSHCustomAuth(SCPSSHCustomAuthEventParams *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SCPSSHKeyboardInteractiveEventParams *e) {return 0;}
    virtual int FireSSHServerAuthentication(SCPSSHServerAuthenticationEventParams *e) {return 0;}
    virtual int FireSSHStatus(SCPSSHStatusEventParams *e) {return 0;}
    virtual int FireStartTransfer(SCPStartTransferEventParams *e) {return 0;}
    virtual int FireTransfer(SCPTransferEventParams *e) {return 0;}


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SCPEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      if (event_id > 10000) return ((SCP*)lpObj)->SCPEventSinkW(event_id - 10000, cparam, param, cbparam);
      switch (event_id) {
         case 1: {
            SCPConnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SCP*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SCPConnectionStatusEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SCP*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SCPDisconnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SCP*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SCPEndTransferEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]),  0};
            ret_code = ((SCP*)lpObj)->FireEndTransfer(&e);
            break;
         }
         case 5: {
            SCPErrorEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]),  0};
            ret_code = ((SCP*)lpObj)->FireError(&e);
            break;
         }
         case 6: {
            SCPSSHCustomAuthEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)IPH64CAST(e.Packet);
            break;
         }
         case 7: {
            SCPSSHKeyboardInteractiveEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)IPH64CAST(e.Response);
            break;
         }
         case 8: {
            SCPSSHServerAuthenticationEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 9: {
            SCPSSHStatusEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 10: {
            SCPStartTransferEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]),  0};
            ret_code = ((SCP*)lpObj)->FireStartTransfer(&e);
            param[4] = (void*)IPH64CAST(e.FilePermissions);
            break;
         }
         case 11: {
            SCPTransferEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (ns_int64*)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (char*)IPH64CAST(param[6]), (int)IPH64CAST(cbparam[6]),  0};
            ret_code = ((SCP*)lpObj)->FireTransfer(&e);
            break;
         }

      }
      return ret_code;
    }

    virtual int SCPEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {return 0;}

  public:

    SCP(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_18) {
      m_pObj = IPWorksSSH_SCP_Create(SCPEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~SCP() {
      IPWorksSSH_SCP_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_SCP_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_SCP_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_SCP_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline int GetConnected() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 1, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)IPH64CAST(bConnected);
      return IPWorksSSH_SCP_Set(m_pObj, 1, 0, val, 0);
    }
    inline char* GetFilePermissions() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 2, 0, 0);
      return (char*)val;
    }

    inline int SetFilePermissions(const char *lpFilePermissions) {
      return IPWorksSSH_SCP_Set(m_pObj, 2, 0, (void*)lpFilePermissions, 0);
    }

    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 3, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)IPH64CAST(bFirewallAutoDetect);
      return IPWorksSSH_SCP_Set(m_pObj, 3, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 4, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)IPH64CAST(iFirewallType);
      return IPWorksSSH_SCP_Set(m_pObj, 4, 0, val, 0);
    }
    inline char* GetFirewallHost() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 5, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallHost(const char *lpFirewallHost) {
      return IPWorksSSH_SCP_Set(m_pObj, 5, 0, (void*)lpFirewallHost, 0);
    }

    inline char* GetFirewallPassword() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 6, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallPassword(const char *lpFirewallPassword) {
      return IPWorksSSH_SCP_Set(m_pObj, 6, 0, (void*)lpFirewallPassword, 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 7, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)IPH64CAST(lFirewallPort);
      return IPWorksSSH_SCP_Set(m_pObj, 7, 0, val, 0);
    }
    inline char* GetFirewallUser() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 8, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallUser(const char *lpFirewallUser) {
      return IPWorksSSH_SCP_Set(m_pObj, 8, 0, (void*)lpFirewallUser, 0);
    }

    inline char* GetLocalFile() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 9, 0, 0);
      return (char*)val;
    }

    inline int SetLocalFile(const char *lpLocalFile) {
      return IPWorksSSH_SCP_Set(m_pObj, 9, 0, (void*)lpLocalFile, 0);
    }

    inline char* GetLocalHost() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 10, 0, 0);
      return (char*)val;
    }

    inline int SetLocalHost(const char *lpLocalHost) {
      return IPWorksSSH_SCP_Set(m_pObj, 10, 0, (void*)lpLocalHost, 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 11, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)IPH64CAST(lLocalPort);
      return IPWorksSSH_SCP_Set(m_pObj, 11, 0, val, 0);
    }
    inline int GetOverwrite() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 12, 0, 0);
      return (int)(long)val;
    }
    inline int SetOverwrite(int bOverwrite) {
      void* val = (void*)IPH64CAST(bOverwrite);
      return IPWorksSSH_SCP_Set(m_pObj, 12, 0, val, 0);
    }
    inline char* GetRemoteFile() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 13, 0, 0);
      return (char*)val;
    }

    inline int SetRemoteFile(const char *lpRemoteFile) {
      return IPWorksSSH_SCP_Set(m_pObj, 13, 0, (void*)lpRemoteFile, 0);
    }

    inline char* GetRemotePath() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 14, 0, 0);
      return (char*)val;
    }

    inline int SetRemotePath(const char *lpRemotePath) {
      return IPWorksSSH_SCP_Set(m_pObj, 14, 0, (void*)lpRemotePath, 0);
    }

    inline int GetSSHAcceptServerHostKeyEncoded(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SCP_Get(m_pObj, 15, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SCP_Set(m_pObj, 15, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 16, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)IPH64CAST(iSSHAuthMode);
      return IPWorksSSH_SCP_Set(m_pObj, 16, 0, val, 0);
    }
    inline int GetSSHCertEncoded(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SCP_Get(m_pObj, 17, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }

    inline int SetSSHCertEncoded(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SCP_Set(m_pObj, 17, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int GetSSHCertStore(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SCP_Get(m_pObj, 18, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }

    inline int SetSSHCertStore(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SCP_Set(m_pObj, 18, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }

    inline char* GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 19, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertStorePassword(const char *lpSSHCertStorePassword) {
      return IPWorksSSH_SCP_Set(m_pObj, 19, 0, (void*)lpSSHCertStorePassword, 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 20, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)IPH64CAST(iSSHCertStoreType);
      return IPWorksSSH_SCP_Set(m_pObj, 20, 0, val, 0);
    }
    inline char* GetSSHCertSubject() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 21, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertSubject(const char *lpSSHCertSubject) {
      return IPWorksSSH_SCP_Set(m_pObj, 21, 0, (void*)lpSSHCertSubject, 0);
    }

    inline char* GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 22, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCompressionAlgorithms(const char *lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SCP_Set(m_pObj, 22, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline char* GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 23, 0, 0);
      return (char*)val;
    }

    inline int SetSSHEncryptionAlgorithms(const char *lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SCP_Set(m_pObj, 23, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline char* GetSSHHost() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 24, 0, 0);
      return (char*)val;
    }

    inline int SetSSHHost(const char *lpSSHHost) {
      return IPWorksSSH_SCP_Set(m_pObj, 24, 0, (void*)lpSSHHost, 0);
    }

    inline char* GetSSHPassword() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 25, 0, 0);
      return (char*)val;
    }

    inline int SetSSHPassword(const char *lpSSHPassword) {
      return IPWorksSSH_SCP_Set(m_pObj, 25, 0, (void*)lpSSHPassword, 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)IPH64CAST(lSSHPort);
      return IPWorksSSH_SCP_Set(m_pObj, 26, 0, val, 0);
    }
    inline char* GetSSHUser() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 27, 0, 0);
      return (char*)val;
    }

    inline int SetSSHUser(const char *lpSSHUser) {
      return IPWorksSSH_SCP_Set(m_pObj, 27, 0, (void*)lpSSHUser, 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 28, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)IPH64CAST(iTimeout);
      return IPWorksSSH_SCP_Set(m_pObj, 28, 0, val, 0);
    }

  public: //methods

    inline char* Config(const char* lpszConfigurationString) {
      void *param[1+1] = {(void*)IPH64CAST(lpszConfigurationString), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 2, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* DecodePacket(const char* lpszEncodedPacket, int *lpSize = 0) {
      void *param[1+1] = {(void*)IPH64CAST(lpszEncodedPacket), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 3, 1, param, cbparam);
      if (lpSize) *lpSize = cbparam[1];
      return (char*)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 4, 0, param, cbparam);
      
      
    }
    inline int Download() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 5, 0, param, cbparam);
      
      
    }
    inline char* EncodePacket(const char* lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)IPH64CAST(lpPacket), 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SCP_Do(m_pObj, 6, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* GetSSHParam(const char* lpPayload, int lenPayload, const char* lpszField) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 7, 2, param, cbparam);
      
      return (char*)IPH64CAST(param[2]);
    }
    inline char* GetSSHParamBytes(const char* lpPayload, int lenPayload, const char* lpszField, int *lpSize = 0) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 8, 2, param, cbparam);
      if (lpSize) *lpSize = cbparam[2];
      return (char*)IPH64CAST(param[2]);
    }
    inline int Interrupt() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 9, 0, param, cbparam);
      
      
    }
    inline char* SetSSHParam(const char* lpPayload, int lenPayload, const char* lpszFieldType, const char* lpszFieldValue, int *lpSize = 0) {
      void *param[3+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszFieldType), (void*)IPH64CAST(lpszFieldValue), 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 11, 3, param, cbparam);
      if (lpSize) *lpSize = cbparam[3];
      return (char*)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 13, 0, param, cbparam);
      
      
    }
    inline int SSHLogon(const char* lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)IPH64CAST(lpszSSHHost), (void*)IPH64CAST(lSSHPort), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SCP_Do(m_pObj, 14, 2, param, cbparam);
      
      
    }
    inline int Upload() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 15, 0, param, cbparam);
      
      
    }

};


#ifdef WIN32 //UNICODE

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SCPConnectedEventParamsW;

typedef struct {
  LPWSTR ConnectionEvent;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SCPConnectionStatusEventParamsW;

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SCPDisconnectedEventParamsW;

typedef struct {
  int Direction;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  LPWSTR RemotePath;
  int reserved;
} SCPEndTransferEventParamsW;

typedef struct {
  int ErrorCode;
  LPWSTR Description;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  LPWSTR RemotePath;
  int reserved;
} SCPErrorEventParamsW;

typedef struct {
  LPWSTR Packet;
  int reserved;
} SCPSSHCustomAuthEventParamsW;

typedef struct {
  LPWSTR Name;
  LPWSTR Instructions;
  LPWSTR Prompt;
  LPWSTR Response;
  int EchoResponse;
  int reserved;
} SCPSSHKeyboardInteractiveEventParamsW;

typedef struct {
  LPWSTR HostKey;
  LPWSTR Fingerprint;
  LPWSTR KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SCPSSHServerAuthenticationEventParamsW;

typedef struct {
  LPWSTR Message;
  int reserved;
} SCPSSHStatusEventParamsW;

typedef struct {
  int Direction;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  LPWSTR RemotePath;
  LPWSTR FilePermissions;
  int reserved;
} SCPStartTransferEventParamsW;

typedef struct {
  int Direction;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  LPWSTR RemotePath;
  ns_int64 *pBytesTransferred;
  int PercentDone;
  LPWSTR Text;
  int lenText;
  int reserved;
} SCPTransferEventParamsW;



class SCPW : public SCP {

  public: //properties
  


    inline LPWSTR GetFilePermissions() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+2, 0, 0);
    }

    inline int SetFilePermissions(LPWSTR lpFilePermissions) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+2, 0, (void*)lpFilePermissions, 0);
    }





    inline LPWSTR GetFirewallHost() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+5, 0, 0);
    }

    inline int SetFirewallHost(LPWSTR lpFirewallHost) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+5, 0, (void*)lpFirewallHost, 0);
    }

    inline LPWSTR GetFirewallPassword() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+6, 0, 0);
    }

    inline int SetFirewallPassword(LPWSTR lpFirewallPassword) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+6, 0, (void*)lpFirewallPassword, 0);
    }



    inline LPWSTR GetFirewallUser() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+8, 0, 0);
    }

    inline int SetFirewallUser(LPWSTR lpFirewallUser) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+8, 0, (void*)lpFirewallUser, 0);
    }

    inline LPWSTR GetLocalFile() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+9, 0, 0);
    }

    inline int SetLocalFile(LPWSTR lpLocalFile) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+9, 0, (void*)lpLocalFile, 0);
    }

    inline LPWSTR GetLocalHost() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+10, 0, 0);
    }

    inline int SetLocalHost(LPWSTR lpLocalHost) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+10, 0, (void*)lpLocalHost, 0);
    }





    inline LPWSTR GetRemoteFile() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+13, 0, 0);
    }

    inline int SetRemoteFile(LPWSTR lpRemoteFile) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+13, 0, (void*)lpRemoteFile, 0);
    }

    inline LPWSTR GetRemotePath() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+14, 0, 0);
    }

    inline int SetRemotePath(LPWSTR lpRemotePath) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+14, 0, (void*)lpRemotePath, 0);
    }

    inline LPWSTR GetSSHAcceptServerHostKeyEncoded() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+15, 0, 0);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(LPWSTR lpSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+15, 0, (void*)lpSSHAcceptServerHostKeyEncoded, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncodedB(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SCP_Get(m_pObj, 15, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }
    inline int SetSSHAcceptServerHostKeyEncodedB(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SCP_Set(m_pObj, 15, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }


    inline LPWSTR GetSSHCertEncoded() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+17, 0, 0);
    }

    inline int SetSSHCertEncoded(LPWSTR lpSSHCertEncoded) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+17, 0, (void*)lpSSHCertEncoded, 0);
    }
    inline int GetSSHCertEncodedB(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SCP_Get(m_pObj, 17, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }
    inline int SetSSHCertEncodedB(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SCP_Set(m_pObj, 17, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }
    inline LPWSTR GetSSHCertStore() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+18, 0, 0);
    }

    inline int SetSSHCertStore(LPWSTR lpSSHCertStore) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+18, 0, (void*)lpSSHCertStore, 0);
    }
    inline int GetSSHCertStoreB(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SCP_Get(m_pObj, 18, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }
    inline int SetSSHCertStoreB(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SCP_Set(m_pObj, 18, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }
    inline LPWSTR GetSSHCertStorePassword() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+19, 0, 0);
    }

    inline int SetSSHCertStorePassword(LPWSTR lpSSHCertStorePassword) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+19, 0, (void*)lpSSHCertStorePassword, 0);
    }



    inline LPWSTR GetSSHCertSubject() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+21, 0, 0);
    }

    inline int SetSSHCertSubject(LPWSTR lpSSHCertSubject) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+21, 0, (void*)lpSSHCertSubject, 0);
    }

    inline LPWSTR GetSSHCompressionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+22, 0, 0);
    }

    inline int SetSSHCompressionAlgorithms(LPWSTR lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+22, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline LPWSTR GetSSHEncryptionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+23, 0, 0);
    }

    inline int SetSSHEncryptionAlgorithms(LPWSTR lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+23, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline LPWSTR GetSSHHost() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+24, 0, 0);
    }

    inline int SetSSHHost(LPWSTR lpSSHHost) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+24, 0, (void*)lpSSHHost, 0);
    }

    inline LPWSTR GetSSHPassword() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+25, 0, 0);
    }

    inline int SetSSHPassword(LPWSTR lpSSHPassword) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+25, 0, (void*)lpSSHPassword, 0);
    }



    inline LPWSTR GetSSHUser() {
      return (LPWSTR)IPWorksSSH_SCP_Get(m_pObj, 10000+27, 0, 0);
    }

    inline int SetSSHUser(LPWSTR lpSSHUser) {
      return IPWorksSSH_SCP_Set(m_pObj, 10000+27, 0, (void*)lpSSHUser, 0);
    }





  public: //events
  
    virtual int FireConnected(SCPConnectedEventParamsW *e) {return 0;}
    virtual int FireConnectionStatus(SCPConnectionStatusEventParamsW *e) {return 0;}
    virtual int FireDisconnected(SCPDisconnectedEventParamsW *e) {return 0;}
    virtual int FireEndTransfer(SCPEndTransferEventParamsW *e) {return 0;}
    virtual int FireError(SCPErrorEventParamsW *e) {return 0;}
    virtual int FireSSHCustomAuth(SCPSSHCustomAuthEventParamsW *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SCPSSHKeyboardInteractiveEventParamsW *e) {return 0;}
    virtual int FireSSHServerAuthentication(SCPSSHServerAuthenticationEventParamsW *e) {return 0;}
    virtual int FireSSHStatus(SCPSSHStatusEventParamsW *e) {return 0;}
    virtual int FireStartTransfer(SCPStartTransferEventParamsW *e) {return 0;}
    virtual int FireTransfer(SCPTransferEventParamsW *e) {return 0;}


  protected:
  
    virtual int SCPEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {
    	int ret_code = 0;
      switch (event_id) {
         case 1: {
            SCPConnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireConnected(&e);
            break;
         }
         case 2: {
            SCPConnectionStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SCPDisconnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireDisconnected(&e);
            break;
         }
         case 4: {
            SCPEndTransferEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]),  0};
            ret_code = FireEndTransfer(&e);
            break;
         }
         case 5: {
            SCPErrorEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (LPWSTR)IPH64CAST(param[4]),  0};
            ret_code = FireError(&e);
            break;
         }
         case 6: {
            SCPSSHCustomAuthEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 7: {
            SCPSSHKeyboardInteractiveEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 8: {
            SCPSSHServerAuthenticationEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 9: {
            SCPSSHStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHStatus(&e);
            break;
         }
         case 10: {
            SCPStartTransferEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (LPWSTR)IPH64CAST(param[4]),  0};
            ret_code = FireStartTransfer(&e);
            param[4] = (void*)(e.FilePermissions);
            break;
         }
         case 11: {
            SCPTransferEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (ns_int64*)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (LPWSTR)IPH64CAST(param[6]), (int)IPH64CAST(cbparam[6]),  0};
            ret_code = FireTransfer(&e);
            break;
         }

      }
      return ret_code;
    }
  
  public: //event overrides

    virtual int FireConnected(SCPConnectedEventParams *e) {return -10000;}
    virtual int FireConnectionStatus(SCPConnectionStatusEventParams *e) {return -10000;}
    virtual int FireDisconnected(SCPDisconnectedEventParams *e) {return -10000;}
    virtual int FireEndTransfer(SCPEndTransferEventParams *e) {return -10000;}
    virtual int FireError(SCPErrorEventParams *e) {return -10000;}
    virtual int FireSSHCustomAuth(SCPSSHCustomAuthEventParams *e) {return -10000;}
    virtual int FireSSHKeyboardInteractive(SCPSSHKeyboardInteractiveEventParams *e) {return -10000;}
    virtual int FireSSHServerAuthentication(SCPSSHServerAuthenticationEventParams *e) {return -10000;}
    virtual int FireSSHStatus(SCPSSHStatusEventParams *e) {return -10000;}
    virtual int FireStartTransfer(SCPStartTransferEventParams *e) {return -10000;}
    virtual int FireTransfer(SCPTransferEventParams *e) {return -10000;}

  public: //methods

    inline LPWSTR Config(LPWSTR lpszConfigurationString) {
      void *param[1+1] = {(void*)lpszConfigurationString, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 10000+2, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR DecodePacket(LPWSTR lpszEncodedPacket) {
      void *param[1+1] = {(void*)lpszEncodedPacket, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 10000+3, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 10000+4, 0, param, cbparam);
      
    }
    inline int Download() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 10000+5, 0, param, cbparam);
      
    }
    inline LPWSTR EncodePacket(LPWSTR lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)lpPacket, 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SCP_Do(m_pObj, 10000+6, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR GetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 10000+7, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR GetSSHParamBytes(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 10000+8, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline int Interrupt() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 10000+9, 0, param, cbparam);
      
    }
    inline LPWSTR SetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszFieldType, LPWSTR lpszFieldValue) {
      void *param[3+1] = {(void*)lpPayload, (void*)lpszFieldType, (void*)lpszFieldValue, 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SCP_Do(m_pObj, 10000+11, 3, param, cbparam);
      return (LPWSTR)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 10000+13, 0, param, cbparam);
      
    }
    inline int SSHLogon(LPWSTR lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)lpszSSHHost, (void*)lSSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SCP_Do(m_pObj, 10000+14, 2, param, cbparam);
      
    }
    inline int Upload() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 10000+15, 0, param, cbparam);
      
    }

};

#endif //WIN32

#endif //_IPWORKSSSH_SCP_H_




