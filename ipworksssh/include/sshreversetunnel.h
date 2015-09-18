/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHREVERSETUNNEL_H_
#define _IPWORKSSSH_SSHREVERSETUNNEL_H_

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


extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_StaticInit(void *hInst);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHReverseTunnel_StaticDestroy();

#ifdef WIN32
#include <windows.h>
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SSHReverseTunnelConnectedEventParams;

typedef struct {
  const char* ConnectionEvent;
  int StatusCode;
  const char* Description;
  int reserved;
} SSHReverseTunnelConnectionStatusEventParams;

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SSHReverseTunnelDisconnectedEventParams;

typedef struct {
  int ErrorCode;
  const char* Description;
  int reserved;
} SSHReverseTunnelErrorEventParams;

typedef struct {
  const char* ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelClosedEventParams;

typedef struct {
  const char* ChannelId;
  const char* ChannelData;
  int lenChannelData;
  int reserved;
} SSHReverseTunnelSSHChannelDataEventParams;

typedef struct {
  const char* ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelEOFEventParams;

typedef struct {
  const char* ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelOpenedEventParams;

typedef struct {
  const char* ChannelId;
  const char* Service;
  const char* ConnectedAddress;
  int ConnectedPort;
  const char* OriginAddress;
  int OriginPort;
  int Accept;
  int reserved;
} SSHReverseTunnelSSHChannelOpenRequestEventParams;

typedef struct {
  const char* ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelReadyToSendEventParams;

typedef struct {
  const char* ChannelId;
  const char* RequestType;
  const char* Packet;
  int lenPacket;
  int reserved;
} SSHReverseTunnelSSHChannelRequestedEventParams;

typedef struct {
  const char* Packet;
  int reserved;
} SSHReverseTunnelSSHCustomAuthEventParams;

typedef struct {
  const char* Name;
  const char* Instructions;
  const char* Prompt;
  const char* Response;
  int EchoResponse;
  int reserved;
} SSHReverseTunnelSSHKeyboardInteractiveEventParams;

typedef struct {
  const char* HostKey;
  const char* Fingerprint;
  const char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SSHReverseTunnelSSHServerAuthenticationEventParams;

typedef struct {
  const char* Message;
  int reserved;
} SSHReverseTunnelSSHStatusEventParams;



class SSHReverseTunnel {
  
  public: //events
  
    virtual int FireConnected(SSHReverseTunnelConnectedEventParams *e) {return 0;}
    virtual int FireConnectionStatus(SSHReverseTunnelConnectionStatusEventParams *e) {return 0;}
    virtual int FireDisconnected(SSHReverseTunnelDisconnectedEventParams *e) {return 0;}
    virtual int FireError(SSHReverseTunnelErrorEventParams *e) {return 0;}
    virtual int FireSSHChannelClosed(SSHReverseTunnelSSHChannelClosedEventParams *e) {return 0;}
    virtual int FireSSHChannelData(SSHReverseTunnelSSHChannelDataEventParams *e) {return 0;}
    virtual int FireSSHChannelEOF(SSHReverseTunnelSSHChannelEOFEventParams *e) {return 0;}
    virtual int FireSSHChannelOpened(SSHReverseTunnelSSHChannelOpenedEventParams *e) {return 0;}
    virtual int FireSSHChannelOpenRequest(SSHReverseTunnelSSHChannelOpenRequestEventParams *e) {return 0;}
    virtual int FireSSHChannelReadyToSend(SSHReverseTunnelSSHChannelReadyToSendEventParams *e) {return 0;}
    virtual int FireSSHChannelRequested(SSHReverseTunnelSSHChannelRequestedEventParams *e) {return 0;}
    virtual int FireSSHCustomAuth(SSHReverseTunnelSSHCustomAuthEventParams *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SSHReverseTunnelSSHKeyboardInteractiveEventParams *e) {return 0;}
    virtual int FireSSHServerAuthentication(SSHReverseTunnelSSHServerAuthenticationEventParams *e) {return 0;}
    virtual int FireSSHStatus(SSHReverseTunnelSSHStatusEventParams *e) {return 0;}


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SSHReverseTunnelEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      if (event_id > 10000) return ((SSHReverseTunnel*)lpObj)->SSHReverseTunnelEventSinkW(event_id - 10000, cparam, param, cbparam);
      switch (event_id) {
         case 1: {
            SSHReverseTunnelConnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SSHReverseTunnelConnectionStatusEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SSHReverseTunnelDisconnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SSHReverseTunnelErrorEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            SSHReverseTunnelSSHChannelClosedEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelClosed(&e);
            break;
         }
         case 6: {
            SSHReverseTunnelSSHChannelDataEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(cbparam[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelData(&e);
            break;
         }
         case 7: {
            SSHReverseTunnelSSHChannelEOFEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelEOF(&e);
            break;
         }
         case 8: {
            SSHReverseTunnelSSHChannelOpenedEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelOpened(&e);
            break;
         }
         case 9: {
            SSHReverseTunnelSSHChannelOpenRequestEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (int)IPH64CAST(param[6]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelOpenRequest(&e);
            param[6] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 10: {
            SSHReverseTunnelSSHChannelReadyToSendEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelReadyToSend(&e);
            break;
         }
         case 11: {
            SSHReverseTunnelSSHChannelRequestedEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelRequested(&e);
            break;
         }
         case 12: {
            SSHReverseTunnelSSHCustomAuthEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)IPH64CAST(e.Packet);
            break;
         }
         case 13: {
            SSHReverseTunnelSSHKeyboardInteractiveEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)IPH64CAST(e.Response);
            break;
         }
         case 14: {
            SSHReverseTunnelSSHServerAuthenticationEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 15: {
            SSHReverseTunnelSSHStatusEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }

    virtual int SSHReverseTunnelEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {return 0;}

  public:

    SSHReverseTunnel(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_19) {
      m_pObj = IPWorksSSH_SSHReverseTunnel_Create(SSHReverseTunnelEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~SSHReverseTunnel() {
      IPWorksSSH_SSHReverseTunnel_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_SSHReverseTunnel_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_SSHReverseTunnel_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline int GetSSHChannelCount() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 1, 0, 0);
      return (int)(long)val;
    }

    inline int GetBytesSent(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 2, iSSHChannelId, 0);
      return (int)(long)val;
    }

    inline char* GetChannelId(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 3, iSSHChannelId, 0);
      return (char*)val;
    }



    inline int SetDataToSend(int iSSHChannelId, const char *lpDataToSend, int lenDataToSend) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 4, iSSHChannelId, (void*)lpDataToSend, lenDataToSend);
    }

    inline int GetConnected() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 5, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)IPH64CAST(bConnected);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 5, 0, val, 0);
    }
    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 6, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)IPH64CAST(bFirewallAutoDetect);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 6, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 7, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)IPH64CAST(iFirewallType);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 7, 0, val, 0);
    }
    inline char* GetFirewallHost() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 8, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallHost(const char *lpFirewallHost) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 8, 0, (void*)lpFirewallHost, 0);
    }

    inline char* GetFirewallPassword() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 9, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallPassword(const char *lpFirewallPassword) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 9, 0, (void*)lpFirewallPassword, 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)IPH64CAST(lFirewallPort);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10, 0, val, 0);
    }
    inline char* GetFirewallUser() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 11, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallUser(const char *lpFirewallUser) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 11, 0, (void*)lpFirewallUser, 0);
    }

    inline char* GetLocalHost() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 12, 0, 0);
      return (char*)val;
    }

    inline int SetLocalHost(const char *lpLocalHost) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 12, 0, (void*)lpLocalHost, 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)IPH64CAST(lLocalPort);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 13, 0, val, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncoded(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 14, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 14, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 15, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)IPH64CAST(iSSHAuthMode);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 15, 0, val, 0);
    }
    inline int GetSSHCertEncoded(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 16, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }

    inline int SetSSHCertEncoded(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 16, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int GetSSHCertStore(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 17, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }

    inline int SetSSHCertStore(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 17, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }

    inline char* GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 18, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertStorePassword(const char *lpSSHCertStorePassword) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 18, 0, (void*)lpSSHCertStorePassword, 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 19, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)IPH64CAST(iSSHCertStoreType);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 19, 0, val, 0);
    }
    inline char* GetSSHCertSubject() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 20, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertSubject(const char *lpSSHCertSubject) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 20, 0, (void*)lpSSHCertSubject, 0);
    }

    inline char* GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 21, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCompressionAlgorithms(const char *lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 21, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline char* GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 22, 0, 0);
      return (char*)val;
    }

    inline int SetSSHEncryptionAlgorithms(const char *lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 22, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline char* GetSSHHost() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 23, 0, 0);
      return (char*)val;
    }

    inline int SetSSHHost(const char *lpSSHHost) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 23, 0, (void*)lpSSHHost, 0);
    }

    inline char* GetSSHPassword() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 24, 0, 0);
      return (char*)val;
    }

    inline int SetSSHPassword(const char *lpSSHPassword) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 24, 0, (void*)lpSSHPassword, 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 25, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)IPH64CAST(lSSHPort);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 25, 0, val, 0);
    }
    inline char* GetSSHUser() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 26, 0, 0);
      return (char*)val;
    }

    inline int SetSSHUser(const char *lpSSHUser) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 26, 0, (void*)lpSSHUser, 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 27, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)IPH64CAST(iTimeout);
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 27, 0, val, 0);
    }

  public: //methods

    inline int CancelTcpIpForwarding(const char* lpszAddress, int iPort) {
      void *param[2+1] = {(void*)IPH64CAST(lpszAddress), (void*)IPH64CAST(iPort), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 2, 2, param, cbparam);
      
      
    }
    inline int CloseChannel(const char* lpszChannelId) {
      void *param[1+1] = {(void*)IPH64CAST(lpszChannelId), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 3, 1, param, cbparam);
      
      
    }
    inline char* Config(const char* lpszConfigurationString) {
      void *param[1+1] = {(void*)IPH64CAST(lpszConfigurationString), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 4, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* DecodePacket(const char* lpszEncodedPacket, int *lpSize = 0) {
      void *param[1+1] = {(void*)IPH64CAST(lpszEncodedPacket), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 5, 1, param, cbparam);
      if (lpSize) *lpSize = cbparam[1];
      return (char*)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 6, 0, param, cbparam);
      
      
    }
    inline char* EncodePacket(const char* lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)IPH64CAST(lpPacket), 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 7, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline int ExchangeKeys() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 8, 0, param, cbparam);
      
      
    }
    inline char* GetSSHParam(const char* lpPayload, int lenPayload, const char* lpszField) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 9, 2, param, cbparam);
      
      return (char*)IPH64CAST(param[2]);
    }
    inline char* GetSSHParamBytes(const char* lpPayload, int lenPayload, const char* lpszField, int *lpSize = 0) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10, 2, param, cbparam);
      if (lpSize) *lpSize = cbparam[2];
      return (char*)IPH64CAST(param[2]);
    }
    inline int RequestTcpIpForwarding(const char* lpszAddress, int iPort) {
      void *param[2+1] = {(void*)IPH64CAST(lpszAddress), (void*)IPH64CAST(iPort), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 11, 2, param, cbparam);
      
      
    }
    inline int SendChannelData(const char* lpszChannelId, const char* lpData, int lenData) {
      void *param[2+1] = {(void*)IPH64CAST(lpszChannelId), (void*)IPH64CAST(lpData), 0};
      int cbparam[2+1] = {0, lenData, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 12, 2, param, cbparam);
      
      
    }
    inline char* SetSSHParam(const char* lpPayload, int lenPayload, const char* lpszFieldType, const char* lpszFieldValue, int *lpSize = 0) {
      void *param[3+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszFieldType), (void*)IPH64CAST(lpszFieldValue), 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 13, 3, param, cbparam);
      if (lpSize) *lpSize = cbparam[3];
      return (char*)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 14, 0, param, cbparam);
      
      
    }
    inline int SSHLogon(const char* lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)IPH64CAST(lpszSSHHost), (void*)IPH64CAST(lSSHPort), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 15, 2, param, cbparam);
      
      
    }

};


#ifdef WIN32 //UNICODE

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SSHReverseTunnelConnectedEventParamsW;

typedef struct {
  LPWSTR ConnectionEvent;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SSHReverseTunnelConnectionStatusEventParamsW;

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SSHReverseTunnelDisconnectedEventParamsW;

typedef struct {
  int ErrorCode;
  LPWSTR Description;
  int reserved;
} SSHReverseTunnelErrorEventParamsW;

typedef struct {
  LPWSTR ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelClosedEventParamsW;

typedef struct {
  LPWSTR ChannelId;
  LPWSTR ChannelData;
  int lenChannelData;
  int reserved;
} SSHReverseTunnelSSHChannelDataEventParamsW;

typedef struct {
  LPWSTR ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelEOFEventParamsW;

typedef struct {
  LPWSTR ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelOpenedEventParamsW;

typedef struct {
  LPWSTR ChannelId;
  LPWSTR Service;
  LPWSTR ConnectedAddress;
  int ConnectedPort;
  LPWSTR OriginAddress;
  int OriginPort;
  int Accept;
  int reserved;
} SSHReverseTunnelSSHChannelOpenRequestEventParamsW;

typedef struct {
  LPWSTR ChannelId;
  int reserved;
} SSHReverseTunnelSSHChannelReadyToSendEventParamsW;

typedef struct {
  LPWSTR ChannelId;
  LPWSTR RequestType;
  LPWSTR Packet;
  int lenPacket;
  int reserved;
} SSHReverseTunnelSSHChannelRequestedEventParamsW;

typedef struct {
  LPWSTR Packet;
  int reserved;
} SSHReverseTunnelSSHCustomAuthEventParamsW;

typedef struct {
  LPWSTR Name;
  LPWSTR Instructions;
  LPWSTR Prompt;
  LPWSTR Response;
  int EchoResponse;
  int reserved;
} SSHReverseTunnelSSHKeyboardInteractiveEventParamsW;

typedef struct {
  LPWSTR HostKey;
  LPWSTR Fingerprint;
  LPWSTR KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SSHReverseTunnelSSHServerAuthenticationEventParamsW;

typedef struct {
  LPWSTR Message;
  int reserved;
} SSHReverseTunnelSSHStatusEventParamsW;



class SSHReverseTunnelW : public SSHReverseTunnel {

  public: //properties
  




    inline LPWSTR GetChannelId(int iSSHChannelId) {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+3, iSSHChannelId, 0);
    }





    inline int SetDataToSend(int iSSHChannelId, LPWSTR lpDataToSend) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+4, iSSHChannelId, (void*)lpDataToSend, 0);
    }

    inline int SetDataToSendB(int iSSHChannelId, const char *lpDataToSend, int lenDataToSend) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 4, iSSHChannelId, (void*)lpDataToSend, lenDataToSend);
    }






    inline LPWSTR GetFirewallHost() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+8, 0, 0);
    }

    inline int SetFirewallHost(LPWSTR lpFirewallHost) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+8, 0, (void*)lpFirewallHost, 0);
    }

    inline LPWSTR GetFirewallPassword() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+9, 0, 0);
    }

    inline int SetFirewallPassword(LPWSTR lpFirewallPassword) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+9, 0, (void*)lpFirewallPassword, 0);
    }



    inline LPWSTR GetFirewallUser() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+11, 0, 0);
    }

    inline int SetFirewallUser(LPWSTR lpFirewallUser) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+11, 0, (void*)lpFirewallUser, 0);
    }

    inline LPWSTR GetLocalHost() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+12, 0, 0);
    }

    inline int SetLocalHost(LPWSTR lpLocalHost) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+12, 0, (void*)lpLocalHost, 0);
    }



    inline LPWSTR GetSSHAcceptServerHostKeyEncoded() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+14, 0, 0);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(LPWSTR lpSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+14, 0, (void*)lpSSHAcceptServerHostKeyEncoded, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncodedB(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 14, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }
    inline int SetSSHAcceptServerHostKeyEncodedB(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 14, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }


    inline LPWSTR GetSSHCertEncoded() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+16, 0, 0);
    }

    inline int SetSSHCertEncoded(LPWSTR lpSSHCertEncoded) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+16, 0, (void*)lpSSHCertEncoded, 0);
    }
    inline int GetSSHCertEncodedB(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 16, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }
    inline int SetSSHCertEncodedB(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 16, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }
    inline LPWSTR GetSSHCertStore() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+17, 0, 0);
    }

    inline int SetSSHCertStore(LPWSTR lpSSHCertStore) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+17, 0, (void*)lpSSHCertStore, 0);
    }
    inline int GetSSHCertStoreB(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 17, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }
    inline int SetSSHCertStoreB(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 17, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }
    inline LPWSTR GetSSHCertStorePassword() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+18, 0, 0);
    }

    inline int SetSSHCertStorePassword(LPWSTR lpSSHCertStorePassword) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+18, 0, (void*)lpSSHCertStorePassword, 0);
    }



    inline LPWSTR GetSSHCertSubject() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+20, 0, 0);
    }

    inline int SetSSHCertSubject(LPWSTR lpSSHCertSubject) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+20, 0, (void*)lpSSHCertSubject, 0);
    }

    inline LPWSTR GetSSHCompressionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+21, 0, 0);
    }

    inline int SetSSHCompressionAlgorithms(LPWSTR lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+21, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline LPWSTR GetSSHEncryptionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+22, 0, 0);
    }

    inline int SetSSHEncryptionAlgorithms(LPWSTR lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+22, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline LPWSTR GetSSHHost() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+23, 0, 0);
    }

    inline int SetSSHHost(LPWSTR lpSSHHost) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+23, 0, (void*)lpSSHHost, 0);
    }

    inline LPWSTR GetSSHPassword() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+24, 0, 0);
    }

    inline int SetSSHPassword(LPWSTR lpSSHPassword) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+24, 0, (void*)lpSSHPassword, 0);
    }



    inline LPWSTR GetSSHUser() {
      return (LPWSTR)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10000+26, 0, 0);
    }

    inline int SetSSHUser(LPWSTR lpSSHUser) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10000+26, 0, (void*)lpSSHUser, 0);
    }





  public: //events
  
    virtual int FireConnected(SSHReverseTunnelConnectedEventParamsW *e) {return 0;}
    virtual int FireConnectionStatus(SSHReverseTunnelConnectionStatusEventParamsW *e) {return 0;}
    virtual int FireDisconnected(SSHReverseTunnelDisconnectedEventParamsW *e) {return 0;}
    virtual int FireError(SSHReverseTunnelErrorEventParamsW *e) {return 0;}
    virtual int FireSSHChannelClosed(SSHReverseTunnelSSHChannelClosedEventParamsW *e) {return 0;}
    virtual int FireSSHChannelData(SSHReverseTunnelSSHChannelDataEventParamsW *e) {return 0;}
    virtual int FireSSHChannelEOF(SSHReverseTunnelSSHChannelEOFEventParamsW *e) {return 0;}
    virtual int FireSSHChannelOpened(SSHReverseTunnelSSHChannelOpenedEventParamsW *e) {return 0;}
    virtual int FireSSHChannelOpenRequest(SSHReverseTunnelSSHChannelOpenRequestEventParamsW *e) {return 0;}
    virtual int FireSSHChannelReadyToSend(SSHReverseTunnelSSHChannelReadyToSendEventParamsW *e) {return 0;}
    virtual int FireSSHChannelRequested(SSHReverseTunnelSSHChannelRequestedEventParamsW *e) {return 0;}
    virtual int FireSSHCustomAuth(SSHReverseTunnelSSHCustomAuthEventParamsW *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SSHReverseTunnelSSHKeyboardInteractiveEventParamsW *e) {return 0;}
    virtual int FireSSHServerAuthentication(SSHReverseTunnelSSHServerAuthenticationEventParamsW *e) {return 0;}
    virtual int FireSSHStatus(SSHReverseTunnelSSHStatusEventParamsW *e) {return 0;}


  protected:
  
    virtual int SSHReverseTunnelEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {
    	int ret_code = 0;
      switch (event_id) {
         case 1: {
            SSHReverseTunnelConnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireConnected(&e);
            break;
         }
         case 2: {
            SSHReverseTunnelConnectionStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SSHReverseTunnelDisconnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireDisconnected(&e);
            break;
         }
         case 4: {
            SSHReverseTunnelErrorEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireError(&e);
            break;
         }
         case 5: {
            SSHReverseTunnelSSHChannelClosedEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHChannelClosed(&e);
            break;
         }
         case 6: {
            SSHReverseTunnelSSHChannelDataEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (int)IPH64CAST(cbparam[1]),  0};
            ret_code = FireSSHChannelData(&e);
            break;
         }
         case 7: {
            SSHReverseTunnelSSHChannelEOFEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHChannelEOF(&e);
            break;
         }
         case 8: {
            SSHReverseTunnelSSHChannelOpenedEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHChannelOpened(&e);
            break;
         }
         case 9: {
            SSHReverseTunnelSSHChannelOpenRequestEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (LPWSTR)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (int)IPH64CAST(param[6]),  0};
            ret_code = FireSSHChannelOpenRequest(&e);
            param[6] = (void*)(e.Accept);
            break;
         }
         case 10: {
            SSHReverseTunnelSSHChannelReadyToSendEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHChannelReadyToSend(&e);
            break;
         }
         case 11: {
            SSHReverseTunnelSSHChannelRequestedEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = FireSSHChannelRequested(&e);
            break;
         }
         case 12: {
            SSHReverseTunnelSSHCustomAuthEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 13: {
            SSHReverseTunnelSSHKeyboardInteractiveEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 14: {
            SSHReverseTunnelSSHServerAuthenticationEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 15: {
            SSHReverseTunnelSSHStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }
  
  public: //event overrides

    virtual int FireConnected(SSHReverseTunnelConnectedEventParams *e) {return -10000;}
    virtual int FireConnectionStatus(SSHReverseTunnelConnectionStatusEventParams *e) {return -10000;}
    virtual int FireDisconnected(SSHReverseTunnelDisconnectedEventParams *e) {return -10000;}
    virtual int FireError(SSHReverseTunnelErrorEventParams *e) {return -10000;}
    virtual int FireSSHChannelClosed(SSHReverseTunnelSSHChannelClosedEventParams *e) {return -10000;}
    virtual int FireSSHChannelData(SSHReverseTunnelSSHChannelDataEventParams *e) {return -10000;}
    virtual int FireSSHChannelEOF(SSHReverseTunnelSSHChannelEOFEventParams *e) {return -10000;}
    virtual int FireSSHChannelOpened(SSHReverseTunnelSSHChannelOpenedEventParams *e) {return -10000;}
    virtual int FireSSHChannelOpenRequest(SSHReverseTunnelSSHChannelOpenRequestEventParams *e) {return -10000;}
    virtual int FireSSHChannelReadyToSend(SSHReverseTunnelSSHChannelReadyToSendEventParams *e) {return -10000;}
    virtual int FireSSHChannelRequested(SSHReverseTunnelSSHChannelRequestedEventParams *e) {return -10000;}
    virtual int FireSSHCustomAuth(SSHReverseTunnelSSHCustomAuthEventParams *e) {return -10000;}
    virtual int FireSSHKeyboardInteractive(SSHReverseTunnelSSHKeyboardInteractiveEventParams *e) {return -10000;}
    virtual int FireSSHServerAuthentication(SSHReverseTunnelSSHServerAuthenticationEventParams *e) {return -10000;}
    virtual int FireSSHStatus(SSHReverseTunnelSSHStatusEventParams *e) {return -10000;}

  public: //methods

    inline int CancelTcpIpForwarding(LPWSTR lpszAddress, int iPort) {
      void *param[2+1] = {(void*)lpszAddress, (void*)iPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+2, 2, param, cbparam);
      
    }
    inline int CloseChannel(LPWSTR lpszChannelId) {
      void *param[1+1] = {(void*)lpszChannelId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+3, 1, param, cbparam);
      
    }
    inline LPWSTR Config(LPWSTR lpszConfigurationString) {
      void *param[1+1] = {(void*)lpszConfigurationString, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+4, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR DecodePacket(LPWSTR lpszEncodedPacket) {
      void *param[1+1] = {(void*)lpszEncodedPacket, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+5, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+6, 0, param, cbparam);
      
    }
    inline LPWSTR EncodePacket(LPWSTR lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)lpPacket, 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+7, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int ExchangeKeys() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+8, 0, param, cbparam);
      
    }
    inline LPWSTR GetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+9, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR GetSSHParamBytes(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+10, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline int RequestTcpIpForwarding(LPWSTR lpszAddress, int iPort) {
      void *param[2+1] = {(void*)lpszAddress, (void*)iPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+11, 2, param, cbparam);
      
    }
    inline int SendChannelData(LPWSTR lpszChannelId, LPWSTR lpData, int lenData) {
      void *param[2+1] = {(void*)lpszChannelId, (void*)lpData, 0};
      int cbparam[2+1] = {0, lenData, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+12, 2, param, cbparam);
      
    }
    inline LPWSTR SetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszFieldType, LPWSTR lpszFieldValue) {
      void *param[3+1] = {(void*)lpPayload, (void*)lpszFieldType, (void*)lpszFieldValue, 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+13, 3, param, cbparam);
      return (LPWSTR)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+14, 0, param, cbparam);
      
    }
    inline int SSHLogon(LPWSTR lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)lpszSSHHost, (void*)lSSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10000+15, 2, param, cbparam);
      
    }

};

#endif //WIN32

#endif //_IPWORKSSSH_SSHREVERSETUNNEL_H_




