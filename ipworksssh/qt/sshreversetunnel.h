/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHREVERSETUNNEL_H_
#define _IPWORKSSSH_SSHREVERSETUNNEL_H_

#include "ipworksssh.h"
#include "../include/ipworksssh.key"
#include <QObject.h>

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


struct SSHReverseTunnelConnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHReverseTunnelConnectionStatusEventParams {
  int EventRetVal;
  char* ConnectionEvent;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHReverseTunnelDisconnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHReverseTunnelErrorEventParams {
  int EventRetVal;
  int ErrorCode;
  char* Description;
  int reserved;
};

struct SSHReverseTunnelSSHChannelClosedEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHReverseTunnelSSHChannelDataEventParams {
  int EventRetVal;
  char* ChannelId;
  char* ChannelData;
  int lenChannelData;
  int reserved;
};

struct SSHReverseTunnelSSHChannelEOFEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHReverseTunnelSSHChannelOpenedEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHReverseTunnelSSHChannelOpenRequestEventParams {
  int EventRetVal;
  char* ChannelId;
  char* Service;
  char* ConnectedAddress;
  int ConnectedPort;
  char* OriginAddress;
  int OriginPort;
  int Accept;
  int reserved;
};

struct SSHReverseTunnelSSHChannelReadyToSendEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHReverseTunnelSSHChannelRequestedEventParams {
  int EventRetVal;
  char* ChannelId;
  char* RequestType;
  char* Packet;
  int lenPacket;
  int reserved;
};

struct SSHReverseTunnelSSHCustomAuthEventParams {
  int EventRetVal;
  char* Packet;
  int reserved;
};

struct SSHReverseTunnelSSHKeyboardInteractiveEventParams {
  int EventRetVal;
  char* Name;
  char* Instructions;
  char* Prompt;
  char* Response;
  int EchoResponse;
  int reserved;
};

struct SSHReverseTunnelSSHServerAuthenticationEventParams {
  int EventRetVal;
  char* HostKey;
  char* Fingerprint;
  char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
};

struct SSHReverseTunnelSSHStatusEventParams {
  int EventRetVal;
  char* Message;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class SSHReverseTunnel : public QObject {

  Q_OBJECT
signals: //events

    void Connected(SSHReverseTunnelConnectedEventParams *e);
    void ConnectionStatus(SSHReverseTunnelConnectionStatusEventParams *e);
    void Disconnected(SSHReverseTunnelDisconnectedEventParams *e);
    void Error(SSHReverseTunnelErrorEventParams *e);
    void SSHChannelClosed(SSHReverseTunnelSSHChannelClosedEventParams *e);
    void SSHChannelData(SSHReverseTunnelSSHChannelDataEventParams *e);
    void SSHChannelEOF(SSHReverseTunnelSSHChannelEOFEventParams *e);
    void SSHChannelOpened(SSHReverseTunnelSSHChannelOpenedEventParams *e);
    void SSHChannelOpenRequest(SSHReverseTunnelSSHChannelOpenRequestEventParams *e);
    void SSHChannelReadyToSend(SSHReverseTunnelSSHChannelReadyToSendEventParams *e);
    void SSHChannelRequested(SSHReverseTunnelSSHChannelRequestedEventParams *e);
    void SSHCustomAuth(SSHReverseTunnelSSHCustomAuthEventParams *e);
    void SSHKeyboardInteractive(SSHReverseTunnelSSHKeyboardInteractiveEventParams *e);
    void SSHServerAuthentication(SSHReverseTunnelSSHServerAuthenticationEventParams *e);
    void SSHStatus(SSHReverseTunnelSSHStatusEventParams *e);

protected: // event firers
    virtual int FireConnected(SSHReverseTunnelConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionStatus(SSHReverseTunnelConnectionStatusEventParams *e) {
      emit ConnectionStatus(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(SSHReverseTunnelDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireError(SSHReverseTunnelErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelClosed(SSHReverseTunnelSSHChannelClosedEventParams *e) {
      emit SSHChannelClosed(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelData(SSHReverseTunnelSSHChannelDataEventParams *e) {
      emit SSHChannelData(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelEOF(SSHReverseTunnelSSHChannelEOFEventParams *e) {
      emit SSHChannelEOF(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelOpened(SSHReverseTunnelSSHChannelOpenedEventParams *e) {
      emit SSHChannelOpened(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelOpenRequest(SSHReverseTunnelSSHChannelOpenRequestEventParams *e) {
      emit SSHChannelOpenRequest(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelReadyToSend(SSHReverseTunnelSSHChannelReadyToSendEventParams *e) {
      emit SSHChannelReadyToSend(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelRequested(SSHReverseTunnelSSHChannelRequestedEventParams *e) {
      emit SSHChannelRequested(e);
      return e->EventRetVal;
    }
    virtual int FireSSHCustomAuth(SSHReverseTunnelSSHCustomAuthEventParams *e) {
      emit SSHCustomAuth(e);
      return e->EventRetVal;
    }
    virtual int FireSSHKeyboardInteractive(SSHReverseTunnelSSHKeyboardInteractiveEventParams *e) {
      emit SSHKeyboardInteractive(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServerAuthentication(SSHReverseTunnelSSHServerAuthenticationEventParams *e) {
      emit SSHServerAuthentication(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(SSHReverseTunnelSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SSHReverseTunnelEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            SSHReverseTunnelConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SSHReverseTunnelConnectionStatusEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SSHReverseTunnelDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SSHReverseTunnelErrorEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            SSHReverseTunnelSSHChannelClosedEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelClosed(&e);
            break;
         }
         case 6: {
            SSHReverseTunnelSSHChannelDataEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(cbparam[1]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelData(&e);
            break;
         }
         case 7: {
            SSHReverseTunnelSSHChannelEOFEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelEOF(&e);
            break;
         }
         case 8: {
            SSHReverseTunnelSSHChannelOpenedEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelOpened(&e);
            break;
         }
         case 9: {
            SSHReverseTunnelSSHChannelOpenRequestEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (int)IPH64CAST(param[6]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelOpenRequest(&e);
            param[6] = (void*)(e.Accept);
            break;
         }
         case 10: {
            SSHReverseTunnelSSHChannelReadyToSendEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelReadyToSend(&e);
            break;
         }
         case 11: {
            SSHReverseTunnelSSHChannelRequestedEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHChannelRequested(&e);
            break;
         }
         case 12: {
            SSHReverseTunnelSSHCustomAuthEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 13: {
            SSHReverseTunnelSSHKeyboardInteractiveEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 14: {
            SSHReverseTunnelSSHServerAuthenticationEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 15: {
            SSHReverseTunnelSSHStatusEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHReverseTunnel*)lpObj)->FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }

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

    inline QString GetChannelId(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 3, iSSHChannelId, 0);
      return QString((char*)val);
    }



    inline int SetDataToSend(int iSSHChannelId, const QByteArray &qba) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 4, iSSHChannelId, (void*)qba.data(), qba.size());
    }

    inline int GetConnected() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 5, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)bConnected;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 5, 0, val, 0);
    }
    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 6, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)bFirewallAutoDetect;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 6, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 7, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)iFirewallType;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 7, 0, val, 0);
    }
    inline QString GetFirewallHost() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 8, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallHost(const QString &FirewallHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallHost.toLatin1();
      #else
      QByteArray qba = FirewallHost.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 8, 0, (void*)qba.data(), 0);
    }

    inline QString GetFirewallPassword() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 9, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallPassword(const QString &FirewallPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallPassword.toLatin1();
      #else
      QByteArray qba = FirewallPassword.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 9, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 10, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)lFirewallPort;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 10, 0, val, 0);
    }
    inline QString GetFirewallUser() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 11, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallUser(const QString &FirewallUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallUser.toLatin1();
      #else
      QByteArray qba = FirewallUser.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 11, 0, (void*)qba.data(), 0);
    }

    inline QString GetLocalHost() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 12, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 12, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 13, 0, val, 0);
    }
    inline QByteArray GetSSHAcceptServerHostKeyEncoded() {
      char *lpSSHAcceptServerHostKeyEncoded = NULL;
      int lenSSHAcceptServerHostKeyEncoded = 0;
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 14, 0, &lenSSHAcceptServerHostKeyEncoded);
      return QByteArray(lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const QByteArray &qba) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 14, 0, (void*)qba.data(), qba.size());
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 15, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)iSSHAuthMode;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 15, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 16, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 16, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 17, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 17, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 18, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 18, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 19, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 19, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 20, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 20, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 21, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 21, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 22, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 22, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHHost() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 23, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHHost(const QString &SSHHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHHost.toLatin1();
      #else
      QByteArray qba = SSHHost.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 23, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHPassword() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 24, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPassword(const QString &SSHPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPassword.toLatin1();
      #else
      QByteArray qba = SSHPassword.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 24, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 25, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)lSSHPort;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 25, 0, val, 0);
    }
    inline QString GetSSHUser() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 26, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHUser(const QString &SSHUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHUser.toLatin1();
      #else
      QByteArray qba = SSHUser.toAscii();
      #endif
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 26, 0, (void*)qba.data(), 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SSHReverseTunnel_Get(m_pObj, 27, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)iTimeout;
      return IPWorksSSH_SSHReverseTunnel_Set(m_pObj, 27, 0, val, 0);
    }

  public: //methods

    inline int CancelTcpIpForwarding(const QString &Address, int Port) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Address = Address.toLatin1();
      #else
      QByteArray t_Address = Address.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_Address.data(), (void*)Port, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 2, 2, param, cbparam);
      
    }
    inline int CloseChannel(const QString &ChannelId) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelId = ChannelId.toLatin1();
      #else
      QByteArray t_ChannelId = ChannelId.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ChannelId.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 3, 1, param, cbparam);
      
    }
    inline QString Config(const QString &ConfigurationString) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ConfigurationString = ConfigurationString.toLatin1();
      #else
      QByteArray t_ConfigurationString = ConfigurationString.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ConfigurationString.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 4, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline QByteArray DecodePacket(const QString &EncodedPacket) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_EncodedPacket = EncodedPacket.toLatin1();
      #else
      QByteArray t_EncodedPacket = EncodedPacket.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_EncodedPacket.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 5, 1, param, cbparam);
      return QByteArray((char*)param[1],cbparam[1]);
      
    }
    inline int DoEvents() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 6, 0, param, cbparam);
      
    }
    inline QString EncodePacket(const QByteArray &Packet) {
       
      void *param[1+1] = {(void*)Packet.data(), 0};
      int cbparam[1+1] = {Packet.size(), 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 7, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline int ExchangeKeys() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 8, 0, param, cbparam);
      
    }
    inline QString GetSSHParam(const QByteArray &Payload, const QString &Field) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Field = Field.toLatin1();
      #else
      QByteArray t_Field = Field.toAscii();
      #endif
      
      void *param[2+1] = {(void*)Payload.data(), (void*)t_Field.data(), 0};
      int cbparam[2+1] = {Payload.size(), 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 9, 2, param, cbparam);
      return QString((char*)param[2]);
      
    }
    inline QByteArray GetSSHParamBytes(const QByteArray &Payload, const QString &Field) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Field = Field.toLatin1();
      #else
      QByteArray t_Field = Field.toAscii();
      #endif
      
      void *param[2+1] = {(void*)Payload.data(), (void*)t_Field.data(), 0};
      int cbparam[2+1] = {Payload.size(), 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 10, 2, param, cbparam);
      return QByteArray((char*)param[2],cbparam[2]);
      
    }
    inline int RequestTcpIpForwarding(const QString &Address, int Port) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Address = Address.toLatin1();
      #else
      QByteArray t_Address = Address.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_Address.data(), (void*)Port, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 11, 2, param, cbparam);
      
    }
    inline int SendChannelData(const QString &ChannelId, const QByteArray &Data) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelId = ChannelId.toLatin1();
      #else
      QByteArray t_ChannelId = ChannelId.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_ChannelId.data(), (void*)Data.data(), 0};
      int cbparam[2+1] = {0, Data.size(), 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 12, 2, param, cbparam);
      
    }
    inline QByteArray SetSSHParam(const QByteArray &Payload, const QString &FieldType, const QString &FieldValue) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_FieldType = FieldType.toLatin1();
      #else
      QByteArray t_FieldType = FieldType.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_FieldValue = FieldValue.toLatin1();
      #else
      QByteArray t_FieldValue = FieldValue.toAscii();
      #endif
      
      void *param[3+1] = {(void*)Payload.data(), (void*)t_FieldType.data(), (void*)t_FieldValue.data(), 0};
      int cbparam[3+1] = {Payload.size(), 0, 0, 0};
      IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 13, 3, param, cbparam);
      return QByteArray((char*)param[3],cbparam[3]);
      
    }
    inline int SSHLogoff() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 14, 0, param, cbparam);
      
    }
    inline int SSHLogon(const QString &SSHHost, long SSHPort) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_SSHHost = SSHHost.toLatin1();
      #else
      QByteArray t_SSHHost = SSHHost.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_SSHHost.data(), (void*)SSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHReverseTunnel_Do(m_pObj, 15, 2, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_SSHREVERSETUNNEL_H_




