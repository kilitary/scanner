/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHCLIENT_H_
#define _IPWORKSSSH_SSHCLIENT_H_

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



extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHClient_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHClient_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHClient_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHClient_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHClient_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHClient_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SSHClient_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHClient_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHClient_StaticInit(void *hInst);


struct SSHClientConnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHClientConnectionStatusEventParams {
  int EventRetVal;
  char* ConnectionEvent;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHClientDisconnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHClientErrorEventParams {
  int EventRetVal;
  int ErrorCode;
  char* Description;
  int reserved;
};

struct SSHClientSSHChannelClosedEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHClientSSHChannelDataEventParams {
  int EventRetVal;
  char* ChannelId;
  char* ChannelData;
  int lenChannelData;
  int reserved;
};

struct SSHClientSSHChannelEOFEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHClientSSHChannelOpenedEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHClientSSHChannelOpenRequestEventParams {
  int EventRetVal;
  char* ChannelId;
  char* Service;
  char* Parameters;
  int Accept;
  int lenParameters;
  int reserved;
};

struct SSHClientSSHChannelReadyToSendEventParams {
  int EventRetVal;
  char* ChannelId;
  int reserved;
};

struct SSHClientSSHChannelRequestEventParams {
  int EventRetVal;
  char* ChannelId;
  char* RequestType;
  char* Packet;
  int Success;
  int lenPacket;
  int reserved;
};

struct SSHClientSSHChannelRequestedEventParams {
  int EventRetVal;
  char* ChannelId;
  char* RequestType;
  char* Packet;
  int lenPacket;
  int reserved;
};

struct SSHClientSSHCustomAuthEventParams {
  int EventRetVal;
  char* Packet;
  int reserved;
};

struct SSHClientSSHKeyboardInteractiveEventParams {
  int EventRetVal;
  char* Name;
  char* Instructions;
  char* Prompt;
  char* Response;
  int EchoResponse;
  int reserved;
};

struct SSHClientSSHServerAuthenticationEventParams {
  int EventRetVal;
  char* HostKey;
  char* Fingerprint;
  char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
};

struct SSHClientSSHStatusEventParams {
  int EventRetVal;
  char* Message;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class SSHClient : public QObject {

  Q_OBJECT
signals: //events

    void Connected(SSHClientConnectedEventParams *e);
    void ConnectionStatus(SSHClientConnectionStatusEventParams *e);
    void Disconnected(SSHClientDisconnectedEventParams *e);
    void Error(SSHClientErrorEventParams *e);
    void SSHChannelClosed(SSHClientSSHChannelClosedEventParams *e);
    void SSHChannelData(SSHClientSSHChannelDataEventParams *e);
    void SSHChannelEOF(SSHClientSSHChannelEOFEventParams *e);
    void SSHChannelOpened(SSHClientSSHChannelOpenedEventParams *e);
    void SSHChannelOpenRequest(SSHClientSSHChannelOpenRequestEventParams *e);
    void SSHChannelReadyToSend(SSHClientSSHChannelReadyToSendEventParams *e);
    void SSHChannelRequest(SSHClientSSHChannelRequestEventParams *e);
    void SSHChannelRequested(SSHClientSSHChannelRequestedEventParams *e);
    void SSHCustomAuth(SSHClientSSHCustomAuthEventParams *e);
    void SSHKeyboardInteractive(SSHClientSSHKeyboardInteractiveEventParams *e);
    void SSHServerAuthentication(SSHClientSSHServerAuthenticationEventParams *e);
    void SSHStatus(SSHClientSSHStatusEventParams *e);

protected: // event firers
    virtual int FireConnected(SSHClientConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionStatus(SSHClientConnectionStatusEventParams *e) {
      emit ConnectionStatus(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(SSHClientDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireError(SSHClientErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelClosed(SSHClientSSHChannelClosedEventParams *e) {
      emit SSHChannelClosed(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelData(SSHClientSSHChannelDataEventParams *e) {
      emit SSHChannelData(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelEOF(SSHClientSSHChannelEOFEventParams *e) {
      emit SSHChannelEOF(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelOpened(SSHClientSSHChannelOpenedEventParams *e) {
      emit SSHChannelOpened(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelOpenRequest(SSHClientSSHChannelOpenRequestEventParams *e) {
      emit SSHChannelOpenRequest(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelReadyToSend(SSHClientSSHChannelReadyToSendEventParams *e) {
      emit SSHChannelReadyToSend(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelRequest(SSHClientSSHChannelRequestEventParams *e) {
      emit SSHChannelRequest(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelRequested(SSHClientSSHChannelRequestedEventParams *e) {
      emit SSHChannelRequested(e);
      return e->EventRetVal;
    }
    virtual int FireSSHCustomAuth(SSHClientSSHCustomAuthEventParams *e) {
      emit SSHCustomAuth(e);
      return e->EventRetVal;
    }
    virtual int FireSSHKeyboardInteractive(SSHClientSSHKeyboardInteractiveEventParams *e) {
      emit SSHKeyboardInteractive(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServerAuthentication(SSHClientSSHServerAuthenticationEventParams *e) {
      emit SSHServerAuthentication(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(SSHClientSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SSHClientEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            SSHClientConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHClient*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SSHClientConnectionStatusEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHClient*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SSHClientDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHClient*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SSHClientErrorEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHClient*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            SSHClientSSHChannelClosedEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelClosed(&e);
            break;
         }
         case 6: {
            SSHClientSSHChannelDataEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(cbparam[1]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelData(&e);
            break;
         }
         case 7: {
            SSHClientSSHChannelEOFEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelEOF(&e);
            break;
         }
         case 8: {
            SSHClientSSHChannelOpenedEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelOpened(&e);
            break;
         }
         case 9: {
            SSHClientSSHChannelOpenRequestEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelOpenRequest(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 10: {
            SSHClientSSHChannelReadyToSendEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelReadyToSend(&e);
            break;
         }
         case 11: {
            SSHClientSSHChannelRequestEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelRequest(&e);
            param[3] = (void*)(e.Success);
            break;
         }
         case 12: {
            SSHClientSSHChannelRequestedEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHChannelRequested(&e);
            break;
         }
         case 13: {
            SSHClientSSHCustomAuthEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 14: {
            SSHClientSSHKeyboardInteractiveEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 15: {
            SSHClientSSHServerAuthenticationEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 16: {
            SSHClientSSHStatusEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHClient*)lpObj)->FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }

  public:

    SSHClient(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_92) {
      m_pObj = IPWorksSSH_SSHClient_Create(SSHClientEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~SSHClient() {
      IPWorksSSH_SSHClient_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_SSHClient_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_SSHClient_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_SSHClient_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline int GetSSHChannelCount() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 1, 0, 0);
      return (int)(long)val;
    }

    inline int GetBytesSent(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 2, iSSHChannelId, 0);
      return (int)(long)val;
    }

    inline QString GetChannelId(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 3, iSSHChannelId, 0);
      return QString((char*)val);
    }



    inline int SetDataToSend(int iSSHChannelId, const QByteArray &qba) {
      return IPWorksSSH_SSHClient_Set(m_pObj, 4, iSSHChannelId, (void*)qba.data(), qba.size());
    }

    inline int GetConnected() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 5, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)bConnected;
      return IPWorksSSH_SSHClient_Set(m_pObj, 5, 0, val, 0);
    }
    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 6, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)bFirewallAutoDetect;
      return IPWorksSSH_SSHClient_Set(m_pObj, 6, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 7, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)iFirewallType;
      return IPWorksSSH_SSHClient_Set(m_pObj, 7, 0, val, 0);
    }
    inline QString GetFirewallHost() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 8, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallHost(const QString &FirewallHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallHost.toLatin1();
      #else
      QByteArray qba = FirewallHost.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 8, 0, (void*)qba.data(), 0);
    }

    inline QString GetFirewallPassword() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 9, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallPassword(const QString &FirewallPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallPassword.toLatin1();
      #else
      QByteArray qba = FirewallPassword.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 9, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 10, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)lFirewallPort;
      return IPWorksSSH_SSHClient_Set(m_pObj, 10, 0, val, 0);
    }
    inline QString GetFirewallUser() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 11, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallUser(const QString &FirewallUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallUser.toLatin1();
      #else
      QByteArray qba = FirewallUser.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 11, 0, (void*)qba.data(), 0);
    }

    inline QString GetLocalHost() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 12, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 12, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_SSHClient_Set(m_pObj, 13, 0, val, 0);
    }
    inline QByteArray GetSSHAcceptServerHostKeyEncoded() {
      char *lpSSHAcceptServerHostKeyEncoded = NULL;
      int lenSSHAcceptServerHostKeyEncoded = 0;
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SSHClient_Get(m_pObj, 14, 0, &lenSSHAcceptServerHostKeyEncoded);
      return QByteArray(lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const QByteArray &qba) {
      return IPWorksSSH_SSHClient_Set(m_pObj, 14, 0, (void*)qba.data(), qba.size());
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 15, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)iSSHAuthMode;
      return IPWorksSSH_SSHClient_Set(m_pObj, 15, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHClient_Get(m_pObj, 16, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_SSHClient_Set(m_pObj, 16, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_SSHClient_Get(m_pObj, 17, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_SSHClient_Set(m_pObj, 17, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 18, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 18, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 19, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_SSHClient_Set(m_pObj, 19, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 20, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 20, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 21, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 21, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 22, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 22, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHHost() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 23, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHHost(const QString &SSHHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHHost.toLatin1();
      #else
      QByteArray qba = SSHHost.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 23, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHKeyExchangeAlgorithms() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 24, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHKeyExchangeAlgorithms(const QString &SSHKeyExchangeAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHKeyExchangeAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHKeyExchangeAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 24, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHMacAlgorithms() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 25, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHMacAlgorithms(const QString &SSHMacAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHMacAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHMacAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 25, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHPassword() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 26, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPassword(const QString &SSHPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPassword.toLatin1();
      #else
      QByteArray qba = SSHPassword.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 26, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 27, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)lSSHPort;
      return IPWorksSSH_SSHClient_Set(m_pObj, 27, 0, val, 0);
    }
    inline QString GetSSHPublicKeyAlgorithms() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 28, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPublicKeyAlgorithms(const QString &SSHPublicKeyAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPublicKeyAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHPublicKeyAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 28, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHUser() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 29, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHUser(const QString &SSHUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHUser.toLatin1();
      #else
      QByteArray qba = SSHUser.toAscii();
      #endif
      return IPWorksSSH_SSHClient_Set(m_pObj, 29, 0, (void*)qba.data(), 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SSHClient_Get(m_pObj, 30, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)iTimeout;
      return IPWorksSSH_SSHClient_Set(m_pObj, 30, 0, val, 0);
    }

  public: //methods

    inline int CloseChannel(const QString &ChannelId) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelId = ChannelId.toLatin1();
      #else
      QByteArray t_ChannelId = ChannelId.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ChannelId.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 2, 1, param, cbparam);
      
    }
    inline QString Config(const QString &ConfigurationString) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ConfigurationString = ConfigurationString.toLatin1();
      #else
      QByteArray t_ConfigurationString = ConfigurationString.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ConfigurationString.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHClient_Do(m_pObj, 3, 1, param, cbparam);
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
      IPWorksSSH_SSHClient_Do(m_pObj, 4, 1, param, cbparam);
      return QByteArray((char*)param[1],cbparam[1]);
      
    }
    inline int DoEvents() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 5, 0, param, cbparam);
      
    }
    inline QString EncodePacket(const QByteArray &Packet) {
       
      void *param[1+1] = {(void*)Packet.data(), 0};
      int cbparam[1+1] = {Packet.size(), 0};
      IPWorksSSH_SSHClient_Do(m_pObj, 6, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline int ExchangeKeys() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 7, 0, param, cbparam);
      
    }
    inline QString GetSSHParam(const QByteArray &Payload, const QString &Field) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Field = Field.toLatin1();
      #else
      QByteArray t_Field = Field.toAscii();
      #endif
      
      void *param[2+1] = {(void*)Payload.data(), (void*)t_Field.data(), 0};
      int cbparam[2+1] = {Payload.size(), 0, 0};
      IPWorksSSH_SSHClient_Do(m_pObj, 8, 2, param, cbparam);
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
      IPWorksSSH_SSHClient_Do(m_pObj, 9, 2, param, cbparam);
      return QByteArray((char*)param[2],cbparam[2]);
      
    }
    inline QString OpenChannel(const QString &ChannelType) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelType = ChannelType.toLatin1();
      #else
      QByteArray t_ChannelType = ChannelType.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ChannelType.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHClient_Do(m_pObj, 10, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline QString OpenTcpIpChannel(const QString &DestHost, long DestPort, const QString &SrcHost, long SrcPort) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_DestHost = DestHost.toLatin1();
      #else
      QByteArray t_DestHost = DestHost.toAscii();
      #endif
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_SrcHost = SrcHost.toLatin1();
      #else
      QByteArray t_SrcHost = SrcHost.toAscii();
      #endif
       
      void *param[4+1] = {(void*)t_DestHost.data(), (void*)DestPort, (void*)t_SrcHost.data(), (void*)SrcPort, 0};
      int cbparam[4+1] = {0, 0, 0, 0, 0};
      IPWorksSSH_SSHClient_Do(m_pObj, 11, 4, param, cbparam);
      return QString((char*)param[4]);
      
    }
    inline int OpenTerminal(const QString &ChannelId, const QString &TerminalType, int Width, int Height, int UsePixels, const QString &Modes) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelId = ChannelId.toLatin1();
      #else
      QByteArray t_ChannelId = ChannelId.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_TerminalType = TerminalType.toLatin1();
      #else
      QByteArray t_TerminalType = TerminalType.toAscii();
      #endif
         #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Modes = Modes.toLatin1();
      #else
      QByteArray t_Modes = Modes.toAscii();
      #endif
      
      void *param[6+1] = {(void*)t_ChannelId.data(), (void*)t_TerminalType.data(), (void*)Width, (void*)Height, (void*)UsePixels, (void*)t_Modes.data(), 0};
      int cbparam[6+1] = {0, 0, 0, 0, 0, 0, 0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 12, 6, param, cbparam);
      
    }
    inline int SendChannelData(const QString &ChannelId, const QByteArray &Data) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelId = ChannelId.toLatin1();
      #else
      QByteArray t_ChannelId = ChannelId.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_ChannelId.data(), (void*)Data.data(), 0};
      int cbparam[2+1] = {0, Data.size(), 0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 13, 2, param, cbparam);
      
    }
    inline int SendSSHPacket(const QString &ChannelId, int PacketType, const QByteArray &Payload) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelId = ChannelId.toLatin1();
      #else
      QByteArray t_ChannelId = ChannelId.toAscii();
      #endif
        
      void *param[3+1] = {(void*)t_ChannelId.data(), (void*)PacketType, (void*)Payload.data(), 0};
      int cbparam[3+1] = {0, 0, Payload.size(), 0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 14, 3, param, cbparam);
      
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
      IPWorksSSH_SSHClient_Do(m_pObj, 15, 3, param, cbparam);
      return QByteArray((char*)param[3],cbparam[3]);
      
    }
    inline int SSHLogoff() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 16, 0, param, cbparam);
      
    }
    inline int SSHLogon(const QString &SSHHost, long SSHPort) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_SSHHost = SSHHost.toLatin1();
      #else
      QByteArray t_SSHHost = SSHHost.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_SSHHost.data(), (void*)SSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 17, 2, param, cbparam);
      
    }
    inline int StartService(const QString &ChannelId, const QString &Service, const QString &Parameter) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelId = ChannelId.toLatin1();
      #else
      QByteArray t_ChannelId = ChannelId.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Service = Service.toLatin1();
      #else
      QByteArray t_Service = Service.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Parameter = Parameter.toLatin1();
      #else
      QByteArray t_Parameter = Parameter.toAscii();
      #endif
      
      void *param[3+1] = {(void*)t_ChannelId.data(), (void*)t_Service.data(), (void*)t_Parameter.data(), 0};
      int cbparam[3+1] = {0, 0, 0, 0};
      return IPWorksSSH_SSHClient_Do(m_pObj, 18, 3, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_SSHCLIENT_H_




