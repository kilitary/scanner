/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHTUNNEL_H_
#define _IPWORKSSSH_SSHTUNNEL_H_

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



extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHTunnel_StaticInit(void *hInst);


struct SSHTunnelConnectedEventParams {
  int EventRetVal;
  int ConnectionId;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHTunnelConnectionRequestEventParams {
  int EventRetVal;
  char* Address;
  int Port;
  int Accept;
  int reserved;
};

struct SSHTunnelDataInEventParams {
  int EventRetVal;
  int ConnectionId;
  char* Text;
  int EOL;
  int lenText;
  int reserved;
};

struct SSHTunnelDisconnectedEventParams {
  int EventRetVal;
  int ConnectionId;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHTunnelErrorEventParams {
  int EventRetVal;
  int ConnectionId;
  int ErrorCode;
  char* Description;
  int reserved;
};

struct SSHTunnelSSHCustomAuthEventParams {
  int EventRetVal;
  char* Packet;
  int reserved;
};

struct SSHTunnelSSHKeyboardInteractiveEventParams {
  int EventRetVal;
  char* Name;
  char* Instructions;
  char* Prompt;
  char* Response;
  int EchoResponse;
  int reserved;
};

struct SSHTunnelSSHServerAuthenticationEventParams {
  int EventRetVal;
  char* HostKey;
  char* Fingerprint;
  char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
};

struct SSHTunnelSSHStatusEventParams {
  int EventRetVal;
  char* Message;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class SSHTunnel : public QObject {

  Q_OBJECT
signals: //events

    void Connected(SSHTunnelConnectedEventParams *e);
    void ConnectionRequest(SSHTunnelConnectionRequestEventParams *e);
    void DataIn(SSHTunnelDataInEventParams *e);
    void Disconnected(SSHTunnelDisconnectedEventParams *e);
    void Error(SSHTunnelErrorEventParams *e);
    void SSHCustomAuth(SSHTunnelSSHCustomAuthEventParams *e);
    void SSHKeyboardInteractive(SSHTunnelSSHKeyboardInteractiveEventParams *e);
    void SSHServerAuthentication(SSHTunnelSSHServerAuthenticationEventParams *e);
    void SSHStatus(SSHTunnelSSHStatusEventParams *e);

protected: // event firers
    virtual int FireConnected(SSHTunnelConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionRequest(SSHTunnelConnectionRequestEventParams *e) {
      emit ConnectionRequest(e);
      return e->EventRetVal;
    }
    virtual int FireDataIn(SSHTunnelDataInEventParams *e) {
      emit DataIn(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(SSHTunnelDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireError(SSHTunnelErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireSSHCustomAuth(SSHTunnelSSHCustomAuthEventParams *e) {
      emit SSHCustomAuth(e);
      return e->EventRetVal;
    }
    virtual int FireSSHKeyboardInteractive(SSHTunnelSSHKeyboardInteractiveEventParams *e) {
      emit SSHKeyboardInteractive(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServerAuthentication(SSHTunnelSSHServerAuthenticationEventParams *e) {
      emit SSHServerAuthentication(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(SSHTunnelSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SSHTunnelEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            SSHTunnelConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SSHTunnelConnectionRequestEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireConnectionRequest(&e);
            param[2] = (void*)(e.Accept);
            break;
         }
         case 3: {
            SSHTunnelDataInEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[1]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireDataIn(&e);
            break;
         }
         case 4: {
            SSHTunnelDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 5: {
            SSHTunnelErrorEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireError(&e);
            break;
         }
         case 6: {
            SSHTunnelSSHCustomAuthEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 7: {
            SSHTunnelSSHKeyboardInteractiveEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 8: {
            SSHTunnelSSHServerAuthenticationEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 9: {
            SSHTunnelSSHStatusEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SSHTunnel*)lpObj)->FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }

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
      void* val = (void*)bConnected;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 1, 0, val, 0);
    }
    inline int GetConnectionBacklog() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnectionBacklog(int iConnectionBacklog) {
      void* val = (void*)iConnectionBacklog;
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
      void* val = (void*)bClientAcceptData;
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
      void* val = (void*)bClientConnected;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 6, iClientId, val, 0);
    }
    inline QString GetClientConnectionId(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 7, iClientId, 0);
      return QString((char*)val);
    }



    inline int SetClientDataToSend(int iClientId, const QByteArray &qba) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 8, iClientId, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetClientEOL(int iClientId) {
      char *lpClientEOL = NULL;
      int lenClientEOL = 0;
      lpClientEOL = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 9, iClientId, &lenClientEOL);
      return QByteArray(lpClientEOL, lenClientEOL);
    }

    inline int SetClientEOL(int iClientId, const QByteArray &qba) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 9, iClientId, (void*)qba.data(), qba.size());
    }

    inline QString GetClientLocalAddress(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 10, iClientId, 0);
      return QString((char*)val);
    }


    inline QString GetClientRemoteHost(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 11, iClientId, 0);
      return QString((char*)val);
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
      void* val = (void*)bClientSingleLineMode;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 13, iClientId, val, 0);
    }
    inline int GetClientTimeout(int iClientId) {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 14, iClientId, 0);
      return (int)(long)val;
    }
    inline int SetClientTimeout(int iClientId, int iClientTimeout) {
      void* val = (void*)iClientTimeout;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 14, iClientId, val, 0);
    }
    inline QByteArray GetDefaultEOL() {
      char *lpDefaultEOL = NULL;
      int lenDefaultEOL = 0;
      lpDefaultEOL = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 15, 0, &lenDefaultEOL);
      return QByteArray(lpDefaultEOL, lenDefaultEOL);
    }

    inline int SetDefaultEOL(const QByteArray &qba) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 15, 0, (void*)qba.data(), qba.size());
    }

    inline int GetDefaultSingleLineMode() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 16, 0, 0);
      return (int)(long)val;
    }
    inline int SetDefaultSingleLineMode(int bDefaultSingleLineMode) {
      void* val = (void*)bDefaultSingleLineMode;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 16, 0, val, 0);
    }
    inline int GetDefaultTimeout() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 17, 0, 0);
      return (int)(long)val;
    }
    inline int SetDefaultTimeout(int iDefaultTimeout) {
      void* val = (void*)iDefaultTimeout;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 17, 0, val, 0);
    }
    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 18, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)bFirewallAutoDetect;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 18, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 19, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)iFirewallType;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 19, 0, val, 0);
    }
    inline QString GetFirewallHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 20, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallHost(const QString &FirewallHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallHost.toLatin1();
      #else
      QByteArray qba = FirewallHost.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 20, 0, (void*)qba.data(), 0);
    }

    inline QString GetFirewallPassword() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 21, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallPassword(const QString &FirewallPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallPassword.toLatin1();
      #else
      QByteArray qba = FirewallPassword.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 21, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 22, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)lFirewallPort;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 22, 0, val, 0);
    }
    inline QString GetFirewallUser() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 23, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallUser(const QString &FirewallUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallUser.toLatin1();
      #else
      QByteArray qba = FirewallUser.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 23, 0, (void*)qba.data(), 0);
    }

    inline int GetKeepAlive() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 24, 0, 0);
      return (int)(long)val;
    }
    inline int SetKeepAlive(int bKeepAlive) {
      void* val = (void*)bKeepAlive;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 24, 0, val, 0);
    }
    inline int GetLinger() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 25, 0, 0);
      return (int)(long)val;
    }
    inline int SetLinger(int bLinger) {
      void* val = (void*)bLinger;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 25, 0, val, 0);
    }
    inline int GetListening() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetListening(int bListening) {
      void* val = (void*)bListening;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 26, 0, val, 0);
    }
    inline QString GetLocalHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 27, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 27, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 28, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 28, 0, val, 0);
    }
    inline QByteArray GetSSHAcceptServerHostKeyEncoded() {
      char *lpSSHAcceptServerHostKeyEncoded = NULL;
      int lenSSHAcceptServerHostKeyEncoded = 0;
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 29, 0, &lenSSHAcceptServerHostKeyEncoded);
      return QByteArray(lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const QByteArray &qba) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 29, 0, (void*)qba.data(), qba.size());
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 30, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)iSSHAuthMode;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 30, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 31, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 31, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_SSHTunnel_Get(m_pObj, 32, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 32, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 33, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 33, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 34, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 34, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 35, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 35, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 36, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 36, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 37, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 37, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHForwardHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 38, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHForwardHost(const QString &SSHForwardHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHForwardHost.toLatin1();
      #else
      QByteArray qba = SSHForwardHost.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 38, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHForwardPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 39, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHForwardPort(int lSSHForwardPort) {
      void* val = (void*)lSSHForwardPort;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 39, 0, val, 0);
    }
    inline QString GetSSHHost() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 40, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHHost(const QString &SSHHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHHost.toLatin1();
      #else
      QByteArray qba = SSHHost.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 40, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHPassword() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 41, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPassword(const QString &SSHPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPassword.toLatin1();
      #else
      QByteArray qba = SSHPassword.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 41, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 42, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)lSSHPort;
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 42, 0, val, 0);
    }
    inline QString GetSSHUser() {
      void* val = IPWorksSSH_SSHTunnel_Get(m_pObj, 43, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHUser(const QString &SSHUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHUser.toLatin1();
      #else
      QByteArray qba = SSHUser.toAscii();
      #endif
      return IPWorksSSH_SSHTunnel_Set(m_pObj, 43, 0, (void*)qba.data(), 0);
    }


  public: //methods

    inline QString Config(const QString &ConfigurationString) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ConfigurationString = ConfigurationString.toLatin1();
      #else
      QByteArray t_ConfigurationString = ConfigurationString.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ConfigurationString.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 2, 1, param, cbparam);
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
      IPWorksSSH_SSHTunnel_Do(m_pObj, 3, 1, param, cbparam);
      return QByteArray((char*)param[1],cbparam[1]);
      
    }
    inline int Disconnect(int ConnectionId) {
       
      void *param[1+1] = {(void*)ConnectionId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 4, 1, param, cbparam);
      
    }
    inline int DoEvents() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 5, 0, param, cbparam);
      
    }
    inline QString EncodePacket(const QByteArray &Packet) {
       
      void *param[1+1] = {(void*)Packet.data(), 0};
      int cbparam[1+1] = {Packet.size(), 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 6, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline QString GetSSHParam(const QByteArray &Payload, const QString &Field) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Field = Field.toLatin1();
      #else
      QByteArray t_Field = Field.toAscii();
      #endif
      
      void *param[2+1] = {(void*)Payload.data(), (void*)t_Field.data(), 0};
      int cbparam[2+1] = {Payload.size(), 0, 0};
      IPWorksSSH_SSHTunnel_Do(m_pObj, 7, 2, param, cbparam);
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
      IPWorksSSH_SSHTunnel_Do(m_pObj, 8, 2, param, cbparam);
      return QByteArray((char*)param[2],cbparam[2]);
      
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
      IPWorksSSH_SSHTunnel_Do(m_pObj, 9, 3, param, cbparam);
      return QByteArray((char*)param[3],cbparam[3]);
      
    }
    inline int Shutdown() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHTunnel_Do(m_pObj, 10, 0, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_SSHTUNNEL_H_




