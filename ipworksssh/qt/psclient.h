/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_PSCLIENT_H_
#define _IPWORKSSSH_PSCLIENT_H_

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


struct PSClientConnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct PSClientConnectionStatusEventParams {
  int EventRetVal;
  char* ConnectionEvent;
  int StatusCode;
  char* Description;
  int reserved;
};

struct PSClientDisconnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct PSClientErrorEventParams {
  int EventRetVal;
  int ErrorCode;
  char* Description;
  int reserved;
};

struct PSClientPSObjectEventParams {
  int EventRetVal;
  char* BaseType;
  char* Value;
  int reserved;
};

struct PSClientSSHKeyboardInteractiveEventParams {
  int EventRetVal;
  char* Name;
  char* Instructions;
  char* Prompt;
  char* Response;
  int EchoResponse;
  int reserved;
};

struct PSClientSSHServerAuthenticationEventParams {
  int EventRetVal;
  char* HostKey;
  char* Fingerprint;
  char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
};

struct PSClientSSHStatusEventParams {
  int EventRetVal;
  char* Message;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class PSClient : public QObject {

  Q_OBJECT
signals: //events

    void Connected(PSClientConnectedEventParams *e);
    void ConnectionStatus(PSClientConnectionStatusEventParams *e);
    void Disconnected(PSClientDisconnectedEventParams *e);
    void Error(PSClientErrorEventParams *e);
    void PSObject(PSClientPSObjectEventParams *e);
    void SSHKeyboardInteractive(PSClientSSHKeyboardInteractiveEventParams *e);
    void SSHServerAuthentication(PSClientSSHServerAuthenticationEventParams *e);
    void SSHStatus(PSClientSSHStatusEventParams *e);

protected: // event firers
    virtual int FireConnected(PSClientConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionStatus(PSClientConnectionStatusEventParams *e) {
      emit ConnectionStatus(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(PSClientDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireError(PSClientErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FirePSObject(PSClientPSObjectEventParams *e) {
      emit PSObject(e);
      return e->EventRetVal;
    }
    virtual int FireSSHKeyboardInteractive(PSClientSSHKeyboardInteractiveEventParams *e) {
      emit SSHKeyboardInteractive(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServerAuthentication(PSClientSSHServerAuthenticationEventParams *e) {
      emit SSHServerAuthentication(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(PSClientSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL PSClientEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            PSClientConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            PSClientConnectionStatusEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((PSClient*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            PSClientDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            PSClientErrorEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            PSClientPSObjectEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((PSClient*)lpObj)->FirePSObject(&e);
            break;
         }
         case 6: {
            PSClientSSHKeyboardInteractiveEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((PSClient*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 7: {
            PSClientSSHServerAuthenticationEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((PSClient*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 8: {
            PSClientSSHStatusEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((PSClient*)lpObj)->FireSSHStatus(&e);
            break;
         }

      }
      return ret_code;
    }

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
      void* val = (void*)bConnected;
      return IPWorksSSH_PSClient_Set(m_pObj, 1, 0, val, 0);
    }
    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)bFirewallAutoDetect;
      return IPWorksSSH_PSClient_Set(m_pObj, 2, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 3, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)iFirewallType;
      return IPWorksSSH_PSClient_Set(m_pObj, 3, 0, val, 0);
    }
    inline QString GetFirewallHost() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 4, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallHost(const QString &FirewallHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallHost.toLatin1();
      #else
      QByteArray qba = FirewallHost.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 4, 0, (void*)qba.data(), 0);
    }

    inline QString GetFirewallPassword() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 5, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallPassword(const QString &FirewallPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallPassword.toLatin1();
      #else
      QByteArray qba = FirewallPassword.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 5, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 6, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)lFirewallPort;
      return IPWorksSSH_PSClient_Set(m_pObj, 6, 0, val, 0);
    }
    inline QString GetFirewallUser() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 7, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallUser(const QString &FirewallUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallUser.toLatin1();
      #else
      QByteArray qba = FirewallUser.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 7, 0, (void*)qba.data(), 0);
    }

    inline QString GetLocalHost() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 8, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 8, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 9, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_PSClient_Set(m_pObj, 9, 0, val, 0);
    }
    inline int GetPSObjectPropertyCount() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 10, 0, 0);
      return (int)(long)val;
    }

    inline QString GetPSObjectPropertyDataType(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 11, iPSObjectPropertyIndex, 0);
      return QString((char*)val);
    }


    inline int GetPSObjectPropertyIsNull(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 12, iPSObjectPropertyIndex, 0);
      return (int)(long)val;
    }

    inline QString GetPSObjectPropertyName(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 13, iPSObjectPropertyIndex, 0);
      return QString((char*)val);
    }


    inline QString GetPSObjectPropertyValue(int iPSObjectPropertyIndex) {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 14, iPSObjectPropertyIndex, 0);
      return QString((char*)val);
    }


    inline QString GetPSObjectBaseType() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 15, 0, 0);
      return QString((char*)val);
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
      void* val = (void*)lPSObjectIndex;
      return IPWorksSSH_PSClient_Set(m_pObj, 17, 0, val, 0);
    }
    inline QString GetPSObjectValue() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 18, 0, 0);
      return QString((char*)val);
    }


    inline QByteArray GetSSHAcceptServerHostKeyEncoded() {
      char *lpSSHAcceptServerHostKeyEncoded = NULL;
      int lenSSHAcceptServerHostKeyEncoded = 0;
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_PSClient_Get(m_pObj, 19, 0, &lenSSHAcceptServerHostKeyEncoded);
      return QByteArray(lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const QByteArray &qba) {
      return IPWorksSSH_PSClient_Set(m_pObj, 19, 0, (void*)qba.data(), qba.size());
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 20, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)iSSHAuthMode;
      return IPWorksSSH_PSClient_Set(m_pObj, 20, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_PSClient_Get(m_pObj, 21, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_PSClient_Set(m_pObj, 21, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_PSClient_Get(m_pObj, 22, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_PSClient_Set(m_pObj, 22, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 23, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 23, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 24, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_PSClient_Set(m_pObj, 24, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 25, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 25, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 26, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 26, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 27, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 27, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHHost() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 28, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHHost(const QString &SSHHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHHost.toLatin1();
      #else
      QByteArray qba = SSHHost.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 28, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHKeyExchangeAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 29, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHKeyExchangeAlgorithms(const QString &SSHKeyExchangeAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHKeyExchangeAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHKeyExchangeAlgorithms.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 29, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHMacAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 30, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHMacAlgorithms(const QString &SSHMacAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHMacAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHMacAlgorithms.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 30, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHPassword() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 31, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPassword(const QString &SSHPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPassword.toLatin1();
      #else
      QByteArray qba = SSHPassword.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 31, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 32, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)lSSHPort;
      return IPWorksSSH_PSClient_Set(m_pObj, 32, 0, val, 0);
    }
    inline QString GetSSHPublicKeyAlgorithms() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 33, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPublicKeyAlgorithms(const QString &SSHPublicKeyAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPublicKeyAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHPublicKeyAlgorithms.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 33, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHUser() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 34, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHUser(const QString &SSHUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHUser.toLatin1();
      #else
      QByteArray qba = SSHUser.toAscii();
      #endif
      return IPWorksSSH_PSClient_Set(m_pObj, 34, 0, (void*)qba.data(), 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_PSClient_Get(m_pObj, 35, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)iTimeout;
      return IPWorksSSH_PSClient_Set(m_pObj, 35, 0, val, 0);
    }

  public: //methods

    inline int ClearOutput() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 2, 0, param, cbparam);
      
    }
    inline QString Config(const QString &ConfigurationString) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ConfigurationString = ConfigurationString.toLatin1();
      #else
      QByteArray t_ConfigurationString = ConfigurationString.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ConfigurationString.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_PSClient_Do(m_pObj, 3, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline int DoEvents() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_PSClient_Do(m_pObj, 4, 0, param, cbparam);
      
    }
    inline int Execute(const QString &Command) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Command = Command.toLatin1();
      #else
      QByteArray t_Command = Command.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_Command.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_PSClient_Do(m_pObj, 5, 1, param, cbparam);
      
    }
    inline QString GetPropertyValue(const QString &Name) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Name = Name.toLatin1();
      #else
      QByteArray t_Name = Name.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_Name.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_PSClient_Do(m_pObj, 6, 1, param, cbparam);
      return QString((char*)param[1]);
      
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
    inline int SSHLogon(const QString &SSHHost, long SSHPort) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_SSHHost = SSHHost.toLatin1();
      #else
      QByteArray t_SSHHost = SSHHost.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_SSHHost.data(), (void*)SSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_PSClient_Do(m_pObj, 9, 2, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_PSCLIENT_H_




