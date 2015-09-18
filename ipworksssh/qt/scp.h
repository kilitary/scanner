/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SCP_H_
#define _IPWORKSSSH_SCP_H_

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



extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SCP_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SCP_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SCP_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SCP_StaticInit(void *hInst);


struct SCPConnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SCPConnectionStatusEventParams {
  int EventRetVal;
  char* ConnectionEvent;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SCPDisconnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SCPEndTransferEventParams {
  int EventRetVal;
  int Direction;
  char* LocalFile;
  char* RemoteFile;
  char* RemotePath;
  int reserved;
};

struct SCPErrorEventParams {
  int EventRetVal;
  int ErrorCode;
  char* Description;
  char* LocalFile;
  char* RemoteFile;
  char* RemotePath;
  int reserved;
};

struct SCPSSHCustomAuthEventParams {
  int EventRetVal;
  char* Packet;
  int reserved;
};

struct SCPSSHKeyboardInteractiveEventParams {
  int EventRetVal;
  char* Name;
  char* Instructions;
  char* Prompt;
  char* Response;
  int EchoResponse;
  int reserved;
};

struct SCPSSHServerAuthenticationEventParams {
  int EventRetVal;
  char* HostKey;
  char* Fingerprint;
  char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
};

struct SCPSSHStatusEventParams {
  int EventRetVal;
  char* Message;
  int reserved;
};

struct SCPStartTransferEventParams {
  int EventRetVal;
  int Direction;
  char* LocalFile;
  char* RemoteFile;
  char* RemotePath;
  char* FilePermissions;
  int reserved;
};

struct SCPTransferEventParams {
  int EventRetVal;
  int Direction;
  char* LocalFile;
  char* RemoteFile;
  char* RemotePath;
  ns_int64 *pBytesTransferred;
  int PercentDone;
  char* Text;
  int lenText;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class SCP : public QObject {

  Q_OBJECT
signals: //events

    void Connected(SCPConnectedEventParams *e);
    void ConnectionStatus(SCPConnectionStatusEventParams *e);
    void Disconnected(SCPDisconnectedEventParams *e);
    void EndTransfer(SCPEndTransferEventParams *e);
    void Error(SCPErrorEventParams *e);
    void SSHCustomAuth(SCPSSHCustomAuthEventParams *e);
    void SSHKeyboardInteractive(SCPSSHKeyboardInteractiveEventParams *e);
    void SSHServerAuthentication(SCPSSHServerAuthenticationEventParams *e);
    void SSHStatus(SCPSSHStatusEventParams *e);
    void StartTransfer(SCPStartTransferEventParams *e);
    void Transfer(SCPTransferEventParams *e);

protected: // event firers
    virtual int FireConnected(SCPConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionStatus(SCPConnectionStatusEventParams *e) {
      emit ConnectionStatus(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(SCPDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireEndTransfer(SCPEndTransferEventParams *e) {
      emit EndTransfer(e);
      return e->EventRetVal;
    }
    virtual int FireError(SCPErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireSSHCustomAuth(SCPSSHCustomAuthEventParams *e) {
      emit SSHCustomAuth(e);
      return e->EventRetVal;
    }
    virtual int FireSSHKeyboardInteractive(SCPSSHKeyboardInteractiveEventParams *e) {
      emit SSHKeyboardInteractive(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServerAuthentication(SCPSSHServerAuthenticationEventParams *e) {
      emit SSHServerAuthentication(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(SCPSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }
    virtual int FireStartTransfer(SCPStartTransferEventParams *e) {
      emit StartTransfer(e);
      return e->EventRetVal;
    }
    virtual int FireTransfer(SCPTransferEventParams *e) {
      emit Transfer(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SCPEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            SCPConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SCP*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SCPConnectionStatusEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SCP*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SCPDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SCP*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SCPEndTransferEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]),  0};
            ret_code = ((SCP*)lpObj)->FireEndTransfer(&e);
            break;
         }
         case 5: {
            SCPErrorEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]),  0};
            ret_code = ((SCP*)lpObj)->FireError(&e);
            break;
         }
         case 6: {
            SCPSSHCustomAuthEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 7: {
            SCPSSHKeyboardInteractiveEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 8: {
            SCPSSHServerAuthenticationEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 9: {
            SCPSSHStatusEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SCP*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 10: {
            SCPStartTransferEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]),  0};
            ret_code = ((SCP*)lpObj)->FireStartTransfer(&e);
            param[4] = (void*)(e.FilePermissions);
            break;
         }
         case 11: {
            SCPTransferEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (ns_int64*)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (char*)IPH64CAST(param[6]), (int)IPH64CAST(cbparam[6]),  0};
            ret_code = ((SCP*)lpObj)->FireTransfer(&e);
            break;
         }

      }
      return ret_code;
    }

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
      void* val = (void*)bConnected;
      return IPWorksSSH_SCP_Set(m_pObj, 1, 0, val, 0);
    }
    inline QString GetFilePermissions() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 2, 0, 0);
      return QString((char*)val);
    }

    inline int SetFilePermissions(const QString &FilePermissions) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FilePermissions.toLatin1();
      #else
      QByteArray qba = FilePermissions.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 2, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 3, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)bFirewallAutoDetect;
      return IPWorksSSH_SCP_Set(m_pObj, 3, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 4, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)iFirewallType;
      return IPWorksSSH_SCP_Set(m_pObj, 4, 0, val, 0);
    }
    inline QString GetFirewallHost() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 5, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallHost(const QString &FirewallHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallHost.toLatin1();
      #else
      QByteArray qba = FirewallHost.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 5, 0, (void*)qba.data(), 0);
    }

    inline QString GetFirewallPassword() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 6, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallPassword(const QString &FirewallPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallPassword.toLatin1();
      #else
      QByteArray qba = FirewallPassword.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 6, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 7, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)lFirewallPort;
      return IPWorksSSH_SCP_Set(m_pObj, 7, 0, val, 0);
    }
    inline QString GetFirewallUser() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 8, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallUser(const QString &FirewallUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallUser.toLatin1();
      #else
      QByteArray qba = FirewallUser.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 8, 0, (void*)qba.data(), 0);
    }

    inline QString GetLocalFile() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 9, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalFile(const QString &LocalFile) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalFile.toLatin1();
      #else
      QByteArray qba = LocalFile.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 9, 0, (void*)qba.data(), 0);
    }

    inline QString GetLocalHost() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 10, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 10, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 11, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_SCP_Set(m_pObj, 11, 0, val, 0);
    }
    inline int GetOverwrite() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 12, 0, 0);
      return (int)(long)val;
    }
    inline int SetOverwrite(int bOverwrite) {
      void* val = (void*)bOverwrite;
      return IPWorksSSH_SCP_Set(m_pObj, 12, 0, val, 0);
    }
    inline QString GetRemoteFile() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 13, 0, 0);
      return QString((char*)val);
    }

    inline int SetRemoteFile(const QString &RemoteFile) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = RemoteFile.toLatin1();
      #else
      QByteArray qba = RemoteFile.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 13, 0, (void*)qba.data(), 0);
    }

    inline QString GetRemotePath() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 14, 0, 0);
      return QString((char*)val);
    }

    inline int SetRemotePath(const QString &RemotePath) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = RemotePath.toLatin1();
      #else
      QByteArray qba = RemotePath.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 14, 0, (void*)qba.data(), 0);
    }

    inline QByteArray GetSSHAcceptServerHostKeyEncoded() {
      char *lpSSHAcceptServerHostKeyEncoded = NULL;
      int lenSSHAcceptServerHostKeyEncoded = 0;
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SCP_Get(m_pObj, 15, 0, &lenSSHAcceptServerHostKeyEncoded);
      return QByteArray(lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const QByteArray &qba) {
      return IPWorksSSH_SCP_Set(m_pObj, 15, 0, (void*)qba.data(), qba.size());
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 16, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)iSSHAuthMode;
      return IPWorksSSH_SCP_Set(m_pObj, 16, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_SCP_Get(m_pObj, 17, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_SCP_Set(m_pObj, 17, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_SCP_Get(m_pObj, 18, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_SCP_Set(m_pObj, 18, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 19, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 19, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 20, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_SCP_Set(m_pObj, 20, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 21, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 21, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 22, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 22, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 23, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 23, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHHost() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 24, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHHost(const QString &SSHHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHHost.toLatin1();
      #else
      QByteArray qba = SSHHost.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 24, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHPassword() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 25, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPassword(const QString &SSHPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPassword.toLatin1();
      #else
      QByteArray qba = SSHPassword.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 25, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)lSSHPort;
      return IPWorksSSH_SCP_Set(m_pObj, 26, 0, val, 0);
    }
    inline QString GetSSHUser() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 27, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHUser(const QString &SSHUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHUser.toLatin1();
      #else
      QByteArray qba = SSHUser.toAscii();
      #endif
      return IPWorksSSH_SCP_Set(m_pObj, 27, 0, (void*)qba.data(), 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SCP_Get(m_pObj, 28, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)iTimeout;
      return IPWorksSSH_SCP_Set(m_pObj, 28, 0, val, 0);
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
      IPWorksSSH_SCP_Do(m_pObj, 2, 1, param, cbparam);
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
      IPWorksSSH_SCP_Do(m_pObj, 3, 1, param, cbparam);
      return QByteArray((char*)param[1],cbparam[1]);
      
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
    inline QString EncodePacket(const QByteArray &Packet) {
       
      void *param[1+1] = {(void*)Packet.data(), 0};
      int cbparam[1+1] = {Packet.size(), 0};
      IPWorksSSH_SCP_Do(m_pObj, 6, 1, param, cbparam);
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
      IPWorksSSH_SCP_Do(m_pObj, 7, 2, param, cbparam);
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
      IPWorksSSH_SCP_Do(m_pObj, 8, 2, param, cbparam);
      return QByteArray((char*)param[2],cbparam[2]);
      
    }
    inline int Interrupt() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 9, 0, param, cbparam);
      
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
      IPWorksSSH_SCP_Do(m_pObj, 11, 3, param, cbparam);
      return QByteArray((char*)param[3],cbparam[3]);
      
    }
    inline int SSHLogoff() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 13, 0, param, cbparam);
      
    }
    inline int SSHLogon(const QString &SSHHost, long SSHPort) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_SSHHost = SSHHost.toLatin1();
      #else
      QByteArray t_SSHHost = SSHHost.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_SSHHost.data(), (void*)SSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SCP_Do(m_pObj, 14, 2, param, cbparam);
      
    }
    inline int Upload() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SCP_Do(m_pObj, 15, 0, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_SCP_H_




