/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHELL_H_
#define _IPWORKSSSH_SSHELL_H_

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



extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SShell_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SShell_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SShell_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SShell_StaticInit(void *hInst);


struct SShellConnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SShellConnectionStatusEventParams {
  int EventRetVal;
  char* ConnectionEvent;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SShellDisconnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SShellErrorEventParams {
  int EventRetVal;
  int ErrorCode;
  char* Description;
  int reserved;
};

struct SShellSSHCustomAuthEventParams {
  int EventRetVal;
  char* Packet;
  int reserved;
};

struct SShellSSHKeyboardInteractiveEventParams {
  int EventRetVal;
  char* Name;
  char* Instructions;
  char* Prompt;
  char* Response;
  int EchoResponse;
  int reserved;
};

struct SShellSSHServerAuthenticationEventParams {
  int EventRetVal;
  char* HostKey;
  char* Fingerprint;
  char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
};

struct SShellSSHStatusEventParams {
  int EventRetVal;
  char* Message;
  int reserved;
};

struct SShellStderrEventParams {
  int EventRetVal;
  char* Text;
  int lenText;
  int reserved;
};

struct SShellStdoutEventParams {
  int EventRetVal;
  char* Text;
  int lenText;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class SShell : public QObject {

  Q_OBJECT
signals: //events

    void Connected(SShellConnectedEventParams *e);
    void ConnectionStatus(SShellConnectionStatusEventParams *e);
    void Disconnected(SShellDisconnectedEventParams *e);
    void Error(SShellErrorEventParams *e);
    void SSHCustomAuth(SShellSSHCustomAuthEventParams *e);
    void SSHKeyboardInteractive(SShellSSHKeyboardInteractiveEventParams *e);
    void SSHServerAuthentication(SShellSSHServerAuthenticationEventParams *e);
    void SSHStatus(SShellSSHStatusEventParams *e);
    void Stderr(SShellStderrEventParams *e);
    void Stdout(SShellStdoutEventParams *e);

protected: // event firers
    virtual int FireConnected(SShellConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionStatus(SShellConnectionStatusEventParams *e) {
      emit ConnectionStatus(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(SShellDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireError(SShellErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireSSHCustomAuth(SShellSSHCustomAuthEventParams *e) {
      emit SSHCustomAuth(e);
      return e->EventRetVal;
    }
    virtual int FireSSHKeyboardInteractive(SShellSSHKeyboardInteractiveEventParams *e) {
      emit SSHKeyboardInteractive(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServerAuthentication(SShellSSHServerAuthenticationEventParams *e) {
      emit SSHServerAuthentication(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(SShellSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }
    virtual int FireStderr(SShellStderrEventParams *e) {
      emit Stderr(e);
      return e->EventRetVal;
    }
    virtual int FireStdout(SShellStdoutEventParams *e) {
      emit Stdout(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SShellEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            SShellConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SShell*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SShellConnectionStatusEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SShell*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SShellDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SShell*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SShellErrorEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SShell*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            SShellSSHCustomAuthEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 6: {
            SShellSSHKeyboardInteractiveEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 7: {
            SShellSSHServerAuthenticationEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 8: {
            SShellSSHStatusEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SShell*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 9: {
            SShellStderrEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SShell*)lpObj)->FireStderr(&e);
            break;
         }
         case 10: {
            SShellStdoutEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SShell*)lpObj)->FireStdout(&e);
            break;
         }

      }
      return ret_code;
    }

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

    inline QString GetCommand() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 1, 0, 0);
      return QString((char*)val);
    }

    inline int SetCommand(const QString &Command) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = Command.toLatin1();
      #else
      QByteArray qba = Command.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 1, 0, (void*)qba.data(), 0);
    }

    inline int GetConnected() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)bConnected;
      return IPWorksSSH_SShell_Set(m_pObj, 2, 0, val, 0);
    }
    inline QString GetErrorMessage() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 3, 0, 0);
      return QString((char*)val);
    }


    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 4, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)bFirewallAutoDetect;
      return IPWorksSSH_SShell_Set(m_pObj, 4, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 5, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)iFirewallType;
      return IPWorksSSH_SShell_Set(m_pObj, 5, 0, val, 0);
    }
    inline QString GetFirewallHost() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 6, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallHost(const QString &FirewallHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallHost.toLatin1();
      #else
      QByteArray qba = FirewallHost.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 6, 0, (void*)qba.data(), 0);
    }

    inline QString GetFirewallPassword() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 7, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallPassword(const QString &FirewallPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallPassword.toLatin1();
      #else
      QByteArray qba = FirewallPassword.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 7, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 8, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)lFirewallPort;
      return IPWorksSSH_SShell_Set(m_pObj, 8, 0, val, 0);
    }
    inline QString GetFirewallUser() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 9, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallUser(const QString &FirewallUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallUser.toLatin1();
      #else
      QByteArray qba = FirewallUser.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 9, 0, (void*)qba.data(), 0);
    }

    inline QString GetLocalHost() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 10, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 10, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 11, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_SShell_Set(m_pObj, 11, 0, val, 0);
    }
    inline QByteArray GetSSHAcceptServerHostKeyEncoded() {
      char *lpSSHAcceptServerHostKeyEncoded = NULL;
      int lenSSHAcceptServerHostKeyEncoded = 0;
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SShell_Get(m_pObj, 12, 0, &lenSSHAcceptServerHostKeyEncoded);
      return QByteArray(lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const QByteArray &qba) {
      return IPWorksSSH_SShell_Set(m_pObj, 12, 0, (void*)qba.data(), qba.size());
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)iSSHAuthMode;
      return IPWorksSSH_SShell_Set(m_pObj, 13, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_SShell_Get(m_pObj, 14, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_SShell_Set(m_pObj, 14, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_SShell_Get(m_pObj, 15, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_SShell_Set(m_pObj, 15, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 16, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 16, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 17, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_SShell_Set(m_pObj, 17, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 18, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 18, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 19, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 19, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 20, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 20, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHHost() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 21, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHHost(const QString &SSHHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHHost.toLatin1();
      #else
      QByteArray qba = SSHHost.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 21, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHPassword() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 22, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPassword(const QString &SSHPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPassword.toLatin1();
      #else
      QByteArray qba = SSHPassword.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 22, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 23, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)lSSHPort;
      return IPWorksSSH_SShell_Set(m_pObj, 23, 0, val, 0);
    }
    inline QString GetSSHUser() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 24, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHUser(const QString &SSHUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHUser.toLatin1();
      #else
      QByteArray qba = SSHUser.toAscii();
      #endif
      return IPWorksSSH_SShell_Set(m_pObj, 24, 0, (void*)qba.data(), 0);
    }


    inline int SetStdin(const QByteArray &qba) {
      return IPWorksSSH_SShell_Set(m_pObj, 25, 0, (void*)qba.data(), qba.size());
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SShell_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)iTimeout;
      return IPWorksSSH_SShell_Set(m_pObj, 26, 0, val, 0);
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
      IPWorksSSH_SShell_Do(m_pObj, 2, 1, param, cbparam);
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
      IPWorksSSH_SShell_Do(m_pObj, 3, 1, param, cbparam);
      return QByteArray((char*)param[1],cbparam[1]);
      
    }
    inline int DoEvents() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 4, 0, param, cbparam);
      
    }
    inline QString EncodePacket(const QByteArray &Packet) {
       
      void *param[1+1] = {(void*)Packet.data(), 0};
      int cbparam[1+1] = {Packet.size(), 0};
      IPWorksSSH_SShell_Do(m_pObj, 5, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline int Execute(const QString &Command) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Command = Command.toLatin1();
      #else
      QByteArray t_Command = Command.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_Command.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 6, 1, param, cbparam);
      
    }
    inline QString GetSSHParam(const QByteArray &Payload, const QString &Field) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Field = Field.toLatin1();
      #else
      QByteArray t_Field = Field.toAscii();
      #endif
      
      void *param[2+1] = {(void*)Payload.data(), (void*)t_Field.data(), 0};
      int cbparam[2+1] = {Payload.size(), 0, 0};
      IPWorksSSH_SShell_Do(m_pObj, 7, 2, param, cbparam);
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
      IPWorksSSH_SShell_Do(m_pObj, 8, 2, param, cbparam);
      return QByteArray((char*)param[2],cbparam[2]);
      
    }
    inline int Interrupt() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 9, 0, param, cbparam);
      
    }
    inline int Send(const QByteArray &Text) {
       
      void *param[1+1] = {(void*)Text.data(), 0};
      int cbparam[1+1] = {Text.size(), 0};
      return IPWorksSSH_SShell_Do(m_pObj, 10, 1, param, cbparam);
      
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
      IPWorksSSH_SShell_Do(m_pObj, 11, 3, param, cbparam);
      return QByteArray((char*)param[3],cbparam[3]);
      
    }
    inline int SSHLogoff() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SShell_Do(m_pObj, 12, 0, param, cbparam);
      
    }
    inline int SSHLogon(const QString &SSHHost, long SSHPort) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_SSHHost = SSHHost.toLatin1();
      #else
      QByteArray t_SSHHost = SSHHost.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_SSHHost.data(), (void*)SSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SShell_Do(m_pObj, 13, 2, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_SSHELL_H_




