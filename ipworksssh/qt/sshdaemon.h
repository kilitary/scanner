/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHDAEMON_H_
#define _IPWORKSSSH_SSHDAEMON_H_

#include "ipworksssh.h"
#include "../include/ipworksssh.key"
#include <QObject.h>

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



extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_StaticInit(void *hInst);


struct SSHDaemonConnectedEventParams {
  int EventRetVal;
  int ConnectionId;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHDaemonConnectionRequestEventParams {
  int EventRetVal;
  char* Address;
  int Port;
  int Accept;
  int reserved;
};

struct SSHDaemonDisconnectedEventParams {
  int EventRetVal;
  int ConnectionId;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SSHDaemonErrorEventParams {
  int EventRetVal;
  int ConnectionId;
  int ErrorCode;
  char* Description;
  int reserved;
};

struct SSHDaemonSSHChannelClosedEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  int reserved;
};

struct SSHDaemonSSHChannelDataInEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  char* Data;
  int lenData;
  int reserved;
};

struct SSHDaemonSSHChannelEOFEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  int reserved;
};

struct SSHDaemonSSHChannelOpenedEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  int reserved;
};

struct SSHDaemonSSHChannelOpenRequestEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  char* Service;
  char* Parameters;
  int Accept;
  int lenParameters;
  int reserved;
};

struct SSHDaemonSSHChannelReadyToSendEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  int reserved;
};

struct SSHDaemonSSHChannelRequestEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  char* RequestType;
  char* Packet;
  int Success;
  int lenPacket;
  int reserved;
};

struct SSHDaemonSSHChannelRequestedEventParams {
  int EventRetVal;
  int ConnectionId;
  int ChannelId;
  char* RequestType;
  char* Packet;
  int lenPacket;
  int reserved;
};

struct SSHDaemonSSHServiceRequestEventParams {
  int EventRetVal;
  int ConnectionId;
  char* Service;
  int Accept;
  int reserved;
};

struct SSHDaemonSSHStatusEventParams {
  int EventRetVal;
  int ConnectionId;
  char* Message;
  int reserved;
};

struct SSHDaemonSSHUserAuthRequestEventParams {
  int EventRetVal;
  int ConnectionId;
  char* User;
  char* Service;
  char* AuthMethod;
  char* AuthParam;
  int Accept;
  int PartialSuccess;
  char* AvailableMethods;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class SSHDaemon : public QObject {

  Q_OBJECT
signals: //events

    void Connected(SSHDaemonConnectedEventParams *e);
    void ConnectionRequest(SSHDaemonConnectionRequestEventParams *e);
    void Disconnected(SSHDaemonDisconnectedEventParams *e);
    void Error(SSHDaemonErrorEventParams *e);
    void SSHChannelClosed(SSHDaemonSSHChannelClosedEventParams *e);
    void SSHChannelDataIn(SSHDaemonSSHChannelDataInEventParams *e);
    void SSHChannelEOF(SSHDaemonSSHChannelEOFEventParams *e);
    void SSHChannelOpened(SSHDaemonSSHChannelOpenedEventParams *e);
    void SSHChannelOpenRequest(SSHDaemonSSHChannelOpenRequestEventParams *e);
    void SSHChannelReadyToSend(SSHDaemonSSHChannelReadyToSendEventParams *e);
    void SSHChannelRequest(SSHDaemonSSHChannelRequestEventParams *e);
    void SSHChannelRequested(SSHDaemonSSHChannelRequestedEventParams *e);
    void SSHServiceRequest(SSHDaemonSSHServiceRequestEventParams *e);
    void SSHStatus(SSHDaemonSSHStatusEventParams *e);
    void SSHUserAuthRequest(SSHDaemonSSHUserAuthRequestEventParams *e);

protected: // event firers
    virtual int FireConnected(SSHDaemonConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionRequest(SSHDaemonConnectionRequestEventParams *e) {
      emit ConnectionRequest(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(SSHDaemonDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireError(SSHDaemonErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelClosed(SSHDaemonSSHChannelClosedEventParams *e) {
      emit SSHChannelClosed(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelDataIn(SSHDaemonSSHChannelDataInEventParams *e) {
      emit SSHChannelDataIn(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelEOF(SSHDaemonSSHChannelEOFEventParams *e) {
      emit SSHChannelEOF(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelOpened(SSHDaemonSSHChannelOpenedEventParams *e) {
      emit SSHChannelOpened(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelOpenRequest(SSHDaemonSSHChannelOpenRequestEventParams *e) {
      emit SSHChannelOpenRequest(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelReadyToSend(SSHDaemonSSHChannelReadyToSendEventParams *e) {
      emit SSHChannelReadyToSend(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelRequest(SSHDaemonSSHChannelRequestEventParams *e) {
      emit SSHChannelRequest(e);
      return e->EventRetVal;
    }
    virtual int FireSSHChannelRequested(SSHDaemonSSHChannelRequestedEventParams *e) {
      emit SSHChannelRequested(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServiceRequest(SSHDaemonSSHServiceRequestEventParams *e) {
      emit SSHServiceRequest(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(SSHDaemonSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }
    virtual int FireSSHUserAuthRequest(SSHDaemonSSHUserAuthRequestEventParams *e) {
      emit SSHUserAuthRequest(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SSHDaemonEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            SSHDaemonConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SSHDaemonConnectionRequestEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireConnectionRequest(&e);
            param[2] = (void*)(e.Accept);
            break;
         }
         case 3: {
            SSHDaemonDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SSHDaemonErrorEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            SSHDaemonSSHChannelClosedEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelClosed(&e);
            break;
         }
         case 6: {
            SSHDaemonSSHChannelDataInEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelDataIn(&e);
            break;
         }
         case 7: {
            SSHDaemonSSHChannelEOFEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelEOF(&e);
            break;
         }
         case 8: {
            SSHDaemonSSHChannelOpenedEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelOpened(&e);
            break;
         }
         case 9: {
            SSHDaemonSSHChannelOpenRequestEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelOpenRequest(&e);
            param[4] = (void*)(e.Accept);
            break;
         }
         case 10: {
            SSHDaemonSSHChannelReadyToSendEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelReadyToSend(&e);
            break;
         }
         case 11: {
            SSHDaemonSSHChannelRequestEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelRequest(&e);
            param[4] = (void*)(e.Success);
            break;
         }
         case 12: {
            SSHDaemonSSHChannelRequestedEventParams e = {0, (int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelRequested(&e);
            break;
         }
         case 13: {
            SSHDaemonSSHServiceRequestEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHServiceRequest(&e);
            param[2] = (void*)(e.Accept);
            break;
         }
         case 14: {
            SSHDaemonSSHStatusEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 15: {
            SSHDaemonSSHUserAuthRequestEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (int)IPH64CAST(param[6]), (char*)IPH64CAST(param[7]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHUserAuthRequest(&e);
            param[5] = (void*)(e.Accept);
            param[6] = (void*)(e.PartialSuccess);
            param[7] = (void*)(e.AvailableMethods);
            break;
         }

      }
      return ret_code;
    }

  public:

    SSHDaemon(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_73) {
      m_pObj = IPWorksSSH_SSHDaemon_Create(SSHDaemonEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~SSHDaemon() {
      IPWorksSSH_SSHDaemon_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_SSHDaemon_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_SSHDaemon_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_SSHDaemon_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline int GetSSHChannelCount() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 1, 0, 0);
      return (int)(long)val;
    }

    inline int GetBytesSent(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 2, iSSHChannelId, 0);
      return (int)(long)val;
    }

    inline QString GetChannelId(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 3, iSSHChannelId, 0);
      return QString((char*)val);
    }



    inline int SetDataToSend(int iSSHChannelId, const QByteArray &qba) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 4, iSSHChannelId, (void*)qba.data(), qba.size());
    }

    inline int GetConnectionBacklog() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 5, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnectionBacklog(int iConnectionBacklog) {
      void* val = (void*)iConnectionBacklog;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 5, 0, val, 0);
    }
    inline int GetSSHConnectionCount() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 6, 0, 0);
      return (int)(long)val;
    }

    inline int GetSSHConnectionConnected(int iConnectionId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 7, iConnectionId, 0);
      return (int)(long)val;
    }
    inline int SetSSHConnectionConnected(int iConnectionId, int bSSHConnectionConnected) {
      void* val = (void*)bSSHConnectionConnected;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 7, iConnectionId, val, 0);
    }
    inline QString GetSSHConnectionLocalAddress(int iConnectionId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 8, iConnectionId, 0);
      return QString((char*)val);
    }


    inline QString GetSSHConnectionRemoteHost(int iConnectionId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 9, iConnectionId, 0);
      return QString((char*)val);
    }


    inline int GetSSHConnectionRemotePort(int iConnectionId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 10, iConnectionId, 0);
      return (int)(long)val;
    }

    inline int GetSSHConnectionTimeout(int iConnectionId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 11, iConnectionId, 0);
      return (int)(long)val;
    }
    inline int SetSSHConnectionTimeout(int iConnectionId, int iSSHConnectionTimeout) {
      void* val = (void*)iSSHConnectionTimeout;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 11, iConnectionId, val, 0);
    }
    inline QString GetDefaultAuthMethods() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 12, 0, 0);
      return QString((char*)val);
    }

    inline int SetDefaultAuthMethods(const QString &DefaultAuthMethods) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = DefaultAuthMethods.toLatin1();
      #else
      QByteArray qba = DefaultAuthMethods.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 12, 0, (void*)qba.data(), 0);
    }

    inline int GetDefaultTimeout() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }
    inline int SetDefaultTimeout(int iDefaultTimeout) {
      void* val = (void*)iDefaultTimeout;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 13, 0, val, 0);
    }
    inline QString GetKeyboardInteractiveMessage() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 14, 0, 0);
      return QString((char*)val);
    }

    inline int SetKeyboardInteractiveMessage(const QString &KeyboardInteractiveMessage) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = KeyboardInteractiveMessage.toLatin1();
      #else
      QByteArray qba = KeyboardInteractiveMessage.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 14, 0, (void*)qba.data(), 0);
    }

    inline int GetKeyboardInteractivePromptCount() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 15, 0, 0);
      return (int)(long)val;
    }
    inline int SetKeyboardInteractivePromptCount(int iKeyboardInteractivePromptCount) {
      void* val = (void*)iKeyboardInteractivePromptCount;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 15, 0, val, 0);
    }
    inline int GetKeyboardInteractivePromptEcho(int iPromptIndex) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 16, iPromptIndex, 0);
      return (int)(long)val;
    }
    inline int SetKeyboardInteractivePromptEcho(int iPromptIndex, int bKeyboardInteractivePromptEcho) {
      void* val = (void*)bKeyboardInteractivePromptEcho;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 16, iPromptIndex, val, 0);
    }
    inline QString GetKeyboardInteractivePromptPrompt(int iPromptIndex) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 17, iPromptIndex, 0);
      return QString((char*)val);
    }

    inline int SetKeyboardInteractivePromptPrompt(int iPromptIndex, const QString &KeyboardInteractivePromptPrompt) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = KeyboardInteractivePromptPrompt.toLatin1();
      #else
      QByteArray qba = KeyboardInteractivePromptPrompt.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 17, iPromptIndex, (void*)qba.data(), 0);
    }

    inline int GetListening() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 18, 0, 0);
      return (int)(long)val;
    }
    inline int SetListening(int bListening) {
      void* val = (void*)bListening;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 18, 0, val, 0);
    }
    inline QString GetLocalHost() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 19, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 19, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 20, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 20, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHDaemon_Get(m_pObj, 21, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 21, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_SSHDaemon_Get(m_pObj, 22, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 22, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 23, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 23, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 24, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 24, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 25, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 25, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 26, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 26, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 27, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 27, 0, (void*)qba.data(), 0);
    }


  public: //methods

    inline int CloseChannel(int ChannelId) {
       
      void *param[1+1] = {(void*)ChannelId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 2, 1, param, cbparam);
      
    }
    inline QString Config(const QString &ConfigurationString) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ConfigurationString = ConfigurationString.toLatin1();
      #else
      QByteArray t_ConfigurationString = ConfigurationString.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ConfigurationString.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 3, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline int Disconnect(int ConnectionId) {
       
      void *param[1+1] = {(void*)ConnectionId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 4, 1, param, cbparam);
      
    }
    inline int DoEvents() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 5, 0, param, cbparam);
      
    }
    inline int ExchangeKeys(int ConnectionId) {
       
      void *param[1+1] = {(void*)ConnectionId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 6, 1, param, cbparam);
      
    }
    inline QString GetSSHParam(const QByteArray &Payload, const QString &Field) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Field = Field.toLatin1();
      #else
      QByteArray t_Field = Field.toAscii();
      #endif
      
      void *param[2+1] = {(void*)Payload.data(), (void*)t_Field.data(), 0};
      int cbparam[2+1] = {Payload.size(), 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 7, 2, param, cbparam);
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
      IPWorksSSH_SSHDaemon_Do(m_pObj, 8, 2, param, cbparam);
      return QByteArray((char*)param[2],cbparam[2]);
      
    }
    inline QString OpenChannel(int ConnectionId, const QString &ChannelType) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ChannelType = ChannelType.toLatin1();
      #else
      QByteArray t_ChannelType = ChannelType.toAscii();
      #endif
      
      void *param[2+1] = {(void*)ConnectionId, (void*)t_ChannelType.data(), 0};
      int cbparam[2+1] = {0, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 9, 2, param, cbparam);
      return QString((char*)param[2]);
      
    }
    inline int SendChannelData(int ChannelId, const QByteArray &Data) {
        
      void *param[2+1] = {(void*)ChannelId, (void*)Data.data(), 0};
      int cbparam[2+1] = {0, Data.size(), 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10, 2, param, cbparam);
      
    }
    inline int SendSSHPacket(int ChannelId, int PacketType, const QByteArray &Payload) {
         
      void *param[3+1] = {(void*)ChannelId, (void*)PacketType, (void*)Payload.data(), 0};
      int cbparam[3+1] = {0, 0, Payload.size(), 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 11, 3, param, cbparam);
      
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
      IPWorksSSH_SSHDaemon_Do(m_pObj, 12, 3, param, cbparam);
      return QByteArray((char*)param[3],cbparam[3]);
      
    }
    inline int Shutdown() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 13, 0, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_SSHDAEMON_H_




