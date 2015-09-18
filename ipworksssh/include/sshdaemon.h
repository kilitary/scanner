/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SSHDAEMON_H_
#define _IPWORKSSSH_SSHDAEMON_H_

#define IPWORKSSSH_ONLY_TYPES
#include "ipworksssh.h"
#include "ipworksssh.key"

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
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SSHDaemon_StaticDestroy();

#ifdef WIN32
#include <windows.h>
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

typedef struct {
  int ConnectionId;
  int StatusCode;
  const char* Description;
  int reserved;
} SSHDaemonConnectedEventParams;

typedef struct {
  const char* Address;
  int Port;
  int Accept;
  int reserved;
} SSHDaemonConnectionRequestEventParams;

typedef struct {
  int ConnectionId;
  int StatusCode;
  const char* Description;
  int reserved;
} SSHDaemonDisconnectedEventParams;

typedef struct {
  int ConnectionId;
  int ErrorCode;
  const char* Description;
  int reserved;
} SSHDaemonErrorEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelClosedEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  const char* Data;
  int lenData;
  int reserved;
} SSHDaemonSSHChannelDataInEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelEOFEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelOpenedEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  const char* Service;
  const char* Parameters;
  int Accept;
  int lenParameters;
  int reserved;
} SSHDaemonSSHChannelOpenRequestEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelReadyToSendEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  const char* RequestType;
  const char* Packet;
  int Success;
  int lenPacket;
  int reserved;
} SSHDaemonSSHChannelRequestEventParams;

typedef struct {
  int ConnectionId;
  int ChannelId;
  const char* RequestType;
  const char* Packet;
  int lenPacket;
  int reserved;
} SSHDaemonSSHChannelRequestedEventParams;

typedef struct {
  int ConnectionId;
  const char* Service;
  int Accept;
  int reserved;
} SSHDaemonSSHServiceRequestEventParams;

typedef struct {
  int ConnectionId;
  const char* Message;
  int reserved;
} SSHDaemonSSHStatusEventParams;

typedef struct {
  int ConnectionId;
  const char* User;
  const char* Service;
  const char* AuthMethod;
  const char* AuthParam;
  int Accept;
  int PartialSuccess;
  const char* AvailableMethods;
  int reserved;
} SSHDaemonSSHUserAuthRequestEventParams;



class SSHDaemon {
  
  public: //events
  
    virtual int FireConnected(SSHDaemonConnectedEventParams *e) {return 0;}
    virtual int FireConnectionRequest(SSHDaemonConnectionRequestEventParams *e) {return 0;}
    virtual int FireDisconnected(SSHDaemonDisconnectedEventParams *e) {return 0;}
    virtual int FireError(SSHDaemonErrorEventParams *e) {return 0;}
    virtual int FireSSHChannelClosed(SSHDaemonSSHChannelClosedEventParams *e) {return 0;}
    virtual int FireSSHChannelDataIn(SSHDaemonSSHChannelDataInEventParams *e) {return 0;}
    virtual int FireSSHChannelEOF(SSHDaemonSSHChannelEOFEventParams *e) {return 0;}
    virtual int FireSSHChannelOpened(SSHDaemonSSHChannelOpenedEventParams *e) {return 0;}
    virtual int FireSSHChannelOpenRequest(SSHDaemonSSHChannelOpenRequestEventParams *e) {return 0;}
    virtual int FireSSHChannelReadyToSend(SSHDaemonSSHChannelReadyToSendEventParams *e) {return 0;}
    virtual int FireSSHChannelRequest(SSHDaemonSSHChannelRequestEventParams *e) {return 0;}
    virtual int FireSSHChannelRequested(SSHDaemonSSHChannelRequestedEventParams *e) {return 0;}
    virtual int FireSSHServiceRequest(SSHDaemonSSHServiceRequestEventParams *e) {return 0;}
    virtual int FireSSHStatus(SSHDaemonSSHStatusEventParams *e) {return 0;}
    virtual int FireSSHUserAuthRequest(SSHDaemonSSHUserAuthRequestEventParams *e) {return 0;}


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SSHDaemonEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      if (event_id > 10000) return ((SSHDaemon*)lpObj)->SSHDaemonEventSinkW(event_id - 10000, cparam, param, cbparam);
      switch (event_id) {
         case 1: {
            SSHDaemonConnectedEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SSHDaemonConnectionRequestEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireConnectionRequest(&e);
            param[2] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 3: {
            SSHDaemonDisconnectedEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 4: {
            SSHDaemonErrorEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireError(&e);
            break;
         }
         case 5: {
            SSHDaemonSSHChannelClosedEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelClosed(&e);
            break;
         }
         case 6: {
            SSHDaemonSSHChannelDataInEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelDataIn(&e);
            break;
         }
         case 7: {
            SSHDaemonSSHChannelEOFEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelEOF(&e);
            break;
         }
         case 8: {
            SSHDaemonSSHChannelOpenedEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelOpened(&e);
            break;
         }
         case 9: {
            SSHDaemonSSHChannelOpenRequestEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelOpenRequest(&e);
            param[4] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 10: {
            SSHDaemonSSHChannelReadyToSendEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelReadyToSend(&e);
            break;
         }
         case 11: {
            SSHDaemonSSHChannelRequestEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelRequest(&e);
            param[4] = (void*)IPH64CAST(e.Success);
            break;
         }
         case 12: {
            SSHDaemonSSHChannelRequestedEventParams e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHChannelRequested(&e);
            break;
         }
         case 13: {
            SSHDaemonSSHServiceRequestEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHServiceRequest(&e);
            param[2] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 14: {
            SSHDaemonSSHStatusEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 15: {
            SSHDaemonSSHUserAuthRequestEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (int)IPH64CAST(param[6]), (char*)IPH64CAST(param[7]),  0};
            ret_code = ((SSHDaemon*)lpObj)->FireSSHUserAuthRequest(&e);
            param[5] = (void*)IPH64CAST(e.Accept);
            param[6] = (void*)IPH64CAST(e.PartialSuccess);
            param[7] = (void*)IPH64CAST(e.AvailableMethods);
            break;
         }

      }
      return ret_code;
    }

    virtual int SSHDaemonEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {return 0;}

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

    inline char* GetChannelId(int iSSHChannelId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 3, iSSHChannelId, 0);
      return (char*)val;
    }



    inline int SetDataToSend(int iSSHChannelId, const char *lpDataToSend, int lenDataToSend) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 4, iSSHChannelId, (void*)lpDataToSend, lenDataToSend);
    }

    inline int GetConnectionBacklog() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 5, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnectionBacklog(int iConnectionBacklog) {
      void* val = (void*)IPH64CAST(iConnectionBacklog);
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
      void* val = (void*)IPH64CAST(bSSHConnectionConnected);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 7, iConnectionId, val, 0);
    }
    inline char* GetSSHConnectionLocalAddress(int iConnectionId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 8, iConnectionId, 0);
      return (char*)val;
    }


    inline char* GetSSHConnectionRemoteHost(int iConnectionId) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 9, iConnectionId, 0);
      return (char*)val;
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
      void* val = (void*)IPH64CAST(iSSHConnectionTimeout);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 11, iConnectionId, val, 0);
    }
    inline char* GetDefaultAuthMethods() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 12, 0, 0);
      return (char*)val;
    }

    inline int SetDefaultAuthMethods(const char *lpDefaultAuthMethods) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 12, 0, (void*)lpDefaultAuthMethods, 0);
    }

    inline int GetDefaultTimeout() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }
    inline int SetDefaultTimeout(int iDefaultTimeout) {
      void* val = (void*)IPH64CAST(iDefaultTimeout);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 13, 0, val, 0);
    }
    inline char* GetKeyboardInteractiveMessage() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 14, 0, 0);
      return (char*)val;
    }

    inline int SetKeyboardInteractiveMessage(const char *lpKeyboardInteractiveMessage) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 14, 0, (void*)lpKeyboardInteractiveMessage, 0);
    }

    inline int GetKeyboardInteractivePromptCount() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 15, 0, 0);
      return (int)(long)val;
    }
    inline int SetKeyboardInteractivePromptCount(int iKeyboardInteractivePromptCount) {
      void* val = (void*)IPH64CAST(iKeyboardInteractivePromptCount);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 15, 0, val, 0);
    }
    inline int GetKeyboardInteractivePromptEcho(int iPromptIndex) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 16, iPromptIndex, 0);
      return (int)(long)val;
    }
    inline int SetKeyboardInteractivePromptEcho(int iPromptIndex, int bKeyboardInteractivePromptEcho) {
      void* val = (void*)IPH64CAST(bKeyboardInteractivePromptEcho);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 16, iPromptIndex, val, 0);
    }
    inline char* GetKeyboardInteractivePromptPrompt(int iPromptIndex) {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 17, iPromptIndex, 0);
      return (char*)val;
    }

    inline int SetKeyboardInteractivePromptPrompt(int iPromptIndex, const char *lpKeyboardInteractivePromptPrompt) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 17, iPromptIndex, (void*)lpKeyboardInteractivePromptPrompt, 0);
    }

    inline int GetListening() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 18, 0, 0);
      return (int)(long)val;
    }
    inline int SetListening(int bListening) {
      void* val = (void*)IPH64CAST(bListening);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 18, 0, val, 0);
    }
    inline char* GetLocalHost() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 19, 0, 0);
      return (char*)val;
    }

    inline int SetLocalHost(const char *lpLocalHost) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 19, 0, (void*)lpLocalHost, 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 20, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)IPH64CAST(lLocalPort);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 20, 0, val, 0);
    }
    inline int GetSSHCertEncoded(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHDaemon_Get(m_pObj, 21, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }

    inline int SetSSHCertEncoded(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 21, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int GetSSHCertStore(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SSHDaemon_Get(m_pObj, 22, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }

    inline int SetSSHCertStore(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 22, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }

    inline char* GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 23, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertStorePassword(const char *lpSSHCertStorePassword) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 23, 0, (void*)lpSSHCertStorePassword, 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 24, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)IPH64CAST(iSSHCertStoreType);
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 24, 0, val, 0);
    }
    inline char* GetSSHCertSubject() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 25, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertSubject(const char *lpSSHCertSubject) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 25, 0, (void*)lpSSHCertSubject, 0);
    }

    inline char* GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 26, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCompressionAlgorithms(const char *lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 26, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline char* GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SSHDaemon_Get(m_pObj, 27, 0, 0);
      return (char*)val;
    }

    inline int SetSSHEncryptionAlgorithms(const char *lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 27, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }


  public: //methods

    inline int CloseChannel(int iChannelId) {
      void *param[1+1] = {(void*)IPH64CAST(iChannelId), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 2, 1, param, cbparam);
      
      
    }
    inline char* Config(const char* lpszConfigurationString) {
      void *param[1+1] = {(void*)IPH64CAST(lpszConfigurationString), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 3, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline int Disconnect(int iConnectionId) {
      void *param[1+1] = {(void*)IPH64CAST(iConnectionId), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 4, 1, param, cbparam);
      
      
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 5, 0, param, cbparam);
      
      
    }
    inline int ExchangeKeys(int iConnectionId) {
      void *param[1+1] = {(void*)IPH64CAST(iConnectionId), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 6, 1, param, cbparam);
      
      
    }
    inline char* GetSSHParam(const char* lpPayload, int lenPayload, const char* lpszField) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 7, 2, param, cbparam);
      
      return (char*)IPH64CAST(param[2]);
    }
    inline char* GetSSHParamBytes(const char* lpPayload, int lenPayload, const char* lpszField, int *lpSize = 0) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 8, 2, param, cbparam);
      if (lpSize) *lpSize = cbparam[2];
      return (char*)IPH64CAST(param[2]);
    }
    inline char* OpenChannel(int iConnectionId, const char* lpszChannelType) {
      void *param[2+1] = {(void*)IPH64CAST(iConnectionId), (void*)IPH64CAST(lpszChannelType), 0};
      int cbparam[2+1] = {0, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 9, 2, param, cbparam);
      
      return (char*)IPH64CAST(param[2]);
    }
    inline int SendChannelData(int iChannelId, const char* lpData, int lenData) {
      void *param[2+1] = {(void*)IPH64CAST(iChannelId), (void*)IPH64CAST(lpData), 0};
      int cbparam[2+1] = {0, lenData, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10, 2, param, cbparam);
      
      
    }
    inline int SendSSHPacket(int iChannelId, int iPacketType, const char* lpPayload, int lenPayload) {
      void *param[3+1] = {(void*)IPH64CAST(iChannelId), (void*)IPH64CAST(iPacketType), (void*)IPH64CAST(lpPayload), 0};
      int cbparam[3+1] = {0, 0, lenPayload, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 11, 3, param, cbparam);
      
      
    }
    inline char* SetSSHParam(const char* lpPayload, int lenPayload, const char* lpszFieldType, const char* lpszFieldValue, int *lpSize = 0) {
      void *param[3+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszFieldType), (void*)IPH64CAST(lpszFieldValue), 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 12, 3, param, cbparam);
      if (lpSize) *lpSize = cbparam[3];
      return (char*)IPH64CAST(param[3]);
    }
    inline int Shutdown() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 13, 0, param, cbparam);
      
      
    }

};


#ifdef WIN32 //UNICODE

typedef struct {
  int ConnectionId;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SSHDaemonConnectedEventParamsW;

typedef struct {
  LPWSTR Address;
  int Port;
  int Accept;
  int reserved;
} SSHDaemonConnectionRequestEventParamsW;

typedef struct {
  int ConnectionId;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SSHDaemonDisconnectedEventParamsW;

typedef struct {
  int ConnectionId;
  int ErrorCode;
  LPWSTR Description;
  int reserved;
} SSHDaemonErrorEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelClosedEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  LPWSTR Data;
  int lenData;
  int reserved;
} SSHDaemonSSHChannelDataInEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelEOFEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelOpenedEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  LPWSTR Service;
  LPWSTR Parameters;
  int Accept;
  int lenParameters;
  int reserved;
} SSHDaemonSSHChannelOpenRequestEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  int reserved;
} SSHDaemonSSHChannelReadyToSendEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  LPWSTR RequestType;
  LPWSTR Packet;
  int Success;
  int lenPacket;
  int reserved;
} SSHDaemonSSHChannelRequestEventParamsW;

typedef struct {
  int ConnectionId;
  int ChannelId;
  LPWSTR RequestType;
  LPWSTR Packet;
  int lenPacket;
  int reserved;
} SSHDaemonSSHChannelRequestedEventParamsW;

typedef struct {
  int ConnectionId;
  LPWSTR Service;
  int Accept;
  int reserved;
} SSHDaemonSSHServiceRequestEventParamsW;

typedef struct {
  int ConnectionId;
  LPWSTR Message;
  int reserved;
} SSHDaemonSSHStatusEventParamsW;

typedef struct {
  int ConnectionId;
  LPWSTR User;
  LPWSTR Service;
  LPWSTR AuthMethod;
  LPWSTR AuthParam;
  int Accept;
  int PartialSuccess;
  LPWSTR AvailableMethods;
  int reserved;
} SSHDaemonSSHUserAuthRequestEventParamsW;



class SSHDaemonW : public SSHDaemon {

  public: //properties
  




    inline LPWSTR GetChannelId(int iSSHChannelId) {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+3, iSSHChannelId, 0);
    }





    inline int SetDataToSend(int iSSHChannelId, LPWSTR lpDataToSend) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+4, iSSHChannelId, (void*)lpDataToSend, 0);
    }

    inline int SetDataToSendB(int iSSHChannelId, const char *lpDataToSend, int lenDataToSend) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 4, iSSHChannelId, (void*)lpDataToSend, lenDataToSend);
    }






    inline LPWSTR GetSSHConnectionLocalAddress(int iConnectionId) {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+8, iConnectionId, 0);
    }



    inline LPWSTR GetSSHConnectionRemoteHost(int iConnectionId) {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+9, iConnectionId, 0);
    }







    inline LPWSTR GetDefaultAuthMethods() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+12, 0, 0);
    }

    inline int SetDefaultAuthMethods(LPWSTR lpDefaultAuthMethods) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+12, 0, (void*)lpDefaultAuthMethods, 0);
    }



    inline LPWSTR GetKeyboardInteractiveMessage() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+14, 0, 0);
    }

    inline int SetKeyboardInteractiveMessage(LPWSTR lpKeyboardInteractiveMessage) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+14, 0, (void*)lpKeyboardInteractiveMessage, 0);
    }





    inline LPWSTR GetKeyboardInteractivePromptPrompt(int iPromptIndex) {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+17, iPromptIndex, 0);
    }

    inline int SetKeyboardInteractivePromptPrompt(int iPromptIndex, LPWSTR lpKeyboardInteractivePromptPrompt) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+17, iPromptIndex, (void*)lpKeyboardInteractivePromptPrompt, 0);
    }



    inline LPWSTR GetLocalHost() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+19, 0, 0);
    }

    inline int SetLocalHost(LPWSTR lpLocalHost) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+19, 0, (void*)lpLocalHost, 0);
    }



    inline LPWSTR GetSSHCertEncoded() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+21, 0, 0);
    }

    inline int SetSSHCertEncoded(LPWSTR lpSSHCertEncoded) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+21, 0, (void*)lpSSHCertEncoded, 0);
    }
    inline int GetSSHCertEncodedB(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SSHDaemon_Get(m_pObj, 21, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }
    inline int SetSSHCertEncodedB(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 21, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }
    inline LPWSTR GetSSHCertStore() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+22, 0, 0);
    }

    inline int SetSSHCertStore(LPWSTR lpSSHCertStore) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+22, 0, (void*)lpSSHCertStore, 0);
    }
    inline int GetSSHCertStoreB(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SSHDaemon_Get(m_pObj, 22, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }
    inline int SetSSHCertStoreB(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 22, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }
    inline LPWSTR GetSSHCertStorePassword() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+23, 0, 0);
    }

    inline int SetSSHCertStorePassword(LPWSTR lpSSHCertStorePassword) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+23, 0, (void*)lpSSHCertStorePassword, 0);
    }



    inline LPWSTR GetSSHCertSubject() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+25, 0, 0);
    }

    inline int SetSSHCertSubject(LPWSTR lpSSHCertSubject) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+25, 0, (void*)lpSSHCertSubject, 0);
    }

    inline LPWSTR GetSSHCompressionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+26, 0, 0);
    }

    inline int SetSSHCompressionAlgorithms(LPWSTR lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+26, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline LPWSTR GetSSHEncryptionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SSHDaemon_Get(m_pObj, 10000+27, 0, 0);
    }

    inline int SetSSHEncryptionAlgorithms(LPWSTR lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SSHDaemon_Set(m_pObj, 10000+27, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }



  public: //events
  
    virtual int FireConnected(SSHDaemonConnectedEventParamsW *e) {return 0;}
    virtual int FireConnectionRequest(SSHDaemonConnectionRequestEventParamsW *e) {return 0;}
    virtual int FireDisconnected(SSHDaemonDisconnectedEventParamsW *e) {return 0;}
    virtual int FireError(SSHDaemonErrorEventParamsW *e) {return 0;}
    virtual int FireSSHChannelClosed(SSHDaemonSSHChannelClosedEventParamsW *e) {return 0;}
    virtual int FireSSHChannelDataIn(SSHDaemonSSHChannelDataInEventParamsW *e) {return 0;}
    virtual int FireSSHChannelEOF(SSHDaemonSSHChannelEOFEventParamsW *e) {return 0;}
    virtual int FireSSHChannelOpened(SSHDaemonSSHChannelOpenedEventParamsW *e) {return 0;}
    virtual int FireSSHChannelOpenRequest(SSHDaemonSSHChannelOpenRequestEventParamsW *e) {return 0;}
    virtual int FireSSHChannelReadyToSend(SSHDaemonSSHChannelReadyToSendEventParamsW *e) {return 0;}
    virtual int FireSSHChannelRequest(SSHDaemonSSHChannelRequestEventParamsW *e) {return 0;}
    virtual int FireSSHChannelRequested(SSHDaemonSSHChannelRequestedEventParamsW *e) {return 0;}
    virtual int FireSSHServiceRequest(SSHDaemonSSHServiceRequestEventParamsW *e) {return 0;}
    virtual int FireSSHStatus(SSHDaemonSSHStatusEventParamsW *e) {return 0;}
    virtual int FireSSHUserAuthRequest(SSHDaemonSSHUserAuthRequestEventParamsW *e) {return 0;}


  protected:
  
    virtual int SSHDaemonEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {
    	int ret_code = 0;
      switch (event_id) {
         case 1: {
            SSHDaemonConnectedEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireConnected(&e);
            break;
         }
         case 2: {
            SSHDaemonConnectionRequestEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = FireConnectionRequest(&e);
            param[2] = (void*)(e.Accept);
            break;
         }
         case 3: {
            SSHDaemonDisconnectedEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireDisconnected(&e);
            break;
         }
         case 4: {
            SSHDaemonErrorEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireError(&e);
            break;
         }
         case 5: {
            SSHDaemonSSHChannelClosedEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = FireSSHChannelClosed(&e);
            break;
         }
         case 6: {
            SSHDaemonSSHChannelDataInEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(cbparam[2]),  0};
            ret_code = FireSSHChannelDataIn(&e);
            break;
         }
         case 7: {
            SSHDaemonSSHChannelEOFEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = FireSSHChannelEOF(&e);
            break;
         }
         case 8: {
            SSHDaemonSSHChannelOpenedEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = FireSSHChannelOpened(&e);
            break;
         }
         case 9: {
            SSHDaemonSSHChannelOpenRequestEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = FireSSHChannelOpenRequest(&e);
            param[4] = (void*)(e.Accept);
            break;
         }
         case 10: {
            SSHDaemonSSHChannelReadyToSendEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]),  0};
            ret_code = FireSSHChannelReadyToSend(&e);
            break;
         }
         case 11: {
            SSHDaemonSSHChannelRequestEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = FireSSHChannelRequest(&e);
            param[4] = (void*)(e.Success);
            break;
         }
         case 12: {
            SSHDaemonSSHChannelRequestedEventParamsW e = {(int)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[3]),  0};
            ret_code = FireSSHChannelRequested(&e);
            break;
         }
         case 13: {
            SSHDaemonSSHServiceRequestEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (int)IPH64CAST(param[2]),  0};
            ret_code = FireSSHServiceRequest(&e);
            param[2] = (void*)(e.Accept);
            break;
         }
         case 14: {
            SSHDaemonSSHStatusEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireSSHStatus(&e);
            break;
         }
         case 15: {
            SSHDaemonSSHUserAuthRequestEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (LPWSTR)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (int)IPH64CAST(param[6]), (LPWSTR)IPH64CAST(param[7]),  0};
            ret_code = FireSSHUserAuthRequest(&e);
            param[5] = (void*)(e.Accept);
            param[6] = (void*)(e.PartialSuccess);
            param[7] = (void*)(e.AvailableMethods);
            break;
         }

      }
      return ret_code;
    }
  
  public: //event overrides

    virtual int FireConnected(SSHDaemonConnectedEventParams *e) {return -10000;}
    virtual int FireConnectionRequest(SSHDaemonConnectionRequestEventParams *e) {return -10000;}
    virtual int FireDisconnected(SSHDaemonDisconnectedEventParams *e) {return -10000;}
    virtual int FireError(SSHDaemonErrorEventParams *e) {return -10000;}
    virtual int FireSSHChannelClosed(SSHDaemonSSHChannelClosedEventParams *e) {return -10000;}
    virtual int FireSSHChannelDataIn(SSHDaemonSSHChannelDataInEventParams *e) {return -10000;}
    virtual int FireSSHChannelEOF(SSHDaemonSSHChannelEOFEventParams *e) {return -10000;}
    virtual int FireSSHChannelOpened(SSHDaemonSSHChannelOpenedEventParams *e) {return -10000;}
    virtual int FireSSHChannelOpenRequest(SSHDaemonSSHChannelOpenRequestEventParams *e) {return -10000;}
    virtual int FireSSHChannelReadyToSend(SSHDaemonSSHChannelReadyToSendEventParams *e) {return -10000;}
    virtual int FireSSHChannelRequest(SSHDaemonSSHChannelRequestEventParams *e) {return -10000;}
    virtual int FireSSHChannelRequested(SSHDaemonSSHChannelRequestedEventParams *e) {return -10000;}
    virtual int FireSSHServiceRequest(SSHDaemonSSHServiceRequestEventParams *e) {return -10000;}
    virtual int FireSSHStatus(SSHDaemonSSHStatusEventParams *e) {return -10000;}
    virtual int FireSSHUserAuthRequest(SSHDaemonSSHUserAuthRequestEventParams *e) {return -10000;}

  public: //methods

    inline int CloseChannel(int iChannelId) {
      void *param[1+1] = {(void*)iChannelId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+2, 1, param, cbparam);
      
    }
    inline LPWSTR Config(LPWSTR lpszConfigurationString) {
      void *param[1+1] = {(void*)lpszConfigurationString, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+3, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int Disconnect(int iConnectionId) {
      void *param[1+1] = {(void*)iConnectionId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+4, 1, param, cbparam);
      
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+5, 0, param, cbparam);
      
    }
    inline int ExchangeKeys(int iConnectionId) {
      void *param[1+1] = {(void*)iConnectionId, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+6, 1, param, cbparam);
      
    }
    inline LPWSTR GetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+7, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR GetSSHParamBytes(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+8, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR OpenChannel(int iConnectionId, LPWSTR lpszChannelType) {
      void *param[2+1] = {(void*)iConnectionId, (void*)lpszChannelType, 0};
      int cbparam[2+1] = {0, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+9, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline int SendChannelData(int iChannelId, LPWSTR lpData, int lenData) {
      void *param[2+1] = {(void*)iChannelId, (void*)lpData, 0};
      int cbparam[2+1] = {0, lenData, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+10, 2, param, cbparam);
      
    }
    inline int SendSSHPacket(int iChannelId, int iPacketType, LPWSTR lpPayload, int lenPayload) {
      void *param[3+1] = {(void*)iChannelId, (void*)iPacketType, (void*)lpPayload, 0};
      int cbparam[3+1] = {0, 0, lenPayload, 0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+11, 3, param, cbparam);
      
    }
    inline LPWSTR SetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszFieldType, LPWSTR lpszFieldValue) {
      void *param[3+1] = {(void*)lpPayload, (void*)lpszFieldType, (void*)lpszFieldValue, 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+12, 3, param, cbparam);
      return (LPWSTR)IPH64CAST(param[3]);
    }
    inline int Shutdown() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SSHDaemon_Do(m_pObj, 10000+13, 0, param, cbparam);
      
    }

};

#endif //WIN32

#endif //_IPWORKSSSH_SSHDAEMON_H_




