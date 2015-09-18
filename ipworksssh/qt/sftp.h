/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SFTP_H_
#define _IPWORKSSSH_SFTP_H_

#include "ipworksssh.h"
#include "../include/ipworksssh.key"
#include <QObject.h>

//SFTPFileTypes
#define SFT_REGULAR                                        1
#define SFT_DIRECTORY                                      2
#define SFT_SYM_LINK                                       3
#define SFT_SPECIAL                                        4
#define SFT_UNKNOWN                                        5
#define SFT_SOCKET                                         6
#define SFT_CHAR_DEVICE                                    7
#define SFT_BLOCK_DEVICE                                   8
#define SFT_FIFO                                           9

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



extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SFTP_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SFTP_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SFTP_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_SFTP_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SFTP_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SFTP_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_SFTP_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SFTP_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SFTP_StaticInit(void *hInst);


struct SFTPConnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SFTPConnectionStatusEventParams {
  int EventRetVal;
  char* ConnectionEvent;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SFTPDirListEventParams {
  int EventRetVal;
  char* DirEntry;
  char* FileName;
  int IsDir;
  ns_int64 *pFileSize;
  char* FileTime;
  int reserved;
};

struct SFTPDisconnectedEventParams {
  int EventRetVal;
  int StatusCode;
  char* Description;
  int reserved;
};

struct SFTPEndTransferEventParams {
  int EventRetVal;
  int Direction;
  char* LocalFile;
  char* RemoteFile;
  int reserved;
};

struct SFTPErrorEventParams {
  int EventRetVal;
  int ErrorCode;
  char* Description;
  char* LocalFile;
  char* RemoteFile;
  int reserved;
};

struct SFTPSSHCustomAuthEventParams {
  int EventRetVal;
  char* Packet;
  int reserved;
};

struct SFTPSSHKeyboardInteractiveEventParams {
  int EventRetVal;
  char* Name;
  char* Instructions;
  char* Prompt;
  char* Response;
  int EchoResponse;
  int reserved;
};

struct SFTPSSHServerAuthenticationEventParams {
  int EventRetVal;
  char* HostKey;
  char* Fingerprint;
  char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
};

struct SFTPSSHStatusEventParams {
  int EventRetVal;
  char* Message;
  int reserved;
};

struct SFTPStartTransferEventParams {
  int EventRetVal;
  int Direction;
  char* LocalFile;
  char* RemoteFile;
  int reserved;
};

struct SFTPTransferEventParams {
  int EventRetVal;
  int Direction;
  char* LocalFile;
  char* RemoteFile;
  ns_int64 *pBytesTransferred;
  int PercentDone;
  char* Text;
  int Cancel;
  int lenText;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class SFTP : public QObject {

  Q_OBJECT
signals: //events

    void Connected(SFTPConnectedEventParams *e);
    void ConnectionStatus(SFTPConnectionStatusEventParams *e);
    void DirList(SFTPDirListEventParams *e);
    void Disconnected(SFTPDisconnectedEventParams *e);
    void EndTransfer(SFTPEndTransferEventParams *e);
    void Error(SFTPErrorEventParams *e);
    void SSHCustomAuth(SFTPSSHCustomAuthEventParams *e);
    void SSHKeyboardInteractive(SFTPSSHKeyboardInteractiveEventParams *e);
    void SSHServerAuthentication(SFTPSSHServerAuthenticationEventParams *e);
    void SSHStatus(SFTPSSHStatusEventParams *e);
    void StartTransfer(SFTPStartTransferEventParams *e);
    void Transfer(SFTPTransferEventParams *e);

protected: // event firers
    virtual int FireConnected(SFTPConnectedEventParams *e) {
      emit Connected(e);
      return e->EventRetVal;
    }
    virtual int FireConnectionStatus(SFTPConnectionStatusEventParams *e) {
      emit ConnectionStatus(e);
      return e->EventRetVal;
    }
    virtual int FireDirList(SFTPDirListEventParams *e) {
      emit DirList(e);
      return e->EventRetVal;
    }
    virtual int FireDisconnected(SFTPDisconnectedEventParams *e) {
      emit Disconnected(e);
      return e->EventRetVal;
    }
    virtual int FireEndTransfer(SFTPEndTransferEventParams *e) {
      emit EndTransfer(e);
      return e->EventRetVal;
    }
    virtual int FireError(SFTPErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireSSHCustomAuth(SFTPSSHCustomAuthEventParams *e) {
      emit SSHCustomAuth(e);
      return e->EventRetVal;
    }
    virtual int FireSSHKeyboardInteractive(SFTPSSHKeyboardInteractiveEventParams *e) {
      emit SSHKeyboardInteractive(e);
      return e->EventRetVal;
    }
    virtual int FireSSHServerAuthentication(SFTPSSHServerAuthenticationEventParams *e) {
      emit SSHServerAuthentication(e);
      return e->EventRetVal;
    }
    virtual int FireSSHStatus(SFTPSSHStatusEventParams *e) {
      emit SSHStatus(e);
      return e->EventRetVal;
    }
    virtual int FireStartTransfer(SFTPStartTransferEventParams *e) {
      emit StartTransfer(e);
      return e->EventRetVal;
    }
    virtual int FireTransfer(SFTPTransferEventParams *e) {
      emit Transfer(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SFTPEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            SFTPConnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SFTP*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SFTPConnectionStatusEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SFTP*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SFTPDirListEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(param[2]), (ns_int64*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]),  0};
            ret_code = ((SFTP*)lpObj)->FireDirList(&e);
            break;
         }
         case 4: {
            SFTPDisconnectedEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SFTP*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 5: {
            SFTPEndTransferEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SFTP*)lpObj)->FireEndTransfer(&e);
            break;
         }
         case 6: {
            SFTPErrorEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]),  0};
            ret_code = ((SFTP*)lpObj)->FireError(&e);
            break;
         }
         case 7: {
            SFTPSSHCustomAuthEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 8: {
            SFTPSSHKeyboardInteractiveEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 9: {
            SFTPSSHServerAuthenticationEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 10: {
            SFTPSSHStatusEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 11: {
            SFTPStartTransferEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SFTP*)lpObj)->FireStartTransfer(&e);
            break;
         }
         case 12: {
            SFTPTransferEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (ns_int64*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (char*)IPH64CAST(param[5]), (int)IPH64CAST(param[6]), (int)IPH64CAST(cbparam[5]),  0};
            ret_code = ((SFTP*)lpObj)->FireTransfer(&e);
            param[6] = (void*)(e.Cancel);
            break;
         }

      }
      return ret_code;
    }

  public:

    SFTP(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_17) {
      m_pObj = IPWorksSSH_SFTP_Create(SFTPEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~SFTP() {
      IPWorksSSH_SFTP_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_SFTP_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_SFTP_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_SFTP_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline int GetConnected() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 1, 0, 0);
      return (int)(long)val;
    }
    inline int SetConnected(int bConnected) {
      void* val = (void*)bConnected;
      return IPWorksSSH_SFTP_Set(m_pObj, 1, 0, val, 0);
    }
    inline int GetDirListCount() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }

    inline QString GetDirListEntry(int iEntryIndex) {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 3, iEntryIndex, 0);
      return QString((char*)val);
    }


    inline QString GetDirListFileName(int iEntryIndex) {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 4, iEntryIndex, 0);
      return QString((char*)val);
    }


    inline ns_int64 GetDirListFileSize(int iEntryIndex) {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 5, iEntryIndex, 0);
      return *pval;
    }


    inline QString GetDirListFileTime(int iEntryIndex) {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 6, iEntryIndex, 0);
      return QString((char*)val);
    }


    inline int GetDirListIsDir(int iEntryIndex) {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 7, iEntryIndex, 0);
      return (int)(long)val;
    }

    inline ns_int64 GetFileAccessTime() {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 8, 0, 0);
      return *pval;
    }

    inline int SetFileAccessTime(ns_int64 lFileAccessTime) {
      void* val = (void*)(&lFileAccessTime);
      return IPWorksSSH_SFTP_Set(m_pObj, 8, 0, val, 0);
    }

    inline QString GetFileACL() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 9, 0, 0);
      return QString((char*)val);
    }

    inline int SetFileACL(const QString &FileACL) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FileACL.toLatin1();
      #else
      QByteArray qba = FileACL.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 9, 0, (void*)qba.data(), 0);
    }

    inline ns_int64 GetFileAllocationSize() {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 10, 0, 0);
      return *pval;
    }


    inline int GetFileAttributeBits() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 11, 0, 0);
      return (int)(long)val;
    }

    inline int GetFileAttributeBitsValid() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 12, 0, 0);
      return (int)(long)val;
    }

    inline ns_int64 GetFileCreationTime() {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 13, 0, 0);
      return *pval;
    }

    inline int SetFileCreationTime(ns_int64 lFileCreationTime) {
      void* val = (void*)(&lFileCreationTime);
      return IPWorksSSH_SFTP_Set(m_pObj, 13, 0, val, 0);
    }

    inline int GetFileType() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 14, 0, 0);
      return (int)(long)val;
    }

    inline QString GetFileGroupId() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 15, 0, 0);
      return QString((char*)val);
    }

    inline int SetFileGroupId(const QString &FileGroupId) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FileGroupId.toLatin1();
      #else
      QByteArray qba = FileGroupId.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 15, 0, (void*)qba.data(), 0);
    }

    inline int GetFileIsDir() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 16, 0, 0);
      return (int)(long)val;
    }

    inline ns_int64 GetFileModifiedTime() {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 17, 0, 0);
      return *pval;
    }

    inline int SetFileModifiedTime(ns_int64 lFileModifiedTime) {
      void* val = (void*)(&lFileModifiedTime);
      return IPWorksSSH_SFTP_Set(m_pObj, 17, 0, val, 0);
    }

    inline QString GetFileOwnerId() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 18, 0, 0);
      return QString((char*)val);
    }

    inline int SetFileOwnerId(const QString &FileOwnerId) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FileOwnerId.toLatin1();
      #else
      QByteArray qba = FileOwnerId.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 18, 0, (void*)qba.data(), 0);
    }

    inline int GetFilePermissions() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 19, 0, 0);
      return (int)(long)val;
    }
    inline int SetFilePermissions(int iFilePermissions) {
      void* val = (void*)iFilePermissions;
      return IPWorksSSH_SFTP_Set(m_pObj, 19, 0, val, 0);
    }
    inline ns_int64 GetFileSize() {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 20, 0, 0);
      return *pval;
    }


    inline int GetFileExists() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 21, 0, 0);
      return (int)(long)val;
    }

    inline int GetFirewallAutoDetect() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 22, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallAutoDetect(int bFirewallAutoDetect) {
      void* val = (void*)bFirewallAutoDetect;
      return IPWorksSSH_SFTP_Set(m_pObj, 22, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 23, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)iFirewallType;
      return IPWorksSSH_SFTP_Set(m_pObj, 23, 0, val, 0);
    }
    inline QString GetFirewallHost() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 24, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallHost(const QString &FirewallHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallHost.toLatin1();
      #else
      QByteArray qba = FirewallHost.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 24, 0, (void*)qba.data(), 0);
    }

    inline QString GetFirewallPassword() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 25, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallPassword(const QString &FirewallPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallPassword.toLatin1();
      #else
      QByteArray qba = FirewallPassword.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 25, 0, (void*)qba.data(), 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)lFirewallPort;
      return IPWorksSSH_SFTP_Set(m_pObj, 26, 0, val, 0);
    }
    inline QString GetFirewallUser() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 27, 0, 0);
      return QString((char*)val);
    }

    inline int SetFirewallUser(const QString &FirewallUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = FirewallUser.toLatin1();
      #else
      QByteArray qba = FirewallUser.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 27, 0, (void*)qba.data(), 0);
    }

    inline int GetIdle() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 28, 0, 0);
      return (int)(long)val;
    }

    inline QString GetLocalFile() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 29, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalFile(const QString &LocalFile) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalFile.toLatin1();
      #else
      QByteArray qba = LocalFile.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 29, 0, (void*)qba.data(), 0);
    }

    inline QString GetLocalHost() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 30, 0, 0);
      return QString((char*)val);
    }

    inline int SetLocalHost(const QString &LocalHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = LocalHost.toLatin1();
      #else
      QByteArray qba = LocalHost.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 30, 0, (void*)qba.data(), 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 31, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)lLocalPort;
      return IPWorksSSH_SFTP_Set(m_pObj, 31, 0, val, 0);
    }
    inline int GetOverwrite() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 32, 0, 0);
      return (int)(long)val;
    }
    inline int SetOverwrite(int bOverwrite) {
      void* val = (void*)bOverwrite;
      return IPWorksSSH_SFTP_Set(m_pObj, 32, 0, val, 0);
    }
    inline QString GetRemoteFile() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 33, 0, 0);
      return QString((char*)val);
    }

    inline int SetRemoteFile(const QString &RemoteFile) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = RemoteFile.toLatin1();
      #else
      QByteArray qba = RemoteFile.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 33, 0, (void*)qba.data(), 0);
    }

    inline QString GetRemotePath() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 34, 0, 0);
      return QString((char*)val);
    }

    inline int SetRemotePath(const QString &RemotePath) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = RemotePath.toLatin1();
      #else
      QByteArray qba = RemotePath.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 34, 0, (void*)qba.data(), 0);
    }

    inline QByteArray GetSSHAcceptServerHostKeyEncoded() {
      char *lpSSHAcceptServerHostKeyEncoded = NULL;
      int lenSSHAcceptServerHostKeyEncoded = 0;
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SFTP_Get(m_pObj, 35, 0, &lenSSHAcceptServerHostKeyEncoded);
      return QByteArray(lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const QByteArray &qba) {
      return IPWorksSSH_SFTP_Set(m_pObj, 35, 0, (void*)qba.data(), qba.size());
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 36, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)iSSHAuthMode;
      return IPWorksSSH_SFTP_Set(m_pObj, 36, 0, val, 0);
    }
    inline QByteArray GetSSHCertEncoded() {
      char *lpSSHCertEncoded = NULL;
      int lenSSHCertEncoded = 0;
      lpSSHCertEncoded = (char*)IPWorksSSH_SFTP_Get(m_pObj, 37, 0, &lenSSHCertEncoded);
      return QByteArray(lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int SetSSHCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_SFTP_Set(m_pObj, 37, 0, (void*)qba.data(), qba.size());
    }

    inline QByteArray GetSSHCertStore() {
      char *lpSSHCertStore = NULL;
      int lenSSHCertStore = 0;
      lpSSHCertStore = (char*)IPWorksSSH_SFTP_Get(m_pObj, 38, 0, &lenSSHCertStore);
      return QByteArray(lpSSHCertStore, lenSSHCertStore);
    }

    inline int SetSSHCertStore(const QByteArray &qba) {
      return IPWorksSSH_SFTP_Set(m_pObj, 38, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 39, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertStorePassword(const QString &SSHCertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertStorePassword.toLatin1();
      #else
      QByteArray qba = SSHCertStorePassword.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 39, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 40, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)iSSHCertStoreType;
      return IPWorksSSH_SFTP_Set(m_pObj, 40, 0, val, 0);
    }
    inline QString GetSSHCertSubject() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 41, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCertSubject(const QString &SSHCertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCertSubject.toLatin1();
      #else
      QByteArray qba = SSHCertSubject.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 41, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 42, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHCompressionAlgorithms(const QString &SSHCompressionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHCompressionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHCompressionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 42, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 43, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHEncryptionAlgorithms(const QString &SSHEncryptionAlgorithms) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHEncryptionAlgorithms.toLatin1();
      #else
      QByteArray qba = SSHEncryptionAlgorithms.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 43, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHHost() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 44, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHHost(const QString &SSHHost) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHHost.toLatin1();
      #else
      QByteArray qba = SSHHost.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 44, 0, (void*)qba.data(), 0);
    }

    inline QString GetSSHPassword() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 45, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHPassword(const QString &SSHPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHPassword.toLatin1();
      #else
      QByteArray qba = SSHPassword.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 45, 0, (void*)qba.data(), 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 46, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)lSSHPort;
      return IPWorksSSH_SFTP_Set(m_pObj, 46, 0, val, 0);
    }
    inline QString GetSSHUser() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 47, 0, 0);
      return QString((char*)val);
    }

    inline int SetSSHUser(const QString &SSHUser) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = SSHUser.toLatin1();
      #else
      QByteArray qba = SSHUser.toAscii();
      #endif
      return IPWorksSSH_SFTP_Set(m_pObj, 47, 0, (void*)qba.data(), 0);
    }

    inline ns_int64 GetStartByte() {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 48, 0, 0);
      return *pval;
    }

    inline int SetStartByte(ns_int64 lStartByte) {
      void* val = (void*)(&lStartByte);
      return IPWorksSSH_SFTP_Set(m_pObj, 48, 0, val, 0);
    }

    inline int GetTimeout() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 49, 0, 0);
      return (int)(long)val;
    }
    inline int SetTimeout(int iTimeout) {
      void* val = (void*)iTimeout;
      return IPWorksSSH_SFTP_Set(m_pObj, 49, 0, val, 0);
    }

  public: //methods

    inline int Append() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 2, 0, param, cbparam);
      
    }
    inline QString Config(const QString &ConfigurationString) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_ConfigurationString = ConfigurationString.toLatin1();
      #else
      QByteArray t_ConfigurationString = ConfigurationString.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_ConfigurationString.data(), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 3, 1, param, cbparam);
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
      IPWorksSSH_SFTP_Do(m_pObj, 4, 1, param, cbparam);
      return QByteArray((char*)param[1],cbparam[1]);
      
    }
    inline int DeleteFile(const QString &FileName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_FileName = FileName.toLatin1();
      #else
      QByteArray t_FileName = FileName.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_FileName.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 5, 1, param, cbparam);
      
    }
    inline int DoEvents() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 6, 0, param, cbparam);
      
    }
    inline int Download() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 7, 0, param, cbparam);
      
    }
    inline QString EncodePacket(const QByteArray &Packet) {
       
      void *param[1+1] = {(void*)Packet.data(), 0};
      int cbparam[1+1] = {Packet.size(), 0};
      IPWorksSSH_SFTP_Do(m_pObj, 8, 1, param, cbparam);
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
      IPWorksSSH_SFTP_Do(m_pObj, 9, 2, param, cbparam);
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
      IPWorksSSH_SFTP_Do(m_pObj, 10, 2, param, cbparam);
      return QByteArray((char*)param[2],cbparam[2]);
      
    }
    inline int Interrupt() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 11, 0, param, cbparam);
      
    }
    inline int ListDirectory() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 12, 0, param, cbparam);
      
    }
    inline int MakeDirectory(const QString &NewDir) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_NewDir = NewDir.toLatin1();
      #else
      QByteArray t_NewDir = NewDir.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_NewDir.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 13, 1, param, cbparam);
      
    }
    inline int QueueFile(const QString &LocalFile, const QString &RemoteFile) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_LocalFile = LocalFile.toLatin1();
      #else
      QByteArray t_LocalFile = LocalFile.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_RemoteFile = RemoteFile.toLatin1();
      #else
      QByteArray t_RemoteFile = RemoteFile.toAscii();
      #endif
      
      void *param[2+1] = {(void*)t_LocalFile.data(), (void*)t_RemoteFile.data(), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 14, 2, param, cbparam);
      
    }
    inline int RemoveDirectory(const QString &DirName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_DirName = DirName.toLatin1();
      #else
      QByteArray t_DirName = DirName.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_DirName.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 15, 1, param, cbparam);
      
    }
    inline int RenameFile(const QString &NewName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_NewName = NewName.toLatin1();
      #else
      QByteArray t_NewName = NewName.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_NewName.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 16, 1, param, cbparam);
      
    }
    inline int ResetQueue() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 17, 0, param, cbparam);
      
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
      IPWorksSSH_SFTP_Do(m_pObj, 19, 3, param, cbparam);
      return QByteArray((char*)param[3],cbparam[3]);
      
    }
    inline int SSHLogoff() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 21, 0, param, cbparam);
      
    }
    inline int SSHLogon(const QString &SSHHost, long SSHPort) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_SSHHost = SSHHost.toLatin1();
      #else
      QByteArray t_SSHHost = SSHHost.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_SSHHost.data(), (void*)SSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 22, 2, param, cbparam);
      
    }
    inline int UpdateFileAttributes() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 23, 0, param, cbparam);
      
    }
    inline int Upload() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 24, 0, param, cbparam);
      
    }

};


#endif //_IPWORKSSSH_SFTP_H_




