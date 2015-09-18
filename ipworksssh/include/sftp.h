/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_SFTP_H_
#define _IPWORKSSSH_SFTP_H_

#define IPWORKSSSH_ONLY_TYPES
#include "ipworksssh.h"
#include "ipworksssh.key"

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
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_SFTP_StaticDestroy();

#ifdef WIN32
#include <windows.h>
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SFTPConnectedEventParams;

typedef struct {
  const char* ConnectionEvent;
  int StatusCode;
  const char* Description;
  int reserved;
} SFTPConnectionStatusEventParams;

typedef struct {
  const char* DirEntry;
  const char* FileName;
  int IsDir;
  ns_int64 *pFileSize;
  const char* FileTime;
  int reserved;
} SFTPDirListEventParams;

typedef struct {
  int StatusCode;
  const char* Description;
  int reserved;
} SFTPDisconnectedEventParams;

typedef struct {
  int Direction;
  const char* LocalFile;
  const char* RemoteFile;
  int reserved;
} SFTPEndTransferEventParams;

typedef struct {
  int ErrorCode;
  const char* Description;
  const char* LocalFile;
  const char* RemoteFile;
  int reserved;
} SFTPErrorEventParams;

typedef struct {
  const char* Packet;
  int reserved;
} SFTPSSHCustomAuthEventParams;

typedef struct {
  const char* Name;
  const char* Instructions;
  const char* Prompt;
  const char* Response;
  int EchoResponse;
  int reserved;
} SFTPSSHKeyboardInteractiveEventParams;

typedef struct {
  const char* HostKey;
  const char* Fingerprint;
  const char* KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SFTPSSHServerAuthenticationEventParams;

typedef struct {
  const char* Message;
  int reserved;
} SFTPSSHStatusEventParams;

typedef struct {
  int Direction;
  const char* LocalFile;
  const char* RemoteFile;
  int reserved;
} SFTPStartTransferEventParams;

typedef struct {
  int Direction;
  const char* LocalFile;
  const char* RemoteFile;
  ns_int64 *pBytesTransferred;
  int PercentDone;
  const char* Text;
  int Cancel;
  int lenText;
  int reserved;
} SFTPTransferEventParams;



class SFTP {
  
  public: //events
  
    virtual int FireConnected(SFTPConnectedEventParams *e) {return 0;}
    virtual int FireConnectionStatus(SFTPConnectionStatusEventParams *e) {return 0;}
    virtual int FireDirList(SFTPDirListEventParams *e) {return 0;}
    virtual int FireDisconnected(SFTPDisconnectedEventParams *e) {return 0;}
    virtual int FireEndTransfer(SFTPEndTransferEventParams *e) {return 0;}
    virtual int FireError(SFTPErrorEventParams *e) {return 0;}
    virtual int FireSSHCustomAuth(SFTPSSHCustomAuthEventParams *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SFTPSSHKeyboardInteractiveEventParams *e) {return 0;}
    virtual int FireSSHServerAuthentication(SFTPSSHServerAuthenticationEventParams *e) {return 0;}
    virtual int FireSSHStatus(SFTPSSHStatusEventParams *e) {return 0;}
    virtual int FireStartTransfer(SFTPStartTransferEventParams *e) {return 0;}
    virtual int FireTransfer(SFTPTransferEventParams *e) {return 0;}


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL SFTPEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      if (event_id > 10000) return ((SFTP*)lpObj)->SFTPEventSinkW(event_id - 10000, cparam, param, cbparam);
      switch (event_id) {
         case 1: {
            SFTPConnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SFTP*)lpObj)->FireConnected(&e);
            break;
         }
         case 2: {
            SFTPConnectionStatusEventParams e = {(char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SFTP*)lpObj)->FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SFTPDirListEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (int)IPH64CAST(param[2]), (ns_int64*)IPH64CAST(param[3]), (char*)IPH64CAST(param[4]),  0};
            ret_code = ((SFTP*)lpObj)->FireDirList(&e);
            break;
         }
         case 4: {
            SFTPDisconnectedEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((SFTP*)lpObj)->FireDisconnected(&e);
            break;
         }
         case 5: {
            SFTPEndTransferEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SFTP*)lpObj)->FireEndTransfer(&e);
            break;
         }
         case 6: {
            SFTPErrorEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]),  0};
            ret_code = ((SFTP*)lpObj)->FireError(&e);
            break;
         }
         case 7: {
            SFTPSSHCustomAuthEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHCustomAuth(&e);
            param[0] = (void*)IPH64CAST(e.Packet);
            break;
         }
         case 8: {
            SFTPSSHKeyboardInteractiveEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHKeyboardInteractive(&e);
            param[3] = (void*)IPH64CAST(e.Response);
            break;
         }
         case 9: {
            SFTPSSHServerAuthenticationEventParams e = {(char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHServerAuthentication(&e);
            param[3] = (void*)IPH64CAST(e.Accept);
            break;
         }
         case 10: {
            SFTPSSHStatusEventParams e = {(char*)IPH64CAST(param[0]),  0};
            ret_code = ((SFTP*)lpObj)->FireSSHStatus(&e);
            break;
         }
         case 11: {
            SFTPStartTransferEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]),  0};
            ret_code = ((SFTP*)lpObj)->FireStartTransfer(&e);
            break;
         }
         case 12: {
            SFTPTransferEventParams e = {(int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (ns_int64*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (char*)IPH64CAST(param[5]), (int)IPH64CAST(param[6]), (int)IPH64CAST(cbparam[5]),  0};
            ret_code = ((SFTP*)lpObj)->FireTransfer(&e);
            param[6] = (void*)IPH64CAST(e.Cancel);
            break;
         }

      }
      return ret_code;
    }

    virtual int SFTPEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {return 0;}

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
      void* val = (void*)IPH64CAST(bConnected);
      return IPWorksSSH_SFTP_Set(m_pObj, 1, 0, val, 0);
    }
    inline int GetDirListCount() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 2, 0, 0);
      return (int)(long)val;
    }

    inline char* GetDirListEntry(int iEntryIndex) {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 3, iEntryIndex, 0);
      return (char*)val;
    }


    inline char* GetDirListFileName(int iEntryIndex) {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 4, iEntryIndex, 0);
      return (char*)val;
    }


    inline ns_int64 GetDirListFileSize(int iEntryIndex) {
      ns_int64 *pval = (ns_int64*)IPWorksSSH_SFTP_Get(m_pObj, 5, iEntryIndex, 0);
      return *pval;
    }


    inline char* GetDirListFileTime(int iEntryIndex) {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 6, iEntryIndex, 0);
      return (char*)val;
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

    inline char* GetFileACL() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 9, 0, 0);
      return (char*)val;
    }

    inline int SetFileACL(const char *lpFileACL) {
      return IPWorksSSH_SFTP_Set(m_pObj, 9, 0, (void*)lpFileACL, 0);
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

    inline char* GetFileGroupId() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 15, 0, 0);
      return (char*)val;
    }

    inline int SetFileGroupId(const char *lpFileGroupId) {
      return IPWorksSSH_SFTP_Set(m_pObj, 15, 0, (void*)lpFileGroupId, 0);
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

    inline char* GetFileOwnerId() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 18, 0, 0);
      return (char*)val;
    }

    inline int SetFileOwnerId(const char *lpFileOwnerId) {
      return IPWorksSSH_SFTP_Set(m_pObj, 18, 0, (void*)lpFileOwnerId, 0);
    }

    inline int GetFilePermissions() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 19, 0, 0);
      return (int)(long)val;
    }
    inline int SetFilePermissions(int iFilePermissions) {
      void* val = (void*)IPH64CAST(iFilePermissions);
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
      void* val = (void*)IPH64CAST(bFirewallAutoDetect);
      return IPWorksSSH_SFTP_Set(m_pObj, 22, 0, val, 0);
    }
    inline int GetFirewallType() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 23, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallType(int iFirewallType) {
      void* val = (void*)IPH64CAST(iFirewallType);
      return IPWorksSSH_SFTP_Set(m_pObj, 23, 0, val, 0);
    }
    inline char* GetFirewallHost() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 24, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallHost(const char *lpFirewallHost) {
      return IPWorksSSH_SFTP_Set(m_pObj, 24, 0, (void*)lpFirewallHost, 0);
    }

    inline char* GetFirewallPassword() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 25, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallPassword(const char *lpFirewallPassword) {
      return IPWorksSSH_SFTP_Set(m_pObj, 25, 0, (void*)lpFirewallPassword, 0);
    }

    inline int GetFirewallPort() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 26, 0, 0);
      return (int)(long)val;
    }
    inline int SetFirewallPort(int lFirewallPort) {
      void* val = (void*)IPH64CAST(lFirewallPort);
      return IPWorksSSH_SFTP_Set(m_pObj, 26, 0, val, 0);
    }
    inline char* GetFirewallUser() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 27, 0, 0);
      return (char*)val;
    }

    inline int SetFirewallUser(const char *lpFirewallUser) {
      return IPWorksSSH_SFTP_Set(m_pObj, 27, 0, (void*)lpFirewallUser, 0);
    }

    inline int GetIdle() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 28, 0, 0);
      return (int)(long)val;
    }

    inline char* GetLocalFile() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 29, 0, 0);
      return (char*)val;
    }

    inline int SetLocalFile(const char *lpLocalFile) {
      return IPWorksSSH_SFTP_Set(m_pObj, 29, 0, (void*)lpLocalFile, 0);
    }

    inline char* GetLocalHost() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 30, 0, 0);
      return (char*)val;
    }

    inline int SetLocalHost(const char *lpLocalHost) {
      return IPWorksSSH_SFTP_Set(m_pObj, 30, 0, (void*)lpLocalHost, 0);
    }

    inline int GetLocalPort() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 31, 0, 0);
      return (int)(long)val;
    }
    inline int SetLocalPort(int lLocalPort) {
      void* val = (void*)IPH64CAST(lLocalPort);
      return IPWorksSSH_SFTP_Set(m_pObj, 31, 0, val, 0);
    }
    inline int GetOverwrite() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 32, 0, 0);
      return (int)(long)val;
    }
    inline int SetOverwrite(int bOverwrite) {
      void* val = (void*)IPH64CAST(bOverwrite);
      return IPWorksSSH_SFTP_Set(m_pObj, 32, 0, val, 0);
    }
    inline char* GetRemoteFile() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 33, 0, 0);
      return (char*)val;
    }

    inline int SetRemoteFile(const char *lpRemoteFile) {
      return IPWorksSSH_SFTP_Set(m_pObj, 33, 0, (void*)lpRemoteFile, 0);
    }

    inline char* GetRemotePath() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 34, 0, 0);
      return (char*)val;
    }

    inline int SetRemotePath(const char *lpRemotePath) {
      return IPWorksSSH_SFTP_Set(m_pObj, 34, 0, (void*)lpRemotePath, 0);
    }

    inline int GetSSHAcceptServerHostKeyEncoded(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SFTP_Get(m_pObj, 35, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }

    inline int SetSSHAcceptServerHostKeyEncoded(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SFTP_Set(m_pObj, 35, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }

    inline int GetSSHAuthMode() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 36, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHAuthMode(int iSSHAuthMode) {
      void* val = (void*)IPH64CAST(iSSHAuthMode);
      return IPWorksSSH_SFTP_Set(m_pObj, 36, 0, val, 0);
    }
    inline int GetSSHCertEncoded(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SFTP_Get(m_pObj, 37, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }

    inline int SetSSHCertEncoded(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SFTP_Set(m_pObj, 37, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }

    inline int GetSSHCertStore(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SFTP_Get(m_pObj, 38, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }

    inline int SetSSHCertStore(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SFTP_Set(m_pObj, 38, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }

    inline char* GetSSHCertStorePassword() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 39, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertStorePassword(const char *lpSSHCertStorePassword) {
      return IPWorksSSH_SFTP_Set(m_pObj, 39, 0, (void*)lpSSHCertStorePassword, 0);
    }

    inline int GetSSHCertStoreType() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 40, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHCertStoreType(int iSSHCertStoreType) {
      void* val = (void*)IPH64CAST(iSSHCertStoreType);
      return IPWorksSSH_SFTP_Set(m_pObj, 40, 0, val, 0);
    }
    inline char* GetSSHCertSubject() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 41, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCertSubject(const char *lpSSHCertSubject) {
      return IPWorksSSH_SFTP_Set(m_pObj, 41, 0, (void*)lpSSHCertSubject, 0);
    }

    inline char* GetSSHCompressionAlgorithms() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 42, 0, 0);
      return (char*)val;
    }

    inline int SetSSHCompressionAlgorithms(const char *lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SFTP_Set(m_pObj, 42, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline char* GetSSHEncryptionAlgorithms() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 43, 0, 0);
      return (char*)val;
    }

    inline int SetSSHEncryptionAlgorithms(const char *lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SFTP_Set(m_pObj, 43, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline char* GetSSHHost() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 44, 0, 0);
      return (char*)val;
    }

    inline int SetSSHHost(const char *lpSSHHost) {
      return IPWorksSSH_SFTP_Set(m_pObj, 44, 0, (void*)lpSSHHost, 0);
    }

    inline char* GetSSHPassword() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 45, 0, 0);
      return (char*)val;
    }

    inline int SetSSHPassword(const char *lpSSHPassword) {
      return IPWorksSSH_SFTP_Set(m_pObj, 45, 0, (void*)lpSSHPassword, 0);
    }

    inline int GetSSHPort() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 46, 0, 0);
      return (int)(long)val;
    }
    inline int SetSSHPort(int lSSHPort) {
      void* val = (void*)IPH64CAST(lSSHPort);
      return IPWorksSSH_SFTP_Set(m_pObj, 46, 0, val, 0);
    }
    inline char* GetSSHUser() {
      void* val = IPWorksSSH_SFTP_Get(m_pObj, 47, 0, 0);
      return (char*)val;
    }

    inline int SetSSHUser(const char *lpSSHUser) {
      return IPWorksSSH_SFTP_Set(m_pObj, 47, 0, (void*)lpSSHUser, 0);
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
      void* val = (void*)IPH64CAST(iTimeout);
      return IPWorksSSH_SFTP_Set(m_pObj, 49, 0, val, 0);
    }

  public: //methods

    inline int Append() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 2, 0, param, cbparam);
      
      
    }
    inline char* Config(const char* lpszConfigurationString) {
      void *param[1+1] = {(void*)IPH64CAST(lpszConfigurationString), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 3, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* DecodePacket(const char* lpszEncodedPacket, int *lpSize = 0) {
      void *param[1+1] = {(void*)IPH64CAST(lpszEncodedPacket), 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 4, 1, param, cbparam);
      if (lpSize) *lpSize = cbparam[1];
      return (char*)IPH64CAST(param[1]);
    }
    inline int DeleteFile(const char* lpszFileName) {
      void *param[1+1] = {(void*)IPH64CAST(lpszFileName), 0};
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
    inline char* EncodePacket(const char* lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)IPH64CAST(lpPacket), 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 8, 1, param, cbparam);
      
      return (char*)IPH64CAST(param[1]);
    }
    inline char* GetSSHParam(const char* lpPayload, int lenPayload, const char* lpszField) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 9, 2, param, cbparam);
      
      return (char*)IPH64CAST(param[2]);
    }
    inline char* GetSSHParamBytes(const char* lpPayload, int lenPayload, const char* lpszField, int *lpSize = 0) {
      void *param[2+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszField), 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 10, 2, param, cbparam);
      if (lpSize) *lpSize = cbparam[2];
      return (char*)IPH64CAST(param[2]);
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
    inline int MakeDirectory(const char* lpszNewDir) {
      void *param[1+1] = {(void*)IPH64CAST(lpszNewDir), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 13, 1, param, cbparam);
      
      
    }
    inline int QueueFile(const char* lpszLocalFile, const char* lpszRemoteFile) {
      void *param[2+1] = {(void*)IPH64CAST(lpszLocalFile), (void*)IPH64CAST(lpszRemoteFile), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 14, 2, param, cbparam);
      
      
    }
    inline int RemoveDirectory(const char* lpszDirName) {
      void *param[1+1] = {(void*)IPH64CAST(lpszDirName), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 15, 1, param, cbparam);
      
      
    }
    inline int RenameFile(const char* lpszNewName) {
      void *param[1+1] = {(void*)IPH64CAST(lpszNewName), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 16, 1, param, cbparam);
      
      
    }
    inline int ResetQueue() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 17, 0, param, cbparam);
      
      
    }
    inline char* SetSSHParam(const char* lpPayload, int lenPayload, const char* lpszFieldType, const char* lpszFieldValue, int *lpSize = 0) {
      void *param[3+1] = {(void*)IPH64CAST(lpPayload), (void*)IPH64CAST(lpszFieldType), (void*)IPH64CAST(lpszFieldValue), 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 19, 3, param, cbparam);
      if (lpSize) *lpSize = cbparam[3];
      return (char*)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 21, 0, param, cbparam);
      
      
    }
    inline int SSHLogon(const char* lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)IPH64CAST(lpszSSHHost), (void*)IPH64CAST(lSSHPort), 0};
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


#ifdef WIN32 //UNICODE

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SFTPConnectedEventParamsW;

typedef struct {
  LPWSTR ConnectionEvent;
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SFTPConnectionStatusEventParamsW;

typedef struct {
  LPWSTR DirEntry;
  LPWSTR FileName;
  int IsDir;
  ns_int64 *pFileSize;
  LPWSTR FileTime;
  int reserved;
} SFTPDirListEventParamsW;

typedef struct {
  int StatusCode;
  LPWSTR Description;
  int reserved;
} SFTPDisconnectedEventParamsW;

typedef struct {
  int Direction;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  int reserved;
} SFTPEndTransferEventParamsW;

typedef struct {
  int ErrorCode;
  LPWSTR Description;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  int reserved;
} SFTPErrorEventParamsW;

typedef struct {
  LPWSTR Packet;
  int reserved;
} SFTPSSHCustomAuthEventParamsW;

typedef struct {
  LPWSTR Name;
  LPWSTR Instructions;
  LPWSTR Prompt;
  LPWSTR Response;
  int EchoResponse;
  int reserved;
} SFTPSSHKeyboardInteractiveEventParamsW;

typedef struct {
  LPWSTR HostKey;
  LPWSTR Fingerprint;
  LPWSTR KeyAlgorithm;
  int Accept;
  int lenHostKey;
  int reserved;
} SFTPSSHServerAuthenticationEventParamsW;

typedef struct {
  LPWSTR Message;
  int reserved;
} SFTPSSHStatusEventParamsW;

typedef struct {
  int Direction;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  int reserved;
} SFTPStartTransferEventParamsW;

typedef struct {
  int Direction;
  LPWSTR LocalFile;
  LPWSTR RemoteFile;
  ns_int64 *pBytesTransferred;
  int PercentDone;
  LPWSTR Text;
  int Cancel;
  int lenText;
  int reserved;
} SFTPTransferEventParamsW;



class SFTPW : public SFTP {

  public: //properties
  




    inline LPWSTR GetDirListEntry(int iEntryIndex) {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+3, iEntryIndex, 0);
    }



    inline LPWSTR GetDirListFileName(int iEntryIndex) {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+4, iEntryIndex, 0);
    }





    inline LPWSTR GetDirListFileTime(int iEntryIndex) {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+6, iEntryIndex, 0);
    }







    inline LPWSTR GetFileACL() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+9, 0, 0);
    }

    inline int SetFileACL(LPWSTR lpFileACL) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+9, 0, (void*)lpFileACL, 0);
    }











    inline LPWSTR GetFileGroupId() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+15, 0, 0);
    }

    inline int SetFileGroupId(LPWSTR lpFileGroupId) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+15, 0, (void*)lpFileGroupId, 0);
    }





    inline LPWSTR GetFileOwnerId() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+18, 0, 0);
    }

    inline int SetFileOwnerId(LPWSTR lpFileOwnerId) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+18, 0, (void*)lpFileOwnerId, 0);
    }











    inline LPWSTR GetFirewallHost() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+24, 0, 0);
    }

    inline int SetFirewallHost(LPWSTR lpFirewallHost) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+24, 0, (void*)lpFirewallHost, 0);
    }

    inline LPWSTR GetFirewallPassword() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+25, 0, 0);
    }

    inline int SetFirewallPassword(LPWSTR lpFirewallPassword) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+25, 0, (void*)lpFirewallPassword, 0);
    }



    inline LPWSTR GetFirewallUser() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+27, 0, 0);
    }

    inline int SetFirewallUser(LPWSTR lpFirewallUser) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+27, 0, (void*)lpFirewallUser, 0);
    }



    inline LPWSTR GetLocalFile() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+29, 0, 0);
    }

    inline int SetLocalFile(LPWSTR lpLocalFile) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+29, 0, (void*)lpLocalFile, 0);
    }

    inline LPWSTR GetLocalHost() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+30, 0, 0);
    }

    inline int SetLocalHost(LPWSTR lpLocalHost) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+30, 0, (void*)lpLocalHost, 0);
    }





    inline LPWSTR GetRemoteFile() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+33, 0, 0);
    }

    inline int SetRemoteFile(LPWSTR lpRemoteFile) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+33, 0, (void*)lpRemoteFile, 0);
    }

    inline LPWSTR GetRemotePath() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+34, 0, 0);
    }

    inline int SetRemotePath(LPWSTR lpRemotePath) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+34, 0, (void*)lpRemotePath, 0);
    }

    inline LPWSTR GetSSHAcceptServerHostKeyEncoded() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+35, 0, 0);
    }

    inline int SetSSHAcceptServerHostKeyEncoded(LPWSTR lpSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+35, 0, (void*)lpSSHAcceptServerHostKeyEncoded, 0);
    }
    inline int GetSSHAcceptServerHostKeyEncodedB(char *&lpSSHAcceptServerHostKeyEncoded, int &lenSSHAcceptServerHostKeyEncoded) {
      lpSSHAcceptServerHostKeyEncoded = (char*)IPWorksSSH_SFTP_Get(m_pObj, 35, 0, &lenSSHAcceptServerHostKeyEncoded);
      return lpSSHAcceptServerHostKeyEncoded ? 0 : lenSSHAcceptServerHostKeyEncoded;
    }
    inline int SetSSHAcceptServerHostKeyEncodedB(const char *lpSSHAcceptServerHostKeyEncoded, int lenSSHAcceptServerHostKeyEncoded) {
      return IPWorksSSH_SFTP_Set(m_pObj, 35, 0, (void*)lpSSHAcceptServerHostKeyEncoded, lenSSHAcceptServerHostKeyEncoded);
    }


    inline LPWSTR GetSSHCertEncoded() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+37, 0, 0);
    }

    inline int SetSSHCertEncoded(LPWSTR lpSSHCertEncoded) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+37, 0, (void*)lpSSHCertEncoded, 0);
    }
    inline int GetSSHCertEncodedB(char *&lpSSHCertEncoded, int &lenSSHCertEncoded) {
      lpSSHCertEncoded = (char*)IPWorksSSH_SFTP_Get(m_pObj, 37, 0, &lenSSHCertEncoded);
      return lpSSHCertEncoded ? 0 : lenSSHCertEncoded;
    }
    inline int SetSSHCertEncodedB(const char *lpSSHCertEncoded, int lenSSHCertEncoded) {
      return IPWorksSSH_SFTP_Set(m_pObj, 37, 0, (void*)lpSSHCertEncoded, lenSSHCertEncoded);
    }
    inline LPWSTR GetSSHCertStore() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+38, 0, 0);
    }

    inline int SetSSHCertStore(LPWSTR lpSSHCertStore) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+38, 0, (void*)lpSSHCertStore, 0);
    }
    inline int GetSSHCertStoreB(char *&lpSSHCertStore, int &lenSSHCertStore) {
      lpSSHCertStore = (char*)IPWorksSSH_SFTP_Get(m_pObj, 38, 0, &lenSSHCertStore);
      return lpSSHCertStore ? 0 : lenSSHCertStore;
    }
    inline int SetSSHCertStoreB(const char *lpSSHCertStore, int lenSSHCertStore) {
      return IPWorksSSH_SFTP_Set(m_pObj, 38, 0, (void*)lpSSHCertStore, lenSSHCertStore);
    }
    inline LPWSTR GetSSHCertStorePassword() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+39, 0, 0);
    }

    inline int SetSSHCertStorePassword(LPWSTR lpSSHCertStorePassword) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+39, 0, (void*)lpSSHCertStorePassword, 0);
    }



    inline LPWSTR GetSSHCertSubject() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+41, 0, 0);
    }

    inline int SetSSHCertSubject(LPWSTR lpSSHCertSubject) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+41, 0, (void*)lpSSHCertSubject, 0);
    }

    inline LPWSTR GetSSHCompressionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+42, 0, 0);
    }

    inline int SetSSHCompressionAlgorithms(LPWSTR lpSSHCompressionAlgorithms) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+42, 0, (void*)lpSSHCompressionAlgorithms, 0);
    }

    inline LPWSTR GetSSHEncryptionAlgorithms() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+43, 0, 0);
    }

    inline int SetSSHEncryptionAlgorithms(LPWSTR lpSSHEncryptionAlgorithms) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+43, 0, (void*)lpSSHEncryptionAlgorithms, 0);
    }

    inline LPWSTR GetSSHHost() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+44, 0, 0);
    }

    inline int SetSSHHost(LPWSTR lpSSHHost) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+44, 0, (void*)lpSSHHost, 0);
    }

    inline LPWSTR GetSSHPassword() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+45, 0, 0);
    }

    inline int SetSSHPassword(LPWSTR lpSSHPassword) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+45, 0, (void*)lpSSHPassword, 0);
    }



    inline LPWSTR GetSSHUser() {
      return (LPWSTR)IPWorksSSH_SFTP_Get(m_pObj, 10000+47, 0, 0);
    }

    inline int SetSSHUser(LPWSTR lpSSHUser) {
      return IPWorksSSH_SFTP_Set(m_pObj, 10000+47, 0, (void*)lpSSHUser, 0);
    }







  public: //events
  
    virtual int FireConnected(SFTPConnectedEventParamsW *e) {return 0;}
    virtual int FireConnectionStatus(SFTPConnectionStatusEventParamsW *e) {return 0;}
    virtual int FireDirList(SFTPDirListEventParamsW *e) {return 0;}
    virtual int FireDisconnected(SFTPDisconnectedEventParamsW *e) {return 0;}
    virtual int FireEndTransfer(SFTPEndTransferEventParamsW *e) {return 0;}
    virtual int FireError(SFTPErrorEventParamsW *e) {return 0;}
    virtual int FireSSHCustomAuth(SFTPSSHCustomAuthEventParamsW *e) {return 0;}
    virtual int FireSSHKeyboardInteractive(SFTPSSHKeyboardInteractiveEventParamsW *e) {return 0;}
    virtual int FireSSHServerAuthentication(SFTPSSHServerAuthenticationEventParamsW *e) {return 0;}
    virtual int FireSSHStatus(SFTPSSHStatusEventParamsW *e) {return 0;}
    virtual int FireStartTransfer(SFTPStartTransferEventParamsW *e) {return 0;}
    virtual int FireTransfer(SFTPTransferEventParamsW *e) {return 0;}


  protected:
  
    virtual int SFTPEventSinkW(int event_id, int cparam, void *param[], int cbparam[]) {
    	int ret_code = 0;
      switch (event_id) {
         case 1: {
            SFTPConnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireConnected(&e);
            break;
         }
         case 2: {
            SFTPConnectionStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireConnectionStatus(&e);
            break;
         }
         case 3: {
            SFTPDirListEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (int)IPH64CAST(param[2]), (ns_int64*)IPH64CAST(param[3]), (LPWSTR)IPH64CAST(param[4]),  0};
            ret_code = FireDirList(&e);
            break;
         }
         case 4: {
            SFTPDisconnectedEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]),  0};
            ret_code = FireDisconnected(&e);
            break;
         }
         case 5: {
            SFTPEndTransferEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireEndTransfer(&e);
            break;
         }
         case 6: {
            SFTPErrorEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]),  0};
            ret_code = FireError(&e);
            break;
         }
         case 7: {
            SFTPSSHCustomAuthEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHCustomAuth(&e);
            param[0] = (void*)(e.Packet);
            break;
         }
         case 8: {
            SFTPSSHKeyboardInteractiveEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (LPWSTR)IPH64CAST(param[3]), (int)IPH64CAST(param[4]),  0};
            ret_code = FireSSHKeyboardInteractive(&e);
            param[3] = (void*)(e.Response);
            break;
         }
         case 9: {
            SFTPSSHServerAuthenticationEventParamsW e = {(LPWSTR)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (int)IPH64CAST(param[3]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = FireSSHServerAuthentication(&e);
            param[3] = (void*)(e.Accept);
            break;
         }
         case 10: {
            SFTPSSHStatusEventParamsW e = {(LPWSTR)IPH64CAST(param[0]),  0};
            ret_code = FireSSHStatus(&e);
            break;
         }
         case 11: {
            SFTPStartTransferEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]),  0};
            ret_code = FireStartTransfer(&e);
            break;
         }
         case 12: {
            SFTPTransferEventParamsW e = {(int)IPH64CAST(param[0]), (LPWSTR)IPH64CAST(param[1]), (LPWSTR)IPH64CAST(param[2]), (ns_int64*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (LPWSTR)IPH64CAST(param[5]), (int)IPH64CAST(param[6]), (int)IPH64CAST(cbparam[5]),  0};
            ret_code = FireTransfer(&e);
            param[6] = (void*)(e.Cancel);
            break;
         }

      }
      return ret_code;
    }
  
  public: //event overrides

    virtual int FireConnected(SFTPConnectedEventParams *e) {return -10000;}
    virtual int FireConnectionStatus(SFTPConnectionStatusEventParams *e) {return -10000;}
    virtual int FireDirList(SFTPDirListEventParams *e) {return -10000;}
    virtual int FireDisconnected(SFTPDisconnectedEventParams *e) {return -10000;}
    virtual int FireEndTransfer(SFTPEndTransferEventParams *e) {return -10000;}
    virtual int FireError(SFTPErrorEventParams *e) {return -10000;}
    virtual int FireSSHCustomAuth(SFTPSSHCustomAuthEventParams *e) {return -10000;}
    virtual int FireSSHKeyboardInteractive(SFTPSSHKeyboardInteractiveEventParams *e) {return -10000;}
    virtual int FireSSHServerAuthentication(SFTPSSHServerAuthenticationEventParams *e) {return -10000;}
    virtual int FireSSHStatus(SFTPSSHStatusEventParams *e) {return -10000;}
    virtual int FireStartTransfer(SFTPStartTransferEventParams *e) {return -10000;}
    virtual int FireTransfer(SFTPTransferEventParams *e) {return -10000;}

  public: //methods

    inline int Append() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+2, 0, param, cbparam);
      
    }
    inline LPWSTR Config(LPWSTR lpszConfigurationString) {
      void *param[1+1] = {(void*)lpszConfigurationString, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 10000+3, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR DecodePacket(LPWSTR lpszEncodedPacket) {
      void *param[1+1] = {(void*)lpszEncodedPacket, 0};
      int cbparam[1+1] = {0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 10000+4, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline int DeleteFile(LPWSTR lpszFileName) {
      void *param[1+1] = {(void*)lpszFileName, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+5, 1, param, cbparam);
      
    }
    inline int DoEvents() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+6, 0, param, cbparam);
      
    }
    inline int Download() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+7, 0, param, cbparam);
      
    }
    inline LPWSTR EncodePacket(LPWSTR lpPacket, int lenPacket) {
      void *param[1+1] = {(void*)lpPacket, 0};
      int cbparam[1+1] = {lenPacket, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 10000+8, 1, param, cbparam);
      return (LPWSTR)IPH64CAST(param[1]);
    }
    inline LPWSTR GetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 10000+9, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline LPWSTR GetSSHParamBytes(LPWSTR lpPayload, int lenPayload, LPWSTR lpszField) {
      void *param[2+1] = {(void*)lpPayload, (void*)lpszField, 0};
      int cbparam[2+1] = {lenPayload, 0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 10000+10, 2, param, cbparam);
      return (LPWSTR)IPH64CAST(param[2]);
    }
    inline int Interrupt() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+11, 0, param, cbparam);
      
    }
    inline int ListDirectory() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+12, 0, param, cbparam);
      
    }
    inline int MakeDirectory(LPWSTR lpszNewDir) {
      void *param[1+1] = {(void*)lpszNewDir, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+13, 1, param, cbparam);
      
    }
    inline int QueueFile(LPWSTR lpszLocalFile, LPWSTR lpszRemoteFile) {
      void *param[2+1] = {(void*)lpszLocalFile, (void*)lpszRemoteFile, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+14, 2, param, cbparam);
      
    }
    inline int RemoveDirectory(LPWSTR lpszDirName) {
      void *param[1+1] = {(void*)lpszDirName, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+15, 1, param, cbparam);
      
    }
    inline int RenameFile(LPWSTR lpszNewName) {
      void *param[1+1] = {(void*)lpszNewName, 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+16, 1, param, cbparam);
      
    }
    inline int ResetQueue() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+17, 0, param, cbparam);
      
    }
    inline LPWSTR SetSSHParam(LPWSTR lpPayload, int lenPayload, LPWSTR lpszFieldType, LPWSTR lpszFieldValue) {
      void *param[3+1] = {(void*)lpPayload, (void*)lpszFieldType, (void*)lpszFieldValue, 0};
      int cbparam[3+1] = {lenPayload, 0, 0, 0};
      IPWorksSSH_SFTP_Do(m_pObj, 10000+19, 3, param, cbparam);
      return (LPWSTR)IPH64CAST(param[3]);
    }
    inline int SSHLogoff() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+21, 0, param, cbparam);
      
    }
    inline int SSHLogon(LPWSTR lpszSSHHost, int lSSHPort) {
      void *param[2+1] = {(void*)lpszSSHHost, (void*)lSSHPort, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+22, 2, param, cbparam);
      
    }
    inline int UpdateFileAttributes() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+23, 0, param, cbparam);
      
    }
    inline int Upload() {
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_SFTP_Do(m_pObj, 10000+24, 0, param, cbparam);
      
    }

};

#endif //WIN32

#endif //_IPWORKSSSH_SFTP_H_




