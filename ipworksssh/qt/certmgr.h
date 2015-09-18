/******************************************************************
   IP*Works! SSH V9 C++ Edition
   Copyright (c) 2014 /n software inc. - All rights reserved.
*******************************************************************/

#ifndef _IPWORKSSSH_CERTMGR_H_
#define _IPWORKSSSH_CERTMGR_H_

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



extern "C" void* IPWORKSSSH_CALL IPWorksSSH_CertMgr_Create(PIPWORKSSSH_CALLBACK lpSink, void *lpContext, char *lpOemKey);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_CertMgr_Destroy(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_CertMgr_CheckIndex(void *lpObj, int propid, int arridx);
extern "C" void* IPWORKSSSH_CALL IPWorksSSH_CertMgr_Get(void *lpObj, int propid, int arridx, int *lpcbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_CertMgr_Set(void *lpObj, int propid, int arridx, const void *val, int cbVal);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_CertMgr_Do(void *lpObj, int methid, int cparam, void *param[], int cbparam[]);
extern "C" char* IPWORKSSSH_CALL IPWorksSSH_CertMgr_GetLastError(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_CertMgr_GetLastErrorCode(void *lpObj);
extern "C" int   IPWORKSSSH_CALL IPWorksSSH_CertMgr_StaticInit(void *hInst);


struct CertMgrCertChainEventParams {
  int EventRetVal;
  char* CertEncoded;
  char* CertSubject;
  char* CertIssuer;
  char* CertSerialNumber;
  int TrustStatus;
  int TrustInfo;
  int lenCertEncoded;
  int reserved;
};

struct CertMgrCertListEventParams {
  int EventRetVal;
  char* CertEncoded;
  char* CertSubject;
  char* CertIssuer;
  char* CertSerialNumber;
  int HasPrivateKey;
  int lenCertEncoded;
  int reserved;
};

struct CertMgrErrorEventParams {
  int EventRetVal;
  int ErrorCode;
  char* Description;
  int reserved;
};

struct CertMgrKeyListEventParams {
  int EventRetVal;
  char* KeyContainer;
  int KeyType;
  char* AlgId;
  int KeyLen;
  int reserved;
};

struct CertMgrStoreListEventParams {
  int EventRetVal;
  char* CertStore;
  int reserved;
};



#ifdef WIN32
#pragma warning(disable:4311) 
#pragma warning(disable:4312) 
#endif

class CertMgr : public QObject {

  Q_OBJECT
signals: //events

    void CertChain(CertMgrCertChainEventParams *e);
    void CertList(CertMgrCertListEventParams *e);
    void Error(CertMgrErrorEventParams *e);
    void KeyList(CertMgrKeyListEventParams *e);
    void StoreList(CertMgrStoreListEventParams *e);

protected: // event firers
    virtual int FireCertChain(CertMgrCertChainEventParams *e) {
      emit CertChain(e);
      return e->EventRetVal;
    }
    virtual int FireCertList(CertMgrCertListEventParams *e) {
      emit CertList(e);
      return e->EventRetVal;
    }
    virtual int FireError(CertMgrErrorEventParams *e) {
      emit Error(e);
      return e->EventRetVal;
    }
    virtual int FireKeyList(CertMgrKeyListEventParams *e) {
      emit KeyList(e);
      return e->EventRetVal;
    }
    virtual int FireStoreList(CertMgrStoreListEventParams *e) {
      emit StoreList(e);
      return e->EventRetVal;
    }


  protected:

    void *m_pObj;
    
    static int IPWORKSSSH_CALL CertMgrEventSink(void *lpObj, int event_id, int cparam, void *param[], int cbparam[]) {
      int ret_code = 0;
      switch (event_id) {
         case 1: {
            CertMgrCertChainEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(param[5]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((CertMgr*)lpObj)->FireCertChain(&e);
            break;
         }
         case 2: {
            CertMgrCertListEventParams e = {0, (char*)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (char*)IPH64CAST(param[3]), (int)IPH64CAST(param[4]), (int)IPH64CAST(cbparam[0]),  0};
            ret_code = ((CertMgr*)lpObj)->FireCertList(&e);
            break;
         }
         case 3: {
            CertMgrErrorEventParams e = {0, (int)IPH64CAST(param[0]), (char*)IPH64CAST(param[1]),  0};
            ret_code = ((CertMgr*)lpObj)->FireError(&e);
            break;
         }
         case 4: {
            CertMgrKeyListEventParams e = {0, (char*)IPH64CAST(param[0]), (int)IPH64CAST(param[1]), (char*)IPH64CAST(param[2]), (int)IPH64CAST(param[3]),  0};
            ret_code = ((CertMgr*)lpObj)->FireKeyList(&e);
            break;
         }
         case 5: {
            CertMgrStoreListEventParams e = {0, (char*)IPH64CAST(param[0]),  0};
            ret_code = ((CertMgr*)lpObj)->FireStoreList(&e);
            break;
         }

      }
      return ret_code;
    }

  public:

    CertMgr(char *lpOemKey = (char*)IPWORKSSSH_OEMKEY_57) {
      m_pObj = IPWorksSSH_CertMgr_Create(CertMgrEventSink, (void*)this, (char*)lpOemKey);
    }

    virtual ~CertMgr() {
      IPWorksSSH_CertMgr_Destroy(m_pObj);
    }

  public:

    inline char *GetLastError() {
      return IPWorksSSH_CertMgr_GetLastError(m_pObj);
    }
    
    inline int GetLastErrorCode() {
      return IPWorksSSH_CertMgr_GetLastErrorCode(m_pObj);
    }

    inline char *VERSION() {
      return (char*)IPWorksSSH_CertMgr_Get(m_pObj, 0, 0, 0);
    }

  public: //properties

    inline QString GetCertEffectiveDate() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 1, 0, 0);
      return QString((char*)val);
    }


    inline QByteArray GetCertEncoded() {
      char *lpCertEncoded = NULL;
      int lenCertEncoded = 0;
      lpCertEncoded = (char*)IPWorksSSH_CertMgr_Get(m_pObj, 2, 0, &lenCertEncoded);
      return QByteArray(lpCertEncoded, lenCertEncoded);
    }

    inline int SetCertEncoded(const QByteArray &qba) {
      return IPWorksSSH_CertMgr_Set(m_pObj, 2, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetCertExpirationDate() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 3, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertExtendedKeyUsage() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 4, 0, 0);
      return QString((char*)val);
    }

    inline int SetCertExtendedKeyUsage(const QString &CertExtendedKeyUsage) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = CertExtendedKeyUsage.toLatin1();
      #else
      QByteArray qba = CertExtendedKeyUsage.toAscii();
      #endif
      return IPWorksSSH_CertMgr_Set(m_pObj, 4, 0, (void*)qba.data(), 0);
    }

    inline QString GetCertFingerprint() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 5, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertIssuer() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 6, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertKeyPassword() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 7, 0, 0);
      return QString((char*)val);
    }

    inline int SetCertKeyPassword(const QString &CertKeyPassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = CertKeyPassword.toLatin1();
      #else
      QByteArray qba = CertKeyPassword.toAscii();
      #endif
      return IPWorksSSH_CertMgr_Set(m_pObj, 7, 0, (void*)qba.data(), 0);
    }

    inline QString GetCertPrivateKey() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 8, 0, 0);
      return QString((char*)val);
    }


    inline int GetCertPrivateKeyAvailable() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 9, 0, 0);
      return (int)(long)val;
    }

    inline QString GetCertPrivateKeyContainer() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 10, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertPublicKey() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 11, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertPublicKeyAlgorithm() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 12, 0, 0);
      return QString((char*)val);
    }

    inline int SetCertPublicKeyAlgorithm(const QString &CertPublicKeyAlgorithm) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = CertPublicKeyAlgorithm.toLatin1();
      #else
      QByteArray qba = CertPublicKeyAlgorithm.toAscii();
      #endif
      return IPWorksSSH_CertMgr_Set(m_pObj, 12, 0, (void*)qba.data(), 0);
    }

    inline int GetCertPublicKeyLength() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 13, 0, 0);
      return (int)(long)val;
    }

    inline QString GetCertSerialNumber() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 14, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertSignatureAlgorithm() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 15, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertSubject() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 16, 0, 0);
      return QString((char*)val);
    }

    inline int SetCertSubject(const QString &CertSubject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = CertSubject.toLatin1();
      #else
      QByteArray qba = CertSubject.toAscii();
      #endif
      return IPWorksSSH_CertMgr_Set(m_pObj, 16, 0, (void*)qba.data(), 0);
    }

    inline QString GetCertSubjectAltNames() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 17, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertThumbprintMD5() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 18, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertThumbprintSHA1() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 19, 0, 0);
      return QString((char*)val);
    }


    inline QString GetCertUsage() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 20, 0, 0);
      return QString((char*)val);
    }

    inline int SetCertUsage(const QString &CertUsage) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = CertUsage.toLatin1();
      #else
      QByteArray qba = CertUsage.toAscii();
      #endif
      return IPWorksSSH_CertMgr_Set(m_pObj, 20, 0, (void*)qba.data(), 0);
    }

    inline int GetCertUsageFlags() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 21, 0, 0);
      return (int)(long)val;
    }
    inline int SetCertUsageFlags(int lCertUsageFlags) {
      void* val = (void*)lCertUsageFlags;
      return IPWorksSSH_CertMgr_Set(m_pObj, 21, 0, val, 0);
    }
    inline QString GetCertVersion() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 22, 0, 0);
      return QString((char*)val);
    }


    inline int GetCertExtensionCount() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 23, 0, 0);
      return (int)(long)val;
    }
    inline int SetCertExtensionCount(int iCertExtensionCount) {
      void* val = (void*)iCertExtensionCount;
      return IPWorksSSH_CertMgr_Set(m_pObj, 23, 0, val, 0);
    }
    inline int GetCertExtensionCritical(int iCertExtensionIndex) {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 24, iCertExtensionIndex, 0);
      return (int)(long)val;
    }

    inline QString GetCertExtensionOID(int iCertExtensionIndex) {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 25, iCertExtensionIndex, 0);
      return QString((char*)val);
    }


    inline QByteArray GetCertExtensionValue(int iCertExtensionIndex) {
      char *lpCertExtensionValue = NULL;
      int lenCertExtensionValue = 0;
      lpCertExtensionValue = (char*)IPWorksSSH_CertMgr_Get(m_pObj, 26, iCertExtensionIndex, &lenCertExtensionValue);
      return QByteArray(lpCertExtensionValue, lenCertExtensionValue);
    }


    inline QByteArray GetCertStore() {
      char *lpCertStore = NULL;
      int lenCertStore = 0;
      lpCertStore = (char*)IPWorksSSH_CertMgr_Get(m_pObj, 27, 0, &lenCertStore);
      return QByteArray(lpCertStore, lenCertStore);
    }

    inline int SetCertStore(const QByteArray &qba) {
      return IPWorksSSH_CertMgr_Set(m_pObj, 27, 0, (void*)qba.data(), qba.size());
    }

    inline QString GetCertStorePassword() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 28, 0, 0);
      return QString((char*)val);
    }

    inline int SetCertStorePassword(const QString &CertStorePassword) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray qba = CertStorePassword.toLatin1();
      #else
      QByteArray qba = CertStorePassword.toAscii();
      #endif
      return IPWorksSSH_CertMgr_Set(m_pObj, 28, 0, (void*)qba.data(), 0);
    }

    inline int GetCertStoreType() {
      void* val = IPWorksSSH_CertMgr_Get(m_pObj, 29, 0, 0);
      return (int)(long)val;
    }
    inline int SetCertStoreType(int iCertStoreType) {
      void* val = (void*)iCertStoreType;
      return IPWorksSSH_CertMgr_Set(m_pObj, 29, 0, val, 0);
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
      IPWorksSSH_CertMgr_Do(m_pObj, 2, 1, param, cbparam);
      return QString((char*)param[1]);
      
    }
    inline int CreateCertificate(const QString &CertSubject, long SerialNumber) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_CertSubject = CertSubject.toLatin1();
      #else
      QByteArray t_CertSubject = CertSubject.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_CertSubject.data(), (void*)SerialNumber, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 3, 2, param, cbparam);
      
    }
    inline int CreateKey(const QString &KeyName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_KeyName = KeyName.toLatin1();
      #else
      QByteArray t_KeyName = KeyName.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_KeyName.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 4, 1, param, cbparam);
      
    }
    inline int DeleteCertificate() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 5, 0, param, cbparam);
      
    }
    inline int DeleteKey(const QString &KeyName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_KeyName = KeyName.toLatin1();
      #else
      QByteArray t_KeyName = KeyName.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_KeyName.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 6, 1, param, cbparam);
      
    }
    inline int ExportCertificate(const QString &PFXFile, const QString &Password) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_PFXFile = PFXFile.toLatin1();
      #else
      QByteArray t_PFXFile = PFXFile.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Password = Password.toLatin1();
      #else
      QByteArray t_Password = Password.toAscii();
      #endif
      
      void *param[2+1] = {(void*)t_PFXFile.data(), (void*)t_Password.data(), 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 7, 2, param, cbparam);
      
    }
    inline QString GenerateCSR(const QString &CertSubject, const QString &KeyName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_CertSubject = CertSubject.toLatin1();
      #else
      QByteArray t_CertSubject = CertSubject.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_KeyName = KeyName.toLatin1();
      #else
      QByteArray t_KeyName = KeyName.toAscii();
      #endif
      
      void *param[2+1] = {(void*)t_CertSubject.data(), (void*)t_KeyName.data(), 0};
      int cbparam[2+1] = {0, 0, 0};
      IPWorksSSH_CertMgr_Do(m_pObj, 8, 2, param, cbparam);
      return QString((char*)param[2]);
      
    }
    inline int ImportCertificate(const QString &PFXFile, const QString &Password, const QString &Subject) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_PFXFile = PFXFile.toLatin1();
      #else
      QByteArray t_PFXFile = PFXFile.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Password = Password.toLatin1();
      #else
      QByteArray t_Password = Password.toAscii();
      #endif
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_Subject = Subject.toLatin1();
      #else
      QByteArray t_Subject = Subject.toAscii();
      #endif
      
      void *param[3+1] = {(void*)t_PFXFile.data(), (void*)t_Password.data(), (void*)t_Subject.data(), 0};
      int cbparam[3+1] = {0, 0, 0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 9, 3, param, cbparam);
      
    }
    inline int ImportSignedCSR(const QByteArray &SignedCSR, const QString &KeyName) {
       #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_KeyName = KeyName.toLatin1();
      #else
      QByteArray t_KeyName = KeyName.toAscii();
      #endif
      
      void *param[2+1] = {(void*)SignedCSR.data(), (void*)t_KeyName.data(), 0};
      int cbparam[2+1] = {SignedCSR.size(), 0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 10, 2, param, cbparam);
      
    }
    inline int IssueCertificate(const QString &CertSubject, long SerialNumber) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_CertSubject = CertSubject.toLatin1();
      #else
      QByteArray t_CertSubject = CertSubject.toAscii();
      #endif
       
      void *param[2+1] = {(void*)t_CertSubject.data(), (void*)SerialNumber, 0};
      int cbparam[2+1] = {0, 0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 11, 2, param, cbparam);
      
    }
    inline QString ListCertificateStores() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      IPWorksSSH_CertMgr_Do(m_pObj, 12, 0, param, cbparam);
      return QString((char*)param[0]);
      
    }
    inline QString ListKeys() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      IPWorksSSH_CertMgr_Do(m_pObj, 13, 0, param, cbparam);
      return QString((char*)param[0]);
      
    }
    inline QString ListMachineStores() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      IPWorksSSH_CertMgr_Do(m_pObj, 14, 0, param, cbparam);
      return QString((char*)param[0]);
      
    }
    inline QString ListStoreCertificates() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      IPWorksSSH_CertMgr_Do(m_pObj, 15, 0, param, cbparam);
      return QString((char*)param[0]);
      
    }
    inline int ReadCertificate(const QString &FileName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_FileName = FileName.toLatin1();
      #else
      QByteArray t_FileName = FileName.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_FileName.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 16, 1, param, cbparam);
      
    }
    inline int Reset() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 17, 0, param, cbparam);
      
    }
    inline int SaveCertificate(const QString &FileName) {
      #if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
      QByteArray t_FileName = FileName.toLatin1();
      #else
      QByteArray t_FileName = FileName.toAscii();
      #endif
      
      void *param[1+1] = {(void*)t_FileName.data(), 0};
      int cbparam[1+1] = {0, 0};
      return IPWorksSSH_CertMgr_Do(m_pObj, 18, 1, param, cbparam);
      
    }
    inline QString ShowCertificateChain() {
      
      void *param[0+1] = {0};
      int cbparam[0+1] = {0};
      IPWorksSSH_CertMgr_Do(m_pObj, 19, 0, param, cbparam);
      return QString((char*)param[0]);
      
    }
    inline QString SignCSR(const QByteArray &CSR, long SerialNumber) {
        
      void *param[2+1] = {(void*)CSR.data(), (void*)SerialNumber, 0};
      int cbparam[2+1] = {CSR.size(), 0, 0};
      IPWorksSSH_CertMgr_Do(m_pObj, 20, 2, param, cbparam);
      return QString((char*)param[2]);
      
    }

};


#endif //_IPWORKSSSH_CERTMGR_H_




