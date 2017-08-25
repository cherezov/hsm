#include <cassert>
#include <stdio.h>
#include <mutex>

#include <string>
#include <vector>

#include "pkcs11.h"

static CK_FUNCTION_LIST_PTR p11 = NULL_PTR;

extern "C" void *C_LoadModule(const char *name, CK_FUNCTION_LIST_PTR_PTR);
extern "C" CK_RV C_UnloadModule(void *module);

typedef std::vector<CK_BYTE> BYTE_VEC;
typedef std::vector<CK_ATTRIBUTE> ATTR_VEC;

static CK_BBOOL bTrue = true;
static CK_BBOOL bFalse = true;
static CK_BYTE ApplicationID = 1;

static CK_OBJECT_CLASS KeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE KeyType = CKK_AES;
static CK_ULONG KeyLen = 32;

std::string errorName(CK_RV rv)
{
    switch(rv)
    {
        case 3:
            return "CKR_SLOT_ID_INVALID";
        case 6:
            return "CKR_FUNCTION_FAILED";
        case 7:
            return "CKR_ARGUMENTS_BAD";
        case 400:
            return "CKR_CRYPTOKI_NOT_INITIALIZED";
    }

    return "Unknown";
}

// ---------------------------------------------------------------------------------------------------- 
void checkRV(CK_RV rv, const char* msg)
{
    if (rv != CKR_OK)
    {
        printf("%s: %d (%s)\n", msg, rv, errorName(rv).c_str());
    }
    assert(rv == CKR_OK);
}

// ---------------------------------------------------------------------------------------------------- 
void checkRV(CK_RV rv, CK_SESSION_HANDLE& hSession, const char* msg)
{
    if (rv != CKR_OK)
    {
        printf("%s: %d (%s)\n", msg, rv, errorName(rv).c_str());
        p11->C_Logout(hSession);
        p11->C_CloseSession(hSession);
    }
    assert(rv == CKR_OK);
}

// ---------------------------------------------------------------------------------------------------- 
void printSlots()
{
    CK_RV rv;
    CK_ULONG slotCnt;
    rv = p11->C_GetSlotList(CK_FALSE, nullptr, &slotCnt);
    checkRV(rv, "C_GetSlotList to obtain count failed");

    std::vector<CK_SLOT_ID> slotList(slotCnt);
    rv = p11->C_GetSlotList(CK_FALSE, slotList.data(), &slotCnt);
    checkRV(rv, "C_GetSlotList failed");
    if (slotList.size() == 0)
    {
        printf("No available slots.\n");
    }
    for (auto& slot : slotList)
    {
        CK_SLOT_INFO slotInfo;
        rv = p11->C_GetSlotInfo(slot, &slotInfo);
        checkRV(rv, "C_GetSlotInfo failed");

        printf("%.64s\n", slotInfo.slotDescription);

        CK_TOKEN_INFO tokenInfo;
        rv = p11->C_GetTokenInfo(slot, &tokenInfo);
        checkRV(rv, "C_GetTokenInfo failed");

        printf("\ttoken: %.32s\n", tokenInfo.label);
        printf("\n");
    }
}

// ---------------------------------------------------------------------------------------------------- 
void createSessionAndLogin(CK_SLOT_ID slotID, const std::string& pin, CK_SESSION_HANDLE& hSession)
{
    std::vector<CK_UTF8CHAR> userPIN(pin.begin(), pin.end());

    CK_RV rv;
    rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, (CK_VOID_PTR)&ApplicationID, nullptr, &hSession);
    checkRV(rv, hSession, "C_OpenSession failed");

    rv = p11->C_Login(hSession, CKU_USER, userPIN.data(), userPIN.size());
    checkRV(rv, hSession, "C_Login failed");
}

// ---------------------------------------------------------------------------------------------------- 
void generateKey(CK_SESSION_HANDLE& hSession, const std::string& label, CK_OBJECT_HANDLE& hKey)
{
    CK_RV rv;
    CK_MECHANISM mechanism = {
        CKM_AES_KEY_GEN, nullptr, 0
    };

    BYTE_VEC keyLabel(label.begin(), label.end());
    ATTR_VEC attrs = {
        { CKA_CLASS, &KeyClass, sizeof(KeyClass ) },
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_LABEL, keyLabel.data(), keyLabel.size() },
        { CKA_ID, keyLabel.data(), keyLabel.size()},
        { CKA_MODIFIABLE, &bFalse, sizeof(bFalse) },
        { CKA_KEY_TYPE, &KeyType, sizeof(KeyType ) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue ) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue ) },
        { CKA_VALUE_LEN, &KeyLen, sizeof(KeyLen ) }
    };

    rv = p11->C_GenerateKey(hSession, &mechanism, attrs.data(), attrs.size(), &hKey);
    checkRV(rv, hSession, "C_GenerateKey failed");
}

// ---------------------------------------------------------------------------------------------------- 
void createKeyObject(CK_SESSION_HANDLE& hSession, CK_OBJECT_HANDLE& hKey)
{
    CK_RV rv;
    ATTR_VEC attrs = {
        {CKA_CLASS, &KeyClass, sizeof(KeyClass)} ,
        {CKA_KEY_TYPE, &KeyType, sizeof(KeyType)} ,
        {CKA_TOKEN, &bTrue, sizeof(bTrue)} ,
        {CKA_PRIVATE, &bTrue, sizeof(bTrue ) },
        {CKA_VALUE, &KeyLen, sizeof(KeyLen)},
        {CKA_ENCRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = p11->C_CreateObject(hSession, attrs.data(), attrs.size(), &hKey);
    checkRV(rv, hSession, "C_CreateObject failed");
}

// ---------------------------------------------------------------------------------------------------- 
void findObjects(CK_SESSION_HANDLE& hSession, const std::string& label, CK_OBJECT_HANDLE& hKey)
{
    CK_RV rv;

    BYTE_VEC keyLabel(label.begin(), label.end());
    ATTR_VEC attrs = {
        { CKA_LABEL, keyLabel.data(), keyLabel.size() },
    };

    rv = p11->C_FindObjectsInit(hSession, attrs.data(), attrs.size());
    checkRV(rv, hSession, "C_FindObjectsInit failed");

    const size_t maxObjectsToFind = 16;
    std::vector<CK_OBJECT_HANDLE> objectList(maxObjectsToFind);
    CK_ULONG objCnt;
    while (1)
    {
        rv = p11->C_FindObjects(hSession, objectList.data(), maxObjectsToFind, &objCnt);
        objectList.resize(objCnt);
        checkRV(rv, hSession, "C_FindObjects failed");
        if (objCnt == 0)
                break;

        printf("objCnt=%d\n", objCnt);
        for (auto& obj : objectList)
        {
            hKey = obj;

            CK_ULONG ulSize;
            rv = p11->C_GetObjectSize(hSession, hKey, &ulSize);
            printf("key size=%lu\n", ulSize);
        }
    }

    rv = p11->C_FindObjectsFinal(hSession);
    checkRV(rv, hSession, "C_FindObjectsFinal failed");
}

// ---------------------------------------------------------------------------------------------------- 
void encrypt(CK_SESSION_HANDLE& hSession, CK_OBJECT_HANDLE& hKey, BYTE_VEC& cypher)
{
    CK_RV rv;
    // similar to decrypt!
    CK_MECHANISM mechanism = {
        CKM_AES_ECB, NULL_PTR, 0
    };
    
    rv = p11->C_EncryptInit(hSession, &mechanism, hKey);
    checkRV(rv, hSession, "C_EncryptInit failed");

    // must be multiple of block size (32 in our case)
    std::string text = "testDatatestDatatestDatatestData";
    BYTE_VEC plainText(text.begin(), text.end());

    printf("plainText size = %d\n", plainText.size());

    CK_ULONG cypherLen;
    // figure out the cypher len first
    rv = p11->C_Encrypt(hSession, plainText.data(), plainText.size(), nullptr, &cypherLen);
    checkRV(rv, hSession, "C_Encrypt 1 failed");

    printf("cypher len = %u\n", cypherLen);
    cypher.resize(cypherLen);

    // encryption itself
    rv = p11->C_Encrypt(hSession, plainText.data(), plainText.size(), cypher.data(), &cypherLen);
    checkRV(rv, hSession, "C_Encrypt 2 failed");

    // No need to finalize for single encrypt
    //rv = p11->C_EncryptFinal(hSession, nullptr, 0));
    //checkRV(rv, hSession, "C_EncryptFinal failed");
}

// ---------------------------------------------------------------------------------------------------- 
void decrypt(CK_SESSION_HANDLE& hSession, const BYTE_VEC& cypher, CK_OBJECT_HANDLE& hKey)
{
    CK_RV rv;
    // similar to encrypt!
    CK_MECHANISM mechanism = {
        CKM_AES_ECB, NULL_PTR, 0
    };

    rv = p11->C_DecryptInit(hSession, &mechanism, hKey);
    checkRV(rv, hSession, "C_DecryptInit failed");

    CK_ULONG plainLen;
    rv = p11->C_Decrypt(hSession, const_cast<CK_BYTE*>(cypher.data()), cypher.size(), nullptr, &plainLen);
    checkRV(rv, hSession, "C_Decrypt 1 failed");

    BYTE_VEC decoded(plainLen);
    rv = p11->C_Decrypt(hSession, const_cast<CK_BYTE*>(cypher.data()), cypher.size(), decoded.data(), &plainLen);
    checkRV(rv, hSession, "C_Decrypt 2 failed");

    printf("Decoded: %s\n", decoded.data());
}

// ---------------------------------------------------------------------------------------------------- 
CK_RV customCreateMutex(CK_VOID_PTR_PTR ppMutex)
{
    *ppMutex = new std::mutex();
    return CKR_OK;
}

// ---------------------------------------------------------------------------------------------------- 
CK_RV customDestroyMutex(CK_VOID_PTR pMutex)
{
    delete static_cast<std::mutex*>(pMutex);
    return CKR_OK;
}

// ---------------------------------------------------------------------------------------------------- 
CK_RV customLockMutex(CK_VOID_PTR pMutex)
{
    static_cast<std::mutex*>(pMutex)->lock();
    return CKR_OK;
}

// ---------------------------------------------------------------------------------------------------- 
CK_RV customUnlockMutex(CK_VOID_PTR pMutex)
{
    static_cast<std::mutex*>(pMutex)->unlock();
    return CKR_OK;
}

// ---------------------------------------------------------------------------------------------------- 
int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("Usage: %s <pkcs11 module>\n", __FILE__);
        return 0;
    }
    
    auto module = C_LoadModule(argv[1], &p11);
    std::string pin = "qwerty";
    std::string aesKeyLabel = "devel3";
    CK_SLOT_ID slotID = 0x8fb33c6;

    CK_C_INITIALIZE_ARGS initArgs;
    initArgs.flags = CKF_OS_LOCKING_OK;
    initArgs.pReserved = NULL_PTR;
    initArgs.CreateMutex = &customCreateMutex;
    initArgs.DestroyMutex = &customDestroyMutex;
    initArgs.LockMutex = &customLockMutex;
    initArgs.UnlockMutex = &customUnlockMutex;

    CK_RV rv;
    rv = p11->C_Initialize(static_cast<CK_VOID_PTR>(&initArgs));

    checkRV(rv, "C_Initialize failed");

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE hFoundKey;

    printSlots();
    createSessionAndLogin(slotID, pin, hSession);
    //generateKey(hSession, aesKeyLabel, hKey);
    findObjects(hSession, aesKeyLabel, hFoundKey);

    BYTE_VEC cypher;
    encrypt(hSession, hFoundKey, cypher);
    decrypt(hSession, cypher, hFoundKey);

    p11->C_CloseSession(hSession);
    p11->C_Finalize(NULL_PTR);
    C_UnloadModule(module);
    return 0;
}
