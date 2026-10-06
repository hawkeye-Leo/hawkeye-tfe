#ifndef HAWK_CIPHER_H
#define HAWK_CIPHER_H

#include <fltKernel.h>

#define HAWK_XOR_BLOCK 0x1000
#define HAWK_CIPHER_KEY_SIZE 32

extern const UCHAR g_HawkCipherKey[HAWK_CIPHER_KEY_SIZE];

VOID
HawkXorEncrypt(
    __out void * encryptedBuf,
    __in void * buf,
    __in ULONG byteOffset,
    __in ULONG length,
    __in char * key,
    __in int keySize
    );

VOID
HawkXorDecrypt(
    __in void * encryptedBuf,
    __in ULONG byteOffset,
    __in ULONG realLen,
    __out void * buf,
    __in char * key,
    __in int keySize
    );

#endif
