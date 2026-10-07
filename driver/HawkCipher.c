#include "HawkCipher.h"


/* Hawkeye TFE */
#define XOR_KEYSTREAM_LEN 64

const UCHAR g_HawkCipherKey[HAWK_CIPHER_KEY_SIZE] = {
    0x2B, 0x91, 0xE4, 0x5C, 0xA8, 0x73, 0x1D, 0xF6,
    0x44, 0xC0, 0x8E, 0x27, 0xB5, 0x69, 0x03, 0xDA,
    0x7A, 0x12, 0xFE, 0x88, 0x51, 0x3C, 0x9F, 0x06,
    0xD4, 0x62, 0xAF, 0x19, 0xE7, 0x5B, 0x30, 0x84
};

static __forceinline VOID
HawkXorBuildKeystream(
    __out_ecount(XOR_KEYSTREAM_LEN) PUCHAR keystream,
    __in ULONG blockIndex,
    __in PUCHAR key,
    __in int keySize
    )
{
    int n;
    if (keySize <= 0)
    {
        keySize = 1;
    }
    for (n = 0; n < XOR_KEYSTREAM_LEN; n++)
    {
        keystream[n] = (UCHAR)(key[n % keySize] ^ (UCHAR)(blockIndex + n));
    }
}

/* Hawkeye TFE: Cipher */
VOID
HawkXorEncrypt(
    __out void * encryptedBuf,
    __in void * buf,
    __in ULONG byteOffset,
    __in ULONG length,
    __in char * key,
    __in int keySize
    )
{
    PUCHAR inBuf = (PUCHAR)buf;
    PUCHAR outBuf = (PUCHAR)encryptedBuf;
    ULONG tmpOffset = 0;
    ULONG currentOff = byteOffset;
    UCHAR keystream[XOR_KEYSTREAM_LEN];
    ULONG blockIndex;
    ULONG i;

    while (length > HAWK_XOR_BLOCK)
    {
        blockIndex = currentOff / HAWK_XOR_BLOCK;
        HawkXorBuildKeystream(keystream, blockIndex, (PUCHAR)key, keySize);
        for (i = 0; i < HAWK_XOR_BLOCK; i++)
        {
            outBuf[tmpOffset + i] = inBuf[tmpOffset + i] ^ keystream[i % XOR_KEYSTREAM_LEN];
        }
        currentOff += HAWK_XOR_BLOCK;
        tmpOffset += HAWK_XOR_BLOCK;
        length -= HAWK_XOR_BLOCK;
    }
    if (length != 0)
    {
        blockIndex = currentOff / HAWK_XOR_BLOCK;
        HawkXorBuildKeystream(keystream, blockIndex, (PUCHAR)key, keySize);
        for (i = 0; i < length; i++)
        {
            outBuf[tmpOffset + i] = inBuf[tmpOffset + i] ^ keystream[i % XOR_KEYSTREAM_LEN];
        }
    }
}

VOID
HawkXorDecrypt(
    __in void * encryptedBuf,
    __in ULONG byteOffset,
    __in ULONG realLen,
    __out void * buf,
    __in char * key,
    __in int keySize
    )
{
    PUCHAR inBuf = (PUCHAR)encryptedBuf;
    PUCHAR outBuf = (PUCHAR)buf;
    ULONG tmpOffset = 0;
    ULONG currentOff = byteOffset;
    UCHAR keystream[XOR_KEYSTREAM_LEN];
    ULONG blockIndex;
    ULONG i;

    while (realLen > HAWK_XOR_BLOCK)
    {
        blockIndex = currentOff / HAWK_XOR_BLOCK;
        HawkXorBuildKeystream(keystream, blockIndex, (PUCHAR)key, keySize);
        for (i = 0; i < HAWK_XOR_BLOCK; i++)
        {
            outBuf[tmpOffset + i] = inBuf[tmpOffset + i] ^ keystream[i % XOR_KEYSTREAM_LEN];
        }
        currentOff += HAWK_XOR_BLOCK;
        tmpOffset += HAWK_XOR_BLOCK;
        realLen -= HAWK_XOR_BLOCK;
    }
    if (realLen != 0)
    {
        blockIndex = currentOff / HAWK_XOR_BLOCK;
        HawkXorBuildKeystream(keystream, blockIndex, (PUCHAR)key, keySize);
        for (i = 0; i < realLen; i++)
        {
            outBuf[tmpOffset + i] = inBuf[tmpOffset + i] ^ keystream[i % XOR_KEYSTREAM_LEN];
        }
    }
}
