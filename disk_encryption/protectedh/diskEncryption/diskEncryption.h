/* diskEncryption.h - Disk Encryption Header File */

/*
 * Copyright (c) 2017, 2021 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

#ifndef __INCdiskEncryptionh
#define __INCdiskEncryptionh

/* includes */

#include <types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <vxWorks.h>
#include <drv/xbd/xbd.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* defines */

#define XBD_DISK_ENCRYPTION_EN      (0x1 << 0)
#define XBD_DISK_DECRYPTION_EN      (0x1 << 1)

#define DISK_DECRYPTION_KEY_ID_MAX  (64)

/* typedefs */

typedef struct xbdEncryptionInfo
    {
    char    keyId[DISK_DECRYPTION_KEY_ID_MAX + 1];
    UINT32  flags;
    } XBD_ENCRYPTION_INFO;

typedef struct diskEncryptionFunc
    {
    void *          (*init) (device_t xbdDev, char * pKeyId);
    struct bio *    (*createBio) (void * pCtx, struct bio * bio);
    void            (*cleanup) (void * pCtx);
    } DISK_ENCRYPTION_FUNC;

/* function declarations */

void *          diskEncrInit (device_t xbdDev, char * pKeyId);
struct bio *    diskEncrCreateBio (void * pCtx, struct bio * bio);
void            diskEncrCleanup (void * pCtx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INCdiskEncryptionh */
