/* diskEncryptionLib.c - Disk Encryption Library */

/*
 * Copyright (c) 2016-2017, 2019, 2021-2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
DESCRIPTION
The file implements disk encryption by using XEX-AES encryption method.
The routines in the file are internal. Please don't call them in other code.
*/

/* includes */

#include <secCrypto/secCipherXexAes.h>
#include <diskEncryption/diskEncryption.h>
#include <secSecret.h>
#include <secHash.h>
#include <cacheLib.h>
#include <memLib.h>
#include <ioLib.h>
#include <drv/xbd/xbd.h>
#include <fsEventUtilLib.h>
#include <fsMonitor.h>
#include <taskLib.h>
#include <private/secSecretP.h>
#include <timerDev.h>

/* defines */

#define DISK_ENCRYPTION_RETRY_TASK_PRIO             255
#define DISK_ENCRYPTION_RETRY_TASK_STACK_SIZE       (1024 * 8)

/* typedefs */

typedef struct secXbdBioData
    {
    struct bio          bio;
    SEC_XEX_AES_CTX *   pCtx;
    }SEC_XBD_BIO_DATA;

/* forward declarations */

LOCAL void                          diskEncrLibBioDone (struct bio *bioPtr);
LOCAL void *                        diskEncrLibInit (device_t xbdDev, char *
                                                     pKeyId);
LOCAL struct bio *                  diskEncrLibCreateBio (void * pCtx, struct
                                                          bio * bio);
LOCAL void                          diskEncrLibCleanup (void * pCtx);
LOCAL STATUS                        diskEncrLibGetKey (char * keyId, UINT8 *
                                                       pKey1, UINT8 * pKey2);
LOCAL STATUS                        diskEncrLibRetry (device_t xbdDev);

extern STATUS                       diskEncrLibKeyIdGet (device_t xbdDev,
                                                         char * pKeyId);
extern void                         diskEncrSetFuncs (DISK_ENCRYPTION_FUNC *
                                                      pHandle);
extern const SEC_CIPHER_TEMPLATE *  diskEncrLibXexAesTemplateGet (void);

/* locals */

LOCAL DISK_ENCRYPTION_FUNC  libFuncs =
    {
    diskEncrLibInit,
    diskEncrLibCreateBio,
    diskEncrLibCleanup
    };

/* functions */

/*******************************************************************************
*
* diskEncrLibBioDone - Callback function for BIO read/write
*
* This routine is the callback function for BIO read/write.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

LOCAL void diskEncrLibBioDone
    (
    struct bio *    bioPtr
    )
    {
    SEC_XBD_BIO_DATA *  pSecBioData = (SEC_XBD_BIO_DATA *)bioPtr;
    struct bio *        bio = pSecBioData->bio.bio_caller1;
    int                 outLen;

    bio->bio_error = pSecBioData->bio.bio_error;

    if ((bio->bio_error == 0) && ((bio->bio_flags & BIO_READ) != 0))
        {
        outLen = (int) bio->bio_bcount;
        if (secXexAesUpdate (pSecBioData->pCtx,
                             (UINT8 *)pSecBioData->bio.bio_data, &outLen,
                             (UINT8 *)pSecBioData->bio.bio_data,
                             (int) bio->bio_bcount, bio->bio_blkno,
                             SEC_CIPHER_DECR) != OK)
            bio->bio_error = EIO;
        else
            bcopy ((char *)(pSecBioData->bio.bio_data),
                   (char *)(bio->bio_data), bio->bio_bcount);
        }

    free (pSecBioData->bio.bio_data);
    free (pSecBioData);

    bio_done (bio, (int) bio->bio_error);
    }

/*******************************************************************************
*
* diskEncrLibInit - Initialize disk encryption environment
*
* This routine initializes disk encryption environment.
*
* RETURNS: the context pointer, NULL if it failed.
*
* ERRNO: N/A
*/

LOCAL void * diskEncrLibInit
    (
    device_t    xbdDev,
    char *      pKeyId
    )
    {
    XBD_GEOMETRY        geo;
    char                keyId[SEC_SECRET_KEY_ID_MAX + 1];
    SEC_XEX_AES_CTX *   pCtx = NULL;
    UINT8               key1[SEC_HASH_DIGEST_LEN_SHA512 / 2];
    UINT8               key2[SEC_HASH_DIGEST_LEN_SHA512 / 2];
    void *              handle;

    if (xbdIoctl (xbdDev, (int)XBD_GETGEOMETRY, &geo) != 0)
        return NULL;

    bzero (keyId, sizeof (keyId));
    if ((pKeyId != NULL) && (strlen (pKeyId) > 0))
        {
        if (strlen (pKeyId) > SEC_SECRET_KEY_ID_MAX)
            return NULL;
        else
            (void)strncpy (keyId, pKeyId, strlen (pKeyId));
        }
    else
        {
        if (diskEncrLibKeyIdGet (xbdDev, keyId) != OK)
            return NULL;
        }

    handle = secSecretOpen ();
    if (handle == NULL)
        {
        (void)taskSpawn ("diskEncrRetry",
                         DISK_ENCRYPTION_RETRY_TASK_PRIO, 0,
                         DISK_ENCRYPTION_RETRY_TASK_STACK_SIZE,
                         (FUNCPTR)diskEncrLibRetry,
                         (_Vx_usr_arg_t)xbdDev,
                         0, 0, 0, 0, 0, 0, 0, 0, 0);
        return NULL;
        }
    else
        (void)secSecretClose (handle);

    pCtx = (SEC_XEX_AES_CTX *)calloc (1, sizeof (SEC_XEX_AES_CTX));
    if (pCtx == NULL)
        return NULL;

    bzero ((char *)key1, sizeof (key1));
    bzero ((char *)key2, sizeof (key2));
    if (diskEncrLibGetKey (keyId, key1, key2) == ERROR)
        {
        bzero ((char *)key1, sizeof (key1));
        bzero ((char *)key2, sizeof (key2));
        free (pCtx);
        return NULL;
        }

    if (secXexAesInit (pCtx, diskEncrLibXexAesTemplateGet (), key1, key2,
        geo.blocksize) == ERROR)
        {
        bzero ((char *)key1, sizeof (key1));
        bzero ((char *)key2, sizeof (key2));
        free (pCtx);
        return NULL;
        }

    bzero ((char *)key1, sizeof (key1));
    bzero ((char *)key2, sizeof (key2));
    return (void *)pCtx;
    }

/*******************************************************************************
*
* diskEncrLibCreateBio - create a new bio descriptor to transfer cipher
*
* This routine creates a new bio descriptor to transfer cipher.
*
* RETURNS: the BIO pointer, NULL if it failed.
*
* ERRNO: N/A
*/

LOCAL struct bio * diskEncrLibCreateBio
    (
    void *          pCtx,
    struct bio *    bio
    )
    {
    SEC_XBD_BIO_DATA *  pSecBioData;
    char *              pSecData;
    int                 outLen;

    if ((pCtx == NULL) || (bio == NULL))
        return NULL;

    pSecBioData = (SEC_XBD_BIO_DATA *)malloc (sizeof (SEC_XBD_BIO_DATA));
    if (pSecBioData == NULL)
        return NULL;

    bcopy ((char *)bio, (char *)&(pSecBioData->bio), sizeof (struct bio));
    pSecBioData->bio.bio_done       = diskEncrLibBioDone;
    pSecBioData->bio.bio_caller1    = bio;
    pSecBioData->pCtx               = (SEC_XEX_AES_CTX *)pCtx;

    pSecData = (char *)memalign ((size_t)(_CACHE_ALIGN_SIZE), (size_t)bio->bio_bcount);
    if (pSecData == NULL)
        {
        free (pSecBioData);
        return NULL;
        }

    if ((bio->bio_flags & BIO_WRITE) != 0)
        {
        bcopy ((char *)bio->bio_data, pSecData, bio->bio_bcount);
        outLen = (int) bio->bio_bcount;
        if (secXexAesUpdate ((SEC_XEX_AES_CTX *)pCtx,(UINT8 *)pSecData, &outLen,
                             (UINT8 *)pSecData, (int) bio->bio_bcount, bio->bio_blkno,
                             SEC_CIPHER_ENCR) != OK)
            {
            free (pSecBioData);
            free (pSecData);
            return NULL;
            }
        }
    else
        bzero (pSecData, bio->bio_bcount);

    CACHE_USER_FLUSH (pSecData, bio->bio_bcount);
    CACHE_USER_INVALIDATE (pSecData, bio->bio_bcount);

    pSecBioData->bio.bio_data = (void *)pSecData;

    return &(pSecBioData->bio);
    }

/*******************************************************************************
*
* diskEncrLibCleanup - Clean up an initialized context
*
* This function cleans up an initialized context.
*
* RETURNS: N/A
*
* ERRNO: N/A
*/

LOCAL void diskEncrLibCleanup
    (
    void *  pCtx
    )
    {
    if (pCtx != NULL)
        {
        (void)secXexAesCleanup ((SEC_XEX_AES_CTX *)pCtx);
        free (pCtx);
        }
    }

/*******************************************************************************
*
* diskEncrLibFuncsInit - Initialize disk encryption library
*
* This routine initializes disk encryption library.
*
* RETURNS: N/A.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

void diskEncrLibFuncsInit (void)
    {
    diskEncrSetFuncs (&libFuncs);
    }

/*******************************************************************************
*
* diskEncrLibGetKey - Get keys from secSecret
*
* This function gets keys from secSecret.
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*/

LOCAL STATUS diskEncrLibGetKey
    (
    char *  keyId,
    UINT8 * pKey1,      /* key for encrypting data */
    UINT8 * pKey2       /* key for encrypting sector tweak */
    )
    {
    SEC_HASH_CTX    ctx;
    char            pw[SEC_SECRET_MAX_SECRET];
    int             pwLen = SEC_SECRET_MAX_SECRET;
    unsigned int    keySize = SEC_HASH_DIGEST_LEN_SHA512;
    UINT8           key[SEC_HASH_DIGEST_LEN_SHA512];
    STATUS          rc = ERROR;

    bzero (pw, (size_t) pwLen);
    bzero (key, (size_t) keySize);

    if (secSecretGet (keyId, pw, &pwLen) != OK)
        return rc;

    bzero ((char *)&ctx, sizeof (SEC_HASH_CTX));
    if (secHashInit (&ctx, secHashSha512TemplateGet()) != OK)
        goto cleanup;

    if (secHashUpdate (&ctx, (void *)pw, (size_t)pwLen) != OK)
        goto cleanup;

    if (secHashFinal (&ctx, key, &keySize) != OK)
        goto cleanup;

    bcopy (key, pKey1, keySize / 2);
    bcopy ((char *)&(key[keySize / 2]), pKey2, keySize / 2);

    rc = OK;

cleanup:
    secHashCleanup (&ctx);
    bzero (pw, (size_t) pwLen);
    bzero (key, (size_t) keySize);

    return rc;
    }

/*******************************************************************************
*
* diskEncrLibRetry - retry to mount a disk partition
*
* This function retries to mount a disk partition.
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*/

LOCAL STATUS diskEncrLibRetry
    (
    device_t    xbdDev
    )
    {
    FS_PATH_WAIT_STRUCT waitData;
    int                 fd;
    XBD_ENCRYPTION_INFO info;
    fsmName_t           volName;
    devname_t           xbdName;

    if (!secSecretReadyCheck (10))
        return ERROR;

    if (devName (xbdDev, xbdName) != OK)
        return ERROR;

    (void) fsmNameMap(xbdName, volName);

    fd = open ((char *)volName, O_RDWR, 0777);
    if (fd < 0)
        {
        /* register on the path instantiator event */

        if (fsPathAddedEventSetup (&waitData, (char *)volName) != OK)
            return ERROR;

        if (fsWaitForPath (&waitData) != OK)
            return ERROR;

        fd = open ((char *)volName, O_RDWR, 0777);
        if (fd < 0)
            return ERROR;
        }

    bzero ((char *)&info, sizeof (XBD_ENCRYPTION_INFO));
    info.flags = XBD_DISK_ENCRYPTION_EN | XBD_DISK_DECRYPTION_EN;

    if (ioctl (fd, XBD_CFG_ENCRYPTION, (_Vx_ioctl_arg_t)&info) != OK)
        {
        (void)close (fd);
        return ERROR;
        }

    /* kick off RAWFS so that other file system can be instantiated */

    if (ioctl (fd, XBD_HARD_EJECT, (_Vx_ioctl_arg_t)XBD_TOP) != OK)
        {
        (void)close (fd);
        return ERROR;
        }

    (void)close (fd);
    return OK;
    }
