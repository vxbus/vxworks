/* diskEncryption.c - Disk Encryption Library */

/*
 * Copyright (c) 2016, 2021 Wind River Systems, Inc.
 * 
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
DESCRIPTION
The file provides a set of internal routines for implementing disk encryption.
The routines only can be used in xbdPartition.c. Please don't call them in other
 code.
*/

/* includes */

#include <diskEncryption/diskEncryption.h>

/* locals */

LOCAL DISK_ENCRYPTION_FUNC *    pLibFuncs = NULL;

/* functions */

/*******************************************************************************
*
* diskEncrInit - Initialize disk encryption environment
*
* This routine initializes disk encryption environment.
*
* RETURNS: the context pointer, NULL if it failed.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

void * diskEncrInit
    (
    device_t    xbdDev,
    char *      pKeyId
    )
    {
    if ((pLibFuncs != NULL) && (pLibFuncs->init != NULL))
        return pLibFuncs->init (xbdDev, pKeyId);
    else
        return NULL;
    }

/*******************************************************************************
*
* diskEncrCreateBio - create a new bio descriptor to transfer cipher
*
* This routine creates a new bio descriptor to transfer cipher.
*
* RETURNS: the BIO pointer, NULL if it failed.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

struct bio * diskEncrCreateBio
    (
    void *          pCtx,
    struct bio *    bio
    )
    {
    if ((pCtx != NULL) && (bio != NULL) && (pLibFuncs != NULL) &&
        (pLibFuncs->createBio != NULL))
        return pLibFuncs->createBio (pCtx, bio);
    else
        return NULL;
    }

/*******************************************************************************
*
* diskEncrCleanup - Clean up an initialized context
*
* This function cleans up an initialized context.
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* \NOMANUAL
*/

void diskEncrCleanup
    (
    void *  pCtx
    )
    {
    if ((pCtx != NULL) && (pLibFuncs != NULL) && (pLibFuncs->cleanup != NULL))
        pLibFuncs->cleanup (pCtx);
    }

/*******************************************************************************
*
* diskEncrSetFuncs - set the pointer of the disk encryption functions
*
* This function sets the pointer of the disk encryption functions. The routine
* only can be used in disk encryption library.
*
* RETURNS: N/A
*
* ERRNO: N/A
* 
* \NOMANUAL
*/

void diskEncrSetFuncs
    (
    DISK_ENCRYPTION_FUNC *  pFuncs
    )
    {
    if ((pLibFuncs != NULL) || (pFuncs == NULL))
        return;

    pLibFuncs = pFuncs;
    }
