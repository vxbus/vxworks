/* diskEncryptionTools.h - Disk Encryption Tools Header File */

/*
 * Copyright (c) 2016, 2021 Wind River Systems, Inc.
 * 
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

#ifndef __INCdiskEncryptionToolsh
#define __INCdiskEncryptionToolsh

/* includes */

#include <types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vxWorks.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* function declarations */

STATUS  diskEncrypt (char * pDevName, char * pKeyId);
STATUS  diskDecrypt (char * pDevName, char * pKeyId);
STATUS  diskMountCrypto (char * pDevName, char * pKeyId);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INCdiskEncryptionToolsh */
