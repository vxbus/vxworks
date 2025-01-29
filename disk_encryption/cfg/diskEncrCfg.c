/* diskEncrCfg.c - disk encryption configlette file */

/*
 * Copyright (c) 2016-2017, 2019, 2021 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/* includes */

#include <types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <secCrypto.h>
#include <secSecret.h>
#include <fsMonitor.h>

/* typedefs */

typedef struct automountCfg
    {
    char *  pName;
    char *  pKeyId;
    }AUTOMOUNT_CFG;

/* locals */

LOCAL AUTOMOUNT_CFG mountCfg[] =
    {
#ifdef INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_1
    {PARTITION_NAME_1, PARTITION_KEY_ID_1},
#endif /* INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_1 */

#ifdef INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_2
    {PARTITION_NAME_2, PARTITION_KEY_ID_2},
#endif /* INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_2 */

#ifdef INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_3
    {PARTITION_NAME_3, PARTITION_KEY_ID_3},
#endif /* INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_3 */

#ifdef INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_4
    {PARTITION_NAME_4, PARTITION_KEY_ID_4},
#endif /* INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_4 */
    {NULL, NULL}
    };

/* functions */

/*******************************************************************************
*
* diskEncrLibKeyIdGet - Get key ID from configuration string
*
* This function gets key ID from configuration string.
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*
* \NOMANUAL
*/

STATUS diskEncrLibKeyIdGet
    (
    device_t xbdDev,
    char *  pKeyId
    )
    {
    int     i;
    STATUS  rc = ERROR;

    if ((xbdDev == NULLDEV) || (pKeyId == NULL))
        return rc;

    for (i = 0; i < (sizeof (mountCfg) / sizeof (AUTOMOUNT_CFG)); i++)
        {
        if ((mountCfg[i].pName == NULL) || (mountCfg[i].pKeyId == NULL))
            break;

        if (fsmDevGetByNameEx(mountCfg[i].pName, 1) == xbdDev)
            {
            if (strlen (mountCfg[i].pKeyId) <= SEC_SECRET_KEY_ID_MAX)
                {
                (void)strncpy (pKeyId, mountCfg[i].pKeyId,
                               strlen (mountCfg[i].pKeyId));
                rc = OK;
                }

            break;
            }
        }

    return rc;
    }

/*******************************************************************************
*
* diskEncrLibXexAesTemplateGet - Get selected AES algorithm
*
* This function gets selected AES algorithm.
*
* RETURNS: the pointer of chosen AES algorithm or NULL
*
* ERRNO: N/A
*
* \NOMANUAL
*/

const SEC_CIPHER_TEMPLATE * diskEncrLibXexAesTemplateGet (void)
    {
#ifdef INCLUDE_SEL_AES_128_ECB
    return secCipherAes128EcbTemplateGet ();
#endif

#ifdef INCLUDE_SEL_AES_256_ECB
    return secCipherAes256EcbTemplateGet ();
#endif

    return NULL;
    }

#ifdef INCLUDE_DISK_ENCRYPTION_AUTO_ENCRYPT
/*******************************************************************************
*
* diskEncrLibKeyIdGet - Get disk partition name
*
* This function gets disk partition name
*
* RETURNS: disk partition name or NULL
*
* ERRNO: N/A
*
* \NOMANUAL
*/

char * getAutoEncryptPartitionName
    (
    int index
    )
    {
    switch (index)
        {
        case 0:
            return AUTO_ENCRYPT_PARTITION_NAME_1;
        case 1:
            return AUTO_ENCRYPT_PARTITION_NAME_2;
        case 2:
            return AUTO_ENCRYPT_PARTITION_NAME_3;
        case 3:
            return AUTO_ENCRYPT_PARTITION_NAME_4;
        default:
            return NULL;
        }
    }

/*******************************************************************************
*
* diskEncrLibKeyIdGet - Get disk partition key ID
*
* This function gets disk partition key ID
*
* RETURNS: disk partition key ID or NULL
*
* ERRNO: N/A
*
* \NOMANUAL
*/

char * getAutoEncryptPartitionKeyID
    (
    int index
    )
    {
    switch (index)
        {
        case 0:
            return AUTO_ENCRYPT_PARTITION_KEY_ID_1;
        case 1:
            return AUTO_ENCRYPT_PARTITION_KEY_ID_2;
        case 2:
            return AUTO_ENCRYPT_PARTITION_KEY_ID_3;
        case 3:
            return AUTO_ENCRYPT_PARTITION_KEY_ID_4;
        default:
            return NULL;
        }
    }
#endif
