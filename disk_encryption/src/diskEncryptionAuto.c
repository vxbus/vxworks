/* diskEncryptionAuto.c - disk partitions auto encryption */

/*
 * Copyright (c) 2021 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

#include <vxWorks.h>
#include <taskLib.h>
#include <stdio.h>
#include <ioLib.h>
#include <sysLib.h>
#include <xbdPartition.h>
#include <dosFsLib.h>
#include <dirent.h>
#include <fsUtilityFuncs.h>
#include <diskEncryptionTools.h>
#include <openssl/evp.h>
#include <secSecret.h>
#include <randomNumGen.h>
#include <drv/manager/device.h>
#include <fsUtilityFuncs.h>

/* defines */

#define PARTITION_NUM     4

#ifdef DEBUG
#define dbgPrint(fmt, args...) (void)printf_s(fmt, ## args)
#else
#define dbgPrint(fmt, args...)
#endif

/* externs */

extern char * getAutoEncryptPartitionName(int);
extern char * getAutoEncryptPartitionKeyID(int);

/*****************************************************************************
*  secureSecret - create a random base64 secret 
*
*  Generate a random secret string for use in the vault.
*  Will block until sufficient entropy is available 
*  to generate a random key. 
*  
*  RETURNS: OK, or ERROR
*
*/

static STATUS secureSecret
    (
    unsigned char * buffer,
    size_t length
    )
    {
    unsigned char key[32];
    STATUS rc = ERROR;

    /* check of input arguments, 32 bytes are encoded as 44 ascii chars + EOS */

    if ((buffer == NULL) || (length < 45))
        {
        return ERROR;
        }

    do
        {
        rc = randABytes(key, sizeof(key));
        if (rc != OK)
            {
            taskDelay(1);
            }
        } while(rc != OK);

    if ( EVP_EncodeBlock(buffer, key, sizeof(key)) > 0)
        {
        return OK;
        }

    return ERROR;
    }

/*****************************************************************************
*
* setupPartitionEncrypt - encrypt a partition.
*
* This routine encrypts a partition.
*
* RETURNS: OK, or ERROR if encrypt fail.
*
* For example : 
*        setupPartitionEncrypt("/bd16:2", "disk", 
*           "q7dWn538LjbakcnGlK3js81ns@901*42Sdb1Ik9")
*/

static STATUS setupPartitionEncrypt
    (
    const char * pPartName, 
    const char * pKeyId, 
    const char * pKeyValue
    )
    {
    STATUS ret;
    int fd;
    devname_t xbdName;
    size_t partNameLen;
    size_t keyIdLen;
    size_t keyValueLen;
    size_t xbdNameLen;

    if ((pPartName == NULL) || (pKeyId == NULL) || (pKeyValue == NULL))
        {
        dbgPrint("NULL argument\n");
        return ERROR;
        }

    keyIdLen = strnlen_s(pKeyId, SEC_SECRET_KEY_ID_MAX+1);
    if (keyIdLen > SEC_SECRET_KEY_ID_MAX)
        {
        dbgPrint("pKeyId argument is invalid\n");
        return ERROR;
        }
    
    keyValueLen = strnlen_s(pKeyValue, SEC_SECRET_MAX_SECRET+1);
    if (keyValueLen > SEC_SECRET_MAX_SECRET)
        {
        dbgPrint("pKeyValue argument is invalid\n");
        return ERROR;
        }

    fd = open (pPartName, O_RDONLY, 0);
    if (fd < 0)
        {
        dbgPrint("Open %s partition failed\n", pPartName);
        return ERROR;
        }

    ret = ioctl(fd, XBD_GETBASENAME, (void *)xbdName);
    if (ret != 0)
        {
        dbgPrint("Get xbdbase name failed, this is not a disk\n");
        close(fd);
        return ERROR;
        }
    close(fd);

    partNameLen = strnlen_s(pPartName, MAX_DEVNAME);
    xbdNameLen = strnlen_s(xbdName, MAX_DEVNAME);
    if (partNameLen > (xbdNameLen+3))
        {
        dbgPrint("partition name is too long\n");
        return ERROR;
        }

    if (strncmp(pPartName, xbdName, xbdNameLen) > 0)
        {
        dbgPrint("partition name does not begin with device name\n");
        return ERROR;
        }

    ret = secSecretImport((char *)pKeyId, pKeyValue, (int)keyValueLen+1);
    if (ret != OK)
        {
        dbgPrint("Failed to import Key into secret vault!\n");
        return ERROR;
        }

    dbgPrint("Encrypting partition %s\n", pPartName);

    if (diskEncrypt((char *)pPartName, (char*) pKeyId) != OK)
        {
        dbgPrint("Failed to encrypt partition!\n");
        return ERROR;
        }

    dbgPrint("Partition encrypted successfully\n");
    return OK;
    }

/*****************************************************************************
*
* setupPartitionEncryptGen - encrypt a partition.
*
* This routine encrypts a partition with an auto-generated secret key.
*
* RETURNS: OK, or ERROR on failure.
*
* For example : 
*        setupPartitionEncryptGen("/bd16:2", "disk")
*/

static STATUS setupPartitionEncryptGen
    (
    const char * pPartName,
    const char * pKeyId
    )
    {
    unsigned char keyValue[45];

    if (secureSecret(keyValue, sizeof(keyValue)) != OK)
        {
        dbgPrint("Failed to generate secret key for disk encryption\n");
        return ERROR;
        }

    return setupPartitionEncrypt(pPartName, pKeyId, (char *)keyValue);
    }

/*****************************************************************************
*
* secureDiskInit - initialize disk partitions
*
* This routine partitions, formats and encrypts a disk.
*
* RETURNS: OK, or ERROR on failure.
*/

STATUS secureDiskInit (void)
    {
    int i;
    STATUS ret = ERROR;
    char * PARTITION_NAME = NULL;
    char * DISK_SECRET_ID = NULL;
    DOS_VOLUME_DESC_ID pVolDesc = NULL;

    /* Verify vault file is mounted */

    if (secSecretReadyCheck(10) != TRUE)
        {
        dbgPrint("vault file mount failed \n");		
        return ERROR;
        }
	
     /* Verify PARTITION_NAME is mounted */

    for (i = 0; i < PARTITION_NUM; i++)
        {
        PARTITION_NAME = getAutoEncryptPartitionName(i);
        if (PARTITION_NAME == NULL)
            continue;
        if (securePartitionWaitMount(PARTITION_NAME) != OK)
            {
            dbgPrint("partition %s mount failed \n", PARTITION_NAME);		
            return ERROR;
            }
        }

    /*
     * If PARTITION_NAME is already encrypted, mount it and return.
     * Otherwise, this call will fail and we'll proceed to initialize the
     * partition.
     */

    for (i = 0; i < PARTITION_NUM; i++)
        {
        PARTITION_NAME = getAutoEncryptPartitionName(i);
        DISK_SECRET_ID = getAutoEncryptPartitionKeyID(i);
        if ((PARTITION_NAME == NULL) || (DISK_SECRET_ID == NULL))
            continue;
        ret = diskMountCrypto (PARTITION_NAME, DISK_SECRET_ID);
        pVolDesc = dosFsVolDescGetByName (PARTITION_NAME, NULL);
        if ((ret == OK) && (pVolDesc != NULL))
            continue;
        else
            {
            /* Format partitions. If already formatted, proceed to encryption */

            if (pVolDesc == NULL)
                {
                dbgPrint("Formatting partition %s\n", PARTITION_NAME);
                if(dosFsVolFormat(PARTITION_NAME, 0, NULL) != OK)
                    {
                    dbgPrint("Failed to format partition %s!\n", PARTITION_NAME);
                    return ERROR;
                    }
                taskDelay(sysClkRateGet());
                }
            
            /* Encrypt PARTITION_NAME */

            ret = setupPartitionEncryptGen (PARTITION_NAME, DISK_SECRET_ID);
            if (ret != OK)
                {
                dbgPrint("Failed to encrypt partition %s by using key id %s!\n", 
                         PARTITION_NAME, DISK_SECRET_ID);
                return ERROR;
                }
            }
        }

    return OK;
    }

/******************************************************************************
 *
 * secureDiskTaskInit - initialize disk security features task
 *
 * This routine do a taskSpawn for disk security initialization
 *
 * RETURNS: N/A
 */

void secureDiskTaskInit (void)
    {
    TASK_ID tid;

    tid = taskSpawn ("SecureInitTask", 100, 0, 0x8000, (FUNCPTR)secureDiskInit,
                     0,0,0,0,0,0,0,0,0,0);
    if (tid == TASK_ID_NULL)
        {
        dbgPrint("Unable to spawn SecureInit task.\n");
        }

    return;
    }
