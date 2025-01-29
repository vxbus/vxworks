/* diskEncryptionTools.c - Disk encryption tools */

/*
 * Copyright (c) 2016-2017, 2020-2021 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
DESCRIPTION
Provide a set of APIs for encrypting, decrypting and mount a disk partition.

You must create a secrets store and import a valid key into the secrets store 
before call the APIs, otherwise the operations will fail. For information 
about the secret store and encryption keys, see the VxWorks Cryptography  
Libraries Programmer's Guide.

A typical usage of the APIs is shown below. It shows how to encrypt "/ata0:1".
\cs
secSecretImport ("0", "vxworks", 8);
diskEncrypt ("/ata0:1", "0");
\ce

CONFIGURATION 
See Configuring VxWorks for Full Disk Encryption in VxWorks Security 
Programmer's Guide.

INCLUDE FILES: diskEncryptionTools.h

SEE ALSO
\tb [VxWorks Security Programmer's Guide](https://docs.windriver.com/bundle/vxworks_security_programmers_guide_@vx_release/page/cyl1469493111443.html),
\tb [VxWorks Cryptography Libraries Programmer's Guide](https://docs.windriver.com/bundle/vxworks_cryptography_libraries_programmers_guide_@vx_release/page/gqf1496095336739.html)
*/

/* includes */

#include <diskEncryptionTools.h>
#include <ioLib.h>
#include <drv/xbd/xbd.h>
#include <fsEventUtilLib.h>
#include <diskEncryption/diskEncryption.h>

/* defines */

#define ENCRYPT_BUF_SIZE    (1024 * 1024 * 1)
#define OPERATE_ENCRYPT     (0x1 << 0)
#define OPERATE_DECRYPT     (0x1 << 1)
#define OPERATE_MOUNT       (0x1 << 2)

/* functions */

/*******************************************************************************
*
* diskEncryptSeek - set a file read/write pointer
*
* This routine sets the file read/write pointer of file <fd> to <offset>.
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*/

LOCAL STATUS diskEncryptSeek
    (
    int     fd,            /* file descriptor */
    off_t   offset         /* new byte offset to seek to */
    )
    {
    BOOL        must64      = FALSE;
    int         where       = 0;
    long long   offset64    = offset;
    long long   where64     = 0;

    /* get the current position */

    if (ioctl (fd, FIOWHERE64, (_Vx_ioctl_arg_t)&where64) == ERROR)
        {
        /* goes to FIOWHERE */

        if ((where = ioctl (fd, FIOWHERE, 0)) == ERROR)
            return ERROR;
        else
            where64 = (unsigned int)where;
        }

    offset64 = where64 + offset;

    /* If the given offset is beyond 32 bits, the 64 bit ioctls must work */

    must64 = (offset64 > (unsigned int)UINT_MAX) ? TRUE : FALSE ;

    if (must64)
        {
        if (ioctl (fd, FIOSEEK64, (_Vx_ioctl_arg_t)&offset64) == ERROR)
            return ERROR;
        else
            return OK;
        }
    else
        {
        if (ioctl (fd, FIOSEEK, (_Vx_ioctl_arg_t)offset64) == ERROR)
            {
            /* goes to FIOSEEK64 if get errno ENOTSUP */

            if (errno == ENOTSUP)
                {
                if (ioctl (fd, FIOSEEK64, (_Vx_ioctl_arg_t)&offset64) == ERROR)
                    return ERROR;
                else
                    return OK;
                }
            else
                return ERROR;
            }
        else
            return OK;
        }
    }

/*******************************************************************************
*
* diskEncryptInternal - encrypt, decrypt or mount a disk partition
*
* This function encrypts, decrypts or mounts a disk partition.
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*/

LOCAL STATUS diskEncryptInternal
    (
    char *  pDevName,
    char *  pKeyId,
    int     operate
    )
    {
    STATUS              status = ERROR;
    FS_PATH_WAIT_STRUCT waitData;
    int                 fd;
    XBD_ENCRYPTION_INFO info;
    char *              pBuf = NULL;
    ssize_t             readSize;
    size_t              bufSize = ENCRYPT_BUF_SIZE;

    if ((pDevName == NULL) || (pKeyId == NULL) ||
        (strlen (pKeyId) >= sizeof (info.keyId)))
        return status;

    fd = open (pDevName, O_RDONLY, 0777);
    if (fd < 0)
        {
        (void)printf ("Couldn't open supplied path.\n");
        return status;
        }

    /* register on the path instantiator event */

    status = fsPathAddedEventSetup (&waitData, pDevName);
    if (status != OK)
        {
        (void)close (fd);
        return status;
        }

    /*
     * eject the current file system (HRFS, DOSFS, or even rawFS) and
     * instantiate rawFs
     */

    status = ioctl (fd, XBD_SOFT_EJECT, (_Vx_ioctl_arg_t)XBD_TOP);

    /* our FD is now invalid */

    (void)close (fd);

    if (status != OK)
        return status;

    /* wait for path to appear in core I/O */

    status = fsWaitForPath (&waitData);
    if (status != OK)
        return status;

    /* re-open volume on rawFs */

    fd = open (pDevName, O_RDWR, 0777);
    if (fd < 0)
        return ERROR;

    bzero ((char *)&info, sizeof (XBD_ENCRYPTION_INFO));
    (void)strncpy (info.keyId, pKeyId, sizeof (info.keyId) - 1);

    switch (operate)
        {
        case OPERATE_ENCRYPT:
            info.flags = XBD_DISK_ENCRYPTION_EN;
            break;

        case OPERATE_DECRYPT:
            info.flags = XBD_DISK_DECRYPTION_EN;
            break;

        default:
            info.flags = XBD_DISK_ENCRYPTION_EN | XBD_DISK_DECRYPTION_EN;
            break;
        }

    status = ioctl (fd, XBD_CFG_ENCRYPTION, (_Vx_ioctl_arg_t)&info);
    if (status != OK)
        goto cleanup;

    if (operate != OPERATE_MOUNT)
        {
        pBuf = malloc (bufSize);
        if (pBuf == NULL)
            {
            status = ERROR;
            goto cleanup;
            }

        readSize = (ssize_t)bufSize;
        (void)lseek (fd, 0, SEEK_SET);
        while (readSize == (ssize_t)bufSize)
            {
            readSize = read (fd, pBuf, bufSize);
            if (readSize <= 0)
                break;

            if (diskEncryptSeek (fd, -readSize) != OK)
                {
                status = ERROR;
                goto cleanup;
                }

            if (readSize != write (fd, pBuf, (size_t)readSize))
                {
                status = ERROR;
                goto cleanup;
                }
            }

        /* flush data to disk */

        (void)ioctl (fd, XBD_SYNC, 0);

        if (operate == OPERATE_ENCRYPT)
            info.flags = XBD_DISK_ENCRYPTION_EN | XBD_DISK_DECRYPTION_EN;
        else
            info.flags = 0;

        status = ioctl (fd, XBD_CFG_ENCRYPTION, (_Vx_ioctl_arg_t)&info);
        if (status != OK)
            goto cleanup;
        }

cleanup:
    /* register on the path instantiator event */

    if (fsPathAddedEventSetup (&waitData, pDevName) != OK)
        status = ERROR;

    /* kick off RAWFS so that other file system can be instantiated */

    if (ioctl (fd, XBD_HARD_EJECT, (_Vx_ioctl_arg_t)XBD_TOP) == OK)
        {
        /* wait for path to appear in core I/O */

        if (fsWaitForPath (&waitData) != OK)
            status = ERROR;
        }
    else
        status = ERROR;

    if (pBuf != NULL)
        free (pBuf);

    (void)close (fd);
    return status;
    }

/*******************************************************************************
*
* diskEncrypt - encrypt an entire disk partition
*
* This function encrypts an entire disk partition. Before encrypting, be sure
* that a valid file system has been instantiated on the partition. (dosFs or
* HRFS). Do not attempt to halt encryption while it is in process. Doing so will
* corrupt the data in the partition.
*
* ARGUMENTS
* \is
* \i pDevName
* pointer to the partition name
* \i pKeyId
* the key ID associated with the partition (which is used to fetch the master
* key from the secrets store).
* \ie
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*/

STATUS diskEncrypt
    (
    char *  pDevName,
    char *  pKeyId
    )
    {
    return diskEncryptInternal (pDevName, pKeyId, OPERATE_ENCRYPT);
    }

/*******************************************************************************
*
* diskDecrypt - decrypt an entire encrypted disk partition
*
* This function decrypts an entire encrypted disk partition. Be sure that the
* key ID and associated key are correct before calling the routine. Otherwise,
* the data on the partition will be corrupted. Do not attempt to halt decryption
* while it is in process. Doing so will corrupt the data in the partition.
*
* ARGUMENTS
* \is
* \i pDevName
* pointer to the partition name
* \i pKeyId
* the key ID associated with the partition (which is used to fetch the master
* key from the secrets store).
* \ie
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*/

STATUS diskDecrypt
    (
    char *  pDevName,
    char *  pKeyId
    )
    {
    return diskEncryptInternal (pDevName, pKeyId, OPERATE_DECRYPT);
    }

/*******************************************************************************
*
* diskMountCrypto - mount an encrypted disk partition
*
* This function mounts an encrypted disk partition. If you have not enabled
* auto-mounting, or if a mount operation has failed, you can call this routine
* to mount an encrypted partition at runtime (programmatically or from the
* kernel shell).
*
* ARGUMENTS
* \is
* \i pDevName
* pointer to the partition name
* \i pKeyId
* the key ID associated with the partition (which is used to fetch the master
* key from the secrets store).
* \ie
*
* RETURNS: OK if the operation was successfully performed, ERROR if it failed.
*
* ERRNO: N/A
*/

STATUS diskMountCrypto
    (
    char *  pDevName,
    char *  pKeyId
    )
    {
    return diskEncryptInternal (pDevName, pKeyId, OPERATE_MOUNT);
    }
