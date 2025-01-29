/* tmDiskEncryptTest.c - diskEncryption Test Module */

/*
 * Copyright (c) 2016-2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
DESCRIPTION

This is the test code for diskEncryption. It tests the following APIs:
	 diskMountCrypto()
	 diskEncrypt()
	 diskDecrypt()


TEST SPECIFICATIONS
\cs
<module>
    <modUnderTest> diskEncryption </modUnderTest>
    <component>  INCLUDE_TM_DISK_ENCRYPTION_TEST  </component>
    <minVxWorksVer> 7.0 </minVxWorksVer>
    <maxVxWorksVer> .* </maxVxWorksVer>
    <arch> .* </arch>
    <cpu> .* </cpu>
    <bsp> .* </bsp>
</module>
\ce

*/

#undef COVARAGE_TEST

#include <vxWorks.h>
#include <types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ioLib.h>
#include <iosLib.h>
#include <string.h>
#include <taskLib.h>
#include <private/taskLibP.h>
#include <drv/xbd/xbd.h>
#include <xbdRamDisk.h>
#include <xbdPartition.h>
#include <dosFsLib.h>
#include <private/dosFsLibP.h>
#include <rawFsLib.h>
#include <mount.h>
#include <fsEventUtilLib.h>
#include <secCrypto.h>
#include <secCrypto/secCipherXexAes.h>
#include <diskEncryption/diskEncryption.h>
#include <diskEncryptionTools.h>
#include <private/secVaultP.h>
#include <subsys/timer/vxbTimerLib.h>
#include <memLib.h>
#include <wdLib.h>
#include <semLib.h>
#include <vxTest.h>
#include <fsMonitor.h>
#include <sys/statfs.h>
/* typedefs */

#define SEC_VAULT_DEV_KEY_CNT       32

typedef struct secVaultDevData
    {
    DEV_HDR devHdr;
    char *  pKeyId[SEC_VAULT_DEV_KEY_CNT];
    char *  pKey[SEC_VAULT_DEV_KEY_CNT];
    int     keyIdLen[SEC_VAULT_DEV_KEY_CNT];
    int     keyLen[SEC_VAULT_DEV_KEY_CNT];
    int     curLocation[SEC_VAULT_DEV_KEY_CNT];
    int     curId;
    } SEC_VAULT_DEV_DATA;

typedef struct
    {
    device_t    dev;
    char *      fsName;
    UINT8 *     pBuf;
    UINT32      bufSize;
    SEM_ID      semBioDone;
    UINT32      bioError;
    } XBD_TEST_DESC;

/* scale */

#define KB                      (1024LL)
#define MB                      (1024LL*KB)
#define GB                      (1024LL*MB)
#define TB                      (1024LL*GB)
#define ONE_SECTOR_SIZE         (512)
#define DISK_CAP                (32*GB)
#define SAMPLE_ARRAY_LEN        (1024)
#define XBD_DEFAULT_BUF_SIZE    (2 * MB)

#ifdef _WRS_CONFIG_ARM
#define RAM0_DISK_SIZE MB*4
#define RAM1_DISK_SIZE MB*4
#else
#define RAM0_DISK_SIZE MB*4
#define RAM1_DISK_SIZE MB*16
#endif

#define TENCHARS            "1234567890"
#define RAM_DISK_SRC        "/ram0"
#define RAW_DISK            RAM_DISK_SRC
#define RAM_DISK_DST        "/ram1"
#define RAM_DISK_PART_0     RAM_DISK_DST ":1"
#define RAM_DISK_PART_1     RAM_DISK_DST ":2"
#define RAM_DISK_PART_2     RAM_DISK_DST ":3"
#define RAM_DISK_PART_3     RAM_DISK_DST ":4"

#define SATA_DOSFS_NAME     "DosFS"
#define SATA_RAWFS_NAME     "RawFS"
#define SATA_HRFS_NAME      "HRFS"
#define SATA_XBD_NAME       "XBD"

#define SATA_DEFAULT_AUX_CLK_RATE   1000

/* flags */

#define VALUE       0
#define RANDOM      1
#define ZERO        0
#define SEQUENCE    1
#define SAME        1
#define DIFF        0

/* debug */

#define LOG_FAILURE do\
{\
    (void) printf ("fail on %s:%d\n",__FILE__,__LINE__);\
}while(0)

#define LOG_HERE do\
{\
    (void) printf ("%s:%d\n",__FILE__,__LINE__);\
}while(0)

#undef DEBUG

#ifdef DEBUG
#define LOCAL
#endif

#undef DEBUG_CONTENT

#ifdef DEBUG_CONTENT

void printCtx(UINT8 *data, UINT size, int format)
    {
    int      i;
    UINT32   *d;
    switch (format)
        {
        case 1:
            for (i = 0; i < size; i++)
                (void) printf ("%02x", data[i]);
            break;
        case 8:
        default:
            d=(UINT32*) data;
            for (i = 0; i < size/4; i++)
                (void) printf ("%08x ",d[i]);
            break;
        }

    (void) printf ("\n");
    }

#else

void printCtx(UINT8 *data, UINT size, int format)
    {
    return;
    }

#endif

/* locals */

LOCAL BOOL              testInitRet;
LOCAL char *            secretId; /* secret ID used for testing */
LOCAL int               aesmode;
LOCAL WDOG_ID           wdId;
LOCAL SEM_ID            semId;
LOCAL BOOL              endFlag;
LOCAL UINT32            xbdClkTicks = 0;
LOCAL XBD_TEST_DESC     xbdTestHd;

#if 0

LOCAL void * secVaultIoOpen
    (
    SEC_VAULT_DEV_DATA *    pIoData,
    const char *            name,
    int                     flags,
    int                     mode
    );

LOCAL STATUS secVaultIoClose
    (
    SEC_VAULT_DEV_DATA * pIoData
    );

LOCAL size_t secVaultIoRead
    (
    SEC_VAULT_DEV_DATA *    pIoData,
    char *                  buffer,
    size_t                  nBytes
    );

LOCAL size_t secVaultIoWrite
    (
    SEC_VAULT_DEV_DATA *    pIoData,
    char *                  buffer,
    size_t                  nBytes
    );

LOCAL STATUS secVaultIoInit (void);

#endif

LOCAL void endPerfTest()
    {
    endFlag = TRUE;
    }

/*******************************************************************************
 *
 * xbdClockInt - interrupt routine of auxiliary clock
 *
 * This routine increases the tick count at the frequency of the auxiliary clock.
 *
 * RETURNS: N/A
 */

LOCAL void xbdClockInt (void)
    {
    xbdClkTicks++;
    }

/*******************************************************************************
 *
 * xbdClockInit - initialize auxiliary clock
 *
 * This routine initialize the auxiliary clock.
 *
 * RETURNS: OK or ERROR
 */

LOCAL STATUS xbdTestClockInit (void)
    {
    if (vxbAuxClkConnect ((FUNCPTR)xbdClockInt, 0) != OK)
        {
        LOG_FAILURE;
        return ERROR;
        }
    (void) vxbAuxClkRateSet (SATA_DEFAULT_AUX_CLK_RATE);
    (void) vxbAuxClkDisable ();
    xbdClkTicks = 0;
    return OK;
    }

#if 0
/*******************************************************************************
*
* xbdTestTimeSoFar - determine the current time
*
* This routine determines the current auxiliary clock time elapsed
*
* RETURNS: auxiliary clock time in seconds
*/

LOCAL double xbdTestTimeSoFar (void)
    {
    return ((double) xbdClkTicks) / ((double) vxbAuxClkRateGet ());
    }
#endif

/*******************************************************************************
*
* sataTestBioDone - callback function for BIO read/write
*
* This routine is the callback function for BIO read/write.
*
* RETURNS: N/A
*/

LOCAL void xbdTestBioDone
    (
    struct bio *    bioPtr
    )
    {
    XBD_TEST_DESC *    pXbdTest = &xbdTestHd;

    pXbdTest->bioError = bioPtr->bio_error;
    (void) semGive (pXbdTest->semBioDone);
    }

/*******************************************************************************
*
* xbdTestDevGet - find out the device handle by using device name
*
* This routine finds out the device handle by using device name.
*
* RETURNS: the device handle if successful, otherwise 0
*/

LOCAL device_t xbdTestDevGet
    (
    const char *        pDevName
    )
    {
    XBD_TEST_DESC *     pXbdTest = &xbdTestHd;
    int                 fd;
    struct statfs       buf = {0};

    if (NULL == pDevName)
        return NULLDEV;

    fd = open(pDevName, O_RDONLY, 0);

    if (fd < 0)
        {
        (void) printf("Error of accessing %s\n", pDevName);

        return NULLDEV;
        }

    if (fstatfs(fd, &buf) != OK)
        {
        (void) printf("Error of getting device information\n");

        (void) close(fd);

        return NULLDEV;
        }

    (void) close(fd);

    switch(buf.f_type)
        {
        case (long) DOS_FS_MAGIC:
            pXbdTest->fsName = SATA_DOSFS_NAME;
            break;
        case (long) RAW_FS_MAGIC:
            pXbdTest->fsName = SATA_RAWFS_NAME;
            break;
        case (long) HRFS_MAGIC:
            pXbdTest->fsName = SATA_HRFS_NAME;
            break;
        default:
            return NULLDEV;
        }

    return fsmDevGetByName ((char *)pDevName);
    }

/*******************************************************************************
*
* xbdTestXbdRW - read or write data by using XBD API
*
* This routine reads or writes data by using XBD API.
*
* RETURNS: OK if successful, otherwise ERROR
*/

LOCAL STATUS xbdTestXbdRW
    (
    UINT8 * buf,
    UINT32  size,
    UINT32  startBlock,
    BOOL    isWrite
    )
    {
    struct bio          bio;
    XBD_TEST_DESC *     pXbdTest = &xbdTestHd;

    memset(&bio, 0, sizeof(bio));

    if (isWrite)
        {
        bio.bio_flags   = BIO_WRITE;
        }
    else
        {
        bio.bio_flags   = BIO_READ;
        }

    bio.bio_dev     = pXbdTest->dev;
    bio.bio_data    = (void *)buf;
    bio.bio_done    = xbdTestBioDone;
    bio.bio_caller1 = NULL;
    bio.bio_chain   = NULL;
    bio.bio_bcount  = size;
    bio.bio_blkno   = startBlock;
    bio.bio_error   = OK;
    bio.bio_resid   = 0;

    (void) xbdStrategy (bio.bio_dev, &bio);
    (void) semTake (pXbdTest->semBioDone, WAIT_FOREVER);

    if (pXbdTest->bioError != 0)
        {
        pXbdTest->bioError = 0;
        return ERROR;
        }
    else
        {
        return OK;
        }
    }

#if 0
LOCAL void bcopyTest
    (
    char * buf,
    UINT32  size,
    int testTime
    )
    {
    char * src=buf+KB;
    char * dst=buf;
    double xbdSpeed;
    UINT64 testCount=0;
    endFlag = FALSE;
    wdStart (wdId,sysClkRateGet()*testTime,(FUNCPTR)endPerfTest,0);

    while(endFlag==FALSE)
        {
        bcopy (src,dst,size);
        testCount++;
        }

    xbdSpeed = (double)(((double)size * (double)testCount) / (testTime));
    xbdSpeed = (double)((double)xbdSpeed / ((double)MB));
    (void) printf ("in bcopyTest: size=%d\tspeed=%5.2f(M/S)\ttestCount=%llu\n",
            size, xbdSpeed,testCount);
    }

LOCAL void bcopyTest2
    (
    char * buf,
    UINT32  size,
    int testTime
    )
    {
    char * src=(char*)malloc(4*MB);
    char * dst=(char*)malloc(4*MB);
    double xbdSpeed;
    UINT64 testCount=0;
    endFlag = FALSE;

    offset = (offset+4) & (2*MB-1);

    src += offset;
    dst += offset;
    wdStart (wdId,sysClkRateGet()*testTime,(FUNCPTR)endPerfTest,0);

    while(endFlag==FALSE)
        {
        bcopy (src,dst,size);
        testCount++;
        }

    xbdSpeed = (double)(((double)size * (double)testCount) / (testTime));
    xbdSpeed = (double)((double)xbdSpeed / ((double)MB));
    (void) printf ("in bcopyTest2: size=%d\tspeed=%5.2f(M/S)\ttestCount=%llu\n",
            size, xbdSpeed,testCount);
    free (src);
    free (dst);
    }
#endif

#if USE_AUXCLK

LOCAL void bcopyTest
    (
    UINT8 * buf,
    UINT32  size,
    int testTimes
    )
    {
    char * src=buf;
    char * dst=buf+KB;
    double xbdSpeed;
    int  i;

    xbdClkTicks = 0;
    vxbAuxClkEnable ();
    for (i=0; i<testTimes; i++)
        {
        bcopy (src,dst,size);
        }
    vxbAuxClkDisable ();

    xbdSpeed = (double)(((double)size * (double)testTimes) /
                (xbdTestTimeSoFar()));
    xbdSpeed = (double)((double)xbdSpeed / ((double)MB));
    (void) printf ("\tbcopy() speed=%5.2f\n", xbdSpeed);
    (void) printf ("in bcopyTest: size=%d xbdClkTicks = %d\n\n",size,xbdClkTicks);
    }
#endif

/* externs */

extern const SEC_CIPHER_TEMPLATE * diskEncrLibXexAesTemplateGet (void);

extern STATUS secCipherInit
    (
    SEC_CIPHER_CTX* ctx,
    const SEC_CIPHER_TEMPLATE* template,
    const unsigned char* key,
    const unsigned char* iv,
    const int encr
    );

STATUS secCipherCleanup
    (
    SEC_CIPHER_CTX* ctx
    );

extern STATUS hrfsFormat
    (
    char *      path,
    UINT64      diskSize,
    UINT32      blkSize,
    UINT32      numInodes
    );
extern STATUS ls
    (
    const char *    dirName,
    BOOL            doLong
    );

/*
 * Test codes
 *
 * */

#ifdef COVARAGE_TEST

STATUS secCipherInitStub
    (
    SEC_CIPHER_CTX* ctx,
    const SEC_CIPHER_TEMPLATE* template,
    const unsigned char* key,
    const unsigned char* iv,
    const int encr
    )
    {
    STATUS ret;
    if (diskEncrLibXexAesTemplateGet () == template)
        return ERROR;
    else
        {
        tdkCertFuncUnstub ((void*)secCipherInit);
        ret = secCipherInit (ctx, template, key, iv, encr);
        tdkCertFuncStub ((void*)secCipherInit, (void*)secCipherInitStub);
        return ret;
        }
    }

LOCAL int secCipherCleanupCall=0;

LOCAL STATUS secCipherCleanupStub
    (
    SEC_CIPHER_CTX* ctx
    )
    {
    STATUS ret;
    secCipherCleanupCall++;
    tdkCertFuncUnstub ((void*)secCipherCleanup);
    ret = secCipherCleanup (ctx);
    tdkCertFuncStub ((void*)secCipherCleanup, (void*)secCipherCleanupStub);
    return ret;
    }
#endif

LOCAL void inputSecVault(char * keyID, char *key, int keyLen)
    {
    char   input[64];
    char * in;
    int    i=0;
    STATUS  ret;

    in=input;
    bzero(input,64);

    while (i<keyLen*2)
        {
        long x;
        char byte[3];
        byte[0]=key[i];
        byte[1]=key[i+1];
        byte[2]=0;
        x = strtol(byte,NULL,16);
        *in=(char)x;
        in++;
        i+=2;
        }

    ret = secSecretImport (keyID,input, keyLen);
    if (ret != OK)
        {
        (void) printf ("secVaultImport fail, erron = %d\n",errno);
        }
    }

/* calculations */

LOCAL STATUS cmpData
    (
    void * pData1,
    void * pData2,
    size_t size,
    int    sameflag
    )
    {
    if (sameflag == SAME)
        {
        if (0 != memcmp(pData1, pData2, size))
            {
            LOG_FAILURE;
            return ERROR;
            }
        }
    else
        {
        if (0 == memcmp(pData1, pData2, size))
            {
            LOG_FAILURE;
            return ERROR;
            }
        }
    return OK;
    }

#ifdef DEBUG_CONTENT
LOCAL UINT32 test[SAMPLE_ARRAY_LEN][4][2];
void printTest()
{
    int i,j;
    for (i=0;i<128;i++)
        {
        (void) printf("[%d]:  ",i);
        for(j=0;j<4;j++)
            {
            (void) printf("[%02x,%02x] ",test[i][j][0],test[i][j][1]);
            }
        (void) printf("\n");
        }
}
#endif

void unSetEncrypt
    (
    char * pDevName
    )
    {
    XBD_ENCRYPTION_INFO info;
    int fd;

    bzero ((char *)&info, sizeof (XBD_ENCRYPTION_INFO));

    fd = open (pDevName, O_RDWR, 0777);
    if (fd>=0)
        {
        (void) ioctl (fd, (int)XBD_CFG_ENCRYPTION, (_Vx_ioctl_arg_t)&info);
        (void) close (fd);
        }
    }

STATUS reMountPartition
    (
    char * pDevName
    )
    {
    FS_PATH_WAIT_STRUCT waitData;
    int                 fd;
    STATUS       status;

    fsmName_t basePath;
    devname_t xbdName;

    /* code refer xbdCreatePartition() */

    fd = open (pDevName, O_RDONLY, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        (void) printf ("\n\nopen %s fail\n\n", pDevName);
        return ERROR;
        }

    (void) ioctl(fd, (int)XBD_GETBASENAME, (_Vx_ioctl_arg_t)xbdName);

    (void) fsmNameMap(xbdName, basePath);

    status = fsPathAddedEventSetup (&waitData, basePath);
    if (status != OK)
        {
        LOG_FAILURE;
        (void) close (fd);
        return ERROR;
        }

    status = ioctl (fd, (int)XBD_SOFT_EJECT, (_Vx_ioctl_arg_t)XBD_BASE);

    status = fsWaitForPath (&waitData);
    if (status != OK)
        {
        (void) close(fd);
        return ERROR;
        }

    (void) close (fd);

    fd = open(basePath, O_RDWR, 0);
    if (fd  < 0)
        {
        LOG_FAILURE;
        return ERROR;
        }

    (void) fsPathAddedEventSetup(&waitData, pDevName);

    (void) ioctl(fd, (int)XBD_HARD_EJECT, XBD_BASE);

    status = fsWaitForPath (&waitData);
    if (status != OK)
        {
        (void) close(fd);
        return ERROR;
        }

    (void) close(fd);

    (void)taskDelay (sysClkRateGet() * 2);
    return OK;
    }

void initPartitions()
    {
    unSetEncrypt(RAM_DISK_PART_0);
    unSetEncrypt(RAM_DISK_PART_1);
    unSetEncrypt(RAM_DISK_PART_2);
    unSetEncrypt(RAM_DISK_PART_3);
    (void) dosFsVolFormat (RAM_DISK_PART_0,0,NULL);
    (void) dosFsVolFormat (RAM_DISK_PART_1,0,NULL);
    (void) hrfsFormat (RAM_DISK_PART_2,0L,0L,0L);
    (void) hrfsFormat (RAM_DISK_PART_3,0L,0L,0L);
    (void) mkdir (RAM_DISK_PART_0 "/r1", 0777);
    (void) mkdir (RAM_DISK_PART_1 "/r2", 0777);
    (void) mkdir (RAM_DISK_PART_2 "/r3", 0777);
    (void) mkdir (RAM_DISK_PART_3 "/r4", 0777);
    }


LOCAL void initContent
    (
    UINT32 *   pData,
    UINT32     inLen,
    int        randFlag,
    UINT32     val
    )
    {
    size_t i;

    for (i = 0; i < (inLen / sizeof (UINT32)); i++)
        {
        switch (randFlag){
            case VALUE:
                *(pData + i) = val;
                break;
            case RANDOM:
                /* coverity[secure_coding] */
                *(pData + i) = (UINT32)rand();
                break;
            }
        }
    }

LOCAL STATUS writePartition(char * name, int flag)
    {
    int     fd;
    char    buf[ONE_SECTOR_SIZE];
    ssize_t writeLen;

    fd = open (name, O_RDWR, 0777);
    if (fd < 0)   return ERROR;
    (void) lseek (fd, 0, SEEK_SET);

    if (flag == ZERO)
        {
        bzero (buf, ONE_SECTOR_SIZE);
        do {
            writeLen = write(fd, buf, ONE_SECTOR_SIZE);  /* clean the partition */
            }while (writeLen > 0);
        }
    else
        {
        int i=0;
        UINT32 secNum=0;
        UINT32 *b=(UINT32*)buf;
        do {
            for (i=0; i<ONE_SECTOR_SIZE/4; i++)
                {
                b[i]=secNum;
                }
                writeLen = write(fd, buf, ONE_SECTOR_SIZE);  /* write sector by sector */
                secNum++;
            }while (writeLen > 0);
        }

    (void)(void) close(fd);

    return OK;
    }

void prSector(int fd,UINT64 secNumA,UINT64 secNumB)
    {
    char    buf[512];
    ssize_t len;

    bzero(buf,512);
    (void) lseek (fd, (off_t)(secNumA*512), SEEK_SET);
    len = read (fd,buf,512);
    if (len<0)
        {
        LOG_FAILURE;
        return;
        }
    (void) printf("====sector [%llu]=======\n",secNumA);
    printCtx ((UINT8*)buf, 512, 8);
    (void) printf("\n");

    bzero(buf,512);
    (void) lseek (fd, (off_t)(secNumB*512), SEEK_SET);

    len = read (fd,buf,512);
    if (len<0)
        {
        LOG_FAILURE;
        return;
        }

    (void) printf("====sector [%llu]=======\n",secNumB);
    printCtx ((UINT8*)buf, 512, 8);
    (void) printf("\n");
    }

void psec(char *device)
    {
    int fd;
    fd=open(device, 0, 0777);
    if (fd>=0) prSector (fd,100LL,101LL);
    else return;
    (void) close (fd);
    }
#if 0
/*****************************************************************************
 *  psudo secvault
 * ***************************************************************************/

LOCAL void * secVaultIoOpen
    (
    SEC_VAULT_DEV_DATA *    pIoData,
    const char *            name,
    int                     flags,
    int                     mode
    )
    {
    char *  pCurStr;
    char *  pKeyId;
    char *  pString;
    int     i;
    BOOL    found = FALSE;

    pString = calloc (1, (strlen (name) + 1));
    if (pString == NULL)
        return (void *)ERROR;

    (void)strncpy (pString, name, strlen (name));

    pCurStr = strtok (pString, "/");
    if (pCurStr == NULL)
        {
        free (pString);
        return (void *)ERROR;
        }

    while (pCurStr != NULL)
        {
        pKeyId = pCurStr;
        pCurStr = strtok (NULL, "/");
        }

    for (i = 0; i < SEC_VAULT_DEV_KEY_CNT; i++)
        {
        if (strncmp (pKeyId, pIoData->pKeyId[i], strlen (pKeyId)) == 0)
            {
            pIoData->curId = i;
            found = TRUE;
            break;
            }
        }

    if (found)
        {
        if (((flags == O_RDONLY) && (pIoData->pKey[pIoData->curId] == NULL)) ||
            ((flags == O_WRONLY) && (pIoData->pKey[pIoData->curId] != NULL)))
            {
            free (pString);
            return (void *)ERROR;
            }
        else
            {
            free (pString);
            pIoData->curLocation[pIoData->curId] = 0;
            return (void *)pIoData;
            }
        }
    else
        {
        free (pString);
        return (void *)ERROR;
        }
    }

LOCAL STATUS secVaultIoClose
    (
    SEC_VAULT_DEV_DATA * pIoData
    )
    {
    return OK;
    }

LOCAL size_t secVaultIoRead
    (
    SEC_VAULT_DEV_DATA *    pIoData,
    char *                  buffer,
    size_t                  nBytes
    )
    {
    int readBytes;

    if ((nBytes <= 0) || (pIoData->keyLen[pIoData->curId] <= 0))
        return 0;

    readBytes = pIoData->keyLen[pIoData->curId] -
                pIoData->curLocation[pIoData->curId];

    if (readBytes > (int)nBytes)
        readBytes = (int)nBytes;

    if ((pIoData->pKey[pIoData->curId] != NULL) && (readBytes > 0))
        {
        bcopy (pIoData->pKey[pIoData->curId], buffer, readBytes);
        pIoData->curLocation[pIoData->curId] += readBytes;
        if (pIoData->curLocation[pIoData->curId] >
            pIoData->keyLen[pIoData->curId])
            pIoData->curLocation[pIoData->curId] =
                pIoData->keyLen[pIoData->curId];
        return readBytes;
        }
    else
        return 0;
    }

LOCAL size_t secVaultIoWrite
    (
    SEC_VAULT_DEV_DATA *    pIoData,
    char *                  buffer,
    size_t                  nBytes
    )
    {
    if ((nBytes <= 0) || (pIoData->pKey[pIoData->curId] != NULL))
        return 0;

    pIoData->pKey[pIoData->curId] = calloc (1, nBytes);
    if (pIoData->pKey[pIoData->curId] == NULL)
        return 0;

    bcopy (buffer, pIoData->pKey[pIoData->curId], nBytes);
    pIoData->keyLen[pIoData->curId] = (int)nBytes;

    return nBytes;
    }
LOCAL STATUS secVaultIoInit (void)
    {
    int                     drvNum = ERROR;
    int                     i;
    SEC_VAULT_DEV_DATA *    pIoData;

    pIoData = calloc (1, sizeof (SEC_VAULT_DEV_DATA));
    if (pIoData == NULL)
        return ERROR;

    drvNum = iosDrvInstall (NULL,                           /* creat() */
                            NULL,                           /* remove() */
                            (DRV_OPEN_PTR)secVaultIoOpen,   /* open() */
                            (DRV_CLOSE_PTR)secVaultIoClose, /* close() */
                            (DRV_READ_PTR)secVaultIoRead,   /* read() */
                            (DRV_WRITE_PTR)secVaultIoWrite, /* write() */
                            NULL);                          /* ioctl() */

    if (ERROR == drvNum)
        goto error;

    if (ERROR == iosDevAdd (&(pIoData->devHdr), "/ram", drvNum))
        goto error;

    for (i = 0; i < SEC_VAULT_DEV_KEY_CNT; i++)
        {
        pIoData->pKeyId[i] = calloc (1, SEC_VAULT_KEY_ID_MAX);
        if (pIoData->pKeyId[i] == NULL)
            goto error;

        (void) snprintf (pIoData->pKeyId[i], SEC_VAULT_KEY_ID_MAX, "%d", i);
        }

    return OK;

error:
    if (NULL != pIoData->devHdr.name)
        (void)iosDevDelete (&(pIoData->devHdr));

    if (ERROR != drvNum)
        (void)iosDrvRemove (drvNum, FALSE);

    for (i = 0; i < SEC_VAULT_DEV_KEY_CNT; i++)
        {
        if (pIoData->pKeyId[i] != NULL)
            free (pIoData->pKeyId[i]);
        }

    free (pIoData);
    return ERROR;
    }
#endif

LOCAL void tmDiskEncryptionTestInitTask()
    {
    char * key0;
    int   keyLen;
    char * key10;
    char * key11;
    char * key12;
    char * key13;
    XBD_TEST_DESC * pXbdTest = &xbdTestHd;
    UINT8 data;

    (void) taskDelay (5);

    if (diskEncrLibXexAesTemplateGet() == secCipherAes128EcbTemplateGet())
        {
        keyLen = 32;
        key0 = "2718281828459045235360287471352631415926535897932384626433832795";
        key10="1111111111111111111111111111111111111111111111111111111111111111";
        key11="2222222222222222222222222222222222222222222222222222222222222222";
        key12="3333333333333333333333333333333333333333333333333333333333333333";
        key13="4444444444444444444444444444444444444444444444444444444444444444";
        secretId = "0";
        (void) printf ("use AES-128-ECB mode\n");
        aesmode = 0;
        }
    else
        {
        keyLen = 64;
        key0 = "27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592";
        key10="11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        key11="22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
        key12="33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
        key13="44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444";
        secretId = "0";
        (void) printf ("use AES-256-ECB mode\n");
        aesmode = 1;
        }

   /* (void) secVaultIoInit ();*/
    inputSecVault ("0",key0,keyLen);
    inputSecVault ("10",key10,keyLen);
    inputSecVault ("11",key11,keyLen);
    inputSecVault ("12",key12,keyLen);
    inputSecVault ("13",key13,keyLen);

    wdId = wdCreate ();
    semId = semBCreate (SEM_Q_PRIORITY, SEM_EMPTY);

    if (xbdTestClockInit () != OK)
        {
        LOG_FAILURE;
        goto err_ret;
        }

    bzero ((char *)pXbdTest, sizeof (XBD_TEST_DESC));
    pXbdTest->bufSize  = XBD_DEFAULT_BUF_SIZE;
    pXbdTest->pBuf     = (UINT8 *)malloc (pXbdTest->bufSize);
    if (pXbdTest->pBuf == NULL)
        {
        LOG_FAILURE;
        goto err_ret;
        }

    /* coverity[secure_coding] */
    data = (UINT8)(rand () % 0xFF);
    memset ((void *)pXbdTest->pBuf, data, pXbdTest->bufSize);

    pXbdTest->semBioDone = semBCreate (SEM_Q_PRIORITY, SEM_EMPTY);
    if (pXbdTest->semBioDone == NULL)
        {
        LOG_FAILURE;
        goto err_ret;
        }

    (void) xbdRamDiskDevCreate (512, RAM0_DISK_SIZE, TRUE, RAM_DISK_SRC);
    (void) xbdRamDiskDevCreate (512, RAM1_DISK_SIZE, TRUE, RAM_DISK_DST);
    (void) xbdCreatePartition (RAM_DISK_DST,4,25,25,25);

    testInitRet = OK;
    (void) printf ("tmDiskEncryptionTestInit OK!\n");
    return;

 err_ret:
    testInitRet = ERROR;
    return;
    }

void tmDiskEncryptionTestInit()
    {
    (void) taskSpawn ("tmDiskEncryptionTestInitTask",49,0,(size_t)4096,
               (FUNCPTR)tmDiskEncryptionTestInitTask,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0,
                   (_Vx_usr_arg_t)0);
    }

#if 0
void viho()
    {
    char *key0;
    int   key0Len;
    char *key10="1111111111111111111111111111111111111111111111111111111111111111";
    char *key11="2222222222222222222222222222222222222222222222222222222222222222";
    char *key12="3333333333333333333333333333333333333333333333333333333333333333";
    char *key13="4444444444444444444444444444444444444444444444444444444444444444";
    XBD_TEST_DESC * pXbdTest = &xbdTestHd;
    UINT8 data;

    if (diskEncrLibXexAesTemplateGet() == secCipherAes128EcbTemplateGet())
        {
        key0 = "2718281828459045235360287471352631415926535897932384626433832795";
        key0Len = 32;
        secretId = "0";
        (void) printf ("use AES-128-ECB mode\n");
        aesmode = 0;
        }
    else
        {
        key0 = "27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592";
        key0Len = 64;
        secretId = "0";
        (void) printf ("use AES-256-ECB mode\n");
        aesmode = 1;
        }

    secVaultIoInit ();
    inputSecVault ("0",key0,key0Len);
    inputSecVault ("10",key10,32);
    inputSecVault ("11",key11,32);
    inputSecVault ("12",key12,32);
    inputSecVault ("13",key13,32);

    wdId = wdCreate ();
    semId = semBCreate (SEM_Q_PRIORITY, SEM_EMPTY);

    if (xbdTestClockInit () != OK)
        {
        LOG_FAILURE;
        goto err_ret;
        }
    LOG_FAILURE;
    bzero ((char *)pXbdTest, sizeof (XBD_TEST_DESC));
    pXbdTest->bufSize  = XBD_DEFAULT_BUF_SIZE;
    pXbdTest->pBuf     = (UINT8 *)malloc (pXbdTest->bufSize);
    if (pXbdTest->pBuf == NULL)
        {
        LOG_FAILURE;
        goto err_ret;
        }
    LOG_FAILURE;
    data = (UINT8)(rand () % 0xFF);
    memset ((void *)pXbdTest->pBuf, data, pXbdTest->bufSize);

    pXbdTest->semBioDone = semBCreate (SEM_Q_PRIORITY, SEM_EMPTY);
    if (pXbdTest->semBioDone == NULL)
        {
        LOG_FAILURE;
        goto err_ret;
        }

    LOG_FAILURE;
    xbdRamDiskDevCreate (512, 1024 * 1024 * 4, TRUE, RAM_DISK_SRC);
    xbdRamDiskDevCreate (512, 1024 * 1024 * 4, TRUE, RAM_DISK_DST);
    xbdCreatePartition (RAM_DISK_DST,4,25,25,25);

    testInitRet = OK;
    (void) printf ("tmDiskEncryptionTestInit OK!\n");
    return;

 err_ret:
    testInitRet = ERROR;
    return;
    }
#endif


/*****************************************************************************
 *  test cases
 * ***************************************************************************/

typedef struct {
    char *  ptxfile;
    char *  ctxfile;
    UINT32  sector;
    char *  casename;
}ALG_TEST_DATA;

ALG_TEST_DATA algTestData[] = {
    {
    "/romfs/aes_128/ptx1.txt",
    "/romfs/aes_128/ctx1.txt",
    0,
    "XEX_AES_128_algorismTest_1"
    },
    {
    "/romfs/aes_128/ptx2.txt",
    "/romfs/aes_128/ctx2.txt",
    1,
    "XEX_AES_128_algorismTest_2"
    },
    {
    "/romfs/aes_128/ptx3.txt",
    "/romfs/aes_128/ctx3.txt",
    2,
    "XEX_AES_128_algorismTest_3"
    },
    {
    "/romfs/aes_128/ptx4.txt",
    "/romfs/aes_128/ctx4.txt",
    3,
    "XEX_AES_128_algorismTest_4"
    },
    {
    "/romfs/aes_128/ptx5.txt",
    "/romfs/aes_128/ctx5.txt",
    4,
    "XEX_AES_128_algorismTest_5"
    },
    {
    "/romfs/aes_128/ptx6.txt",
    "/romfs/aes_128/ctx6.txt",
    5,
    "XEX_AES_128_algorismTest_6"
    },
    {
    "/romfs/aes_256/ptx1.txt",
    "/romfs/aes_256/ctx1.txt",
    0,
    "XEX_AES_256_algorismTest_1"
    },
    {
    "/romfs/aes_256/ptx2.txt",
    "/romfs/aes_256/ctx2.txt",
    1,
    "XEX_AES_256_algorismTest_2"
    },
    {
    "/romfs/aes_256/ptx3.txt",
    "/romfs/aes_256/ctx3.txt",
    2,
    "XEX_AES_256_algorismTest_3"
    },
    {
    "/romfs/aes_256/ptx4.txt",
    "/romfs/aes_256/ctx4.txt",
    3,
    "XEX_AES_256_algorismTest_4"
    },
    {
    "/romfs/aes_256/ptx5.txt",
    "/romfs/aes_256/ctx5.txt",
    4,
    "XEX_AES_256_algorismTest_5"
    },
    {
    "/romfs/aes_256/ptx6.txt",
    "/romfs/aes_256/ctx6.txt",
    5,
    "XEX_AES_256_algorismTest_6"
    }
};

STATUS XEX_AES_algorismTest_helper(int testItem)
    {
    char                out[1]; /*buffer for writing to disk*/
    char                in[3]; /*buffer for reading from disk */
    char                rdback[512]; /*cypher text used for compare*/
    UINT8               ctx[512];
    int                 fd1=-1;
    int                 fd2=-1;
    int                 i;
    ssize_t             redLen;
    char *              ptxfile;
    char *              ctxfile;
    char *              casename;
    UINT32              sector;
    STATUS              stat = 0, ret;

    ptxfile = algTestData[testItem].ptxfile;
    ctxfile = algTestData[testItem].ctxfile;
    sector = algTestData[testItem].sector;
    casename = algTestData[testItem].casename;

    (void) printf ("\n\n############################\n"
                 "%s\n"
                  "############################\n\n",casename);

    /* read the correct cypher text to buffer*/

    bzero(ctx,512);
    fd1 = open(ctxfile,O_RDONLY, 0777);
    if (fd1<0)
        {
        LOG_FAILURE;
        stat = ERROR;
        goto cleanup;
        }

    for (i=0;i<512;i++)
    {
        long x;
            ssize_t len;
        len = read(fd1,in,2);
        if (len>0)
        {
            in[2]='\0';
            x = strtol(in,NULL,16);
            ctx[i]=(UINT8)x;
        }
    }
    (void) close(fd1);

    /* write plain text to disk */

    unSetEncrypt(RAW_DISK);

    fd1 = open(ptxfile,O_RDONLY, 0777);
    fd2 = open (RAW_DISK, O_RDWR, 0777);

    if (fd1<0 || fd2<0)
        {
        LOG_FAILURE;
        goto cleanup;
        }

    /* seek to the test sector */

    (void) lseek (fd2, (off_t)(sector*ONE_SECTOR_SIZE), SEEK_SET);

#ifdef  DEBUG_CONTENT
    (void) printf("plain data on sector [%d]:\n\n",sector);
#endif
    for (i=0;i<512;i++)
    {
        long x;
            ssize_t len;
        len = read(fd1,in,2); /* read two chars to make a byte*/
        if (len>0)
            {
            in[2]='\0';
            x = strtol(in,NULL,16);
            out[0] = (char)x;
#ifdef  DEBUG_CONTENT
        (void) printf ("%02x",(UINT8)out[0]);
#endif
            (void) write(fd2,out,1);
            }
    }
    (void) close(fd1);
    (void) close(fd2);
    fd1=-1;
    fd2=-1;

#ifdef  DEBUG_CONTENT
    (void) printf("\n\nexpected cypher data on sector [%d]:\n\n",sector);
    printCtx((UINT8*)ctx, 512, 1);
#endif

    ret = diskEncrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = ERROR;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd2 = open (RAW_DISK, O_RDWR, 0777);
    if (fd2<0)
        {
        LOG_FAILURE;
        stat = ERROR;
        goto cleanup;
        }

    (void) lseek (fd2, (off_t)(sector*ONE_SECTOR_SIZE), SEEK_SET);

    bzero(rdback,512);
    redLen = read(fd2,rdback,512);
    if (redLen <=0 )
        {
        LOG_FAILURE;
        stat = ERROR;
        goto cleanup;
        }

    ret = cmpData (ctx, rdback, ONE_SECTOR_SIZE, SAME);

#ifdef  DEBUG_CONTENT
    (void) printf ("\ncypher data on sector [%d]:\n\n", sector);
    printCtx((UINT8*)rdback, 512, 1);
#endif

    if (ret == ERROR)
          {
          LOG_FAILURE;
          (void) printf ("===contents are not correctly encrypted===\n");
          for (i=0;i<512;i++)
              {
              (void) printf("[%02x %02x]",(UINT8)ctx[i],(UINT8)rdback[i]);
              if (ctx[i]!=rdback[i])
                  {
                  (void) printf ("\ndifferent at byte [%d]\n",i);
                  break;
                  }
              }
          stat = ERROR;
          goto cleanup;
          }

    stat = OK;
cleanup:
    if (fd1>=0) (void) close(fd1);
    if (fd2>=0) (void) close(fd2);
    return stat;
    }

/****************************************************************************
 *  aesmode == 0: aes-128
 *  aesmode == 1: aes-256
 * */

void XEX_AES_algorismTest()
    {
    int     i;

    if (aesmode == 0)
        {
        for (i=0;i<6;i++)
            {
            (void) XEX_AES_algorismTest_helper(i);
            }
        }
    else
        {
        for (i=6;i<12;i++)
            {
            (void) XEX_AES_algorismTest_helper(i);
            }
        }
    return;
    }

#if 0
void XEX_AES_algorismTest_gen(char * secret)
    {
    char                out[1]; /*buffer for writing to disk*/
    UINT8               ctx[512]; /*cypher text used for compare*/
    char                rdback[512];
    int                 fd2;
    int                 i,j;
    UINT32              sector;

    if (secret == NULL)
        {
        (void) printf ("lack of secret\n");
        return ;
        }

    sector=0;

    /* write plain text to disk */

    unSetEncrypt(RAW_DISK);

    fd2 = open (RAW_DISK, O_RDWR, 0777);

    /* seek to the test sector */

    (void) lseek (fd2, sector*ONE_SECTOR_SIZE, SEEK_SET);

#ifdef  DEBUG_CONTENT
    (void) printf("plain data on sector [%d]:\n\n",sector);
#endif
    for (i=511;i>=0;i--)
    {
        out[0]=(char)i;
        write(fd2,out,1);
    }

    (void) lseek (fd2, sector*ONE_SECTOR_SIZE, SEEK_SET);

    (void) read(fd2,(char*)ctx,512);

    (void) printf ("\n\n############################\n"
            "\nplain data on sector [%d]:\n\n"
            "############################\n\n", sector);

    printCtx(ctx,512,1);
    (void) close(fd2);

    (void) diskEncrypt(RAW_DISK,secretId);

    for (j=0;j<6;j++,sector++)
        {
        unSetEncrypt(RAW_DISK);

        /* read the cypher data of this sector */

        fd2 = open (RAW_DISK, O_RDWR, 0777);
    (void) lseek (fd2, sector*ONE_SECTOR_SIZE, SEEK_SET);
        bzero(rdback,512);
    (void) read(fd2,rdback,512);
        (void) printf ("\n\n############################\n"
                "\ncypher data on sector [%d]:\n\n"
                "############################\n\n", sector);
        printCtx ((UINT8*)rdback, 512, 1);

        /* write the cypher to next sector has plain text */

    (void) lseek (fd2, (sector+1)*ONE_SECTOR_SIZE, SEEK_SET);
        write(fd2,rdback,512);
        (void) close(fd2);

        (void) diskEncrypt(RAW_DISK,secretId);
        }

    return;
    }
#endif


LOCAL STATUS diskEncryptTest2_helper(int fd)
    {
    int             i;
    ssize_t         len;
    STATUS          ret;
    char *          buf;
    char            *b1, *b2;
    UINT64          secId1=0,secId2=0;
    UINT64          totalSectors = RAM0_DISK_SIZE/ONE_SECTOR_SIZE;
    STATUS          stat=ERROR;

    buf = (char*)malloc(2*ONE_SECTOR_SIZE);
    if (buf == NULL)
        {
        stat = ERROR;
        goto cleanup;
        }

    for (i=0; i<128; i++)
         {
         int c=0;
         /* coverity[secure_coding] */
         secId1 = (UINT64)rand() % totalSectors;
         do{
           if (c++ > 1000) break;
         /* coverity[secure_coding] */
           secId2 = (UINT64)rand() % totalSectors;
         }while (secId1 == secId2 || secId1 == totalSectors || secId2 == totalSectors);

        (void) lseek (fd, (off_t)(secId1*ONE_SECTOR_SIZE), SEEK_SET);
        (void) lseek (fd, (off_t)(secId2*ONE_SECTOR_SIZE), SEEK_SET);
        len = read(fd, buf, ONE_SECTOR_SIZE);
        if (len<=0)
            {
            LOG_FAILURE;
            stat = ERROR;
            goto cleanup;
            }
        len = read(fd, (char*)(buf+ONE_SECTOR_SIZE), ONE_SECTOR_SIZE);
        if (len<=0)
            {
            LOG_FAILURE;
            stat = ERROR;
            goto cleanup;
            }

         /* compare the result */

         b1 = (char*)(buf);
         b2 = (char*)(buf+ONE_SECTOR_SIZE);
#ifdef DEBUG_CONTENT
         printCtx ((UINT8*)b1, 4, 8);
         printCtx ((UINT8*)b2, 4, 8);
         (void) printf ("\n\n");
#endif
         ret = cmpData (b1, b2, ONE_SECTOR_SIZE, DIFF);
         if (ret == ERROR)
              {
              LOG_FAILURE;
              (void) printf ("sector contents are the same:[%llu]==[%llu]\n",secId1,secId2);
              prSector(fd,secId1,secId2);
              stat = ERROR;
              goto cleanup;
              }
         }

    stat = OK;
cleanup:
    if (buf != NULL) free(buf);
    return stat;
    }

LOCAL STATUS diskEncryptTest3_helper(int fd)
    {
    ssize_t         readLen;
    STATUS          ret;
    char            buf[512],cmpbuf[512];
    UINT32          secId = 0;
    STATUS          stat=ERROR;

    do{
      readLen = read(fd, buf, ONE_SECTOR_SIZE);
      if (readLen == 0) break;
      initContent ((UINT32*)cmpbuf, ONE_SECTOR_SIZE, VALUE,secId);
      ret = cmpData (buf, cmpbuf, ONE_SECTOR_SIZE, SAME);
      if (ret == ERROR)
            {
            LOG_FAILURE;
            (void) printf ("sector [%u] contents are NOT DEcrypted\n",secId);
            printCtx((UINT8*)buf,512,8);
            stat = ERROR;
            goto cleanup;
            }
      secId++;
    }while (readLen>0);

    stat = OK;
cleanup:
    return stat;
    }

LOCAL STATUS diskEncryptTest4_helper(int fd)
    {
    ssize_t writeLen;
    STATUS  ret;
    char    buf[512],cmpbuf[512];
    UINT32  secId = 0;
    ssize_t readLen;
    STATUS  stat=ERROR;

    do{
      initContent ((UINT32*)buf, ONE_SECTOR_SIZE, VALUE, secId);
      initContent ((UINT32*)cmpbuf, ONE_SECTOR_SIZE, VALUE, secId);

    (void) lseek (fd, (off_t)(secId*ONE_SECTOR_SIZE), SEEK_SET);
      writeLen = write(fd, buf, ONE_SECTOR_SIZE);
      if (writeLen == 0) break;
    (void) lseek (fd, -ONE_SECTOR_SIZE, SEEK_CUR);
      readLen = read(fd, cmpbuf, ONE_SECTOR_SIZE);
      if (readLen<=0)
          {
          LOG_FAILURE;
          stat = ERROR;
          goto cleanup;
          }

      ret = cmpData (buf, cmpbuf, ONE_SECTOR_SIZE, DIFF);
      if (ret == ERROR)
            {
            LOG_FAILURE;
            (void) printf ("sector [%u] contents are NOT ENcrypted\n",secId);
            printCtx((UINT8*)cmpbuf,512,8);
            stat = ERROR;
            goto cleanup;
            }
      secId++;
    }while (writeLen>0);

    stat = OK;
cleanup:
    return stat;
    }

/*******************************************************************************
*
* diskEncryptTest1 - test the diskEncrypt() scenario 1
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - test if a partition is encrypted
*   - for each sector, the content should not be all zero
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*
*/

VXTEST_STATUS diskEncryptTest1()
    {
    ssize_t             readLen;
    int                 i;
    int                 fd=-1;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_FAIL;
    char                buf1[ONE_SECTOR_SIZE];
    char                buf2[ONE_SECTOR_SIZE];

    unSetEncrypt(RAW_DISK);

    if (writePartition(RAW_DISK,ZERO) == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    (void) lseek (fd, 0, SEEK_SET);
    initContent ((UINT32*)buf2,ONE_SECTOR_SIZE,VALUE,0);

    i = 0;
    do
        {
        readLen = (int)read(fd, buf1, ONE_SECTOR_SIZE);
        if (readLen>0)
        {
            /*printCtx(buf1, 8, 8);*/
            ret = cmpData (buf1, buf2, (size_t)readLen, DIFF);
            if (ret == ERROR)
                {
                LOG_FAILURE;
                (void) printf ("fail sector index=[%d]\n",i);
                stat = VXTEST_FAIL;
                goto cleanup;
                }
        }
        i++;
    }while (readLen > 0);

    stat = VXTEST_PASS;

cleanup:
    if (fd>=0) (void) close (fd);
    (void) diskDecrypt(RAW_DISK,secretId);
    return stat;
    }

/*******************************************************************************
*
* diskEncryptTest2 - test the diskEncrypt() scenario 2 
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - the original content of each sector are all zero
*   - test if different encrypted sector contents are different
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*
*/

VXTEST_STATUS diskEncryptTest2()
    {
    int                 fd=-1;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_FAIL;

    unSetEncrypt(RAW_DISK);

    if (writePartition(RAW_DISK,ZERO) == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }
    ret = diskEncrypt(RAW_DISK,secretId);
    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncryptTest2_helper(fd);
    if (ret == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    stat = VXTEST_PASS;
cleanup:
    if (fd>=0) (void) close (fd);
    (void) diskDecrypt(RAW_DISK,secretId);
    return stat;
    }

/*******************************************************************************
*
* diskEncryptTest3 - test the diskEncrypt() scenario 3
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - the original content of each sector are sequence numbers, i.e.
*     sector 0 is 000...000
*     sector 1 is 111...111
*     sector 2 is 222...222
*   - test if the correct contents are read back from an encrypted disk
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*
*/

VXTEST_STATUS diskEncryptTest3()
    {
    int                 fd=-1;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_FAIL;
    XBD_ENCRYPTION_INFO info;

    unSetEncrypt(RAW_DISK);

    if (writePartition(RAW_DISK,SEQUENCE) == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    bzero ((char *)&info, sizeof (XBD_ENCRYPTION_INFO));
    (void)strncpy (info.keyId, secretId, 1);
    info.flags |= XBD_DISK_DECRYPTION_EN;
    ret = ioctl (fd, (int)XBD_CFG_ENCRYPTION, (_Vx_ioctl_arg_t)&info);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    (void) lseek (fd, 0, SEEK_SET);
    ret = diskEncryptTest3_helper(fd);
    if (ret == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    stat = VXTEST_PASS;
cleanup:
    if (fd>=0) (void) close (fd);
    (void) diskDecrypt(RAW_DISK,secretId);
    return stat;
    }

/*******************************************************************************
*
* diskEncryptTest4 - test the diskEncrypt() scenario 4
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - the plain text written to disk is encrypted.
*   - test if the correct contents are read back from an encrypted disk
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*
*/

VXTEST_STATUS diskEncryptTest4()
    {
    int                 fd=-1;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_FAIL;
    XBD_ENCRYPTION_INFO info;

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    bzero ((char *)&info, sizeof (XBD_ENCRYPTION_INFO));
    (void)strncpy (info.keyId, secretId, 1);
    info.flags |= XBD_DISK_ENCRYPTION_EN;
    info.flags &= (UINT32)(~XBD_DISK_DECRYPTION_EN);

    ret = ioctl (fd, (int)XBD_CFG_ENCRYPTION, (_Vx_ioctl_arg_t)&info);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncryptTest4_helper(fd);
    if (ret == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    stat = VXTEST_PASS;
cleanup:
    if (fd>=0) (void) close (fd);
    (void) diskDecrypt(RAW_DISK,secretId);
    return stat;
    }

/*******************************************************************************
*
* diskEncryptTest5 - test the diskEncrypt() scenario 5
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - when use wrong key to encrypt disk, disk remains the same
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*
*/

VXTEST_STATUS diskEncryptTest5()
    {
    ssize_t              readLen;
    int                 i;
    int                 fd=-1;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_ABORT;
    char                buf1[ONE_SECTOR_SIZE];
    char                buf2[ONE_SECTOR_SIZE];

    unSetEncrypt(RAW_DISK);

    if (writePartition(RAW_DISK,ZERO) == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncrypt(RAW_DISK,"100"); /* use wrong key */

    if (ret != ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    (void) lseek (fd, 0, SEEK_SET);
    initContent ((UINT32*)buf2,ONE_SECTOR_SIZE,VALUE,0);

    i = 0;
    do
        {
        readLen = (int)read(fd, buf1, ONE_SECTOR_SIZE);
        if (readLen>0)
        {
            /*printCtx(buf1, 8, 8);*/
            ret = cmpData (buf1, buf2, (size_t)readLen, SAME);
            if (ret == ERROR)
                {
                LOG_FAILURE;
                (void) printf ("fail sector index=[%d], sector is encrypted\n",i);
                stat = VXTEST_FAIL;
                goto cleanup;
                }
        }
        i++;
    }while (readLen > 0);

    stat = VXTEST_PASS;

cleanup:
    if (fd>=0) (void) close (fd);
    (void) diskDecrypt(RAW_DISK,"0");
    return stat;
    }

/*******************************************************************************
*
* diskDecryptTest1 - test the diskDecrypt() scenario 1
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - test if a partition is decrypted
*   - for each sector, the content should be all zero as it is initialized
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*/

VXTEST_STATUS diskDecryptTest1()
    {
    ssize_t              readLen;
    int                 i;
    int                 fd=-1;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_FAIL;
    char                buf1[ONE_SECTOR_SIZE];
    char                buf2[ONE_SECTOR_SIZE];

    unSetEncrypt(RAW_DISK);

    /* init to all 0 */

    if (writePartition(RAW_DISK,ZERO) == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskDecrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    initContent ((UINT32*)buf2,ONE_SECTOR_SIZE,VALUE,0);
    (void) lseek (fd, 0, SEEK_SET);

    i = 0;
    do
        {
        readLen = read(fd, buf1, ONE_SECTOR_SIZE);
        if (readLen>0)
        {
            /*printCtx(buf1, 8, 8);*/
            ret = cmpData (buf1, buf2, (size_t)readLen, SAME);
            if (ret == ERROR)
                {
                LOG_FAILURE;
                (void) printf ("fail sector index=[%d]\n, it is not decrypted",i);
                stat = VXTEST_FAIL;
                goto cleanup;
                }
        }
        i++;
    }while (readLen > 0);

    stat = VXTEST_PASS;

cleanup:
    if (fd>=0) (void) close (fd);
    return stat;
    }

/*******************************************************************************
*
* diskDecryptTest2 - test the diskDecrypt() scenario 2
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - the original content of each sector are sequence numbers, i.e.
*     sector 0 is 000...000
*     sector 1 is 111...111
*     sector 2 is 222...222
*   - test if the correct contents are read back from an encrypted disk
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*/

VXTEST_STATUS diskDecryptTest2()
    {
    ssize_t             readLen;
    UINT32              i;
    int                 fd=-1;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_FAIL;
    char                buf1[ONE_SECTOR_SIZE];
    char                buf2[ONE_SECTOR_SIZE];

    unSetEncrypt(RAW_DISK);

    if (writePartition(RAW_DISK,SEQUENCE) == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskDecrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    i = 0;
    do
        {
        initContent ((UINT32*)buf2,ONE_SECTOR_SIZE,VALUE,i);
        readLen = read(fd, buf1, ONE_SECTOR_SIZE);
        if (readLen>0)
        {
            /*printCtx(buf1, 8, 8);*/
            ret = cmpData (buf1, buf2, (size_t)readLen, SAME);
            if (ret == ERROR)
                {
                LOG_FAILURE;
                (void) printf ("fail sector index=[%d], it is not decrypted\n",i);
                stat = VXTEST_FAIL;
                goto cleanup;
                }
        }
        i++;
    }while (readLen > 0);

    stat = VXTEST_PASS;
cleanup:
    if (fd>=0) (void) close (fd);
    return stat;
    }

/*******************************************************************************
*
* diskDecryptTest3 - test the diskDecrypt() scenario 3
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - if decryption key does not exist, disk is not decrypted
*   - use correct key to decrypt disk again, will succeed
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*   VXTEST_ABORT if setup fails
*/

VXTEST_STATUS diskDecryptTest3()
    {
    ssize_t             readLen;
    int                 i;
    int                 fd=-1;
    ssize_t             len;
    UINT64              sectorId;
    UINT64              totalSectors = RAM0_DISK_SIZE/ONE_SECTOR_SIZE;
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_FAIL;
    char                buf1[ONE_SECTOR_SIZE];
    char                buf2[ONE_SECTOR_SIZE];

    unSetEncrypt(RAW_DISK);

    if (writePartition(RAW_DISK,ZERO) == ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = diskEncrypt(RAW_DISK,secretId);

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    /* coverity[secure_coding] */
    sectorId = (UINT64)rand() % totalSectors;
    sectorId = (sectorId == 0) ? sectorId-1 : sectorId; /* decrease 1 sector */

    (void) lseek (fd, (off_t)(sectorId*ONE_SECTOR_SIZE), SEEK_SET);

    len = read(fd, buf2, ONE_SECTOR_SIZE);   /* read out a random sector*/
    if (len < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

#ifdef DEBUG_CONTENT
    (void) printf ("sector [%llu] content after encryption:\n",secretId);
    printCtx((UINT8*)buf2, 8, 8);
#endif

    (void) close (fd);
    fd=-1;

    ret = diskDecrypt(RAW_DISK,"100"); /* use wrong key */

    if (ret != ERROR) /* decrypt should fail */
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    unSetEncrypt(RAW_DISK);

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    (void) lseek (fd, (off_t)(sectorId*ONE_SECTOR_SIZE), SEEK_SET);

    readLen = read(fd, buf1, ONE_SECTOR_SIZE);   /* read out the same random sector*/

#ifdef DEBUG_CONTENT
    (void) printf ("sector [%llu] content after decryption with wrong key:\n",secretId);
    printCtx((UINT8*)buf1, 8, 8);
#endif

    if (readLen<0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    ret = cmpData (buf1, buf2, (size_t)readLen, SAME);
    if (ret == ERROR)
        {
        LOG_FAILURE;
        (void) printf ("fail sector index=[%llu], sector is decrypted by wrong key\n",sectorId);
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    (void) close(fd);
    fd=-1;

    ret = diskDecrypt(RAW_DISK,secretId); /* use correct key index */

    if (ret != OK)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    fd = open (RAW_DISK, O_RDWR, 0777);
    if (fd < 0)
        {
        LOG_FAILURE;
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    (void) lseek (fd, 0, SEEK_SET);
    initContent ((UINT32*)buf2,ONE_SECTOR_SIZE,VALUE,0);
    i = 0;
    do
        {
        bzero(buf1,ONE_SECTOR_SIZE);
        readLen = read(fd, buf1, ONE_SECTOR_SIZE);
        if (readLen>0)
        {
            ret = cmpData (buf1, buf2, (size_t)readLen, SAME); /* should be all zero */
            if (ret == ERROR)
                {
                LOG_FAILURE;
                printCtx((UINT8*)buf1, 8, 8);
                (void) printf ("fail sector index=[%d], it is not decrypted\n",i);
                stat = VXTEST_FAIL;
                goto cleanup;
                }
        }
        i++;
    }while (readLen > 0);

    stat = VXTEST_PASS;
cleanup:
    if (fd>=0) (void) close (fd);
    return stat;
    }

/*******************************************************************************
*
* diskMountTest1 - test the diskMount() scenario 1
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - disk can be mounted with correct key
*   - disk can not be mounted with incorrect key
*   - disk can be mounted again with correct key
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*/

VXTEST_STATUS diskMountTest1()
    {
    STATUS ret;

    unSetEncrypt(RAM_DISK_PART_0);
    (void) dosFsVolFormat (RAM_DISK_PART_0,0,NULL);

    (void) diskEncrypt (RAM_DISK_PART_0,secretId);
    (void) diskMountCrypto(RAM_DISK_PART_0,secretId);

    ret = ls (RAM_DISK_PART_0, 0);
    if (ret != OK)
        {
        LOG_FAILURE;
        return VXTEST_FAIL;
        }

    (void) diskMountCrypto(RAM_DISK_PART_0,"100"); /* mount with incorrect key */
    ret = ls (RAM_DISK_PART_0, 0);
    if (ret == OK)
        {
        LOG_FAILURE;
        return VXTEST_FAIL;
        }

    (void) diskMountCrypto(RAM_DISK_PART_0,secretId);

    ret = ls (RAM_DISK_PART_0, 0);
    if (ret != OK)
        {
        LOG_FAILURE;
        return VXTEST_FAIL;
        }

    (void) diskDecrypt (RAM_DISK_PART_0,secretId);

    return VXTEST_PASS;
    }

/*******************************************************************************
*
* diskMountTest2 - test the diskMount() scenario 2 
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - disk can not be mounted after it is decrypted
*   - disk can be mounted again whent is is encrypted
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*/

VXTEST_STATUS diskMountTest2()
    {
    STATUS ret;

    unSetEncrypt(RAM_DISK_PART_0);
    (void) dosFsVolFormat (RAM_DISK_PART_0,0,NULL);

    (void) diskEncrypt (RAM_DISK_PART_0,secretId);
    (void) diskDecrypt (RAM_DISK_PART_0,secretId);

    (void) diskMountCrypto(RAM_DISK_PART_0,secretId);

    ret = ls (RAM_DISK_PART_0, 0);
    if (ret == OK)
        {
        LOG_FAILURE;
        return VXTEST_FAIL;
        }

    (void) diskEncrypt (RAM_DISK_PART_0,secretId); /* encrypt again */
    (void) diskMountCrypto(RAM_DISK_PART_0,secretId);
    ret = ls (RAM_DISK_PART_0, 0);
    if (ret != OK)
        {
        LOG_FAILURE;
        return VXTEST_FAIL;
        }

    (void) diskDecrypt (RAM_DISK_PART_0,secretId);
    return VXTEST_PASS;
    }

LOCAL VXTEST_STATUS diskAutoMountTesthelper
    (
    char * partition,
    char * secretId,
    STATUS ExpectedRet
    )
    {
    STATUS ret;
    (void) diskEncrypt(partition,secretId);
    ret = reMountPartition (partition);
    if (ret != OK)
        {
        LOG_FAILURE;
        return VXTEST_FAIL;
        }

    ret = ls (partition, 0);
    if (ret != ExpectedRet)
        {
        LOG_FAILURE;
        vxTestMsg (V_FAIL,"auto mount test fails on %s with secret id %s",
                          partition, secretId);
        return VXTEST_FAIL;
        }
    else
        {
    (void) diskDecrypt (partition,secretId);
        }
    return VXTEST_PASS;
    }

/*******************************************************************************
*
* diskAutoMountTest1 - test the disk auto mount scenario 1
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* the VIP configure:
*     RAM_DISK_PART_0 : ID "10"
*     RAM_DISK_PART_1 : ID "11"
*     RAM_DISK_PART_2 : ID "12"
*     RAM_DISK_PART_3 : ID "13"
* checkpoints:
*    - the partition name which has keyID will be auto-mounted
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*/

VXTEST_STATUS diskAutoMountTest1()
    {
    VXTEST_STATUS ret;
    VXTEST_STATUS stat = VXTEST_PASS;

    initPartitions();

    ret = diskAutoMountTesthelper (RAM_DISK_PART_0,"10", OK);
    if (ret != VXTEST_PASS) return (VXTEST_FAIL);
    ret = diskAutoMountTesthelper (RAM_DISK_PART_1,"11", OK);
    if (ret != VXTEST_PASS) return (VXTEST_FAIL);
    ret = diskAutoMountTesthelper (RAM_DISK_PART_2,"12", OK);
    if (ret != VXTEST_PASS) return (VXTEST_FAIL);
    ret = diskAutoMountTesthelper (RAM_DISK_PART_3,"13", OK);
    if (ret != VXTEST_PASS) return (VXTEST_FAIL);

    return stat;
    }

/*******************************************************************************
*
* diskAutoMountTest2 - test the disk auto mount scenario 2
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* the VIP configure:
*     RAM_DISK_PART_0 : ID "10"
*     RAM_DISK_PART_1 : ID "11"
*     RAM_DISK_PART_2 : ID "12"
*     RAM_DISK_PART_3 : ID "13"
* checkpoints:
*    - the partition with incorrect key will not be auto-mounted
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*/

VXTEST_STATUS diskAutoMountTest2()
    {
    VXTEST_STATUS ret;
    VXTEST_STATUS stat = VXTEST_PASS;

    initPartitions();

    ret = diskAutoMountTesthelper (RAM_DISK_PART_0,"0", ERROR);
    if (ret != VXTEST_PASS) stat = VXTEST_FAIL;
    ret = diskAutoMountTesthelper (RAM_DISK_PART_1,"0", ERROR);
    if (ret != VXTEST_PASS) stat = VXTEST_FAIL;
    ret = diskAutoMountTesthelper (RAM_DISK_PART_2,"0", ERROR);
    if (ret != VXTEST_PASS) stat = VXTEST_FAIL;
    ret = diskAutoMountTesthelper (RAM_DISK_PART_3,"0", ERROR);
    if (ret != VXTEST_PASS) stat = VXTEST_FAIL;

    (void) diskDecrypt(RAM_DISK_PART_0,"0");
    (void) diskDecrypt(RAM_DISK_PART_1,"0");
    (void) diskDecrypt(RAM_DISK_PART_2,"0");
    (void) diskDecrypt(RAM_DISK_PART_3,"0");

    return stat;
    }

#ifdef COVARAGE_TEST

/*******************************************************************************
*
* secCipherInitTest1 - test the secCipherInit()
*
* \cs
* <testCase>
*   <timeout>   300000  </timeout>
*   <reentrant>   TRUE  </reentrant>
*   <memCheck>    TRUE  </memCheck>
*   <destructive> FALSE </destructive>
* </testCase>
* \ce
*
* checkpoints:
*   - stub secCipherInit() to let it return ERROR,
*     to fill the code coverage gap
*
* RETURNS:
*   VXTEST_PASS if the test case passes
*   VXTEST_FAIL if the test case fails
*/

VXTEST_STATUS secCipherInitTest1()
    {
    STATUS              ret;
    VXTEST_STATUS       stat = VXTEST_ABORT;
    device_t            devt;

    secCipherCleanupCall = 0;
    tdkCertFuncStub ((void*)secCipherInit,(void*)secCipherInitStub);
    tdkCertFuncStub ((void*)secCipherCleanup, (void*)secCipherCleanupStub);

    devt = xbdRamDiskDevCreate (512, 1*1024*1024, TRUE, "/ram2");
    ret = diskEncrypt ("/ram2","0");

    tdkCertUnstubAll();

    xbdRamDiskDevDelete (devt);

    if (ret != ERROR)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }

    if (secCipherCleanupCall <3)
        {
        LOG_FAILURE;
        stat = VXTEST_FAIL;
        goto cleanup;
        }
    stat = VXTEST_PASS;

cleanup:
    return stat;
    }
#endif




#if 0
/******************************************************************************/
/*
 * Performance test of algorism secXexAesUpdate
 *
 */

VXTEST_STATUS secXexAesUpdate_PerfTest(int testTimes)
    {
    SEC_XEX_AES_CTX *   pCtx;
    char *              pSecData;
    VXTEST_STATUS       stat = VXTEST_PASS;
    int                 outLen;
    int                 i,j;
    int                 inLenArray[] = {512,5120,51200,512000,MB};
    double              xexAesSpeed;

    pCtx = (SEC_XEX_AES_CTX *)calloc (1, sizeof (SEC_XEX_AES_CTX));
    if (pCtx == NULL)
        return VXTEST_ABORT;

    if (secXexAesInit (pCtx, "0", ONE_SECTOR_SIZE) == ERROR)
        {
        free (pCtx);
        return VXTEST_ABORT;
        }

    pSecData = (char *)memalign (_CACHE_ALIGN_SIZE, MB);
    if (pSecData == NULL)
        {
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    (void) printf ("---------------XEX-AES Benchmark Test Start---------------\n");
    (void) printf ("SEC_CIPHER_DECR(MB/S)\tSEC_CIPHER_ENCR(MB/S)\n\n");
    for (i=0;i<sizeof (inLenArray) / sizeof (int);i++)
        {
        (void) printf ("Data Size: %d bytes   Loop Times: %d\n", inLenArray[i], testTimes);

        xbdClkTicks = 0;
        vxbAuxClkEnable ();
        for (j=0; j<testTimes; j++)
            {
            outLen = inLenArray[i];
            secXexAesUpdate (pCtx,(UINT8 *)pSecData, &outLen,
                             (UINT8 *)pSecData, inLenArray[i],
                             0,SEC_CIPHER_DECR);
            }
        vxbAuxClkDisable ();

        xexAesSpeed = (double)(((double)inLenArray[i] * (double)testTimes) /
                    (xbdTestTimeSoFar()));
        xexAesSpeed = (double)((double)xexAesSpeed / ((double)MB));
        (void) printf ("%5.2f\t\t\t",xexAesSpeed);
        xbdClkTicks = 0;
        vxbAuxClkEnable ();
        for (j=0; j<testTimes; j++)
            {
            outLen = inLenArray[i];
            secXexAesUpdate (pCtx,(UINT8 *)pSecData, &outLen,
                             (UINT8 *)pSecData, inLenArray[i],
                             0,SEC_CIPHER_ENCR);
            }
        vxbAuxClkDisable ();

        xexAesSpeed = (double)(((double)inLenArray[i] * (double)testTimes) /
                    (xbdTestTimeSoFar()));
        xexAesSpeed = (double)((double)xexAesSpeed / ((double)MB));

        (void) printf ("%5.2f\n",xexAesSpeed);
        }

    (void) printf ("---------------XEX-AES Benchmark Test End-----------------\n");

 cleanup:
    (void) secXexAesCleanup (pCtx);
    free (pSecData);
    free (pCtx);
    return stat;
    }

#endif

#ifdef USE_WDOG

LOCAL void endPerfTest()
    {
    endFlag = TRUE;
    }

LOCAL void secXexAesUpdateTask
    (
    SEC_XEX_AES_CTX *       pCtx,
    unsigned char *         out,
    int *                   outLen,
    const unsigned char *   in,
    int                     inLen,
    long long               sectorNum,
    int                     encr
    )
    {
    semTake(semId,WAIT_FOREVER);
    while(endFlag==FALSE)
        {
        *outLen = inLen;
        secXexAesUpdate (pCtx,(UINT8 *)out, outLen,(UINT8 *)in, inLen,
                         0,SEC_CIPHER_ENCR);
        testCount++;
        }
    semGive (semId);
    }

/******************************************************************************/
/*
 * Performance test of algorism secXexAesUpdate
 *
 */

VXTEST_STATUS secXexAesUpdate_PerfTest()
    {
    SEC_XEX_AES_CTX *   pCtx;
    char *              pSecData;
    VXTEST_STATUS       stat = VXTEST_PASS;
    int                 outLen;
    int                 i;
    int                 inLenArray[] = {512,5120,51200,512000,MB};

    pCtx = (SEC_XEX_AES_CTX *)calloc (1, sizeof (SEC_XEX_AES_CTX));
    if (pCtx == NULL)
        return VXTEST_ABORT;

    if (secXexAesInit (pCtx, "0", ONE_SECTOR_SIZE) == ERROR)
        {
        free (pCtx);
        return VXTEST_ABORT;
        }

    pSecData = (char *)memalign (_CACHE_ALIGN_SIZE, MB);
    if (pSecData == NULL)
        {
        stat = VXTEST_ABORT;
        goto cleanup;
        }

    for (i=0;i<sizeof (inLenArray) / sizeof (int);i++)
        {
        testCount = 0;
        endFlag = FALSE;
        taskSpawn ("tAesPerf",49,0,(size_t)4096,(FUNCPTR)secXexAesUpdateTask,
                    (_Vx_usr_arg_t)pCtx,
                    (_Vx_usr_arg_t)pSecData,
                    (_Vx_usr_arg_t)&outLen,
                    (_Vx_usr_arg_t)pSecData,
                    (_Vx_usr_arg_t)inLenArray[i],
                    (_Vx_usr_arg_t)0,
                    (_Vx_usr_arg_t)SEC_CIPHER_ENCR,
                    (_Vx_usr_arg_t)0,
                    (_Vx_usr_arg_t)0,
                    (_Vx_usr_arg_t)0);

        wdStart (wdId,sysClkRateGet()*5,(FUNCPTR)endPerfTest,0);
        semGive (semId);
        taskDelay(1);
        semTake (semId,WAIT_FOREVER);
        (void) printf ("secXexAesUpdate Encryption runs [%llu] times\n"
                "with buffersize=%d totally deal with [%llu] sectors\n\n",
                testCount,inLenArray[i],inLenArray[i]*testCount/512);
        }

    for (i=0;i<sizeof (inLenArray) / sizeof (int);i++)
        {
        testCount = 0;
        endFlag = FALSE;
        taskSpawn ("tAesPerf",49,0,(size_t)4096,(FUNCPTR)secXexAesUpdateTask,
                    (_Vx_usr_arg_t)pCtx,
                    (_Vx_usr_arg_t)pSecData,
                    (_Vx_usr_arg_t)&outLen,
                    (_Vx_usr_arg_t)pSecData,
                    (_Vx_usr_arg_t)inLenArray[i],
                    (_Vx_usr_arg_t)0,
                    (_Vx_usr_arg_t)SEC_CIPHER_DECR,
                    (_Vx_usr_arg_t)0,
                    (_Vx_usr_arg_t)0,
                    (_Vx_usr_arg_t)0);

        wdStart (wdId,sysClkRateGet()*5,(FUNCPTR)endPerfTest,0);
        semGive (semId);
        taskDelay(1);
        semTake (semId,WAIT_FOREVER);
        (void) printf ("secXexAesUpdate Decryption runs [%llu] times\n"
                "with buffersize=%d totally deal with [%llu] sectors\n\n",
                testCount,inLenArray[i],inLenArray[i]*testCount/512);
        }

 cleanup:
    (void) secXexAesCleanup (pCtx);
    free (pSecData);
    free (pCtx);
    return stat;
    }
#endif


#ifdef USE_AUXCLK

LOCAL void xbdStrategyEncr_PerfTest_helper
    (
    XBD_TEST_DESC * pXbdTest,
    int     testTimes,
    UINT32  datasize,
    UINT32  startblock
    )
    {
    double xbdSpeed;
    int j;
    int sector;

    (void) printf ("Data Size(Bytes)\tRead(MB/S)\tWrite(MB/S)\n");

    /* read - Decryption */

    xbdClkTicks = 0;
    vxbAuxClkEnable ();
    if (startblock != -1)
        {
        for (j=0;j<testTimes;j++)
            {
            xbdTestXbdRW (pXbdTest->pBuf, datasize, 10, FALSE);
            }
        }
    else
        {
        for (j=0;j<testTimes;j++)
            {
            /* coverity[secure_coding] */
            sector = rand() % ((12*MB)/512);
            xbdTestXbdRW (pXbdTest->pBuf, datasize, sector, FALSE);
            }
        }
    vxbAuxClkDisable ();
    xbdSpeed = (double)(((double)datasize * (double)testTimes) /
                (xbdTestTimeSoFar()));
    xbdSpeed = (double)((double)xbdSpeed / ((double)MB));
    (void) printf ("%d\t\t\t%5.2f\t", datasize,xbdSpeed);

    /* write - Encryption */

    xbdClkTicks = 0;
    vxbAuxClkEnable ();
    if (startblock != -1)
        {
        for (j=0;j<testTimes;j++)
            {
            xbdTestXbdRW (pXbdTest->pBuf, datasize, 10, TRUE);

            }
        }
    else
        {
        for (j=0;j<testTimes;j++)
            {
            /* coverity[secure_coding] */
            sector = rand() % ((12*MB)/512);
            xbdTestXbdRW (pXbdTest->pBuf, datasize, sector, TRUE);
            }
        }
    vxbAuxClkDisable ();
    xbdSpeed = (double)(((double)datasize * (double)testTimes) /
                (xbdTestTimeSoFar()));
    xbdSpeed = (double)((double)xbdSpeed / ((double)MB));
    (void) printf ("%5.2f\n",xbdSpeed);
    (void) printf ("in xbdStrategyEncr_PerfTest_helper xbdClkTicks = %d\n",xbdClkTicks);
    }

/******************************************************************************/
/*
 * Performance test of xbdStrategy when encryption is on
 *
 */

VXTEST_STATUS xbdStrategyEncr_PerfTest(UINT32 testTimes)
    {
    XBD_TEST_DESC * pXbdTest = &xbdTestHd;
    int             i;
    UINT32          dataSize[] = {
        1   * ONE_SECTOR_SIZE,
        2   * ONE_SECTOR_SIZE,
        4   * ONE_SECTOR_SIZE,
        8   * ONE_SECTOR_SIZE,
        32  * KB,
        256 * KB,
        512 * KB,
        MB,
        2   * MB
    };

    pXbdTest->dev = xbdTestDevGet (RAW_DISK);
    if (pXbdTest->dev == NULLDEV)
        {
        LOG_FAILURE;
        return VXTEST_ABORT;
        }
    (void) printf ("---------------XBD Benchmark Test Start---------------\n");
    (void) printf ("---------------Interface: %s---------------\n\n",RAW_DISK);
    (void) printf ("Sequential read write:\n\n");

    for (i = 0; i < NELEMENTS (dataSize); i++)
        {
       /* xbdStrategyEncr_PerfTest_helper(pXbdTest,testTimes,dataSize[i],0);*/
        bcopyTest(pXbdTest->pBuf,dataSize[i],testTimes);
        }

    (void) printf ("Random read write:\n\n");

    xbdStrategyEncr_PerfTest_helper(pXbdTest,testTimes,ONE_SECTOR_SIZE,-1);


    (void) printf ("---------------XBD Benchmark Test End-----------------\n");
    return VXTEST_PASS;
    }
#endif


LOCAL void xbdStrategyEncr_PerfTest_helper
    (
    XBD_TEST_DESC * pXbdTest,
    UINT32  datasize,
    INT32   startblock,
    UINT32  testTime
    )
    {
    double xbdSpeed;
    UINT32 sector;
    UINT64 testCount=0;

    (void) printf ("Data Size(Bytes)\tRead(MB/S)\tWrite(MB/S)\n");

    /* read - Decryption */

    endFlag = FALSE;
    (void) wdStart (wdId,sysClkRateGet()*testTime,(FUNCPTR)endPerfTest,0);
    if (startblock != -1)
        {
        while(endFlag==FALSE)
            {
            (void) xbdTestXbdRW (pXbdTest->pBuf, datasize, 10, FALSE);
            testCount++;
            }
        }
    else
        {
        while(endFlag==FALSE)
            {
            /* coverity[secure_coding] */
            sector = (UINT32)(rand() % (GB/512));
            (void) xbdTestXbdRW (pXbdTest->pBuf, datasize, sector, FALSE);
            testCount++;
            }
        }

    xbdSpeed = (double)(((double)datasize * (double)testCount) / (testTime));
    xbdSpeed = (double)((double)xbdSpeed / ((double)MB));
    (void) printf ("%d\t\t\t%5.2f\t\t", datasize,xbdSpeed);

    /* write - Encryption */

    endFlag = FALSE;
    (void) wdStart (wdId,sysClkRateGet()*testTime,(FUNCPTR)endPerfTest,0);
    testCount = 0;
    if (startblock != -1)
        {
        while(endFlag==FALSE)
            {
            (void) xbdTestXbdRW (pXbdTest->pBuf, datasize, 10, TRUE);
            testCount++;
            }
        }
    else
        {
        while(endFlag==FALSE)
            {
            /* coverity[secure_coding] */
            sector = (UINT32)(rand() % ((12*MB)/512));
            (void) xbdTestXbdRW (pXbdTest->pBuf, datasize, sector, TRUE);
            testCount++;
            }
        }

    xbdSpeed = (double)(((double)datasize * (double)testCount) / (testTime));
    xbdSpeed = (double)((double)xbdSpeed / ((double)MB));

    (void) printf ("%5.2f\ttestCount=%llu\n",xbdSpeed,testCount);
    }

/******************************************************************************/
/*
 * Performance test of xbdStrategy when encryption is on
 *
 */

LOCAL VXTEST_STATUS xbdStrategyEncr_PerfTest
    (
    char * testdev,
    UINT32 testTime
    )
    {
    XBD_TEST_DESC * pXbdTest = &xbdTestHd;
    size_t          i;
    UINT32          dataSize[] = {
        1   * ONE_SECTOR_SIZE,
        2   * ONE_SECTOR_SIZE,
        4   * ONE_SECTOR_SIZE,
        8   * ONE_SECTOR_SIZE,
        32  * KB,
        256 * KB,
        512 * KB,
        MB,
        2   * MB
    };

    pXbdTest->dev = xbdTestDevGet (testdev);
    if (pXbdTest->dev == NULLDEV)
        {
        LOG_FAILURE;
        return VXTEST_ABORT;
        }
    (void) printf ("---------------XBD Benchmark Test Start---------------\n");
    (void) printf ("---------------Interface: %s---------------\n\n",testdev);
    (void) printf ("===============Sequential read write===============\n\n");

    for (i = 0; i < NELEMENTS (dataSize); i++)
        {
        xbdStrategyEncr_PerfTest_helper(pXbdTest,dataSize[i],0,testTime);
        (void) printf ("\n");
        }

    (void) printf ("===============Random read write===============\n\n");

    for (i = 0; i < NELEMENTS (dataSize); i++)
        {
        xbdStrategyEncr_PerfTest_helper(pXbdTest,dataSize[i],-1,testTime);
        (void) printf ("\n");
        }

    (void) printf ("---------------XBD Benchmark Test End-----------------\n");
    return VXTEST_PASS;
    }

void doxbdTest(char * testdev)
    {
    (void) printf ("########\nNon-Encrypt\n########\n\n");
    (void) dosFsVolFormat (testdev,0,NULL);
    (void) xbdStrategyEncr_PerfTest(testdev,3);
    (void) printf ("########\nEncrypt\n########\n\n");
    (void) dosFsVolFormat (testdev,0,NULL);
    (void) diskEncrypt (testdev,"0");
    (void) printf ("\n\n");
    (void) xbdStrategyEncr_PerfTest(testdev,3);
    }


LOCAL VXTEST_ENTRY vxTestTbl_tmDiskEncryptTest[] =
{
    /*pTestName,          FUNCPTR,                pArg,   flags,   cpuSet,   timeout,   exeMode,   osMode,   level,  description*/
{"diskEncryptTest1", (FUNCPTR)diskEncryptTest1, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskEncrypt() scenario 1"},
{"diskEncryptTest2", (FUNCPTR)diskEncryptTest2, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskEncrypt() scenario 2"},
{"diskEncryptTest3", (FUNCPTR)diskEncryptTest3, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskEncrypt() scenario 3"},
{"diskEncryptTest4", (FUNCPTR)diskEncryptTest4, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskEncrypt() scenario 4"},
{"diskEncryptTest5", (FUNCPTR)diskEncryptTest5, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskEncrypt() scenario 5"},
{"diskDecryptTest1", (FUNCPTR)diskDecryptTest1, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskDecrypt() scenario 1"},
{"diskDecryptTest2", (FUNCPTR)diskDecryptTest2, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskDecrypt() scenario 2"},
{"diskDecryptTest3", (FUNCPTR)diskDecryptTest3, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskDecrypt() scenario 3"},
{"diskMountTest1", (FUNCPTR)diskMountTest1, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskMount() scenario 1"},
{"diskMountTest2", (FUNCPTR)diskMountTest2, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the diskMount() scenario 2"},
{"diskAutoMountTest1", (FUNCPTR)diskAutoMountTest1, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the disk auto mount scenario 1"},
{"diskAutoMountTest2", (FUNCPTR)diskAutoMountTest2, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the disk auto mount scenario 2"},
#ifdef COVARAGE_TEST
{"secCipherInitTest1", (FUNCPTR)secCipherInitTest1, 0, 0,     0x00000001 , 300000, VXTEST_EXEMODE_ALL, VXTEST_OSMODE_ALL, 0,"test the secCipherInit()"},
#endif
{NULL, (FUNCPTR)"tmDiskEncryptTest", 0, 0, 0, 600000, 0, 0, 0}
};


/**************************************************************************
*
* tmDiskEncryptTestExec - Exec tmDiskEncrypt test module
*
* This routine should be called to execute the test module.
*
* RETURNS: N/A
*
* NOMANUAL
*/

STATUS tmDiskEncryptTestExec
    (
    char * testCaseName,
    VXTEST_RESULT * pTestResult
    )
    {
    if (testInitRet == OK)
        return vxTestRun((VXTEST_ENTRY**)&vxTestTbl_tmDiskEncryptTest, testCaseName, pTestResult);
    else
        {
        vxTestMsg (V_ABORT,"tmDiskEncryptionTestInit fail!!! not run cases!\n");
        return VXTEST_ABORT;
        }
    }
