/* 10comp_vxDiskEncryption.cdf - VxWorks Disk Encryption components configuration file */

/*
 * Copyright (c) 2016-2017, 2021 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */


Folder FOLDER_DISK_ENCRYPTION
    {
    NAME            Disk encryption
    SYNOPSIS        This folder holds the components to configure the disk \
                    encryption module.
    _CHILDREN       FOLDER_SECURITY
    }

Component INCLUDE_DISK_ENCRYPTION
    {
    NAME            Disk encryption support
    SYNOPSIS        VxWorks full disk encryption provides "data at rest" \
                    protection for sector-addressable devices (like hard disks), \
                    using the XEX-AES algorithm. The feature encrypts the data \
                    on specified partitions of the storage devices. It uses the \
                    VxWorks secure vault facility to store the symmetric \
                    encryption keys. The dosFs and HRFS file systems are \
                    supported for full disk encryption.
    _CHILDREN       FOLDER_DISK_ENCRYPTION
    MODULES         diskEncryptionLib.o
    LINK_SYMS       diskEncrInit
    REQUIRES        INCLUDE_XBD                         \
                    SELECT_DISK_ENCRYPTION_XEX_AES_IMPL \
                    INCLUDE_SEC_HASH_SHA512             \
                    INCLUDE_SEC_SECRET
    CONFIGLETTES    diskEncrCfg.c
    PROTOTYPE       void diskEncrLibFuncsInit (void);
    INIT_RTN        diskEncrLibFuncsInit ();
    _INIT_ORDER     usrIosExtraInit
    INIT_BEFORE     INCLUDE_XBD
    }

Component INCLUDE_DISK_ENCRYPTION_TOOLS
    {
    NAME            Disk encryption tools
    SYNOPSIS        Provides the tools for encrypting and decrypting an entire \
                    disk partition
    MODULES         diskEncryptionTools.o
    LINK_SYMS       diskEncrypt
    _CHILDREN       FOLDER_DISK_ENCRYPTION
    REQUIRES        INCLUDE_DISK_ENCRYPTION \
                    INCLUDE_FS_EVENT_UTIL
    }

Selection SELECT_DISK_ENCRYPTION_AUTO_MOUNT
    {
    NAME            Disk encryption auto-mount configurations
    SYNOPSIS        Disk encryption auto-mount configurations. The component \
                    is optional. If it is disabled, the system doesn't mount \
                    the encrypted partition automatically.
    COUNT           0-
    _CHILDREN       FOLDER_DISK_ENCRYPTION
    CHILDREN        INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_1 \
                    INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_2 \
                    INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_3 \
                    INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_4
    DEFAULTS        INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_1
    }

Component INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_1
    {
    NAME            Auto-mount partition #1 configuration
    SYNOPSIS        Auto-mount partition #1 configuration
    REQUIRES        INCLUDE_DISK_ENCRYPTION
    CFG_PARAMS      PARTITION_NAME_1    \
                    PARTITION_KEY_ID_1
    }

Parameter PARTITION_NAME_1
    {
    NAME            Partition name
    SYNOPSIS        The name of the encrypted partition (i.e., "/ata0:0").
    TYPE            char *
    }

Parameter PARTITION_KEY_ID_1
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret.
    TYPE            char *
    }

Component INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_2
    {
    NAME            Auto-mount partition #2 configuration
    SYNOPSIS        Auto-mount partition #2 configuration
    REQUIRES        INCLUDE_DISK_ENCRYPTION
    CFG_PARAMS      PARTITION_NAME_2    \
                    PARTITION_KEY_ID_2
    }

Parameter PARTITION_NAME_2
    {
    NAME            Partition name
    SYNOPSIS        The name of the encrypted partition (i.e., "/ata0:0").
    TYPE            char *
    }

Parameter PARTITION_KEY_ID_2
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret.
    TYPE            char *
    }

Component INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_3
    {
    NAME            Auto-mount partition #3 configuration
    SYNOPSIS        Auto-mount partition #3 configuration
    REQUIRES        INCLUDE_DISK_ENCRYPTION
    CFG_PARAMS      PARTITION_NAME_3    \
                    PARTITION_KEY_ID_3
    }

Parameter PARTITION_NAME_3
    {
    NAME            Partition name
    SYNOPSIS        The name of the encrypted partition (i.e., "/ata0:0").
    TYPE            char *
    }

Parameter PARTITION_KEY_ID_3
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret.
    TYPE            char *
    }

Component INCLUDE_DISK_ENCRYPTION_AUTO_MOUNT_4
    {
    NAME            Auto-mount partition #4 configuration
    SYNOPSIS        Auto-mount partition #4 configuration
    REQUIRES        INCLUDE_DISK_ENCRYPTION
    CFG_PARAMS      PARTITION_NAME_4    \
                    PARTITION_KEY_ID_4
    }

Parameter PARTITION_NAME_4
    {
    NAME            Partition name
    SYNOPSIS        The name of the encrypted partition (i.e., "/ata0:0").
    TYPE            char *
    }

Parameter PARTITION_KEY_ID_4
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret.
    TYPE            char *
    }

Selection SELECT_DISK_ENCRYPTION_XEX_AES_IMPL
    {
    NAME            Select XEX-AES algorithm
    SYNOPSIS        Select AES Algorithm used by XEX-AES encryption
    COUNT           1-1
    _CHILDREN       FOLDER_DISK_ENCRYPTION
    CHILDREN        INCLUDE_SEL_AES_128_ECB \
                    INCLUDE_SEL_AES_256_ECB
    DEFAULTS        INCLUDE_SEL_AES_256_ECB
    }

Component INCLUDE_SEL_AES_128_ECB
    {
    NAME            AES 128 ECB
    SYNOPSIS        Select AES 128 ECB
    REQUIRES        INCLUDE_SEC_CIPHER_AES_128_ECB
    }

Component INCLUDE_SEL_AES_256_ECB
    {
    NAME            AES 256 ECB
    SYNOPSIS        Select AES 256 ECB
    REQUIRES        INCLUDE_SEC_CIPHER_AES_256_ECB
    }

Component INCLUDE_DISK_ENCRYPTION_AUTO_ENCRYPT
    {
    NAME            Disk partition auto encryption
    SYNOPSIS        Disk partition auto encrypt configuration
    _CHILDREN       FOLDER_DISK_ENCRYPTION
    MODULES         diskEncryptionAuto.o
    LINK_SYMS       secureDiskTaskInit
    REQUIRES        INCLUDE_DISK_ENCRYPTION
    CFG_PARAMS      AUTO_ENCRYPT_PARTITION_NAME_1    \
                    AUTO_ENCRYPT_PARTITION_KEY_ID_1  \
                    AUTO_ENCRYPT_PARTITION_NAME_2    \
                    AUTO_ENCRYPT_PARTITION_KEY_ID_2  \
                    AUTO_ENCRYPT_PARTITION_NAME_3    \
                    AUTO_ENCRYPT_PARTITION_KEY_ID_3  \
                    AUTO_ENCRYPT_PARTITION_NAME_4    \
                    AUTO_ENCRYPT_PARTITION_KEY_ID_4
    CONFIGLETTES    diskEncrCfg.c
    PROTOTYPE       void secureDiskTaskInit (void);
    INIT_RTN        secureDiskTaskInit ();
    _INIT_ORDER     usrRoot
    INIT_BEFORE     usrAppInit
    }

Parameter AUTO_ENCRYPT_PARTITION_NAME_1
    {
    NAME            Partition name
    SYNOPSIS        The name of the partition (i.e., "/ata1a").
    TYPE            char *
    DEFAULT         NULL
    }

Parameter AUTO_ENCRYPT_PARTITION_KEY_ID_1
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret (i.e., "/keyid1").
    TYPE            char *
    DEFAULT         NULL
    }

Parameter AUTO_ENCRYPT_PARTITION_NAME_2
    {
    NAME            Partition name
    SYNOPSIS        The name of the partition (i.e., "/ata1b").
    TYPE            char *
    DEFAULT         NULL
    }

Parameter AUTO_ENCRYPT_PARTITION_KEY_ID_2
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret (i.e., "/keyid2").
    TYPE            char *
    DEFAULT         NULL
    }

Parameter AUTO_ENCRYPT_PARTITION_NAME_3
    {
    NAME            Partition name
    SYNOPSIS        The name of the partition (i.e., "/ata1c").
    TYPE            char *
    DEFAULT         NULL
    }

Parameter AUTO_ENCRYPT_PARTITION_KEY_ID_3
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret (i.e., "/keyid3").
    TYPE            char *
    DEFAULT         NULL
    }

Parameter AUTO_ENCRYPT_PARTITION_NAME_4
    {
    NAME            Partition name
    SYNOPSIS        The name of the partition (i.e., "/ata1d").
    TYPE            char *
    DEFAULT         NULL
    }

Parameter AUTO_ENCRYPT_PARTITION_KEY_ID_4
    {
    NAME            Key ID
    SYNOPSIS        The associate key ID in secSecret (i.e., "/keyid4").
    TYPE            char *
    DEFAULT         NULL
    }