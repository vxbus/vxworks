/* 01vxTest_DISK_ENCRYPTION.cdf - DISK_ENCRYPTION test components group */

/*
 * Copyright (c) 2016, 2021, 2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

/*
* The following component definition is for the disk encryption test module.
*/

Component         INCLUDE_TM_DISK_ENCRYPTION_TEST {
        NAME            System test module of disk encryption
        SYNOPSIS        This component adds disk encryption test module
        REQUIRES        INCLUDE_VXTEST_DRIVER \
                        INCLUDE_DISK_ENCRYPTION
        MODULES         tmDiskEncryptTest.o
        PROTOTYPE       void tmDiskEncryptionTestInit (void);
        LINK_SYMS       tmDiskEncryptionTestInit
        INIT_RTN        tmDiskEncryptionTestInit();
}

/*
 * Test Init Group
 */
InitGroup       usrVxTest_SECURITY_DISK_ENCRYPTION_TestsInit {
    INIT_RTN        usrVxTest_SECURITY_DISK_ENCRYPTION_TestsInit ();
    SYNOPSIS        SECURITY_DISK_ENCRYPTION tests initialization sequence
    INIT_ORDER      INCLUDE_TM_DISK_ENCRYPTION_TEST
    _INIT_ORDER     usrVxTestSecurityInit
}

InitGroup       usrVxTestSecurityInit {
    INIT_RTN        usrVxTestSecurityInit ();
    SYNOPSIS        VxTest Security tests initialization sequence
    _INIT_ORDER     usrVxTestInit
}

/*
 *  Tests Folder
 */
Folder        FOLDER_VXTEST_SECURITY_DISK_ENCRYPTION {
    NAME            VxTest SECURITY_DISK_ENCRYPTION test components
    SYNOPSIS        Used to group SECURITY_DISK_ENCRYPTION test components
    CHILDREN        INCLUDE_TM_DISK_ENCRYPTION_TEST
    DEFAULTS        INCLUDE_TM_DISK_ENCRYPTION_TEST
    _CHILDREN       FOLDER_VXTEST_SECURITY_TESTS
}
