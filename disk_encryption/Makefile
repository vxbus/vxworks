# Makefile - DISK_ENCRYPTION layer Makefile
#
# Copyright (c) 2016, 2018, 2021 Wind River Systems, Inc.
#      
# The right to copy, distribute, modify or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
include $(WIND_KRNL_MK)/defs.layers.mk

KERNEL_PUBLIC_H_DIRS += h
KERNEL_PROTECTED_H_DIRS += protectedh
BUILD_DIRS += src
POST_NOBUILD_CDFDIRS += cdf
POST_NOBUILD_CFGDIRS += cfg

# the following wildcard test is used for unshipped code
# and can only be removed if the code is shipped

ifneq ("$(wildcard vxTest/src/Makefile)","")
ifdef _WRS_CONFIG_DISK_ENCRYPTION_VXTEST
BUILD_DIRS += vxTest/src
POST_NOBUILD_CDFDIRS += vxTest/cdf
endif
endif

CC_WARNINGS_BUILD_DIRS = CC_WARNINGS_HIGH_SYS

include $(WIND_KRNL_MK)/rules.layers.mk
