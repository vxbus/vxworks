# Makefile - makefile for vxTest spi dirver.
#
# Copyright (c) 2016, 2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
# DESCRIPTION
# This file contains the makefile rules for building the vxbus subsystem test library
#
#*/

EXTRA_DEFINE += -I$(VSB_DIR)/krnl/h/protected/DISK_ENCRYPTION/ 
EXTRA_DEFINE += -I$(VSB_DIR)/krnl/h/protected/SEC_CRYPTO/ 

LIB_BASE_NAME = vxTest_SECURITY_DISKENCRYPTION


include $(WIND_KRNL_MK)/defs.default.mk

C_SOURCE = $(filter-out $(C_EXCLUDE),$(wildcard *.c))

OBJS = $(C_SOURCE:.c=.o)
RTP_TEST_OBJS = 
KERNEL_TEST_OBJS = $(C_SOURCE:.c=.o)

include $(WIND_KRNL_MK)/rules.vxTest.mk
