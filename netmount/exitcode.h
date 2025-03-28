// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 Jaroslav Rohel, jaroslav.rohel@gmail.com

// Defines netmount application exit (error) codes.

#ifndef _EXITCODE_H_
#define _EXITCODE_H_

#define EXIT_OK 0

// Errors in command line arguments
#define EXIT_MISSING_CMD      1
#define EXIT_MISSING_ARG      2
#define EXIT_UNKNOWN_CMD      3
#define EXIT_UNKNOWN_ARG      4
#define EXIT_BAD_DRIVE_LETTER 5
#define EXIT_BAD_NET_MASK     6
#define EXIT_BAD_ARG          7

// Runtime errors
#define EXIT_UNSUPPORTED_DOS             -1
#define EXIT_ALREADY_INSTALLED           -2
#define EXIT_NOT_FREE_MULTIPLEX          -3
#define EXIT_PKTDRV_INIT_FAILED          -4
#define EXIT_NOT_INSTALLED               -5
#define EXIT_DRIVE_LETTER_ALREADY_USED   -6
#define EXIT_NOT_FREE_SLOT_FOR_REMOTE_IP -7
#define EXIT_DRIVE_NOT_MOUNTED           -8

#endif
