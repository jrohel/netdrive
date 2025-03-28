// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 Jaroslav Rohel, jaroslav.rohel@gmail.com

// Packet driver interface

#ifndef _PKTDRV_H_
#define _PKTDRV_H_

// Basic Packet driver functions
#define PKTDRV_FUNC_DRIVER_INFO     1
#define PKTDRV_FUNC_ACCESS_TYPE     2
#define PKTDRV_FUNC_RELEASE_TYPE    3
#define PKTDRV_FUNC_SEND_PKT        4
#define PKTDRV_FUNC_TERMINATE       5
#define PKTDRV_FUNC_GET_ADDRESS     6
#define PKTDRV_FUNC_RESET_INTERFACE 7

// High-performance packet driver functions
#define PKTDRV_FUNC_GET_PARAMETERS 10
#define PKTDRV_FUNC_AS_SEND_PKT    11

// Extended packet driver functions
#define PKTDRV_FUNC_SET_RCV_MODE       20
#define PKTDRV_FUNC_GET_RCV_MODE       21
#define PKTDRV_FUNC_SET_MULTICAST_LIST 22
#define PKTDRV_FUNC_GET_MULTICAST_LIST 23
#define PKTDRV_FUNC_GET_STATISTICS     24
#define PKTDRV_FUNC_SET_ADDRESS        25

// Packet driver calls indicate error by setting the carry flag on return. The error code is returned in register DH
#define PKTDRV_ERROR_BAD_HANDLE     1   // Invalid handle number,
#define PKTDRV_ERROR_NO_CLASS       2   // No interfaces of specified class found,
#define PKTDRV_ERROR_NO_TYPE        3   // No interfaces of specified type found,
#define PKTDRV_ERROR_NO_NUMBER      4   // No interfaces of specified number found,
#define PKTDRV_ERROR_BAD_TYPE       5   // Bad packet type specified,
#define PKTDRV_ERROR_NO_MULTICAST   6   // This interface does not support multicast,
#define PKTDRV_ERROR_CANT_TERMINATE 7   // This packet driver cannot terminate,
#define PKTDRV_ERROR_BAD_MODE       8   // An invalid receiver mode was specified,
#define PKTDRV_ERROR_NO_SPACE       9   // Operation failed because of insufficient space,
#define PKTDRV_ERROR_TYPE_INUSE     10  // The type had previously been accessed, and not released,
#define PKTDRV_ERROR_BAD_COMMAND    11  // The command was out of range, or not implemented,
#define PKTDRV_ERROR_CANT_SEND      12  // The packet couldn't be sent (usually hardware error),
#define PKTDRV_ERROR_CANT_SET       13  // Hardware address couldn't be changed (more than 1 handle open),
#define PKTDRV_ERROR_BAD_ADDRESS    14  // Hardware address has bad length or format,
#define PKTDRV_ERROR_CANT_RESET     15  // Couldn't reset interface (more than 1 handle open).

#endif
