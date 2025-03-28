// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 Jaroslav Rohel, jaroslav.rohel@gmail.com

#ifndef _DOS_H_
#define _DOS_H_

#include <stdint.h>

// INT 0x2F network redirector functions (value of AL register)
#define INT2F_INSTALL_CHECK             0x00
#define INT2F_REMOVE_DIR                0x01
#define INT2F_MAKE_DIR                  0x03
#define INT2F_CHANGE_DIR                0x05
#define INT2F_CLOSE_FILE                0x06
#define INT2F_COMMIT_FILE               0x07
#define INT2F_READ_FILE                 0x08
#define INT2F_WRITE_FILE                0x09
#define INT2F_LOCK_UNLOCK_FILE          0x0A
#define INT2F_UNLOCK_FILE               0x0B
#define INT2F_DISK_INFO                 0x0C
#define INT2F_SET_ATTRS                 0x0E
#define INT2F_GET_ATTRS                 0x0F
#define INT2F_RENAME_FILE               0x11
#define INT2F_DELETE_FILE               0x13
#define INT2F_OPEN_FILE                 0x16
#define INT2F_CREATE_FILE               0x17
#define INT2F_FIND_FIRST                0x1B
#define INT2F_FIND_NEXT                 0x1C
#define INT2F_SEEK_FROM_END             0x21
#define INT2F_EXTENDED_ATTRS            0x2D
#define INT2F_EXTENDED_OPEN_CREATE_FILE 0x2E
#define INT2F_UNUSED                    0xFF


// CX result codes for NETWORK REDIRECTOR (DOS 4.0+) - EXTENDED OPEN/CREATE FILE
#define DOS_EXT_OPEN_FILE_RESULT_CODE_OPENED    1
#define DOS_EXT_OPEN_FILE_RESULT_CODE_CREATED   2
#define DOS_EXT_OPEN_FILE_RESULT_CODE_TRUNCATED 3


//Values for DOS extended error code:
//---DOS 2.0+ ---
#define DOS_EXTERR_NO_ERROR                 0   // no error
#define DOS_EXTERR_FUNC_NUM_INVALID         1   // function number invalid
#define DOS_EXTERR_FILE_NOT_FOUND           2   // file not found
#define DOS_EXTERR_PATH_NOT_FOUND           3   // path not found
#define DOS_EXTERR_TOO_MANY_OPEN_FILES      4   // too many open files (no handles available)
#define DOS_EXTERR_ACCESS_DENIED            5   // access denied
#define DOS_EXTERR_INVALID_HANDLE           6   // invalid handle
#define DOS_EXTERR_MEM_CTRL_BLOCK_DESTROYED 7   // memory control block destroyed
#define DOS_EXTERR_INSUFICIENT_MEMORY       8   // insufficient memory
#define DOS_EXTERR_MEM_BLOCK_ADDR_INVALID   9   // memory block address invalid
#define DOS_EXTERR_ENVIRONMENT_INVALID      10  // environment invalid (usually >32K in length)
#define DOS_EXTERR_FORMAT_INVALID           11  // format invalid
#define DOS_EXTERR_ACCESS_CODE_INVALID      12  // access code invalid
#define DOS_EXTERR_DATA_INVALID             13  // data invalid
#define DOS_EXTERR_RESERVED                 14  // reserved
//0Eh (14)  (PTS-DOS 6.51+, S/DOS 1.0+) fixup overflow
#define DOS_EXTERR_INVALID_DRIVE          15  // invalid drive
#define DOS_EXTERR_ATTEMPT_REMOVE_CUR_DIR 16  // attempted to remove current directory
#define DOS_EXTERR_NOT_SAME_DEVICE        17  // not same device
#define DOS_EXTERR_NO_MORE_FILES          18  // no more files

// ---DOS 3.0+ (INT 24 errors)---
#define DOS_EXTERR_DISK_WRITE_PROTECTED           19  // disk write-protected
#define DOS_EXTERR_UNKNOWN_UNIT                   20  // unknown unit
#define DOS_EXTERR_DRIVE_NOT_READY                21  // drive not ready
#define DOS_EXTERR_UNKNOWN_COMMAND                22  // unknown command
#define DOS_EXTERR_DATA_ERROR                     23  // data error (CRC)
#define DOS_EXTERR_BAD_REQUEST_STRUCT_LEN         24  // bad request structure length
#define DOS_EXTERR_SEEK_ERROR                     25  // seek error
#define DOS_EXTERR_UNKNOWN_MEDIA_TYPE             26  // unknown media type (non-DOS disk)
#define DOS_EXTERR_SECTOR_NOT_FOUND               27  // sector not found
#define DOS_EXTERR_PRINTER_OUT_OF_PAPER           28  // printer out of paper
#define DOS_EXTERR_WRITE_FAULT                    29  // write fault
#define DOS_EXTERR_READ_FAULT                     30  // read fault
#define DOS_EXTERR_GENERAL_FAILURE                31  // general failure
#define DOS_EXTERR_SHARING_VIOLATION              32  // sharing violation
#define DOS_EXTERR_LOCK_VIOLATION                 33  // lock violation
#define DOS_EXTERR_DISK_CHANGE_INVALID            34  // disk change invalid (ES:DI -> media ID structure)(see #01681)
#define DOS_EXTERR_FCB_UNAVAILABLE                35  // FCB unavailable
#define DOS_EXTERR_BAD_FAT                        35  // (PTS-DOS 6.51+, S/DOS 1.0+) bad FAT
#define DOS_EXTERR_SHARING_BUFFER_OVERFLOW        36  // sharing buffer overflow
#define DOS_EXTERR_CODE_PAGE_MISMATCH             37  // (DOS 4.0+) code page mismatch
#define DOS_EXTERR_CANNOT_COMPLETE_FILE_OPERATION 38  // (DOS 4.0+) cannot complete file operation (EOF / out of input)
#define DOS_EXTERR_INSUFFICIENT_DISK_SPACE        39  // (DOS 4.0+) insufficient disk space
// 28h-31h   reserved

// ---OEM network errors (INT 24)---
#define DOS_EXTERR_NET_REQUEST_NOT_SUPPORTED   50  // network request not supported
#define DOS_EXTERR_REMOTE_NOT_LISTENING        51  // remote computer not listening
#define DOS_EXTERR_DUPLICATE_NAME_ON_NETWORK   52  // duplicate name on network
#define DOS_EXTERR_NET_NAME_NOT_FOUND          53  // network name not found
#define DOS_EXTERR_NET_BUSY                    54  // network busy
#define DOS_EXTERR_NET_DEV_NO_LONGER_EXIST     55  // network device no longer exists
#define DOS_EXTERR_NET_BIOS_CMD_LIMIT_EXCEED   56  // network BIOS command limit exceeded
#define DOS_EXTERR_NET_ADAPTER_HW_ERROR        57  // network adapter hardware error
#define DOS_EXTERR_NET_INCORRECT_RESPONSE      58  // incorrect response from network
#define DOS_EXTERR_NET_UNEXPECTED_ERROR        59  // unexpected network error
#define DOS_EXTERR_INCOMPATIBLE_REMOTE_ADAPTER 60  // incompatible remote adapter
#define DOS_EXTERR_PRINT_QUEUE_FULL            61  // print queue full
#define DOS_EXTERR_QUEUE_NOT_FULL              62  // queue not full
#define DOS_EXTERR_NO_SPACE_TO_PRINT_FILE      63  // not enough space to print file
#define DOS_EXTERR_NET_NAME_WAS_DELETED        64  // network name was deleted

// structs are paked
#pragma pack(push, 1)

#define MAX_CDS_PATH_LEN 67

// Bits for current directory flags (OR combination)
#define DOS_CDSFLAG_NETWDRV 0x8000U
#define DOS_CDSFLAG_PHYSDRV 0x4000U
#define DOS_CDSFLAG_JOINED  0x2000U   // not in combination with NETWDRV or SUBST
#define DOS_CDSFLAG_SUBST   0x1000U   // not in combination with NETWDRV or JOINED
#define DOS_CDSFLAG_HIDDEN  (1 << 7)  // hide drive from redirector's list

#ifdef _far
#define far_pointer(type) type __far *
#else
#define far_pointer(type) uint32_t
#endif

// CDS (current directory structure), as used by DOS 4+
struct dos_current_dir {
    unsigned char
        current_path[MAX_CDS_PATH_LEN];  // ASCIIZ, entire name, starting with the drive ID (e.g., C:\DOS\UTILS).
    uint16_t flags;                      // drive is physical, networked, substed or joined
    far_pointer(void) dpb;               // a pointer to the Drive Parameter Block
    union {
        struct {  // used for local disks
            uint16_t start_cluster;
            uint32_t unknown;
        } local;
        struct {  // used for network disks
            far_pointer(void) net_redirector_record;
            uint16_t net_user_code;  // ??? network user code as stored via fn 5f03H
        } net;
    };
    uint16_t backslash_offset;  // offset in current_path of first '\' (always 2, unless it's a SUBST drive)
    uint8_t reserved;           //unknown
    far_pointer(void) ifs;      // points to IFS (Installable File System) driver
    uint16_t reserved2;         // unknown
};


// FCB (file control block) style file/directory name
struct fcb_file_name {
    unsigned char name_blank_padded[8];  // first character is set to E5h for deleted files (05h for pending delete
                                         // files under Novell DOS / OpenDOS)
    unsigned char ext_blank_padded[3];
};


struct dos_directory_entry {
    struct fcb_file_name name;
    uint8_t attrs;           // (1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEVICE)
    uint8_t reserved[10];    // (MS-DOS 1.0-6.22) reserved
    uint16_t time_update;    // time of creation or last update (see #01665 at AX=5700h) hhhhhmmm mmmsssss
    uint16_t date_update;    // date of creation or last update YYYYYYYM MMMDDDDD
    uint16_t start_cluster;  // starting cluster number  (see also AX=440Dh/CX=0871h)
                             // (may not be set in INT 21/AH=11h return data for FAT32 drives)
    uint32_t size;           // file size
};


// FindFirst and FindNext search record
struct dos_search {
    uint8_t drive_no;
    struct fcb_file_name srch_tmpl;
    uint8_t srch_attr;
    uint16_t dir_entry_no;
    uint16_t cluster;
    uint8_t f1[4];
};


//  Swappable DOS Area (SDA) fields. Layout:
// The struct below is matching FreeDOS and MSDOS 4+
struct dos_sda {
    uint8_t f0[12];
    far_pointer(unsigned char) curr_dta;
    uint8_t f1[32];
    uint8_t dd;
    uint8_t mm;
    uint16_t yy_1980;
    uint8_t f2[106];
    unsigned char fn1[128];
    unsigned char fn2[128];
    struct dos_search sdb;
    struct dos_directory_entry found_file;
    struct dos_current_dir drive_cdscopy;
    struct fcb_file_name fcb_fn1;
    uint8_t f3;
    struct fcb_file_name fcb_fn2;
    uint8_t f4[11];
    unsigned char srch_attr;
    unsigned char open_mode;
    uint8_t f5[51];
    far_pointer(unsigned char) drive_cdsptr;
    uint8_t f6[12];
    unsigned short fn1_csofs;
    unsigned short fn2_csofs;
    uint8_t f7[71];
    unsigned short action_ext;
    unsigned short attr_ext;
    unsigned short mode_ext;
    uint8_t f8[29];
    struct dos_search ren_srcfile;
    struct dos_directory_entry ren_file;
};


// Part of DOS 4.0+ System File Table
struct dos_sft {
    uint16_t handle_count;   // count of handles referring to this file or zero if file is no longer open
    uint16_t open_mode;      // open mode, bit 15 set if opened via FCB 2-0 access mode.
                             // (000 read only. 001 write only. 010 read/write)
    uint8_t file_attr;       // file attributes
    uint16_t dev_info_word;  // device info word
    uint32_t redir_data;     // REDIR data
    uint16_t start_cluster;  // starting cluster of file
    uint32_t file_time;      // file date and time
    uint32_t file_size;      // file length
    uint32_t file_pos;       // current file position
    uint16_t rel_sector;
    uint16_t abs_sector;
    uint16_t dir_sector;
    uint8_t dir_entry_no;  // if local, number of directory entry within sector
    struct fcb_file_name file_name;
};


// DOS List of lists structure - DOS VERSIONS 3.1+
// We need only a small part
struct dos_list_of_list {
    uint8_t f1[22];
    far_pointer(struct dos_current_dir) cds_ptr;
    uint8_t f2[7];
    uint8_t last_drive;
};

#pragma pack(pop)

#endif
