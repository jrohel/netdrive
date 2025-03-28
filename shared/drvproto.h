// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 Jaroslav Rohel, jaroslav.rohel@gmail.com

#ifndef _DRVPROTO_H_
#define _DRVPROTO_H_

#include "dos.h"

#include <stdint.h>

// structs are packed
#pragma pack(push, 1)

#define DRIVE_PROTO_VERSION  1
#define DRIVE_PROTO_MAGIC    0x9524U
#define DRIVE_PROTO_UDP_PORT 12200

// little endian
struct drive_proto_hdr {
    uint8_t version;
    uint16_t length_flags;  // chechsum_used | unused | unused | unused | unused | length
    uint16_t checksum;
    uint8_t sequence;
    union {
        // in request
        struct {
            uint8_t drive;     // (A=0, B=1, C=2, ...)
            uint8_t function;  // AL value of INT 2F
        };

        // in reply
        uint16_t ax;
    };
};


struct drive_proto_closef {
    uint16_t start_cluster;
};


struct drive_proto_readf {
    uint32_t offset;
    uint16_t start_cluster;
    uint16_t length;
};


struct drive_proto_writef {
    uint32_t offset;
    uint16_t start_cluster;
};


struct drive_proto_writef_reply {
    uint16_t written;
};


struct drive_proto_lockf {
    uint16_t params_count;
    uint16_t start_cluster;
};


struct drive_proto_disk_info_reply {
    uint16_t total_clusters;
    uint16_t bytes_per_sector;
    uint16_t available_clusters;
};


struct drive_proto_set_attrs {
    uint8_t attrs;
};


struct drive_proto_get_attrs_reply {
    uint16_t time;
    uint16_t date;
    uint16_t size_lo;
    uint16_t size_hi;
    uint8_t attrs;
};


struct drive_proto_open_create {
    uint16_t attrs;   // bitfields: 5 archive, 4 reserved, 3 volume label, 2 system, 1 hidden, 0 readonly
    uint16_t action;  // high nibble = action if file does NOT exist: 0000 fail, 0001 create
                      // low nibble = action if file does exist: 0000 fail, 0001 open, 0010 replace/open
    uint16_t mode;
};


struct drive_proto_open_create_reply {
    uint8_t attrs;
    struct fcb_file_name name;
    uint32_t date_time;
    uint32_t size;
    uint16_t start_cluster;
    uint16_t result_code;  // 01h opened,  02h created, 03h replaced (truncated)
    uint8_t mode;
};


struct drive_proto_find_first {
    uint8_t attrs;
    // fully-qualified search template without drive part
};


struct drive_proto_find_next {
    uint16_t cluster;
    uint16_t dir_entry;
    uint8_t attrs;
    struct fcb_file_name search_template;
};


struct drive_proto_find_reply {
    uint8_t attrs;              // found file attributes 1=RO, 2=HID, 4=SYS, 8=VOL, 16=DIR, 32=ARCH, 64=DEV
    struct fcb_file_name name;  // found file name
    uint16_t time;
    uint16_t date;
    uint32_t size;
    uint16_t start_cluster;
    uint16_t dir_entry;
};


struct drive_proto_seek_from_end {
    uint16_t offset_from_end_lo;
    uint16_t offset_from_end_hi;
    uint16_t start_cluster;
};


struct drive_proto_seek_from_end_reply {
    uint16_t position_lo;
    uint16_t position_hi;
};

#pragma pack(pop)

#endif
