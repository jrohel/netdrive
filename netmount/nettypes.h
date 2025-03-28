// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 Jaroslav Rohel, jaroslav.rohel@gmail.com

#ifndef _NETTYPES_H_
#define _NETTYPES_H_

#include <stdint.h>

// structs are packed
#pragma pack(push, 1)

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_ARP  0x0806

#define HW_TYPE_ETHERNET      1
#define ARP_OPERATION_REQUEST 1
#define ARP_OPERATION_REPLY   2

struct mac_addr {
    uint8_t bytes[6];
};


struct mac_hdr {
    struct mac_addr dest_hw_addr;
    struct mac_addr source_hw_addr;
    uint16_t ether_type;
};


union ipv4_addr {
    uint8_t bytes[4];
    uint32_t value;  // value in network byte order
};


struct arp_hdr {
    uint16_t hw_type;        //
    uint16_t protocol_type;  // equals to ETHER_TYPE
    uint8_t hw_addr_len;
    uint8_t protocol_addr_len;
    uint16_t operation;
    struct mac_addr sender_hw_addr;
    union ipv4_addr sender_protocol_addr;
    struct mac_addr target_hw_addr;
    union ipv4_addr target_protocol_addr;
};


#define IPV4_PROTOCOL_ICMP 1
#define IPV4_PROTOCOL_TCP  6
#define IPV4_PROTOCOL_UDP  17


struct ipv4_hdr {
    uint8_t version_ihl;  // version:4 | ihl:4
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag_offset;  // flags:3 | frag_ffset:13
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_csum;
    union ipv4_addr src_addr;
    union ipv4_addr dst_addr;
};


struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};


struct ether_frame {
    struct mac_hdr mac;
    union {
        struct arp_hdr arp;
        struct {
            struct ipv4_hdr ipv4;
            struct udp_hdr udp;
            uint8_t udp_data[1];
        };
    };
};

#pragma pack(pop)

#endif
