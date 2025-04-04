// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 Jaroslav Rohel, jaroslav.rohel@gmail.com

#include "../shared/dos.h"
#include "../shared/drvproto.h"
#include "exitcode.h"
#include "i86.h"
#include "nettypes.h"
#include "pktdrv.h"

#include <stdint.h>

#pragma pack(1)

#define PROGRAM_VERSION "1.0.0"

// Program parameters
#define ENABLE_DRIVE_PROTO_CHECKSUM   1
#define MAX_NUMBER_FRAME_SEND_RETRIES 4
#define MAX_FRAMESIZE                 1200


#define MY_STACK_SIZE 1024

// The MS-DOS .com file format is a memory dump of the 16-bit address space starting at offset 0100h,
// and continuing for the size of the program.
// The memory below 0100h also had a specific format, known as the Program Segment Prefix (PSP).
#define PROGRAM_OFFSET 0x100

#define NULL ((void *)0)

#define offsetof(__typ, __id) ((uint16_t)((char *)&(((__typ *)0)->__id) - (char *)0))

// make a __far pointer from segment and offset
#define MK_FP(__s, __o) (((unsigned short)(__s)):>((void __near *)(__o)))

#define DRIVE_DATA_OFFSET (offsetof(struct ether_frame, udp_data) + sizeof(struct drive_proto_hdr))

#define NETWORK_ERROR 0xFFFFU


#define MAX_DRIVERS_COUNT 26
struct shared_data {
    uint8_t ldrv[MAX_DRIVERS_COUNT];        // local to remote drives mappings (0=A, 1=B, 2=C, ...);
                                            // must be first in structure, used in assembler
    uint8_t remote_ips[MAX_DRIVERS_COUNT];  // index of ip in ip_mac_map table
    uint16_t remote_ports[MAX_DRIVERS_COUNT];
    union ipv4_addr local_ipv4;
    union ipv4_addr net_mask;
    uint16_t local_port;
    uint8_t gateway_ip_slot;  // indx of ip in ip_mac_map table
    struct ip_mac_map {
        union ipv4_addr ip;
        struct mac_addr mac_addr;
    } ip_mac_map[4];
    uint8_t requested_pktdrv_int;  // requested packet driver interrupt handle number (0 - autodetect)

    uint8_t used_pktdrv_int;  // used/found packet driver interrupt handle number
    uint16_t arp_pkthandle;
    uint16_t ipv4_pkthandle;
    struct mac_addr local_mac_addr;

    // Last used remote address. Waiting for a response from it.
    union ipv4_addr last_remote_ip;
    uint16_t last_remote_udp_port;
    volatile uint8_t server_response_received;  // 1 - if response in global_recv_buff
};

#define SHARED_DATA_SIZE 174  // It is sizeof(struct shared_data). Must be adjusted if structure size is changed!
// something like static_assert, error during compilation if SHARED_DATA_SIZE != sizeof(struct shared_data)
typedef char st_assert_SHARED_DATA_SIZE[SHARED_DATA_SIZE == sizeof(struct shared_data) ? 1 : -1];


typedef void(__interrupt * interrupt_handler)(void);


static void * get_offset(const void * func);
#pragma aux get_offset = parm[bx] modify exact[] value[bx]


// Defines a variable placed in the code (used for variables placed in the resident part of the code).
// It also defines access function.
// name - name of variable
// type - type of the variable or the first item if it is an array
// size - number of bytes reserved for the variable
#define CS_VARIABLE(name, type, size)          \
    static void __declspec(naked) name(void) { \
        __asm { db size dup (0) }                  \
    }                                          \
    static inline type * getptr_##name(void) { return (type *)get_offset(name); }

CS_VARIABLE(global_my_stack, int16_t, MY_STACK_SIZE)  // stack is array of 16 values
CS_VARIABLE(global_recv_buff, struct ether_frame, MAX_FRAMESIZE)
CS_VARIABLE(global_send_buff, struct ether_frame, MAX_FRAMESIZE)
CS_VARIABLE(global_orig_INT2F_handler, interrupt_handler, 4)
CS_VARIABLE(global_pktdrv_INT_handler, interrupt_handler, 4)
CS_VARIABLE(global_recv_data_len, int16_t, 2)  // length of received data, 0 means "free", neg value means "awaiting"
CS_VARIABLE(global_orig_stack_ptr, int16_t __far *, 4)  // stack is array of 16 values
CS_VARIABLE(global_my_2Fmux_id, uint8_t, 1)
CS_VARIABLE(global_req_drive, uint8_t, 1)  // the requested drive, set by the INT 2F handler and read by process2f()
CS_VARIABLE(global_sda_ptr, struct dos_sda __far *, 4)  // ptr to DOS SDA (set at startup, used by interrupt handler)
CS_VARIABLE(shared_data, struct shared_data, SHARED_DATA_SIZE)  // shared between NetMount processes


#define swap_word(value) (uint16_t)((uint16_t)value << 8 | (uint16_t)value >> 8)


// Copy string without terminating zero from src_pos. Return length of dst string or negative value if src_pos is bigger theh source length.
static int my_strcpy_noterm_nf(char * restrict dst, const char __far * restrict src, unsigned int src_pos) {
    while (src_pos > 0 && *src != '\0') {
        --src_pos;
        ++src;
    }
    if (src_pos > 0) {
        return -src_pos;
    }
    while (*src != '\0') {
        *dst++ = *src++;
        ++src_pos;
    }
    return src_pos;
}


static void my_memcpy_ff(void __far * restrict dst, const void __far * restrict src, int n) {
    for (int i = 0; i < n; ++i) {
        ((uint8_t __far *)dst)[i] = ((uint8_t __far *)src)[i];
    }
}


static uint8_t char_to_upper(uint8_t character) {
    if (character >= 'a' && character <= 'z') {
        return character - 'a' + 'A';
    }
    return character;
}


static int strn_upper_cmp(const char * tested_string, const char * upper_string, uint16_t len) {
    const uint8_t * const endp = tested_string + len;
    int ret = 0;
    while (tested_string < endp) {
        ret = char_to_upper(*tested_string) - *upper_string;
        if (ret != 0) {
            break;
        }
        ++tested_string;
        ++upper_string;
    }
    return ret;
}


static int contains_wildcard(const char __far * s) {
    while (*s != '\0') {
        if (*s == '?' || *s == '*') {
            return 1;
        }
        ++s;
    }
    return 0;
}


// convert filename to fcb_file_name structure
static void to_dos_fn(struct fcb_file_name __far * dos_fn, const char __far * file_name) {
    unsigned int i;
    // fill dos_fd with spaces
    for (i = 0; i < sizeof(dos_fn->name_blank_padded); ++i) {
        dos_fn->name_blank_padded[i] = ' ';
    }
    for (i = 0; i < sizeof(dos_fn->ext_blank_padded); ++i) {
        dos_fn->ext_blank_padded[i] = ' ';
    }

    // copy initial '.'
    for (i = 0; i < sizeof(dos_fn->name_blank_padded) && file_name[i] == '.'; ++i) {
        dos_fn->name_blank_padded[i] = '.';
    }

    // fill in the filename, up to 8 chars or first dot
    for (; i < sizeof(dos_fn->name_blank_padded) && file_name[i] != '.' && file_name[i] != '\0'; ++i) {
        dos_fn->name_blank_padded[i] = file_name[i];
    }
    file_name += i;

    // move to dot
    while ((*file_name != '.') && (*file_name != '\0')) {
        ++file_name;
    }

    if (*file_name == '\0') {
        return;
    }

    ++file_name;  // skip the dot

    // fill in the extension
    for (i = 0; i < sizeof(dos_fn->ext_blank_padded) && file_name[i] != '.' && file_name[i] != '\0'; ++i) {
        dos_fn->ext_blank_padded[i] = file_name[i];
    }
}


// get dos file name from fully qualified path and store it to fcb_file_name structure
static void get_dos_fn_from_full_path(struct fcb_file_name __far * dos_fn, const char __far * full_path) {
    // skip drive if present
    if (full_path[0] != '\0' && full_path[1] == ':') {
        full_path += 2;
    }

    // find last slash or backslash
    const char __far * last_backslash = full_path;
    for (const char __far * it = full_path; *it != '\0'; ++it) {
        if (*it == '\\' || *it == '/') {
            last_backslash = it;
        }
    }

    if (*last_backslash == '\\' || *last_backslash == '/') {
        ++last_backslash;
    }

    to_dos_fn(dos_fn, last_backslash);
}


#pragma aux drive_to_num parm[bx] modify exact[bl] value[bl]
static uint8_t __declspec(naked) drive_to_num(char drive_letter) {
    // suppress Open Watcom warning: "Parameter has been defined, but not referenced"
    drive_letter;

    // clang-format off
    __asm {
        cmp bl, 'a'
        jl upper
        cmp bl, 'z'
        jg upper
        sub bl, 'a'
        ret
    upper:
        sub bl, 'A'
        ret
    }
    // clang-format on
}

// Compute BSD Checksum for "len" bytes beginning at location "addr".
#pragma aux bsd_checksum parm[bx][cx] modify exact[ax bx cx dx] value[ax]
static uint16_t __declspec(naked) bsd_checksum(const void * addr, uint16_t len) {
    // suppress Open Watcom warning: "Parameter has been defined, but not referenced"
    addr;
    len;

    // clang-format off
    __asm {
        xor ax, ax
        test cx, cx
        jz end
        xor dh, dh

    next:
        ror ax, 1
        mov dl, [bx]
        add ax, dx
        inc bx
        loop next

    end:
        ret
    }
    // clang-format on
}


// Compute Internet Checksum for "len" bytes beginning at location "addr".
// Taken from https://tools.ietf.org/html/rfc1071
static uint16_t internet_checksum(const void * addr, uint16_t len) {
    uint32_t sum = 0;
    const uint16_t * ptr = addr;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    //  Add left-over byte, if any
    if (len > 0) {
        sum += *(uint8_t *)ptr;
    }

    //  Fold 32-bit sum to 16 bits
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}


static void create_ip(struct ipv4_hdr * ipv4, union ipv4_addr dst_addr, uint16_t data_len, uint8_t protocol) {
    static uint16_t id = 0;

    ipv4->version_ihl = (4 << 4) | (sizeof(*ipv4) / 4);
    ipv4->tos = 0;
    ipv4->total_len = swap_word(sizeof(*ipv4) + data_len);
    ipv4->id = swap_word(++id);
    ipv4->flags_frag_offset = swap_word(0x2 << 13);  // flags = 0x2 (3 bits, 0x2 = don't fragment); frag_offset = 0
    ipv4->ttl = 64;
    ipv4->protocol = protocol;
    ipv4->hdr_csum = 0;  // 0 is used during computing header csum, then replaced by computed value
    ipv4->src_addr = getptr_shared_data()->local_ipv4;
    ipv4->dst_addr = dst_addr;

    ipv4->hdr_csum = internet_checksum(ipv4, sizeof(*ipv4));
}


static void create_udp(struct udp_hdr * udp, uint16_t src_port, uint16_t dst_port, uint16_t data_len) {
    udp->src_port = swap_word(src_port);
    udp->dst_port = swap_word(dst_port);
    udp->length = swap_word(sizeof(*udp) + data_len);
    udp->checksum = 0;  // 0 - not used
}


#pragma aux send_frame parm[cx][si] modify exact[ax cx dx si]
static void __declspec(naked) send_frame(uint16_t frame_length, const void * sndbuff) {
    // suppress Open Watcom warning: "Parameter has been defined, but not referenced"
    frame_length;
    sndbuff;

    // clang-format off
    __asm {
        mov ah, 0x04  // Packet Driver function Send Packet

        // simulate INT instruction (pushf + cli + call __far)
        pushf
        cli
        call dword ptr global_pktdrv_INT_handler

        ret
    }
    // clang-format on
}


static void handle_arp(void) {
    struct ether_frame * const rcv_framebuf = getptr_global_recv_buff();
    if (rcv_framebuf->arp.hw_type != swap_word(HW_TYPE_ETHERNET)) {
        return;
    }
    if (rcv_framebuf->arp.target_protocol_addr.value != getptr_shared_data()->local_ipv4.value) {
        return;
    }

    // If the remote IP address is in my IP MAC table, update the MAC address in the table.
    for (int i = 0; i < sizeof(getptr_shared_data()->ip_mac_map) / sizeof(getptr_shared_data()->ip_mac_map[0]); ++i) {
        if (getptr_shared_data()->ip_mac_map[i].ip.value == rcv_framebuf->arp.sender_protocol_addr.value) {
            getptr_shared_data()->ip_mac_map[i].mac_addr = rcv_framebuf->arp.sender_hw_addr;

            // If the remote IP address is a gateway, update (use) the MAC for all IP slots outside our network
            if (i == getptr_shared_data()->gateway_ip_slot) {
                const uint32_t network = getptr_shared_data()->local_ipv4.value & getptr_shared_data()->net_mask.value;
                for (int j = 0;
                     j < sizeof(getptr_shared_data()->ip_mac_map) / sizeof(getptr_shared_data()->ip_mac_map[0]);
                     ++j) {
                    if (j != i && getptr_shared_data()->ip_mac_map[j].ip.value &
                                      getptr_shared_data()->net_mask.value != network) {
                        getptr_shared_data()->ip_mac_map[j].mac_addr = rcv_framebuf->arp.sender_hw_addr;
                    }
                }
            }

            break;
        }
    }

    if (rcv_framebuf->arp.operation != swap_word(ARP_OPERATION_REQUEST)) {
        return;
    }

    // It is ARP request, modify it and send it back as ARP reply.
    rcv_framebuf->mac.dest_hw_addr = rcv_framebuf->mac.source_hw_addr;
    rcv_framebuf->mac.source_hw_addr = getptr_shared_data()->local_mac_addr;
    rcv_framebuf->mac.ether_type = swap_word(ETHER_TYPE_ARP);
    rcv_framebuf->arp.hw_type = swap_word(HW_TYPE_ETHERNET);
    rcv_framebuf->arp.protocol_type = swap_word(ETHER_TYPE_IPV4);
    rcv_framebuf->arp.hw_addr_len = sizeof(getptr_shared_data()->local_mac_addr);
    rcv_framebuf->arp.protocol_addr_len = 4;
    rcv_framebuf->arp.operation = swap_word(ARP_OPERATION_REPLY);
    rcv_framebuf->arp.target_hw_addr = rcv_framebuf->arp.sender_hw_addr;
    rcv_framebuf->arp.target_protocol_addr = rcv_framebuf->arp.sender_protocol_addr;
    rcv_framebuf->arp.sender_hw_addr = getptr_shared_data()->local_mac_addr;
    rcv_framebuf->arp.sender_protocol_addr = getptr_shared_data()->local_ipv4;

    const uint16_t length = sizeof(struct mac_hdr) + sizeof(struct arp_hdr);
    send_frame(length, global_recv_buff);
}


#pragma aux handle_ipv4 value[bl]
static uint8_t handle_ipv4(void) {
    const struct ether_frame * const rcv_frame = getptr_global_recv_buff();
    if (rcv_frame->ipv4.protocol != IPV4_PROTOCOL_UDP) {
        return 0xFFU;
    }
    if (rcv_frame->ipv4.dst_addr.value != getptr_shared_data()->local_ipv4.value) {
        return 0xFFU;
    }
    if (rcv_frame->ipv4.src_addr.value != getptr_shared_data()->last_remote_ip.value) {
        return 0xFFU;
    }
    if (rcv_frame->udp.src_port != swap_word(getptr_shared_data()->last_remote_udp_port)) {
        return 0xFFU;
    }
    if (rcv_frame->udp.dst_port != swap_word(getptr_shared_data()->local_port)) {
        return 0xFFU;
    }

    if (*getptr_global_recv_data_len() < offsetof(struct ether_frame, udp_data) + sizeof(struct drive_proto_hdr)) {
        return 0xFFU;
    }

    const struct drive_proto_hdr * drive_proto = (const struct drive_proto_hdr *)rcv_frame->udp_data;
    if (drive_proto->version != DRIVE_PROTO_VERSION) {
        return 0xFFU;
    }

    getptr_shared_data()->server_response_received = 1;

    return 0;  // don't free rcv buffer, will be fried in 2F hadler
}


// Function is called when a packet is received. It is called twice.
// The first time it is called to request a buffer from the application to copy the packet into.
// AX == 0 and CX == received_frame_size on this call. The application may return a pointer to a buffer
// to which the packet should be copied by the driver in ES:DI. If the application has no buffer,
// it may return 0:0 in ES:DI, and the driver should discard the packet and not perform the second call.
// On the second call, AX == 1. This call indicates that the copy has been completed, and the application may
// do whatever it wants with the buffer. DS:SI points to the buffer into which the packet was copied.
static void __declspec(naked) pktdrv_recv(void) {
    // clang-format off
    __asm {
        push ds
        push bx
        pushf

        push cs
        pop ds

        cmp ax, 0
        jne second_call  // if ax != 0, then second call: packet driver filled my buffer

        // first call: the packet driver needs a buffer of CX bytes
        cmp cx, MAX_FRAMESIZE
        ja no_buffer_avail  // received frame is biger then our buffer

        cmp word ptr global_recv_data_len, 0
        jg no_buffer_avail  // if > 0, we're busy, the received buffer has already been filled

        // buffer is available, set its seg:off to es:di
        push ds
        pop es
        mov di, offset global_recv_buff

        // store recvbufflen to expected len and switch it to neg until data comes
        mov word ptr global_recv_data_len, cx
        neg word ptr global_recv_data_len

        jmp restore_and_ret

    no_buffer_avail:
        // no buffer available, or it's too small -> return 0:0 in ES:DI
        xor bx, bx
        push bx
        pop es
        push bx
        pop di

        jmp restore_and_ret

    second_call:
        // second call: the packet driver has stored the data in our buffer
        // switch recvbufflen back to positive value -> indicates that we have received data
        neg word ptr global_recv_data_len

        cmp word ptr global_recv_data_len, 34  // 14 (MAC) + 20 (IPv4)
        jl drop
        push ax
        mov ax, word ptr global_recv_buff[12]
        cmp ax, 0x0008  //swap_word(ETHER_TYPE_IPV4)
        pop ax
        jne try_arp
        call handle_ipv4
        test bl, bl
        jnz drop
        jmp restore_and_ret

    try_arp:
        cmp word ptr global_recv_data_len, 42  // 14 (MAC) + 28 (ARP)
        jl drop
        push ax
        mov ax, word ptr global_recv_buff[12]
        cmp ax, 0x0608  //swap_word(ETHER_TYPE_ARP)
        pop ax
        jne drop
        call handle_arp

    drop:
        mov word ptr global_recv_data_len, 0

        // restore flags, bx and ds, then return
    restore_and_ret:
        popf
        pop bx
        pop ds
        retf
    }
    // clang-format on
}


// Sends the request stored in global_send_buff and waits for a response.
// If no response is received, the send is repeated (the maximum number of sends is MAX_NUMBER_FRAME_SEND_RETRIES).
// Returns the length of reply, or NETWORK_ERROR on error.
static uint16_t send_request(
    uint8_t function, uint8_t local_drive, uint16_t request_data_len, uint8_t ** reply_data, uint16_t * reply_ax) {
    static uint8_t seq = 0;

    // resolve remote drive - no need to validate it, it has been validated already by inthandler()
    const uint8_t drive = getptr_shared_data()->ldrv[local_drive];

    // if function too long then quit
    const uint16_t frame_length = sizeof(struct mac_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) +
                                  sizeof(struct drive_proto_hdr) + request_data_len;
    if (frame_length > MAX_FRAMESIZE)
        return 0;

    // inc seq
    ++seq;

    struct ether_frame * const frame = getptr_global_send_buff();

    // Fill (ethernet) mac destination addres. Source mac address and ethertype was filled during initialization.
    frame->mac.dest_hw_addr = getptr_shared_data()->ip_mac_map[getptr_shared_data()->remote_ips[local_drive]].mac_addr;

    const union ipv4_addr remote_ip =
        getptr_shared_data()->ip_mac_map[getptr_shared_data()->remote_ips[local_drive]].ip;
    create_ip(
        &frame->ipv4,
        remote_ip,
        sizeof(struct udp_hdr) + sizeof(struct drive_proto_hdr) + request_data_len,
        IPV4_PROTOCOL_UDP);
    getptr_shared_data()->last_remote_ip = remote_ip;
    create_udp(
        &frame->udp,
        getptr_shared_data()->local_port,
        getptr_shared_data()->remote_ports[local_drive],
        sizeof(struct drive_proto_hdr) + request_data_len);
    getptr_shared_data()->last_remote_udp_port = getptr_shared_data()->remote_ports[local_drive];


    struct drive_proto_hdr * const snd_drive_proto = (struct drive_proto_hdr *)frame->udp_data;
    const uint16_t len = request_data_len + sizeof(*snd_drive_proto);  // drive_proto_hdr and data length
    snd_drive_proto->version = DRIVE_PROTO_VERSION;
    snd_drive_proto->length_flags = len;
    snd_drive_proto->sequence = seq;  // sequence number
    snd_drive_proto->drive = drive;
    snd_drive_proto->function = function;  // AL value (function)
    if (ENABLE_DRIVE_PROTO_CHECKSUM) {
        snd_drive_proto->length_flags |= 0x8000;  // switch checksum on
        snd_drive_proto->checksum = bsd_checksum(
            (uint8_t *)(&snd_drive_proto->checksum + 1),
            len - ((uint8_t *)(&snd_drive_proto->checksum + 1) - (uint8_t *)snd_drive_proto));
    } else {
        snd_drive_proto->checksum = DRIVE_PROTO_MAGIC;
    }

    getptr_shared_data()->server_response_received = 0;

    volatile int16_t * const recvrequest_data_len_ptr = getptr_global_recv_data_len();
    // Send the function frame and wait about 55ms - 110ms for response. Then, resend
    // the function again and again, up to MAX_NUMBER_FRAME_SEND_RETRIES times.
    // The timeout is increased by 1 tick (55ms) for each retry.
    // The clock at 0x46C address is used as a timing reference. The default frequncy is 18.2Hz.
    for (int retries = 1; retries <= MAX_NUMBER_FRAME_SEND_RETRIES; ++retries) {
        send_frame(frame_length, frame);

        // wait for (and validate) the answer frame
        const struct drive_proto_hdr * const rcv_drive_proto =
            (struct drive_proto_hdr *)((struct ether_frame *)global_recv_buff)->udp_data;
        volatile uint8_t __far * const time =
            (uint8_t __far *)0x46C;  // lowest 8 bits of timer. Warning: this location won't increment while interrupts are disabled!

        for (const uint8_t rcv_start_time = *time;;) {
            if (*time - rcv_start_time > retries) {
                // timeout
                break;
            }

            if (getptr_shared_data()->server_response_received == 0) {
                continue;
            }

            // validate frame length (if provided)
            const uint16_t len = rcv_drive_proto->length_flags & 0x07FF;
            if (len > *recvrequest_data_len_ptr) {
                // frame appears to be truncated
                goto ignore_frame;
            }
            if (len < sizeof(*rcv_drive_proto)) {
                // malformed frame
                goto ignore_frame;
            }

            // validate sequence number
            if (rcv_drive_proto->sequence != seq) {
                // The response has a different sequence number than the request.
                // It may be a delayed response to a previous repeated request.
                goto ignore_frame;
            }

            if (rcv_drive_proto->length_flags & 0x8000) {
                // the received data contains a checksum
                // if enabled, check the received checksum
                if (ENABLE_DRIVE_PROTO_CHECKSUM &&
                    bsd_checksum(
                        (uint8_t *)(&rcv_drive_proto->checksum + 1),
                        len - ((uint8_t *)(&rcv_drive_proto->checksum + 1) - (uint8_t *)rcv_drive_proto)) !=
                        rcv_drive_proto->checksum) {
                    goto ignore_frame;
                }
            } else {
                // the received data contains magic mark, check it
                if (rcv_drive_proto->checksum != DRIVE_PROTO_MAGIC) {
                    goto ignore_frame;
                }
            }

            // return buffer (without headers and seq)
            *reply_data = (uint8_t *)(rcv_drive_proto + 1);  // +1 skip rcv_drive_proto header
            *reply_ax = rcv_drive_proto->ax;  //(uint16_t)rcv_drive_proto->drive << 8 | rcv_drive_proto->function;
            return len - sizeof(*rcv_drive_proto);

        ignore_frame:                       // ignore this frame and wait for the next one
            *recvrequest_data_len_ptr = 0;  // mark the buffer empty
        }
    }

    return NETWORK_ERROR;
}


// set AX (error code) to 0, clear CF
inline static void set_success(union i86_interrupt_regs_pack __far * r) {
    r->w.ax = 0;
    r->w.flags &= ~(I86_FLAG_CF);
}

// copy error code to AX, set CF
inline static void set_error(union i86_interrupt_regs_pack __far * r, uint16_t x) {
    r->w.ax = x;
    r->w.flags |= I86_FLAG_CF;
}

#pragma aux handle_request_for_our_drive modify[ax bx cx dx si di es]
static void handle_request_for_our_drive(void) {
    // caller registers stored on stack
    union i86_interrupt_regs_pack __far * r = (union i86_interrupt_regs_pack __far *)*getptr_global_orig_stack_ptr();

    int len;
    uint16_t i;
    unsigned char * reply;
    uint16_t ax;  // used to collect the resulting value of AX

    struct ether_frame * const frame = getptr_global_send_buff();
    uint8_t * const buff = frame->udp_data + sizeof(struct drive_proto_hdr);  // pointer to the "query arguments"

    const uint8_t subfunction = r->b.al;
    const uint8_t reqdrv = *getptr_global_req_drive();

    set_success(r);  // rewrites r->w.ax and r->w.flags

    struct dos_sda __far * const sda_ptr = *getptr_global_sda_ptr();

    volatile int16_t * const recvbufflen_ptr = getptr_global_recv_data_len();

    switch (subfunction) {
        case INT2F_REMOVE_DIR:
        case INT2F_MAKE_DIR:
            // Create or remove remote directory
            // SS = DOS DS
            // SDA first filename pointer -> fully-qualified directory name
            // SDA CDS pointer -> current directory structure for drive with dir
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code

            // Removing the current directory is forbidden
            if (subfunction == INT2F_REMOVE_DIR) {
                for (short i = 0; sda_ptr->fn1[i] == sda_ptr->drive_cdsptr[i]; ++i) {
                    if (sda_ptr->fn1[i] == 0) {
                        set_error(r, DOS_EXTERR_ATTEMPT_REMOVE_CUR_DIR);
                        goto finish;
                    }
                }
            }

            // copy fn1 to buff (but skip drive part)
            len = my_strcpy_noterm_nf(buff, sda_ptr->fn1, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
                break;
            }

            if (send_request(subfunction, reqdrv, len, &reply, &ax) == 0) {
                if (ax != 0) {
                    set_error(r, ax);
                }
            } else {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            }

            break;

        case INT2F_CHANGE_DIR:
            // Check if target (remote) directory exists
            // SS = DOS DS
            // SDA first filename pointer -> fully-qualified directory name
            // SDA CDS pointer -> current directory structure for drive with dir
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code

            // copy fn1 to buff (but skip drive part)
            len = my_strcpy_noterm_nf(buff, sda_ptr->fn1, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
                break;
            }

            if (send_request(subfunction, reqdrv, len, &reply, &ax) == 0) {
                if (ax != 0) {
                    set_error(r, ax);
                }
            } else {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
            }

            break;

        case INT2F_CLOSE_FILE: {
            // Decrement the SFT's handle open count (note: increment is done by DOS) and inform server
            // ES:DI points to the SFT
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code


            struct dos_sft __far * const sftptr = MK_FP(r->w.es, r->w.di);
            if (sftptr->handle_count > 0) {
                --sftptr->handle_count;
            }

            struct drive_proto_closef * const args = (struct drive_proto_closef * const)buff;
            args->start_cluster = sftptr->start_cluster;
            if (send_request(subfunction, reqdrv, sizeof(*args), &reply, &ax) == 0) {
                if (ax != 0) {
                    set_error(r, ax);
                }
            }
        } break;

        case INT2F_COMMIT_FILE:
            // Flush changes to disk (all file buffers, directory entry), not implemented now
            // ES:DI points to the SFT
            break;

        case INT2F_READ_FILE: {
            // Create or remove remote directory
            // SS = DOS DS
            // ES:DI points to the SFT
            // CX = number of bytes to read
            // SDA DTA field -> user buffer
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code
            // CX = number of bytes read (0000h = end of file)
            // SFT updated

            struct dos_sft __far * const sftptr = MK_FP(r->w.es, r->w.di);

            // is the file open for read?
            if (sftptr->open_mode & 1) {
                set_error(r, DOS_EXTERR_ACCESS_DENIED);
                break;
            }

            // caller wants to read 0 bytes, nothink to do
            if (r->w.cx == 0) {
                break;
            }

            // split read request into chunks that fit into a network frame
            uint16_t total_read_len = 0;
            for (;;) {
                uint16_t len;
                const uint16_t chunklen = r->w.cx - total_read_len > MAX_FRAMESIZE - DRIVE_DATA_OFFSET
                                              ? MAX_FRAMESIZE - DRIVE_DATA_OFFSET
                                              : r->w.cx - total_read_len;
                struct drive_proto_readf * const args = (struct drive_proto_readf * const)buff;
                args->offset = sftptr->file_pos + total_read_len;
                args->start_cluster = sftptr->start_cluster;
                args->length = chunklen;
                len = send_request(subfunction, reqdrv, sizeof(*args), &reply, &ax);
                if (len == NETWORK_ERROR) {
                    set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
                    break;
                } else if (ax != 0) {
                    set_error(r, ax);
                    break;
                } else {  // success
                    my_memcpy_ff(sda_ptr->curr_dta + total_read_len, reply, len);
                    total_read_len += len;
                    if ((len < chunklen) || (total_read_len == r->w.cx)) {
                        // EOF - update SFT and break out
                        sftptr->file_pos += total_read_len;
                        r->w.cx = total_read_len;
                        break;
                    }
                }
                *recvbufflen_ptr = 0;
            }
        } break;

        case INT2F_WRITE_FILE: {
            // SS = DOS DS
            // ES:DI points to the SFT
            // CX = number of bytes to read
            // SDA DTA field -> user buffer
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code
            // CX = number of bytes read (0000h = end of file)
            // SFT updated

            struct dos_sft __far * const sftptr = MK_FP(r->w.es, r->w.di);

            // is the file open for write?
            if ((sftptr->open_mode & 3) == 0) {
                set_error(r, DOS_EXTERR_ACCESS_DENIED);
                break;
            }

            // TODO: From EtherDFS - I should update the file's time in the SFT here
            // split write request into chunks that fit into a network frame
            uint16_t total_written_len = 0;
            uint16_t bytes_left = r->w.cx;
            do {  // 0-bytes write must be sent too, it means "truncate"
                const uint16_t chunklen =
                    bytes_left > MAX_FRAMESIZE - DRIVE_DATA_OFFSET - sizeof(struct drive_proto_writef)
                        ? MAX_FRAMESIZE - DRIVE_DATA_OFFSET - sizeof(struct drive_proto_writef)
                        : bytes_left;
                struct drive_proto_writef * const args = (struct drive_proto_writef * const)buff;
                args->offset = sftptr->file_pos;
                args->start_cluster = sftptr->start_cluster;
                my_memcpy_ff(buff + sizeof(*args), sda_ptr->curr_dta + total_written_len, chunklen);
                uint16_t len = send_request(subfunction, reqdrv, chunklen + sizeof(*args), &reply, &ax);
                if (len == NETWORK_ERROR) {
                    set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
                    break;
                } else if ((ax != 0) || (len != 2)) {
                    set_error(r, ax);
                    break;
                } else {  // success - write amount of bytes written into CX and update SFT
                    struct drive_proto_writef_reply const * const args =
                        (struct drive_proto_writef_reply const * const)reply;
                    len = args->written;
                    total_written_len += len;
                    bytes_left -= len;
                    r->w.cx = total_written_len;
                    sftptr->file_pos += len;
                    if (sftptr->file_pos > sftptr->file_size)
                        sftptr->file_size = sftptr->file_pos;
                    if (len != chunklen)
                        break;  // something bad happened on the other side
                }
                *recvbufflen_ptr = 0;
            } while (bytes_left > 0);
        } break;

        case INT2F_LOCK_UNLOCK_FILE: {
            // BL = function: 0 lock, 1 unlock
            // CX = number of lock/unlock parameters (0001h for DOS 4.0-6.1)
            // DS:DX -> parameter block
            // ES:DI -> SFT
            // SS = DOS DS
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code

            if (r->b.bl > 1) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);  // BL must be 0 (lock) or 1 (unlock)
            }

            struct dos_sft __far * const sftptr = MK_FP(r->w.es, r->w.di);

            struct drive_proto_lockf * const args = (struct drive_proto_lockf * const)buff;
            args->params_count = r->w.cx;
            args->start_cluster = sftptr->start_cluster;

            my_memcpy_ff(buff + sizeof(*args), MK_FP(r->w.ds, r->w.dx), args->params_count << 3);
            if (send_request(
                    INT2F_LOCK_UNLOCK_FILE + r->b.bl, reqdrv, (args->params_count << 3) + sizeof(*args), &reply, &ax) !=
                0) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            }
        } break;

        case INT2F_UNLOCK_FILE:
            // Error - DOS 3.x only
            set_error(r, DOS_EXTERR_FUNC_NUM_INVALID);
            break;

        case INT2F_DISK_INFO:
            // Return:
            // AL = sectors per cluster
            // AH = media ID byte
            // BX = total clusters
            // CX = bytes per sector
            // DX = number of available clusters

            if (send_request(subfunction, reqdrv, 0, &reply, &ax) == 6) {
                r->w.ax = ax;  // AL -  sectors per cluster, AH - media ID byte
                struct drive_proto_disk_info_reply const * const args =
                    (struct drive_proto_disk_info_reply const * const)reply;
                r->w.bx = args->total_clusters;
                r->w.cx = args->bytes_per_sector;
                r->w.dx = args->available_clusters;
            } else {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            }
            break;

        case INT2F_SET_ATTRS: {
            // SS = DOS DS
            // SDA first filename pointer -> fully-qualified name of file
            // SDA CDS pointer -> current directory structure for drive with file.
            // STACK:
            // WORD new file attributes
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code
            // STACK unchanged

            // copy fn1 to buff (but skip drive part)
            len = my_strcpy_noterm_nf(buff + sizeof(struct drive_proto_set_attrs), sda_ptr->fn1, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
                break;
            }

            // new file attributes are on the original stack
            struct drive_proto_set_attrs * const args = (struct drive_proto_set_attrs * const)buff;
            args->attrs = *(*getptr_global_orig_stack_ptr() + sizeof(*r) / 2);
            i = send_request(subfunction, reqdrv, len + sizeof(*args), &reply, &ax);
            if (i != 0) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            } else if (ax != 0) {
                set_error(r, ax);
            }
        } break;

        case INT2F_GET_ATTRS:
            // SS = DOS DS
            // SDA first filename pointer -> fully-qualified name of file (Wildcards and device names are not permitted}
            // SDA CDS pointer -> current directory structure for drive with file
            // (offset = FFFFh if null CDS [net direct request])
            // SDA search attributes = mask of attributes which may be included in search for file
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code or file attributes
            // BX:DI = file size
            // CX = time stamp of file
            // DX = date stamp of file

            // copy fn1 to buff (but skip drive part)
            len = my_strcpy_noterm_nf(buff, sda_ptr->fn1, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
                break;
            }

            i = send_request(subfunction, reqdrv, len, &reply, &ax);
            if ((uint16_t)i == 0xffffU) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            } else if ((i != 9) || (ax != 0)) {
                set_error(r, ax);
            } else {
                struct drive_proto_get_attrs_reply const * const args =
                    (struct drive_proto_get_attrs_reply const * const)reply;
                r->w.cx = args->time;
                r->w.dx = args->date;
                r->w.di = args->size_lo;
                r->w.bx = args->size_hi;
                r->w.ax = args->attrs;
            }
            break;

        case INT2F_RENAME_FILE:
            // SS = DS = DOS DS
            // SDA first filename pointer = offset of fully-qualified old name
            // SDA second filename pointer = offset of fully-qualified new name
            // SDA CDS pointer -> current directory structure for drive with file
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code

            if (sda_ptr->fn1[0] != sda_ptr->fn2[0]) {
                set_error(r, DOS_EXTERR_NOT_SAME_DEVICE);
                break;
            }

            if (contains_wildcard(sda_ptr->fn2)) {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
                break;
            }

            // copy fn1 to buff (but skip drive part)
            len = my_strcpy_noterm_nf(buff + 1, sda_ptr->fn1, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
                break;
            }
            buff[0] = len;  // store length of filename

            // copy fn2 to buff (but skip drive part)
            len = my_strcpy_noterm_nf(buff + 1 + buff[0], sda_ptr->fn2, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
                break;
            }

            i = send_request(subfunction, reqdrv, 1 + buff[0] + len, &reply, &ax);
            if (i != 0) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            } else if (ax != 0) {
                set_error(r, ax);
            }
            break;

        case INT2F_DELETE_FILE:
            // Delete remote file
            // SS = DS = DOS DS
            // SDA first filename pointer -> fully-qualified directory name
            // SDA CDS pointer -> current directory structure for drive with dir
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code

            len = my_strcpy_noterm_nf(buff, sda_ptr->fn1, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
                break;
            }

            i = send_request(subfunction, reqdrv, len, &reply, &ax);
            if (i == NETWORK_ERROR) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            } else if ((i != 0) || (ax != 0)) {
                set_error(r, ax);
            }
            break;

        case INT2F_OPEN_FILE:
        case INT2F_CREATE_FILE:
        case INT2F_EXTENDED_OPEN_CREATE_FILE:
            // ES:DI -> uninitialized SFT
            // SS = DOS DS
            // SDA first filename pointer -> fully-qualified name of file to open
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code
            // In INT2F_EXTENDED_OPEN_CREATE_FILE: CX = result code (01h opened,  02h created, 03h replaced (truncated))
            // SFT filled (except handle count, which DOS manages itself)
            // STACK unchanged

            if (contains_wildcard(sda_ptr->fn1)) {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
                break;
            }

            len = my_strcpy_noterm_nf(buff + 6, sda_ptr->fn1, 2);
            if (len < 0) {
                set_error(r, DOS_EXTERR_PATH_NOT_FOUND);
                break;
            }

            struct drive_proto_open_create * const args = (struct drive_proto_open_create * const)buff;
            args->attrs = *(*getptr_global_orig_stack_ptr() + sizeof(*r) / 2);
            if (subfunction == INT2F_EXTENDED_OPEN_CREATE_FILE) {
                args->action = sda_ptr->action_ext;
                args->mode = sda_ptr->mode_ext;
            }

            i = send_request(subfunction, reqdrv, len + 6, &reply, &ax);
            if (i == NETWORK_ERROR) {
                set_error(r, 2);
            } else if (i != sizeof(struct drive_proto_open_create_reply) || ax != 0) {
                set_error(r, ax);
            } else {
                struct dos_sft __far * const sft_ptr = MK_FP(r->w.es, r->w.di);
                struct drive_proto_open_create_reply const * const args =
                    (struct drive_proto_open_create_reply const * const)reply;
                if (subfunction == INT2F_EXTENDED_OPEN_CREATE_FILE) {
                    r->w.cx = args->result_code;
                }
                if (sft_ptr->open_mode &
                    0x8000) {  // EtherDFS: if bit 15 is set, then it's a "FCB open", and requires the internal DOS
                               // "Set FCB Owner" function to be called: TODO FIXME set_sft_owner()
                }
                sft_ptr->file_attr = args->attrs;
                sft_ptr->dev_info_word = 0x8040 | reqdrv;  // mark device as network & unwritten drive
                sft_ptr->redir_data = 0;
                sft_ptr->start_cluster = args->start_cluster;
                sft_ptr->file_time = args->date_time;
                sft_ptr->file_size = args->size;
                sft_ptr->file_pos = 0;
                sft_ptr->open_mode &= 0xff00u;
                sft_ptr->open_mode |= args->mode;
                sft_ptr->rel_sector = 0xffff;
                sft_ptr->abs_sector = 0xffff;
                sft_ptr->dir_sector = 0;
                sft_ptr->dir_entry_no = 0xff;  // why such value? no idea, EtherDFS says PHANTON.C uses that
                sft_ptr->file_name = args->name;
            }
            break;

        case INT2F_FIND_FIRST:
        case INT2F_FIND_NEXT: {
            // SS = DS = DOS DS
            // INT2F_FIND_FIRST: [DTA] = uninitialized 21-byte findfirst search data (see #01626 at INT 21/AH=4Eh)
            // INT2F_FIND_FIRST: SDA first filename pointer -> fully-qualified search template
            // INT2F_FIND_FIRST: SDA CDS pointer -> current directory structure for drive with file
            // INT2F_FIND_FIRST: SDA search attribute = attribute mask for search
            // INT2F_FIND_NEXT: ES:DI -> CDS
            // INT2F_FIND_NEXT: ES:DI -> DTA (MSDOS v5.0)
            // INT2F_FIND_NEXT: [DTA] = 21-byte findfirst search data (see #01626 at INT 21/AH=4Eh)
            // Return:
            // CF set on error, clear if successful
            // AX = DOS error code (see #01680 at INT 21/AH=59h/BX=0000h) -> http://www.ctyme.com/intr/rb-3012.htm
            // [DTA] = updated findfirst search data
            // (bit 7 of first byte must be set)
            // behind search data ([DTA+15h]) = standard directory entry for file (see #01352)
            // FindNext is the same, but only DTA should be used to fetch search params

            struct dos_search __far * dta;

            // prepare the query buffer
            if (subfunction == INT2F_FIND_FIRST) {
                // file attributes and name
                struct drive_proto_find_first * const args = (struct drive_proto_find_first * const)buff;
                dta = (struct dos_search __far *)(sda_ptr->curr_dta);
                args->attrs = sda_ptr->srch_attr;  // file attributes to look for
                // copy fn1 to buff (but skip drive part)
                len = my_strcpy_noterm_nf(buff + 1, sda_ptr->fn1, 2);
                len += sizeof(*args);
            } else {
                // INT2F_FIND_NEXT use search arguments from DTA (ES:DI)
                dta = MK_FP(r->w.es, r->w.di);
                struct drive_proto_find_next * const args = (struct drive_proto_find_next * const)buff;
                args->cluster = dta->cluster;
                args->dir_entry = dta->dir_entry_no;
                args->attrs = dta->srch_attr;
                args->search_template = dta->srch_tmpl;
                len = sizeof(*args);
            }

            i = send_request(subfunction, reqdrv, len, &reply, &ax);
            if (i == NETWORK_ERROR) {
                if (subfunction == INT2F_FIND_FIRST) {
                    set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
                } else {
                    set_error(r, DOS_EXTERR_NO_MORE_FILES);
                }
                break;
            } else if ((ax != 0) || (i != 24)) {
                set_error(r, ax);
                break;
            }

            // fill in the directory entry 'found_file'
            struct drive_proto_find_reply const * const args = (struct drive_proto_find_reply const * const)reply;
            sda_ptr->found_file.name = args->name;
            sda_ptr->found_file.attrs = args->attrs;
            sda_ptr->found_file.time_update = args->time;
            sda_ptr->found_file.date_update = args->date;
            sda_ptr->found_file.start_cluster = 0;  // start cluster (from EtherDFS: I don't care)
            sda_ptr->found_file.size = args->size;

            // put things into DTA so I can understand where I left should FindNext
            // initialize search (drive, search name template, attributes)
            if (subfunction == INT2F_FIND_FIRST) {
                dta->drive_no = reqdrv | 0x80;  // bit 7 set means "network drive"
                //my_memcpy_ff(&dta->srch_tmpl, &sda_ptr->fcb_fn1, sizeof(dta->srch_tmpl));
                //dta->srch_tmpl = sda_ptr->fcb_fn1; // sda_ptr->fcb_fn1 was not set during tests in dosemu
                get_dos_fn_from_full_path(&dta->srch_tmpl, sda_ptr->fn1);
                //for (int i = 0; i < 8; ++i) dta->srch_tmpl.name_blank_padded[i] = '?';
                //for (int i = 0; i < 3; ++i) dta->srch_tmpl.ext_blank_padded[i] = '?';
                //my_memcpy_ff(&dta->srch_tmpl, "??????????", sizeof(dta->srch_tmpl));
                dta->srch_attr = sda_ptr->srch_attr;
            }

            dta->dir_entry_no = args->dir_entry;
            dta->cluster = args->start_cluster;
            // behind search data ([DTA+15h]) = standard directory entry for file (see #01352)
            *(struct dos_directory_entry *)(dta + 1) = sda_ptr->found_file;
        } break;

        case INT2F_SEEK_FROM_END: {
            // Note:  This function is called by the DOS 3.1+ kernel, but only when seeking from the end of a file
            // opened with sharing modes set in such a manner that another process is able to change the size
            // of the file while it is already open
            // CX:DX = offset (in bytes) from end
            // ES:DI -> SFT
            // SFT DPB field -> DPB of drive with file
            // SS = DOS DS
            // Return:
            // CF set on error, clear if successful
            // AL = DOS error code
            // DX:AX = new file position

            struct dos_sft const __far * const sftptr = MK_FP(r->w.es, r->w.di);
            struct drive_proto_seek_from_end * const args = (struct drive_proto_seek_from_end * const)buff;
            args->offset_from_end_lo = r->w.dx;
            args->offset_from_end_hi = r->w.cx;
            args->start_cluster = sftptr->start_cluster;

            i = send_request(subfunction, reqdrv, sizeof(*args), &reply, &ax);
            if (i == NETWORK_ERROR) {
                set_error(r, DOS_EXTERR_FILE_NOT_FOUND);
            } else if ((ax != 0) || (i != 4)) {
                set_error(r, ax);
            } else {
                struct drive_proto_seek_from_end_reply const * const args =
                    (struct drive_proto_seek_from_end_reply const * const)reply;
                r->w.ax = args->position_lo;
                r->w.dx = args->position_hi;
            }
            break;
        }

        case INT2F_EXTENDED_ATTRS:
            // EXTENDED ATTRIBUTES (DOS 4.x only)
            // BL = subfunction (value of AL on INT 21)
            // 02h get extended attributes
            // 03h get extended attribute properties
            // 04h set extended attributes
            // Return:
            // according to EtherDFS MSCDEX returns AX=2, so do we
            r->w.ax = 2;
            break;
    }

finish:
    *recvbufflen_ptr = 0;
}


// Table of handled INT 2F functions. To quickly determine whether a function should be processed.
static void __declspec(naked) supported_functions_table(void) {
    // clang-format off
    __asm {
        db INT2F_INSTALL_CHECK  // 0x00
        db INT2F_REMOVE_DIR  // 0x01
        db INT2F_UNUSED  // 0x02
        db INT2F_MAKE_DIR  // 0x03
        db INT2F_UNUSED  // 0x04
        db INT2F_CHANGE_DIR  // 0x05
        db INT2F_CLOSE_FILE  // 0x06
        db INT2F_COMMIT_FILE  // 0x07
        db INT2F_READ_FILE  // 0x08
        db INT2F_WRITE_FILE  // 0x09
        db INT2F_LOCK_UNLOCK_FILE  // 0x0A
        db INT2F_UNLOCK_FILE  // 0x0B
        db INT2F_DISK_INFO  // 0x0C
        db INT2F_UNUSED  // 0x0D
        db INT2F_SET_ATTRS  // 0x0E
        db INT2F_GET_ATTRS  // 0x0F
        db INT2F_UNUSED  // 0x10
        db INT2F_RENAME_FILE  // 0x11
        db INT2F_UNUSED  // 0x12
        db INT2F_DELETE_FILE  // 0x13
        db INT2F_UNUSED  // 0x14
        db INT2F_UNUSED  // 0x15
        db INT2F_OPEN_FILE  // 0x16
        db INT2F_CREATE_FILE  // 0x17
        db INT2F_UNUSED  // 0x18
        db INT2F_UNUSED  // 0x19
        db INT2F_UNUSED  // 0x1A
        db INT2F_FIND_FIRST  // 0x1B
        db INT2F_FIND_NEXT  // 0x1C
        db INT2F_UNUSED  // 0x1D
        db INT2F_UNUSED  // 0x1E
        db INT2F_UNUSED  // 0x1F
        db INT2F_UNUSED  // 0x20
        db INT2F_SEEK_FROM_END  // 0x21
        db INT2F_UNUSED  // 0x22
        db INT2F_UNUSED  // 0x23
        db INT2F_UNUSED  // 0x24
        db INT2F_UNUSED  // 0x25
        db INT2F_UNUSED  // 0x26
        db INT2F_UNUSED  // 0x27
        db INT2F_UNUSED  // 0x28
        db INT2F_UNUSED  // 0x2C
        db INT2F_EXTENDED_ATTRS  // 0x2D
        db INT2F_EXTENDED_OPEN_CREATE_FILE  // 0x2E
    }
    // clang-format on
}


// The int2F_redirector is our 2F interrupt handler. It assesses whether the call is destined for our drive.
// If so, it will call our routine - handle_request_for_our_drive. If not, it calls the original interrupt handler.
static void __declspec(naked) int2F_redirector(void) {
    // clang-format off
    __asm {
        // Is it for me (my interrupt 2F multiplex ID)?
        cmp ah, byte ptr cs:global_my_2Fmux_id
        jne not_global_my_2Fmux_id

        // It's for me. Handle it.
        test al, al
        jne not_install_check
        mov al, 0xFF  // installed
        mov bx, 'JA'
        mov cx, 'RO'
        mov dx, 'NM'

    not_install_check:
        cmp al, 1
        jne not_get_shared_data
        cmp bx, 0x0001
        jne not_get_shared_data

        // return pointer to shared data in cx:bx
        mov cx, cs
        mov bx, offset cs:shared_data
        not_get_shared_data:
        iret

    not_global_my_2Fmux_id:
        // if not related to a redirector function (AH=0x11), jump to the previous INT 2F handler
        cmp ah, 0x11
        jne jmp_to_prev_handler2

        // if function is install check (AL=0x00), jump to the previous INT 2F handler
        test al, al
        je jmp_to_prev_handler2

        // if it is a function that is not supported by us, jump to the previous INT 2F handler
        cmp al, 0x2E
        jg jmp_to_prev_handler2
        push bx
        xor bh, bh
        mov bl, al
        cmp byte ptr cs:supported_functions_table[bx], INT2F_UNUSED
        pop bx
        je jmp_to_prev_handler2
        jmp get_drive

        // For a conditional jump, the destination must be within -128...+127 bytes of the next instruction.
        // So we will use an intermediate jump.
    jmp_to_prev_handler2:
        jmp jmp_to_prev_handler

    get_drive:
        push bx

        cmp al, INT2F_SEEK_FROM_END
        je es_di_points_SFT
        cmp al, INT2F_EXTENDED_ATTRS
        je es_di_points_SFT
        cmp al, INT2F_CLOSE_FILE
        jl other_states
        cmp al, INT2F_UNLOCK_FILE
        jg other_states

    es_di_points_SFT:
        // ES:DI points to the SFT: if the bottom 6 bits of the device information
        // word in the SFT are > last drive, then it relates to files not associated
        // with drives, such as LAN Manager named pipes.
        mov bl, [es:di + 5]  //sft->dev_info_word
        and bl, 0x3F
        jmp validate_drive_no

    other_states:
        cmp al, INT2F_FIND_NEXT
        je from_sdb_drive_no
        cmp al, INT2F_SET_ATTRS
        je from_sdaptr
        cmp al, INT2F_GET_ATTRS
        je from_sdaptr
        cmp al, INT2F_DELETE_FILE
        je from_sdaptr
        cmp al, INT2F_OPEN_FILE
        je from_sdaptr
        cmp al, INT2F_CREATE_FILE
        je from_sdaptr
        cmp al, INT2F_EXTENDED_OPEN_CREATE_FILE
        je from_sdaptr
        cmp al, INT2F_MAKE_DIR
        je from_sdaptr
        cmp al, INT2F_REMOVE_DIR
        je from_sdaptr
        cmp al, INT2F_CHANGE_DIR
        je from_sdaptr
        cmp al, INT2F_RENAME_FILE
        je from_sdaptr

        // otherwise check out the CDS (at ES:DI)
        mov bl, [es:di]  // cds->current_path[0]
        call drive_to_num
        jmp validate_drive_no

    from_sdb_drive_no:
        push es
        les bx, dword ptr cs:global_sda_ptr
        mov bl, byte ptr [es:bx + 414]  // global_sda_ptr->sdb.drive_no
        pop es
        and bl, 0x1F
        jmp validate_drive_no

    from_sdaptr:
        push es
        les bx, dword ptr cs:global_sda_ptr
        mov bl, byte ptr [es:bx + 158]  // global_sda_ptr->fn1[0]
        pop es
        call drive_to_num

    validate_drive_no:
        // test if the drive is in our mount table?
        cmp bl, MAX_DRIVERS_COUNT
        jge invalid_drive_no
        push bx
        xor bh, bh
        lea bx, [shared_data + bx]
        cmp byte ptr [cs:bx], 0xFF
        pop bx
        je invalid_drive_no
        mov byte ptr cs:global_req_drive, bl
        pop bx

    use_our_handler:
        push ax
        push cx
        push dx
        push bx
        push sp
        push bp
        push si
        push di
        push ds
        push es

        // set to my data segment - small mode data in code segment
        push cs
        pop ds

        // switch to my stack
        mov word ptr global_orig_stack_ptr + 2, ss
        mov word ptr global_orig_stack_ptr, sp
        push ds
        cli
        pop ss
        lea sp, global_my_stack + MY_STACK_SIZE - 2
        sti

        call handle_request_for_our_drive

        // switch stack back
        cli
        mov ss, word ptr global_orig_stack_ptr + 2
        mov sp, word ptr global_orig_stack_ptr
        sti

        pop es
        pop ds
        pop di
        pop si
        pop bp
        pop ax  // no POP SP here, it does ADD SP, 2 (AX will be overwritten later)
        pop bx
        pop dx
        pop cx
        pop ax
        iret

    invalid_drive_no:
        pop bx

    jmp_to_prev_handler:
        push WORD PTR cs:global_orig_INT2F_handler + 2
        push WORD PTR cs:global_orig_INT2F_handler
        retf
    }
    // clang-format on
}


// ==== End of resident part ====
static void __declspec(naked) resident_part_end_mark(void) {}


uint16_t strto_ui16(const char * restrict str, const char ** restrict endptr) {
    uint16_t number = 0;
    while (*str >= '0' && *str <= '9') {
        number *= 10;
        number += *str - '0';
        ++str;
    }
    if (endptr) {
        *endptr = str;
    }
    return number;
}


static union ipv4_addr parse_ipv4_addr(const char * restrict str, const char ** restrict endptr) {
    union ipv4_addr addr;
    const char * local_endptr;
    int idx;
    for (idx = 0; idx < 3; ++idx) {
        addr.bytes[idx] = strto_ui16(str, &local_endptr);
        if (local_endptr == str || *local_endptr != '.') {
            //error
        }
        str = local_endptr + 1;
    }
    addr.bytes[idx] = strto_ui16(str, &local_endptr);
    if (local_endptr == str) {
        //error
    }
    if (endptr) {
        *endptr = local_endptr;
    }
    return addr;
}


_Packed struct install_info {
    uint8_t installed;     // is installed
    uint8_t multiplex_id;  // my multiplex_id; if i am not installed multiplex_id free to install
};

#pragma aux get_install_info modify[ax bx cx dx si di es] value struct[ax]
static struct install_info __declspec(naked) get_install_info(void) {
    // clang-format off
    __asm {
        mov ax, 0xC000  // free_id(AL) = 0, start scanning at 0xC0(AH); 0x00 - 0xBF are reserved by Microsoft
        push ax

    check_id:
        xor al, al  // subfunction 0x00 - 'installation check'
        int 0x2F

         // is it free?
        test al, al
        jnz not_free

        // it's free - remember it
        pop ax
        mov al, ah
        push ax
        jmp check_next_id

    not_free:
        // is it me?
        cmp al, 0xFF
        jne check_next_id
        cmp bx, 'JA'
        jne check_next_id
        cmp cx, 'RO'
        jne check_next_id
        cmp dx, 'NM'
        jne check_next_id

        // it is me
        pop ax
        mov al, 1  // installed AL = 1
        ret

    check_next_id:
        // not me, check next id
        pop ax
        inc ah
        push ax
        jnz check_id  // if cur_id is zero then the entire range (C0..FF) has been checked

        pop ax
        mov ah, al
        mov al, 0  // not installed AL = 0
        ret
    }
    // clang-format on
}


_Packed struct dos_version {
    uint8_t major;
    uint8_t minor;
} version;

static struct dos_version get_dos_version(void);
#pragma aux get_dos_version = \
    "mov ah, 0x30"            \
    "int 0x21" modify[ax bx cx] value struct[ax]


static uint8_t is_redir_install_allowed(void);
#pragma aux is_redir_install_allowed = \
    "mov ax, 0x1100"                   \
    "int 0x2F"                         \
    "dec al" modify[ax] value[al]


static void set_intr_vector(uint8_t num, interrupt_handler handler);
#pragma aux set_intr_vector = \
    "push ds"                 \
    "push es"                 \
    "pop ds"                  \
    "mov ah, 0x25"            \
    "int 0x21"                \
    "pop ds" parm[al][dx es] modify[ah]


static interrupt_handler get_intr_vector(uint8_t num);
#pragma aux get_intr_vector = \
    "mov ah, 0x35"            \
    "int 0x21" parm[al] modify[ah bx es] value[bx es]


// DOS 3.0+ - GET ADDRESS OF SDA (Swappable Data Area)
// CF set on error (AX=error code)
static struct dos_sda __far * get_sda(void);
#pragma aux get_sda = \
    "mov ax, 0x5d06"  \
    "push ds"         \
    "int 0x21"        \
    "mov cx, ds"      \
    "pop ds" modify exact[ax bx cx dx si] value[cx si]


static struct dos_list_of_list __far * get_dos_list_of_list(void);
#pragma aux get_dos_list_of_list = \
    "mov ah, 0x52"                 \
    "int 0x21" modify exact[ah bx es] value[es bx]


// returns pointer to the CDS struct for drive, requires DOS 4+
static struct dos_current_dir __far * get_cds(uint8_t drive_no) {
    static enum { UNINITIALIZED, OK, ERROR } state = UNINITIALIZED;
    static struct dos_current_dir __far * cds_array;
    static uint8_t last_drive;

    // init - do it only once
    if (state == UNINITIALIZED) {

        struct dos_list_of_list const __far * const list_of_list = get_dos_list_of_list();
        last_drive = list_of_list->last_drive;
        cds_array = list_of_list->cds_ptr;

        // some OS DOS emulators (at least OS/2) set the CDS array pointer to FFFF:FFFF
        state = cds_array == (struct dos_current_dir const __far *)-1L ? ERROR : OK;
    }

    if (state == ERROR || drive_no > last_drive) {
        return NULL;
    }

    // return pointer to the CDS array entry for drive
    return &cds_array[drive_no];
}


static void terminate_remain_resident(uint8_t exit_code, uint16_t memsize_in_paragraphs);
#pragma aux terminate_remain_resident aborts
#pragma aux terminate_remain_resident = \
    "mov ah, 0x31"                      \
    "int 0x21" parm[al][dx]


static uint16_t get_CS(void);
#pragma aux get_CS = "mov ax, cs" modify exact[ax] value[ax]


static uint8_t assign_remote_ip_addr_slot(struct shared_data __far * shared_data_ptr, union ipv4_addr ip) {
    uint8_t ip_idx = 0xFFU;
    uint8_t free_ip_idx = 0xFFU;

    for (int i = 0; i < sizeof(getptr_shared_data()->ip_mac_map) / sizeof(getptr_shared_data()->ip_mac_map[0]); ++i) {
        if (shared_data_ptr->ip_mac_map[i].ip.value == ip.value) {
            ip_idx = i;
            break;
        }
        if (shared_data_ptr->ip_mac_map[i].ip.value == 0xFFFFFFFFUL) {
            free_ip_idx = i;
        }
    }

    if (ip_idx == 0xFFU) {
        if (free_ip_idx != 0xFFU) {
            ip_idx = free_ip_idx;
        } else {
            // try if some IP slot can be reused (umounted drive)
            for (int i = 0; i < sizeof(getptr_shared_data()->ip_mac_map) / sizeof(getptr_shared_data()->ip_mac_map[0]);
                 ++i) {
                if (i == shared_data_ptr->gateway_ip_slot) {
                    continue;  // skip, used by gateway
                }

                uint8_t driver_id = 0;  // skip, used by mounted drive
                while (driver_id < MAX_DRIVERS_COUNT && shared_data_ptr->remote_ips[driver_id] != i) {
                    ++driver_id;
                }

                if (driver_id == MAX_DRIVERS_COUNT) {
                    free_ip_idx = ip_idx = i;
                    break;
                }
            }
        }
    }

    if (ip_idx != 0xFFU && ip_idx == free_ip_idx) {
        shared_data_ptr->ip_mac_map[free_ip_idx].ip = ip;
        for (int byte_idx = 0; byte_idx < sizeof(getptr_shared_data()->ip_mac_map[0].mac_addr); ++byte_idx) {
            shared_data_ptr->ip_mac_map[free_ip_idx].mac_addr.bytes[byte_idx] = 0xFFU;
        }
    }

    return ip_idx;
}


// Registers handler for type. If the return value is nonzero, it represents an error code.
#pragma aux pktdrv_register_type parm[si][di][bx] modify exact[ax cx dx es] value[dh]
static uint8_t __declspec(naked) pktdrv_register_type(
    const uint16_t * packet_type, const void * pktdrv_recv, uint16_t * pkt_handle) {

    // suppress Open Watcom warning: "Parameter has been defined, but not referenced"
    packet_type;
    pktdrv_recv;
    pkt_handle;

    // clang-format off
    __asm {
        push bx  // store pointer to pkt_handle to stack

        mov ah, PKTDRV_FUNC_ACCESS_TYPE
        mov al, 1  // if_class = 1(eth)
        mov bx, 0xffff  // if_type = 0xffff means 'all'
        xor dl, dl  // if_number: 0 (first interface)
        // DS:SI points to the ethertype value in network byte order (SI is func input parameter)
        mov cx, 2  // typelen (ethertype len is 2 bytes)
        // ES:DI points to the receiving routine (DI is func input parameter)
        push cs
        pop es

        // simulate INT instruction (pushf + cli + call __far)
        pushf
        cli
        call dword ptr global_pktdrv_INT_handler

        jc error  // if carry, errorcode returned in DH

        pop bx  // get pointer to pkt_handle from stack
        mov [bx], ax  // store pkt_handle
        xor dh, dh  // set errorcode to 0
        ret

    error:
        pop bx
        ret
    }
    // clang-format on
}


#define STR(...)   #__VA_ARGS__
#define INSTR(...) STR(__VA_ARGS__)

// Releases handle for type. If the return value is nonzero, it represents an error code.
static uint8_t pktdrv_release_type(uint16_t type_handle);
#pragma aux pktdrv_release_type =           \
    INSTR(mov ah, PKTDRV_FUNC_RELEASE_TYPE) \
    "pushf"                                 \
    "cli"                                   \
    "call dword ptr global_pktdrv_INT_handler"    \
    "jc error"                              \
    "xor dh, dh"                            \
    "error:" parm [bx] modify exact [ah dh] value [dh]


// get my own MAC addr. target MUST point to a space of at least 6 chars
#pragma aux pktdrv_getaddr parm[di][bx] modify exact[ah cx dh es]
static void __declspec(naked) pktdrv_getaddr(struct mac_addr * dst, uint16_t pkt_handle) {
    // suppress Open Watcom warning: "Parameter has been defined, but not referenced"
    dst;
    pkt_handle;

    // clang-format off
    __asm {
        mov ah, PKTDRV_FUNC_GET_ADDRESS
        // BX - pkt handle is func input argument
        // ES:DI points to buffer (DI is func input argument)
        push ds
        pop es
        mov cx, 6  // mac address length (ethernet = 6 bytes)

        // simulate INT instruction (pushf + cli + call __far)
        pushf
        cli
        call dword ptr global_pktdrv_INT_handler

        ret
    }
    // clang-format on
}


static uint8_t pktdrv_init(uint8_t pktdrv_int_num) {
    static const char PKTDRV_SIGNATURE[] = "PKT DRVR";

    interrupt_handler pktdrv_pktcall = get_intr_vector(pktdrv_int_num);

    // check packet driver signature
    char __far * pktdrvfunc = (char __far *)pktdrv_pktcall;
    pktdrvfunc += 3;  // skip three bytes of executable code
    for (unsigned int i = 0; i < sizeof(PKTDRV_SIGNATURE); ++i) {
        if (PKTDRV_SIGNATURE[i] != pktdrvfunc[i]) {
            return -1;
        }
    }

    // fetch the vector of the pktdrv interrupt and save it for later
    *getptr_global_pktdrv_INT_handler() = pktdrv_pktcall;

    uint8_t error_code;
    const uint16_t ether_type_arp = swap_word(ETHER_TYPE_ARP);
    error_code = pktdrv_register_type(&ether_type_arp, &pktdrv_recv, &getptr_shared_data()->arp_pkthandle);
    if (error_code == 0) {
        const uint16_t ether_type_ipv4 = swap_word(ETHER_TYPE_IPV4);
        error_code = pktdrv_register_type(&ether_type_ipv4, &pktdrv_recv, &getptr_shared_data()->ipv4_pkthandle);
        if (error_code != 0) {
            pktdrv_release_type(ether_type_arp);
        }
    }

    if (error_code == 0) {
        getptr_shared_data()->used_pktdrv_int = pktdrv_int_num;
    }

    return error_code;
}


static struct shared_data __far * get_installed_shared_data_ptr(uint8_t multiplex_id);
#pragma aux get_installed_shared_data_ptr = \
    "mov al, 1"                             \
    "mov bx, 1"                             \
    "int 0x2F" parm[ah] modify exact[ax bx cx] value[cx bx]


static void uint16_to_str(uint16_t num, char * buf, uint8_t buf_size, uint8_t base, char fill) {
    int i = buf_size;
    buf[--i] = '\0';
    while (i > 0 && num > 0) {
        const int tmp = num / base;
        const int remain = num - (tmp * base);
        buf[--i] = remain <= 9 ? remain + '0' : remain - 10 + 'A';
        num = tmp;
    }
    while (i > 0) {
        buf[--i] = fill;
    }
}


static void my_print_char(char character);
#pragma aux my_print_char = \
    "mov ah, 0x02"          \
    "int 0x21" parm[dx] modify exact[ah]


// Prints C string - zero terminated
static void my_print_string(const char * text) {
    while (*text != '\0') {
        my_print_char(*text);
        ++text;
    }
}


// Prints DOS string - must be terminated by '$' character
#pragma aux my_print_dos_string parm[dx] modify exact[ah]
static void __declspec(naked) my_print_dos_string(const char * dos_string) {
    // suppress Open Watcom warning: "Parameter has been defined, but not referenced"
    dos_string;

    __asm {
        mov ah, 0x09
        int 0x21
        ret
    }
}


static int umount(struct shared_data __far * shared_data_ptr, uint8_t drive_no) {
    struct dos_current_dir __far * cds = get_cds(drive_no);
    if (cds == NULL) {
        my_print_dos_string("Error: Cannot get CDS for mounted drive.\r\n$");
        return 1;
    }
    cds->flags = 0;

    shared_data_ptr->ldrv[drive_no] = 0xFFU;
    shared_data_ptr->remote_ips[drive_no] = 0xFFU;
    return 0;
}


static void print_help(void) {
    my_print_dos_string("NetMount " PROGRAM_VERSION ", Copyright 2024 Jaroslav Rohel <jaroslav.rohel@gmail.com>\r\n$");
    my_print_dos_string(
        "NetMount comes with ABSOLUTELY NO WARRANTY. This is free software\r\n"
        "and you are welcome to redistribute it under the terms of the GNU GPL v2.\r\n\r\n$");

    my_print_dos_string(
        "NETMOUNT INSTALL /IP:<local_ipv4_addr> [/MASK:<net_mask>] [/GW:<gateway_addr>]\r\n"
        "         [/PORT:<local_udp_port>] [/PKT_INT:<packet_driver_int>]\r\n\r\n$");
    my_print_dos_string(
        "NETMOUNT MOUNT <remote_ipv4_addr>[:<remote_udp_port>]/<remote_drive_letter>\r\n"
        "         <local_drive_letter>\r\n\r\n$");
    my_print_dos_string("NETMOUNT UMOUNT <local_drive_letter>\r\n\r\n$");
    my_print_dos_string("NETMOUNT UMOUNT /ALL\r\n\r\n$");

    my_print_dos_string("Commands:\r\n$");
    my_print_dos_string("INSTALL                      Installs NetMount as resident (TSR)\r\n$");
    my_print_dos_string("MOUNT                        Mounts remote drive as local drive\r\n$");
    my_print_dos_string("UMOUNT                       Unmounts local drive(s) from remote drive\r\n\r\n$");

    my_print_dos_string("Arguments:\r\n$");
    my_print_dos_string("/IP:<local_ipv4_addr>        Sets local IP address\r\n$");
    my_print_dos_string("/PORT:<local_udp_port>       Sets local UDP port. 12200 by default\r\n$");
    my_print_dos_string(
        "/PKT_INT:<packet_driver_int> Sets interrupt of used packet driver.\r\n"
        "                             First found in range 0x60 - 0x80 by default.\r\n$");
    my_print_dos_string("/MASK:<net_mask>             Sets network mask\r\n$");
    my_print_dos_string("/GW:<gateway_addr>           Sets gateway address\r\n$");
    my_print_dos_string("<local_drive_letter>         Specifies local drive to mount/unmount (e.g. H)\r\n$");
    my_print_dos_string("<remote_drive_letter>        Specifies remote drive to mount/unmount (e.g. H)\r\n$");
    my_print_dos_string("/ALL                         Unmount all drives\r\n$");
    my_print_dos_string("<remote_ipv4_addr>           Specifies IP address of remote server\r\n$");
    my_print_dos_string("<remote_udp_port>            Specifies remote UDP port. 12200 by default\r\n$");
    my_print_dos_string("/?                           Display this help\r\n$");
}


int main(int argc, char * argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '/' && argv[i][1] == '?' && argv[i][2] == '\0') {
            print_help();
            return EXIT_OK;
        }
    }

    struct dos_version dos_ver = get_dos_version();
    if (dos_ver.major < 5) {
        my_print_dos_string("Unsupported DOS version $");
        my_print_char(dos_ver.major + '0');
        my_print_char('.');
        my_print_char(dos_ver.minor + '0');
        my_print_dos_string(". Required 5.0+\r\n$");
        return EXIT_UNSUPPORTED_DOS;
    }

    if (argc < 2) {
        my_print_dos_string("Missing command. Use \"/?\" to display help.\r\n$");
        return EXIT_UNKNOWN_CMD;
    }

    // "install /IP:<local_ipv4_addr> [/MASK:<ipv4_net_mask>] [/GW:<gateway_ipv4_addr>] [/PORT:<udp_port>] [/PKT_INT:<packet_driver_int>]
    if (strn_upper_cmp(argv[1], "INSTALL", 8) == 0) {
        if (!is_redir_install_allowed()) {
            my_print_dos_string("Redirector installation has been forbidden either by DOS or another process.\r\n$");
        }

        {
            const struct install_info info = get_install_info();

            if (info.installed) {
                my_print_dos_string("Already installed with multiplex id 0x$");
                char buf[3];
                uint16_to_str(info.multiplex_id, buf, sizeof(buf), 16, '0');
                my_print_string(buf);
                my_print_dos_string("\r\n$");
                return EXIT_ALREADY_INSTALLED;
            }

            if (info.multiplex_id == 0) {
                my_print_dos_string("Cannot install. Not free multiplex on the system\r\n$");
                return EXIT_NOT_FREE_MULTIPLEX;
            }

            *getptr_global_my_2Fmux_id() = info.multiplex_id;
        }

        if (argc < 3) {
            my_print_dos_string("Missing arguments\r\n$");
            return EXIT_MISSING_ARG;
        }

        int local_ip_set = 0;
        getptr_shared_data()->gateway_ip_slot = 0xFF;
        getptr_shared_data()->local_port = DRIVE_PROTO_UDP_PORT;
        getptr_shared_data()->net_mask.value = 0;
        getptr_shared_data()->requested_pktdrv_int = 0;
        for (int i = 2; i < argc; ++i) {
            if (argv[i][0] != '/') {
                my_print_dos_string("Unknown argument: $");
                my_print_string(argv[i]);
                my_print_dos_string("\r\n$");
                return EXIT_UNKNOWN_ARG;
            }
            if (strn_upper_cmp(argv[i] + 1, "IP:", 3) == 0) {
                getptr_shared_data()->local_ipv4 = parse_ipv4_addr(argv[i] + 4, NULL);
                local_ip_set = 1;
                continue;
            }
            if (strn_upper_cmp(argv[i] + 1, "MASK:", 5) == 0) {
                getptr_shared_data()->net_mask = parse_ipv4_addr(argv[i] + 6, NULL);
                continue;
            }
            if (strn_upper_cmp(argv[i] + 1, "GW:", 3) == 0) {
                const union ipv4_addr gw = parse_ipv4_addr(argv[i] + 4, NULL);
                getptr_shared_data()->gateway_ip_slot = assign_remote_ip_addr_slot(getptr_shared_data(), gw);
                continue;
            }
            if (strn_upper_cmp(argv[i] + 1, "PORT:", 5) == 0) {
                const char * endptr;
                getptr_shared_data()->local_port = strto_ui16(argv[i] + 6, &endptr);
                continue;
            }
            if (strn_upper_cmp(argv[i] + 1, "PKT_INT:", 8) == 0) {
                const char * endptr;
                getptr_shared_data()->requested_pktdrv_int = strto_ui16(argv[i] + 9, &endptr);
                continue;
            }
            my_print_dos_string("Error: Unknown argument: $");
            my_print_string(argv[i]);
            my_print_dos_string("\r\n$");
        }

        if (!local_ip_set) {
            my_print_dos_string("Local IP must be set!\r\n$");
            return EXIT_MISSING_ARG;
        }

        uint8_t prev_bit = 0;
        for (int byte_idx = sizeof(getptr_shared_data()->net_mask) - 1; byte_idx >= 0; --byte_idx) {
            uint8_t mask_byte = getptr_shared_data()->net_mask.bytes[byte_idx];
            for (int i = 8; i > 0; --i) {
                if (prev_bit && !(mask_byte & 1)) {
                    my_print_dos_string("Incorrect network mask.\r\n$");
                    return EXIT_BAD_NET_MASK;
                }
                prev_bit = mask_byte & 1;
                mask_byte >>= 1;
            }
        }

        // init the packet driver interface
        getptr_shared_data()->used_pktdrv_int = 0;
        if (getptr_shared_data()->requested_pktdrv_int == 0) {
            // detect first packet driver within int 0x60..0x80
            for (int i = 0x60; i <= 0x80; ++i) {
                if (pktdrv_init(i) == 0) {
                    break;
                }
            }
        } else {
            // use the pktdrvr interrupt passed through command line
            pktdrv_init(getptr_shared_data()->requested_pktdrv_int);
        }
        // has it succeeded?
        if (getptr_shared_data()->used_pktdrv_int == 0) {
            my_print_dos_string("Packet driver initialization failed.\r\n$");
            return EXIT_PKTDRV_INIT_FAILED;
        }
        my_print_dos_string("Use packet driver with interrupt number 0x$");
        char num_int[3];
        uint16_to_str(getptr_shared_data()->used_pktdrv_int, num_int, sizeof(num_int), 16, '0');
        my_print_string(num_int);
        my_print_dos_string("\r\n$");
        //printf("Packet driver ARP handler: %d\n", getptr_shared_data()->arp_pkthandle);
        //printf("Packet driver IPv4 handler: %d\n", getptr_shared_data()->ipv4_pkthandle);

        pktdrv_getaddr(&getptr_shared_data()->local_mac_addr, getptr_shared_data()->ipv4_pkthandle);
        my_print_dos_string("Detected local MAC address $");
        int first = 1;
        for (int i = 0; i < 6; ++i) {
            if (!first) {
                my_print_char(':');
            }
            char buf[3];
            uint16_to_str(getptr_shared_data()->local_mac_addr.bytes[i], buf, sizeof(buf), 16, '0');
            my_print_string(buf);
            first = 0;
        }
        my_print_dos_string("\r\n$");

        struct ether_frame * const frame = getptr_global_send_buff();
        frame->mac.source_hw_addr = getptr_shared_data()->local_mac_addr;
        frame->mac.ether_type = swap_word(ETHER_TYPE_IPV4);

        // set all drive mappings as 'unused'
        for (int i = 0; i < sizeof(getptr_shared_data()->ldrv); ++i)
            getptr_shared_data()->ldrv[i] = 0xFFU;

        // init ip_mac_map table
        for (int i = 0; i < sizeof(getptr_shared_data()->ip_mac_map) / sizeof(getptr_shared_data()->ip_mac_map[0]);
             ++i) {
            getptr_shared_data()->ip_mac_map[i].ip.value = 0xFFFFFFFFUL;
        }

        *getptr_global_sda_ptr() = get_sda();

        *getptr_global_orig_INT2F_handler() = get_intr_vector(0x2F);
        set_intr_vector(0x2F, MK_FP(get_CS(), get_offset(int2F_redirector)));

        {
            my_print_dos_string("NetMount registered to interrupt 0x2F with multiplex id $");
            char buf[4];
            uint16_to_str(*getptr_global_my_2Fmux_id(), buf, sizeof(buf), 10, ' ');
            my_print_string(buf);
            my_print_dos_string("\r\n$");
        }
        terminate_remain_resident(EXIT_OK, ((unsigned)get_offset(resident_part_end_mark) + PROGRAM_OFFSET + 15) >> 4);
    }

    if (strn_upper_cmp(argv[1], "MOUNT", 6) == 0) {
        const struct install_info info = get_install_info();
        if (!info.installed) {
            my_print_dos_string("NetMount is not installed. Use install first\r\n$");
            return EXIT_NOT_INSTALLED;
        }

        if (argc != 4) {
            my_print_dos_string(
                "Bad argument count. Use mount <remote_ip>[:remote_port]/<remote_drive_letter> "
                "<local_drive_letter>\r\n$");
            return EXIT_BAD_ARG;
        }

        // NetMount mount <ipv4_addr>[:port]/<remote_drive> <local_drive>
        uint16_t remote_port = DRIVE_PROTO_UDP_PORT;
        const char * endptr;
        const union ipv4_addr remote_ip = parse_ipv4_addr(argv[2], &endptr);
        if (*endptr == ':') {
            remote_port = strto_ui16(endptr + 1, &endptr);
        }
        if (*endptr != '/') {
            my_print_dos_string("Bad remote drive specification\r\n$");
            return EXIT_BAD_ARG;
        }
        const uint8_t remote_drive_no = drive_to_num(endptr[1]);
        if (remote_drive_no >= MAX_DRIVERS_COUNT) {
            my_print_dos_string("Bad remote drive letter\r\n$");
            return EXIT_BAD_DRIVE_LETTER;
        }

        const uint8_t drive_no = drive_to_num(argv[3][0]);
        if (drive_no >= MAX_DRIVERS_COUNT) {
            my_print_dos_string("Bad local drive letter\r\n$");
            return EXIT_BAD_DRIVE_LETTER;
        }

        // if drive is already active, fail
        struct dos_current_dir __far * const cds = get_cds(drive_no);
        if (cds == NULL) {
            my_print_dos_string(
                "Unable to activate the local drive mapping. You are either using an\r\n"
                "unsupported operating system, or your LASTDRIVE directive does not permit\r\n"
                "to define the requested drive letter (try LASTDRIVE=Z in your CONFIG.SYS).\r\n$");
            return 1;
        }
        if (cds->flags != 0) {
            my_print_dos_string(
                "The requested local drive letter is already in use. Please choose another\r\n"
                "drive letter.\r\n$");
            return EXIT_DRIVE_LETTER_ALREADY_USED;
        }

        struct shared_data __far * const shared_data_ptr = get_installed_shared_data_ptr(info.multiplex_id);

        const uint8_t remote_ip_idx = assign_remote_ip_addr_slot(shared_data_ptr, remote_ip);
        if (remote_ip_idx == 0xFFU) {
            my_print_dos_string("Error: Not free slot for remote IP address\r\n$");
            return EXIT_NOT_FREE_SLOT_FOR_REMOTE_IP;
        }

        shared_data_ptr->remote_ips[drive_no] = remote_ip_idx;
        shared_data_ptr->remote_ports[drive_no] = remote_port;
        shared_data_ptr->ldrv[drive_no] = remote_drive_no;

        // set drive as being 'network' drives (also add the PHYSICAL bit,
        // otherwise MS-DOS 6.0 will ignore the drive)
        cds->flags = DOS_CDSFLAG_NETWDRV | DOS_CDSFLAG_PHYSDRV;
        // set 'current path' to root, to avoid inheriting any garbage
        cds->current_path[0] = 'A' + drive_no;
        cds->current_path[1] = ':';
        cds->current_path[2] = '\\';
        cds->current_path[3] = 0;

        return EXIT_OK;
    }

    if (strn_upper_cmp(argv[1], "UMOUNT", 7) == 0) {
        const struct install_info info = get_install_info();
        if (!info.installed) {
            my_print_dos_string("NetMount is not installed.\r\n$");
            return EXIT_NOT_INSTALLED;
        }

        if (argc != 3) {
            my_print_dos_string("Bad argument count. Use umount <local_drive_letter> or /ALL\r\n$");
            return EXIT_BAD_ARG;
        }

        struct shared_data __far * const shared_data_ptr = get_installed_shared_data_ptr(info.multiplex_id);

        int retval = EXIT_OK;

        if (strn_upper_cmp(argv[2], "/ALL", 5) == 0) {
            for (int drive_no = 0; drive_no < MAX_DRIVERS_COUNT; ++drive_no) {
                if (shared_data_ptr->ldrv[drive_no] != 0xFFU) {
                    retval |= umount(shared_data_ptr, drive_no);
                }
            }

        } else {
            const uint8_t drive_no = drive_to_num(argv[2][0]);
            if (drive_no >= MAX_DRIVERS_COUNT) {
                my_print_dos_string("Bad local drive letter\r\n$");
                return EXIT_BAD_DRIVE_LETTER;
            }
            if (shared_data_ptr->ldrv[drive_no] == 0xFFU) {
                my_print_dos_string("Drive is not mounted by NetMount\r\n$");
                return EXIT_DRIVE_NOT_MOUNTED;
            }
            retval = umount(shared_data_ptr, drive_no);
        }

        return retval;
    }

    my_print_dos_string("Error: Unknown command: $");
    my_print_string(argv[1]);
    my_print_dos_string("\r\n$");

    return EXIT_UNKNOWN_CMD;
}
