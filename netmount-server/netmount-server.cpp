// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2025 Jaroslav Rohel, jaroslav.rohel@gmail.com

#include "../shared/dos.h"
#include "../shared/drvproto.h"
#include "fs.hpp"
#include "utils.hpp"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <filesystem>

#define PROGRAM_VERSION "1.0.0"

#define MAX_DRIVERS_COUNT 26

// structs are packed
#pragma pack(1)

namespace netmount_srv {

namespace {

class Shares {
public:
    class ShareInfo {
    public:
        // Returns true if this drive is used (shared)
        bool is_used() const noexcept { return used; }

        // Returns root path of shared drive.
        const std::filesystem::path & get_root() const noexcept { return root; }

        // Returns true if the shared drive is on FAT filesystem.
        bool is_on_fat() const noexcept { return on_fat; }

        // Sets `root` for this drive. Initialize `used` and `on_fat`.
        void set_root(std::filesystem::path root) {
            if (used) {
                throw std::runtime_error("already used");
            }
            this->root = std::move(root);
            used = true;
            on_fat = ::netmount_srv::is_on_fat(this->root);
        }


        ShareInfo() = default;

        // ShareInfo is accessed by reference. Make sure no one copies the ShareInfo by mistake.
        ShareInfo(const ShareInfo &) = delete;
        ShareInfo & operator=(const ShareInfo &) = delete;

    private:
        bool used{false};
        std::filesystem::path root;
        bool on_fat;
    };

    const ShareInfo & get_info(uint8_t drive_num) const { return infos.at(drive_num); }
    ShareInfo & get_info(uint8_t drive_num) { return infos.at(drive_num); }
    const auto & get_infos() const { return infos; }

private:
    std::array<ShareInfo, MAX_DRIVERS_COUNT> infos;
};


// Reply cache - contains the last replies sent to clients
// It is used in case a client has not received reply and resends request so that we don't process
// the request again (which can be dangerous in case of write requests).
constexpr int REPLY_CACHE_SIZE = 16;
class ReplyCache {
public:
    struct ReplyInfo {
        std::array<uint8_t, 1500> packet;  // entire packet that was sent
        uint16_t len{0};                   // packet length
        struct in_addr ipv4_addr;          // remote IP address
        uint16_t udp_port;                 // remote UDP port
        time_t timestamp;                  // time of answer (so if cache full I can drop oldest)

        ReplyInfo() = default;

        // ReplyInfo is accessed by reference. Make sure no one copies the ReplyInfo by mistake.
        ReplyInfo(const ReplyInfo &) = delete;
        ReplyInfo & operator=(const ReplyInfo &) = delete;
    };

    // Finds the cache entry related to given client, or the oldest one for reuse
    ReplyInfo & get_reply_info(struct in_addr ipv4_addr, uint16_t udp_port) noexcept;

private:
    std::array<ReplyInfo, REPLY_CACHE_SIZE> items;
};


ReplyCache::ReplyInfo & ReplyCache::get_reply_info(struct in_addr ipv4_addr, uint16_t udp_port) noexcept {
    auto * oldest_item = &items[0];

    // search for item with matching address (ip and port)
    for (auto & item : items) {
        if (memcmp(&item.ipv4_addr, &ipv4_addr, sizeof(ipv4_addr)) == 0 && item.udp_port == udp_port) {
            return item;  // found
        }
        if (item.timestamp < oldest_item->timestamp) {
            oldest_item = &item;
        }
    }

    // matching item not found, reuse oldest item
    oldest_item->len = 0;  // invalidate old content by setting length to 0
    oldest_item->ipv4_addr = ipv4_addr;
    oldest_item->udp_port = udp_port;
    return *oldest_item;
}


// Define global data
Shares shares;
ReplyCache answer_cache;
FilesystemDB fs;


// the flag is set when netmount-server is expected to terminate
sig_atomic_t volatile exit_flag = 0;

void signal_handler(int sig_number) {
    switch (sig_number) {
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            exit_flag = 1;
            break;
        default:
            break;
    }
}


// Returns a FCB file name as C string (with added null terminator), this is used only by debug routines
#ifdef DEBUG
char * fcb_file_name_to_cstr(const fcb_file_name & s) {
    static char name_cstr[sizeof(fcb_file_name) + 1] = {'\0'};
    memcpy(name_cstr, &s, sizeof(fcb_file_name));
    return name_cstr;
}
#endif


// Creates a relative path from the value in buff
std::filesystem::path create_relative_path(const void * buff, uint16_t len) {
    auto * ptr = reinterpret_cast<const char *>(buff);

    std::string search_template(ptr, len);
    std::transform(search_template.begin(), search_template.end(), search_template.begin(), ascii_to_lower);
    std::replace(search_template.begin(), search_template.end(), '\\', '/');
    return std::filesystem::path(search_template).relative_path();
}


// Processes client requests and prepares responses.
int process_request(ReplyCache::ReplyInfo & reply_info, const uint8_t * request_packet, int request_packet_len) {

    // must contain at least the header
    if (request_packet_len < static_cast<int>(sizeof(struct drive_proto_hdr))) {
        return -1;
    }

    auto const * const request_header = reinterpret_cast<struct drive_proto_hdr const *>(request_packet);
    auto * const reply_header = reinterpret_cast<struct drive_proto_hdr *>(reply_info.packet.data());

    // ReplyCache contains a packet (length > 0) with the same sequence number, re-send it.
    if (reply_info.len > 0 && reply_header->sequence == request_header->sequence) {
        dbg_print("Using a packet from the reply cache (seq {:d})\n", reply_header->sequence);
        return reply_info.len;
    }

    *reply_header = *request_header;

    auto const * const request_data = reinterpret_cast<const uint8_t *>(request_header + 1);
    auto * const reply_data = reinterpret_cast<uint8_t *>(reply_header + 1);
    const uint16_t request_data_len = request_packet_len - sizeof(struct drive_proto_hdr);

    const int reqdrv = request_header->drive & 0x1F;
    const int function = request_header->function;
    uint16_t * const ax = &reply_header->ax;
    int reply_packet_len = 0;

    if ((reqdrv < 2) || (reqdrv >= MAX_DRIVERS_COUNT)) {
        err_print("Requested invalid drive number: {:d}\n", reqdrv);
        return -1;
    }

    // Do I share this drive?
    const auto & share = shares.get_info(reqdrv);
    if (!share.is_used()) {
        err_print("Requested drive is not shared: {:c}: (number {:d})\n", 'A' + reqdrv, reqdrv);
        return -1;
    }

    // assume success
    *ax = htole16(DOS_EXTERR_NO_ERROR);

    dbg_print(
        "Got query: 0x{:02X} [{:02X} {:02X} {:02X} {:02X}]\n",
        function,
        request_data[0],
        request_data[1],
        request_data[2],
        request_data[3]);

    switch (function) {
        case INT2F_REMOVE_DIR:
        case INT2F_MAKE_DIR: {
            std::filesystem::path directory = share.get_root() / create_relative_path(request_data, request_data_len);

            if (function == INT2F_MAKE_DIR) {
                dbg_print("MAKE_DIR \"{}\"\n", directory.native());
                if (!make_dir(directory)) {
                    *ax = htole16(DOS_EXTERR_WRITE_FAULT);
                    err_print("ERROR: MAKE_DIR \"{}\": {}\n", directory.native(), strerror(errno));
                }
            } else {
                dbg_print("REMOVE_DIR \"{}\"\n", directory.native());
                if (!delete_dir(directory)) {
                    *ax = htole16(DOS_EXTERR_WRITE_FAULT);
                    err_print("ERROR: REMOVE_DIR \"{}\": {}\n", directory.native(), strerror(errno));
                }
            }
        } break;

        case INT2F_CHANGE_DIR: {
            std::filesystem::path directory = share.get_root() / create_relative_path(request_data, request_data_len);

            dbg_print("CHANGE_DIR \"{}\"\n", directory.native());
            // Try to chdir to this dir
            if (!change_dir(directory)) {
                err_print("ERROR: CHANGE_DIR \"{}\": {}\n", directory.native(), strerror(errno));
                *ax = htole16(DOS_EXTERR_PATH_NOT_FOUND);
            }
            break;
        }

        case INT2F_CLOSE_FILE: {
            if (request_data_len != sizeof(drive_proto_closef)) {
                return -1;
            }
            // Only checking the existence of the handle because I don't keep files open.
            auto * const request = reinterpret_cast<const drive_proto_closef *>(request_data);
            const uint16_t handle = le16toh(request->start_cluster);
            dbg_print("CLOSE_FILE handle {}\n", handle);
            const auto & path = fs.get_handle_path(handle);
            if (path.empty()) {
                err_print("ERROR: CLOSE_FILE handle {} not found", handle);
                // TODO: Send error to client?
            }
        } break;

        case INT2F_READ_FILE: {
            if (request_data_len != sizeof(drive_proto_readf)) {
                return -1;
            }
            auto * const request = reinterpret_cast<const drive_proto_readf *>(request_data);
            const uint32_t offset = le32toh(request->offset);
            const uint16_t handle = le16toh(request->start_cluster);
            const uint16_t len = le16toh(request->length);
            dbg_print("READ_FILE handle {}, {} bytes, offset {}\n", handle, len, offset);
            try {
                reply_packet_len = fs.read_file(reply_data, handle, offset, len);
            } catch (const std::runtime_error & ex) {
                err_print("ERROR: READ_FILE: {}\n", ex.what());
                *ax = htole16(DOS_EXTERR_ACCESS_DENIED);
            }
        } break;

        case INT2F_WRITE_FILE: {
            if (request_data_len < sizeof(drive_proto_writef)) {
                return -1;
            }
            auto * const request = reinterpret_cast<const drive_proto_writef *>(request_data);
            const uint32_t offset = le32toh(request->offset);
            const uint16_t handle = le16toh(request->start_cluster);
            dbg_print(
                "WRITE_FILE handle {}, {} bytes, offset {}\n",
                handle,
                request_data_len - sizeof(drive_proto_writef),
                offset);
            try {
                const auto write_len = fs.write_file(
                    request_data + sizeof(drive_proto_writef),
                    handle,
                    offset,
                    request_data_len - sizeof(drive_proto_writef));
                auto reply = reinterpret_cast<drive_proto_writef_reply *>(reply_data);
                reply->written = htole16(write_len);
                reply_packet_len = sizeof(drive_proto_writef_reply);
            } catch (const std::runtime_error & ex) {
                err_print("ERROR: WRITE_FILE: {}\n", ex.what());
                *ax = htole16(DOS_EXTERR_ACCESS_DENIED);
            }

        } break;

        case INT2F_LOCK_UNLOCK_FILE: {
            if (request_data_len < sizeof(drive_proto_lockf)) {
                return -1;
            }
            // Only checking the existence of the handle
            // TODO: Try to lock file?
            auto * const request = reinterpret_cast<const drive_proto_lockf *>(request_data);
            const uint16_t handle = le16toh(request->start_cluster);
            dbg_print("LOCK_UNLOCK_FILE handle {}\n", handle);
            const auto & path = fs.get_handle_path(handle);
            if (path.empty()) {
                err_print("ERROR: LOCK_UNLOCK_FILE handle {} not found", handle);
                // TODO: Send error to client?
            }
        } break;

        case INT2F_DISK_INFO: {
            dbg_print("DISK_INFO for drive {:c}:\n", 'A' + reqdrv);
            auto [fs_size, free_space] = fs_space_info(share.get_root());
            // limit results to slightly under 2 GiB (otherwise MS-DOS is confused)
            if (fs_size >= 2lu * 1024 * 1024 * 1024)
                fs_size = 2lu * 1024 * 1024 * 1024 - 1;
            if (free_space >= 2lu * 1024 * 1024 * 1024)
                free_space = 2lu * 1024 * 1024 * 1024 - 1;
            dbg_print("  TOTAL: {} KiB ; FREE: {} KiB\n", fs_size >> 10, free_space >> 10);
            // AX: media id (8 bits) | sectors per cluster (8 bits)
            // etherdfs says: MSDOS tolerates only 1 here!
            *ax = htole16(1);
            auto * reply = reinterpret_cast<drive_proto_disk_info_reply *>(reply_data);
            reply->total_clusters = htole16(fs_size >> 15);  // 32K clusters
            reply->bytes_per_sector = htole16(32768);
            reply->available_clusters = htole16(free_space >> 15);  // 32K clusters
            reply_packet_len = sizeof(drive_proto_disk_info_reply);
        } break;

        case INT2F_SET_ATTRS: {
            if (request_data_len <= sizeof(drive_proto_set_attrs)) {
                return -1;
            }
            auto * const request = reinterpret_cast<const drive_proto_set_attrs *>(request_data);
            unsigned char attrs = request->attrs;
            const std::filesystem::path path =
                share.get_root() / create_relative_path(request_data + 1, request_data_len - 1);

            dbg_print("SET_ATTRS on file \"{}\", attr: 0x{:02X}\n", path.native(), attrs);
            if (share.is_on_fat()) {
                try {
                    set_item_attrs(path, attrs);
                } catch (const std::runtime_error & ex) {
                    err_print("ERROR: SET_ATTR 0x{:02X} to \"{}\": {}\n", attrs, path.native(), ex.what());
                    *ax = htole16(DOS_EXTERR_FILE_NOT_FOUND);
                }
            }
        } break;

        case INT2F_GET_ATTRS: {
            if (request_data_len == 0) {
                return -1;
            }
            std::filesystem::path path = share.get_root() / create_relative_path(request_data, request_data_len);

            dbg_print("GET_ATTRS on file \"{}\"\n", path.native());
            DosFileProperties properties;
            if (get_path_dos_properties(path, &properties, share.is_on_fat()) == FAT_ERROR_ATTR) {
                dbg_print("no file found\n");
                *ax = htole16(DOS_EXTERR_FILE_NOT_FOUND);
            } else {
                dbg_print("found {} bytes, attr 0x{:02X}\n", properties.size, properties.attrs);
                auto reply = reinterpret_cast<drive_proto_get_attrs_reply *>(reply_data);
                reply->time = htole16(properties.time_date);
                reply->date = htole16(properties.time_date >> 16);
                reply->size_lo = htole16(properties.size);
                reply->size_hi = htole16(properties.size >> 16);
                reply->attrs = properties.attrs;
                reply_packet_len = sizeof(drive_proto_get_attrs_reply);
            }
        } break;

        case INT2F_RENAME_FILE: {
            // At least 3 bytes, expected two paths, one is zero terminated
            if (request_data_len < 3) {
                return -1;
            }
            const int path1_len = request_data[0];
            const int path2_len = request_data_len - (1 + path1_len);
            if (request_data_len > path1_len) {
                const auto path1 = share.get_root() / create_relative_path(request_data + 1, path1_len);
                const auto path2 = share.get_root() / create_relative_path(request_data + 1 + path1_len, path2_len);
                dbg_print("RENAME_FILE \"{}\" to \"{}\"\n", path1.native(), path2.native());
                if (get_path_dos_properties(path2, NULL, 0) != FAT_ERROR_ATTR) {
                    err_print("ERROR: RENAME_FILE: destination file \"{}\" already exists\n", path2.native());
                    *ax = htole16(DOS_EXTERR_ACCESS_DENIED);
                } else {
                    if (!rename_file(path1, path2))
                        *ax = htole16(DOS_EXTERR_ACCESS_DENIED);
                }
            } else {
                *ax = htole16(DOS_EXTERR_FILE_NOT_FOUND);
            }
        } break;

        case INT2F_DELETE_FILE: {
            std::filesystem::path path = share.get_root() / create_relative_path(request_data, request_data_len);
            dbg_print("DELETE_FILE \"{}\"\n", path.native());
            if (get_path_dos_properties(path, NULL, share.is_on_fat()) & FAT_RO) {
                *ax = htole16(DOS_EXTERR_ACCESS_DENIED);
            } else if (delete_files(path) < 0) {
                *ax = htole16(DOS_EXTERR_FILE_NOT_FOUND);
            }
        } break;

        case INT2F_FIND_FIRST: {
            if (request_data_len < sizeof(drive_proto_find_first)) {
                return -1;
            }
            auto * const request = reinterpret_cast<const drive_proto_find_first *>(request_data);
            unsigned fattr = request->attrs;

            std::filesystem::path search_template = create_relative_path(request_data + 1, request_data_len - 1);
            std::filesystem::path directory = share.get_root() / search_template.parent_path();
            std::string filemask = search_template.filename();

            auto filemaskfcb = filename_to_fcb(filemask.c_str());
            dbg_print(
                "FIND_FIRST in \"{}\"\n filemask: \"{}\"\n attrs: 0x{:2X}\n", directory.native(), filemask, fattr);
            const uint16_t handle = fs.get_handle(directory);
            DosFileProperties properties;
            uint16_t fpos = 0;
            const bool is_root_dir = std::filesystem::equivalent(directory, share.get_root());
            if ((handle == 0xFFFFu) ||
                !fs.find_file(properties, handle, filemaskfcb, fattr, fpos, is_root_dir, share.is_on_fat())) {
                dbg_print("No matching file found\n");
                // do not use DOS_EXTERR_FILE_NOT_FOUND, some applications rely on a failing FIND_FIRST
                // to return DOS_EXTERR_NO_MORE_FILES (e.g. LapLink 5)
                *ax = htole16(DOS_EXTERR_NO_MORE_FILES);
            } else {
                dbg_print(
                    "Found file: FCB \"{}\", attrs 0x{:02X}\n",
                    fcb_file_name_to_cstr(properties.fcb_name),
                    properties.attrs);
                auto reply = reinterpret_cast<drive_proto_find_reply *>(reply_data);
                reply->attrs = properties.attrs;
                reply->name = properties.fcb_name;
                reply->time = htole16(properties.time_date);
                reply->date = htole16(properties.time_date >> 16);
                reply->size = htole32(properties.size);
                reply->start_cluster = htole16(handle);
                reply->dir_entry = htole16(fpos);
                reply_packet_len = sizeof(drive_proto_find_reply);
            }
        } break;

        case INT2F_FIND_NEXT: {
            if (request_data_len < sizeof(drive_proto_find_next)) {
                return -1;
            }
            auto * const request = reinterpret_cast<const drive_proto_find_next *>(request_data);
            uint16_t handle = le16toh(request->cluster);
            uint16_t fpos = le16toh(request->dir_entry);
            uint8_t fattr = request->attrs;
            const fcb_file_name * fcbmask = &request->search_template;
            dbg_print(
                "FIND_NEXT looks for {} file in dir handle {}\n fcbmask: \"{}\"\n attrs: 0x{:2X}\n",
                fpos,
                handle,
                fcb_file_name_to_cstr(*fcbmask),
                fattr);
            DosFileProperties properties;
            const bool is_root_dir = std::filesystem::equivalent(fs.get_handle_path(handle), share.get_root());
            if (!fs.find_file(properties, handle, *fcbmask, fattr, fpos, is_root_dir, share.is_on_fat())) {
                dbg_print("No more matching files found\n");
                *ax = htole16(DOS_EXTERR_NO_MORE_FILES);
            } else {
                dbg_print(
                    "Found file: FCB \"{}\", attrs 0x{:02X}\n",
                    fcb_file_name_to_cstr(properties.fcb_name),
                    properties.attrs);
                auto reply = reinterpret_cast<drive_proto_find_reply *>(reply_data);
                reply->attrs = properties.attrs;
                reply->name = properties.fcb_name;
                reply->time = htole16(properties.time_date);
                reply->date = htole16(properties.time_date >> 16);
                reply->size = htole32(properties.size);
                reply->start_cluster = htole16(handle);
                reply->dir_entry = htole16(fpos);
                reply_packet_len = sizeof(drive_proto_find_reply);
            }
        } break;

        case INT2F_SEEK_FROM_END: {
            if (request_data_len != sizeof(drive_proto_seek_from_end)) {
                return -1;
            }
            auto * const request = reinterpret_cast<const drive_proto_seek_from_end *>(request_data);
            // translate a "seek from end" offset into an "seek from start" offset
            int32_t offset = le16toh(request->offset_from_end_hi);
            offset = (offset << 16) + le16toh(request->offset_from_end_lo);
            uint16_t handle = le16toh(request->start_cluster);
            dbg_print("SEEK_FROM_END on file handle {}, offset {}\n", handle, offset);
            // if the offset is positive, zero it
            if (offset > 0) {
                offset = 0;
            }
            int32_t fsize = fs.get_file_size(handle);
            if (fsize < 0) {
                dbg_print("ERROR: file not found or other error\n");
                *ax = htole16(DOS_EXTERR_FILE_NOT_FOUND);
            } else {
                // compute new offset and send it back
                offset += fsize;
                if (offset < 0) {
                    offset = 0;
                }
                dbg_print("File handle {}, size {} bytes, new offset {}\n", handle, fsize, offset);
                auto * reply = reinterpret_cast<drive_proto_seek_from_end_reply *>(reply_data);
                reply->position_lo = htole16(offset);
                reply->position_hi = htole16(offset >> 16);
                reply_packet_len = sizeof(drive_proto_seek_from_end_reply);
            }
        } break;

        case INT2F_OPEN_FILE:
        case INT2F_CREATE_FILE:
        case INT2F_EXTENDED_OPEN_CREATE_FILE: {
            // OPEN is only about "does this file exist", and CREATE "create or truncate this file",
            // EXTENDED_OPEN_CREATE is a combination of both with extra flags
            auto * const request = reinterpret_cast<const drive_proto_open_create *>(request_data);
            uint16_t stack_attr = le16toh(request->attrs);
            uint16_t action_code = le16toh(request->action);
            uint16_t ext_open_create_open_mode = le16toh(request->mode);

            std::filesystem::path path =
                share.get_root() / create_relative_path(request_data + 6, request_data_len - 6);
            const std::filesystem::path directory = share.get_root() / path.parent_path();

            dbg_print("OPEN/CREATE/EXTENDED_OPEN_CREATE \"{}\", stack_attr=0x{:04X}\n", path.native(), stack_attr);
            if (!std::filesystem::is_directory(directory)) {
                err_print(
                    "ERROR: OPEN/CREATE/EXTENDED_OPEN_CREATE: Directory \"{}\" does not exist\n", directory.native());
                *ax = htole16(DOS_EXTERR_PATH_NOT_FOUND);
            } else {
                try {
                    bool error = false;
                    uint8_t result_open_mode;
                    uint16_t ext_open_create_result_code = 0;
                    DosFileProperties properties;

                    if (function == INT2F_OPEN_FILE) {
                        dbg_print("OPEN_FILE \"{}\", stack_attr=0x{:04X}\n", path.native(), stack_attr);
                        result_open_mode = stack_attr & 0xFF;
                        // check that item exists, and is neither a volume nor a directory
                        auto attr = get_path_dos_properties(path, &properties, share.is_on_fat());
                        if (attr == 0xFF || ((attr & (FAT_VOLUME | FAT_DIRECTORY)) != 0)) {
                            error = true;
                        }
                    } else if (function == INT2F_CREATE_FILE) {
                        dbg_print("CREATE_FILE \"{}\", stack_attr=0x{:04X}\n", path.native(), stack_attr);
                        properties = create_or_truncate_file(path, stack_attr & 0xFF, share.is_on_fat());
                        result_open_mode = 2;  // read/write
                    } else {
                        dbg_print(
                            "EXTENDED_OPEN_CREATE_FILE \"{}\", stack_attr=0x{:04X}, action_code=0x{:04X}, "
                            "open_mode=0x{:04X}\n",
                            path.native(),
                            stack_attr,
                            action_code,
                            ext_open_create_open_mode);

                        auto attr = get_path_dos_properties(path, &properties, share.is_on_fat());
                        result_open_mode =
                            ext_open_create_open_mode & 0x7f;  // etherdfs says: that's what PHANTOM.C does
                        if (attr == FAT_ERROR_ATTR) {          // file not found
                            dbg_print("File doesn't exist -> ");
                            if ((action_code & IF_NOT_EXIST_MASK) == ACTION_CODE_CREATE_IF_NOT_EXIST) {
                                dbg_print("create file\n");
                                properties = create_or_truncate_file(path, stack_attr & 0xFF, share.is_on_fat());
                                ext_open_create_result_code = DOS_EXT_OPEN_FILE_RESULT_CODE_CREATED;
                            } else {
                                dbg_print("fail\n");
                                error = true;
                            }
                        } else if ((attr & (FAT_VOLUME | FAT_DIRECTORY)) != 0) {
                            err_print("ERROR: Item \"{}\" is either a DIR or a VOL\n", path.native());
                            error = true;
                        } else {
                            dbg_print("File exists already (attr 0x{:02X}) -> ", attr);
                            if ((action_code & IF_EXIST_MASK) == ACTION_CODE_OPEN_IF_EXIST) {
                                dbg_print("open file\n");
                                ext_open_create_result_code = DOS_EXT_OPEN_FILE_RESULT_CODE_OPENED;
                            } else if ((action_code & IF_EXIST_MASK) == ACTION_CODE_REPLACE_IF_EXIST) {
                                dbg_print("truncate file\n");
                                properties = create_or_truncate_file(path, stack_attr & 0xFF, share.is_on_fat());
                                ext_open_create_result_code = DOS_EXT_OPEN_FILE_RESULT_CODE_TRUNCATED;
                            } else {
                                dbg_print("fail\n");
                                error = true;
                            }
                        }
                    }

                    if (error) {
                        dbg_print("OPEN/CREATE/EXTENDED_OPEN_CREATE failed\n");
                        *ax = htole16(DOS_EXTERR_FILE_NOT_FOUND);
                    } else {
                        // success (found a file, created it or truncated it)
                        auto handle = fs.get_handle(path);
                        dbg_print("File \"{}\", handle {}\n", path.native(), handle);
                        dbg_print("    FCB file name: {}\n", fcb_file_name_to_cstr(properties.fcb_name));
                        dbg_print("    size: {}\n", properties.size);
                        dbg_print("    attrs: 0x{:02X}\n", properties.attrs);
                        dbg_print("    date_time: {:04X}\n", properties.time_date);
                        if (handle == 0xFFFFu) {
                            err_print("ERROR: Failed to get file handle\n");
                            return -1;
                        }
                        auto reply = reinterpret_cast<drive_proto_open_create_reply *>(reply_data);
                        reply->attrs = properties.attrs;
                        reply->name = properties.fcb_name;
                        reply->date_time = htole32(properties.time_date);
                        reply->size = htole32(properties.size);
                        reply->start_cluster = htole16(handle);
                        // CX result (only relevant for EXTENDED_OPEN_CREATE)
                        reply->result_code = htole16(ext_open_create_result_code);
                        reply->mode = result_open_mode;
                        reply_packet_len = sizeof(drive_proto_open_create_reply);
                    }
                } catch (const std::runtime_error & ex) {
                    err_print("ERROR: OPEN/CREATE/EXTENDED_OPEN_CREATE: {}\n", ex.what());
                    *ax = htole16(DOS_EXTERR_FILE_NOT_FOUND);
                }
            }
        } break;

        default:  // unknown query - ignore
            return -1;
    }

    return reply_packet_len + sizeof(struct drive_proto_hdr);
}


int udp_sock(const std::string & bind_addr, uint16_t udp_bind_port) {
    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd == -1) {
        perror("socket");
        return -1;
    }

    do {
        auto addr = INADDR_ANY;
        if (!bind_addr.empty()) {
            if (inet_pton(AF_INET, bind_addr.c_str(), &addr) <= 0) {
                perror("Invalid IP address");
                break;
            }
        }

        struct sockaddr_in server;
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = addr;
        server.sin_port = htons(udp_bind_port);

        if (bind(socketfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
            perror("bind");
            break;
        }

        errno = 0;
        return socketfd;
    } while (0);

    {
        const int saved_errno = errno;
        close(socketfd);
        errno = saved_errno;
        return -1;
    }
}


// used for debug output of frames on screen
#ifdef DEBUG
void dump_packet(const unsigned char * frame, int len) {
    constexpr int LINEWIDTH = 16;

    // display line by line
    const int lines = (len + LINEWIDTH - 1) / LINEWIDTH;
    for (int i = 0; i < lines; i++) {
        const int line_offset = i * LINEWIDTH;

        // output hex data
        for (int b = 0; b < LINEWIDTH; ++b) {
            const int offset = line_offset + b;
            if (b == LINEWIDTH / 2)
                print(stdout, " ");
            if (offset < len) {
                print(stdout, " {:02X}", frame[offset]);
            } else {
                print(stdout, "   ");
            }
        }

        print(stdout, " | ");  // delimiter between hex and ascii

        // output ascii data
        for (int b = 0; b < LINEWIDTH; ++b) {
            const int offset = line_offset + b;
            if (b == LINEWIDTH / 2)
                print(stdout, " ");
            if (offset >= len) {
                print(stdout, " ");
                continue;
            }
            if ((frame[offset] >= ' ') && (frame[offset] <= '~')) {
                print(stdout, "{:c}", frame[offset]);
            } else {
                print(stdout, ".");
            }
        }

        print(stdout, "\n");
    }
}
#endif


// Compute BSD Checksum for "len" bytes beginning at location "addr".
uint16_t bsd_checksum(const void * addr, uint16_t len) {
    uint16_t res;
    auto * ptr = static_cast<const uint8_t *>(addr);
    for (res = 0; len > 0; --len) {
        res = (res << 15) | (res >> 1);
        res += *ptr;
        ++ptr;
    }
    return res;
}


void print_help(const char * program_name) {
    print(
        stdout,
        "NetMount server {} , Copyright 2025 Jaroslav Rohel <jaroslav.rohel@gmail.com>\n"
        "NetMount server comes with ABSOLUTELY NO WARRANTY. This is free software\n"
        "and you are welcome to redistribute it under the terms of the GNU GPL v2.\n\n",
        PROGRAM_VERSION);

    print(stdout, "Usage:\n");
    print(
        stdout,
        "{} [--help] [--bind_ip_addr=] [--bind_port=udp_port] <drive>=<root_path> [... <drive>=<root_path>]\n\n",
        program_name);

    print(
        stdout,
        "Options:\n"
        "  --help                   Display this help\n"
        "  --bind-addr=<IP_ADDR>    IP address to bind, all address (\"0.0.0.0\") by default\n"
        "  --bind-port=<UDP_PORT>   UDP port to listen, {} by default\n"
        "  <drive>=<root_path>      drive - DOS drive C-Z, root_path - paths to serve\n",
        DRIVE_PROTO_UDP_PORT);
}

}  // namespace

}  // namespace netmount_srv


using namespace netmount_srv;

int main(int argc, char ** argv) {
    std::string bind_addr;
    uint16_t bind_port = DRIVE_PROTO_UDP_PORT;
    unsigned char cksumflag;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg.size() < 3) {
            print(stdout, "Invalid argument \"{}\"\n", arg);
            return -1;
        }
        if (arg == "--help") {
            print_help(argv[0]);
            return 0;
        }
        if (arg.starts_with("--bind-addr=")) {
            bind_addr = arg.substr(12);
            continue;
        }
        if (arg.starts_with("--bind-port=")) {
            char * end = nullptr;
            auto port = std::strtol(argv[i] + 12, &end, 10);
            if (port <= 0 || port > 0xFFFF || *end != '\0') {
                print(stdout, "Invalid bind port \"{}\". Valid values are in the 1-{} range.\n", argv[i] + 12, 0xFFFF);
                return -1;
            }
            bind_port = port;
            continue;
        }
        if (arg[1] == '=') {
            auto drive_char = ascii_to_upper(arg[0]);
            if (drive_char < 'C' || drive_char > 'Z') {
                print(stdout, "Invalid DOS drive \"{:c}\". Valid drives are in the C - Z range.\n", arg[0]);
                return -1;
            }
            auto & share = shares.get_info(drive_char - 'A');
            if (share.is_used()) {
                print(stdout, "Drive \"{:c}\" already in use.\n", drive_char);
                return -1;
            }
            try {
                share.set_root(std::filesystem::canonical(arg.substr(2)));
            } catch (const std::exception & ex) {
                print(stderr, "ERROR: failed to resolve path \"{}\": {}\n", arg.substr(2), ex.what());
                return 1;
            }
            continue;
        }
        print(stdout, "Unknown argument \"{}\"\n", arg);
        return -1;
    }

    bool drives_defined = false;
    for (auto & share : shares.get_infos()) {
        if (share.is_used()) {
            drives_defined = true;
            break;
        }
    }
    if (!drives_defined) {
        print(stdout, "None shared drive defined. Use \"--help\" to display help.\n");
        return -1;
    }

    // Prepare UDP socket
    auto sock = udp_sock(bind_addr, bind_port);
    if (sock == -1) {
        print(stderr, "ERROR: Failed to open socket: {}\n", strerror(errno));
        return 1;
    }

    // setup signals handler
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGINT, signal_handler);

    // Print table with shared drives
    bool some_drive_not_fat = false;
    for (std::size_t i = 0; i < shares.get_infos().size(); ++i) {
        const auto & share = shares.get_info(i);
        if (!share.is_used()) {
            continue;
        }
        if (!share.is_on_fat()) {
            some_drive_not_fat = true;
        }
        print(stdout, "{:c} {:c}: => {}\n", share.is_on_fat() ? ' ' : '*', 'A' + i, share.get_root().string());
    }
    if (some_drive_not_fat) {
        print(
            stdout,
            "WARNING: It looks like drives marked with '*' are not stored on a FAT file system. "
            "DOS attributes will not be supported on these drives.\n\n");
    }

    // main loop
    uint8_t request_packet[2048];
    while (exit_flag == 0) {
        struct timeval timeout = {10, 0};  // set timeout to 10s
        fd_set rfds, efds;
        FD_ZERO(&rfds);
        FD_ZERO(&efds);
        FD_SET(sock, &rfds);
        FD_SET(sock, &efds);
        const int select_ret = select(sock + 1, &rfds, NULL, &efds, &timeout);

        if (select_ret == -1) {
            if (errno == EINTR) {
                dbg_print("select: A signal was caught\n");
                continue;
            } else {
                err_print("ERROR: select: {}\n", strerror(errno));
                return -1;
            }
        }

        if (select_ret == 0) {
            dbg_print("select: Timeout\n");
            continue;
        }

        struct sockaddr_in peer_addr;
        socklen_t peer_addrlen = sizeof(peer_addr);
        int request_packet_len = recvfrom(
            sock, request_packet, sizeof(request_packet), MSG_DONTWAIT, (struct sockaddr *)&peer_addr, &peer_addrlen);

        dbg_print("--------------------------------\n");
        {
            char peer_addr_str[16];
            dbg_print(
                "Received packet, {} bytes from {}:{}\n",
                request_packet_len,
                inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, sizeof(peer_addr_str)),
                ntohs(peer_addr.sin_port));

            if (request_packet_len < static_cast<int>(sizeof(struct drive_proto_hdr))) {
                err_print(
                    "ERROR: received a truncated/malformed packet from {}:{}\n",
                    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, sizeof(peer_addr_str)),
                    ntohs(peer_addr.sin_port));
                continue;
            }
        }

        // check the protocol version
        auto * header = reinterpret_cast<const drive_proto_hdr *>(request_packet);
        if (header->version != DRIVE_PROTO_VERSION) {
            char peer_addr_str[16];
            err_print(
                "ERROR: unsupported protocol version {:d} from {}:{}\n",
                header->version,
                inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, sizeof(peer_addr_str)),
                ntohs(peer_addr.sin_port));
            continue;
        }

        cksumflag = le16toh(header->length_flags) >> 15;

        const uint16_t length_from_header = le16toh(header->length_flags) & 0x7FF;
        if (length_from_header < sizeof(struct drive_proto_hdr)) {
            char peer_addr_str[16];
            err_print(
                "ERROR: received a malformed packet from {}:{}\n",
                inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, sizeof(peer_addr_str)),
                ntohs(peer_addr.sin_port));
            continue;
        }
        if (length_from_header > request_packet_len) {
            // corupted/truncated packet
            char peer_addr_str[16];
            err_print(
                "ERROR: received a truncated packet from {}:{}\n",
                inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, sizeof(peer_addr_str)),
                ntohs(peer_addr.sin_port));
            continue;
        } else {
#ifdef DEBUG
            if (request_packet_len != length_from_header) {
                char peer_addr_str[16];
                dbg_print(
                    "Received UDP packet with extra data at the end from {}:{} (length in header = {}, packet len "
                    "= "
                    "{})\n",
                    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, sizeof(peer_addr_str)),
                    ntohs(peer_addr.sin_port),
                    length_from_header,
                    request_packet_len);
            }
#endif
            // length_from_header seems sane, use it instead of received lenght
            request_packet_len = length_from_header;
        }

#ifdef DEBUG
        dbg_print(
            "Received packet of {} bytes (cksum = {})\n",
            request_packet_len,
            (cksumflag != 0) ? "ENABLED" : "DISABLED");
        dump_packet(request_packet, request_packet_len);
#endif

#ifdef SIMULATE_PACKET_LOSS
        // simulated random input packet LOSS
        if ((rand() & 31) == 0) {
            print(stderr, "Incoming packet lost!\n");
            continue;
        }
#endif

        // check the checksum, if any
        if (cksumflag != 0) {
            uint16_t cksum_remote, cksum_mine;
            cksum_mine = bsd_checksum(
                &header->checksum + 1,
                request_packet_len - (reinterpret_cast<const uint8_t *>(&header->checksum + 1) -
                                      reinterpret_cast<const uint8_t *>(header)));
            cksum_remote = le16toh(header->checksum);
            if (cksum_mine != cksum_remote) {
                print(stderr, "CHECKSUM MISMATCH! Computed: 0x{:04X} Received: 0x{:04X}\n", cksum_mine, cksum_remote);
                continue;
            }
        } else {
            const uint16_t recv_magic = le16toh(header->checksum);
            if (recv_magic != DRIVE_PROTO_MAGIC) {
                print(stderr, "Bad MAGIC! Expected: 0x{:04X} Received: 0x{:04X}\n", DRIVE_PROTO_MAGIC, recv_magic);
                continue;
            }
        }

        auto & reply_info = answer_cache.get_reply_info(peer_addr.sin_addr, peer_addr.sin_port);
        const int send_msg_len = process_request(reply_info, request_packet, request_packet_len);
        // update reply cache entry
        if (send_msg_len >= 0) {
            reply_info.len = send_msg_len;
            reply_info.timestamp = time(NULL);
        } else {
            reply_info.len = 0;
        }

#ifdef SIMULATE_PACKET_LOSS
        // simulated random ouput packet LOSS
        if ((rand() & 31) == 0) {
            print(stderr, "Outgoing packet lost!\n");
            continue;
        }
#endif

        if (send_msg_len > 0) {
            // fill in header
            auto * const header = reinterpret_cast<struct drive_proto_hdr *>(reply_info.packet.data());
            header->length_flags = htole16(send_msg_len);
            if (cksumflag != 0) {
                uint16_t checksum = bsd_checksum(
                    &header->checksum + 1,
                    send_msg_len -
                        (reinterpret_cast<uint8_t *>(&header->checksum + 1) - reinterpret_cast<uint8_t *>(header)));
                header->checksum = htole16(checksum);
                header->length_flags |= htole16(0x8000);  // set the checksum flag
            } else {
                header->checksum = htole16(DRIVE_PROTO_MAGIC);
                header->length_flags &= htole16(0x7FFF);  // zero the checksum flag
            }
#ifdef DEBUG
            dbg_print("Sending back an answer of {} bytes\n", send_msg_len);
            dump_packet(reply_info.packet.data(), send_msg_len);
#endif
            auto i = sendto(
                sock, reply_info.packet.data(), send_msg_len, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
            if (i < 0) {
                err_print("ERROR: sendto: {}\n", strerror(errno));
            } else if (i != send_msg_len) {
                err_print("ERROR: sendto: {} bytes sent but {} bytes requested\n", i, send_msg_len);
            }
        } else {
            err_print("ERROR: Request ignored: Returned {}\n", send_msg_len);
        }
        dbg_print("--------------------------------\n\n");
    }

    return 0;
}
