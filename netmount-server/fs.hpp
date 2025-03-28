// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2025 Jaroslav Rohel, jaroslav.rohel@gmail.com

#ifndef _FS_HPP_
#define _FS_HPP_

#include "../shared/dos.h"

#include <stdint.h>

#include <array>
#include <filesystem>
#include <vector>

// FAT attributes
#define FAT_RO        0x01
#define FAT_HIDDEN    0x02
#define FAT_SYSTEM    0x04
#define FAT_VOLUME    0x08
#define FAT_DIRECTORY 0x10
#define FAT_ARCHIVE   0x20
#define FAT_DEVICE    0x40

// Invalid attrtibutes, we use it to return error
#define FAT_ERROR_ATTR 0xFF

// Action code use low nibble for DOES exist file
#define IF_EXIST_MASK                0x0F
#define ACTION_CODE_FAIL_IF_EXIST    0x00
#define ACTION_CODE_OPEN_IF_EXIST    0x01
#define ACTION_CODE_REPLACE_IF_EXIST 0x02

// Action code use high nibble for does NOT exist file
#define IF_NOT_EXIST_MASK               0xF0
#define ACTION_CODE_FAIL_IF_NOT_EXIST   0x00
#define ACTION_CODE_CREATE_IF_NOT_EXIST 0x10


namespace netmount_srv {

struct DosFileProperties {
    fcb_file_name fcb_name;  // DOS FCB (file control block) style file name
    uint32_t size;           // file size in bytes
    uint32_t time_date;      // in DOS format
    uint32_t attrs;          // DOS file/directory attributes
};


class FilesystemDB {
public:
    /// Returns the handle (start cluster in dos) of a filesystem item (file or directory).
    /// Returns 0xffff on error
    uint16_t get_handle(const std::filesystem::path & path);

    /// Returns the path to the filesystem item represented by the handle.
    const std::filesystem::path & get_handle_path(uint16_t handle) const;

    // Reads `len` bytes from `offset` from the file defined by `handle` to `buffer`.
    // Returns the number of bytes read
    // Throws exception on error
    int32_t read_file(void * buffer, uint16_t handle, uint32_t offset, uint16_t len);

    // Writes `len` bytes from `buffer` to the file defined by `handle` starting at position `offset`.
    // Returns the number of bytes written.
    // Throws exception on error
    int32_t write_file(const void * buffer, uint16_t handle, uint32_t offset, uint16_t len);

    // returns the size of file defined by handle (or -1 on error)
    int32_t get_file_size(uint16_t handle);

    // Searches for files matching template `tmpl` in directory defined by `handle` with at most attributes `attr`.
    // Fills in `properties` with the next match after `nth` and updates `nth`
    // Returns `true` on success.
    bool find_file(
        DosFileProperties & properties,
        uint16_t handle,
        const fcb_file_name & tmpl,
        unsigned char attr,
        uint16_t & nth,
        bool is_root_dir,
        bool use_fat_ioctl);

private:
    class Item {
    public:
        std::filesystem::path path;                     // path to filesystem item
        time_t last_used_time;                          // when this item was last used
        std::vector<DosFileProperties> directory_list;  // used by FIND_FIRST and FIND_NEXT

        // Creates a directory listing for `path`.
        // Returns the number of filesystem entries, or -1 if an error occurs.
        int32_t create_directory_list(bool use_fat_ioctl);
    };
    std::array<Item, 65535> items;
};


// convert filename to fcb_file_name structure
fcb_file_name filename_to_fcb(const char * filename) noexcept;

// Fills the DosFileProperties structure if `properties` != nullptr.
// Returns DOS attributes for `path` or FAT_ERROR_ATTR on error.
// DOS attr flags: 1=RO 2=HID 4=SYS 8=VOL 16=DIR 32=ARCH 64=DEVICE
uint8_t get_path_dos_properties(const std::filesystem::path & path, DosFileProperties * properties, bool use_fat_ioctl);

// Sets attributes `attrs` on file defined by `path`.
// Throws exception on error.
void set_item_attrs(const std::filesystem::path & path, uint8_t attrs);

// Creates directory
// Returns `true` on success
bool make_dir(const std::filesystem::path & dir) noexcept;

// Removes directory
// Returns `true` on success
bool delete_dir(const std::filesystem::path & dir) noexcept;

// Changes to directory
// Returns `true` on success
bool change_dir(const std::filesystem::path & dir) noexcept;

// Creates or truncates a file `path` with attributes `attrs`.
// Returns properties of created/truncated file.
// Throws exception on error.
DosFileProperties create_or_truncate_file(const std::filesystem::path & path, uint8_t attrs, bool use_fat_ioctl);

// Removes all files matching the pattern
// Returns the number of removed files, or -1 on error or if no matching file found
int delete_files(const std::filesystem::path & pattern);

// Renames `old_name` to `new_name`
// Returns `true` on success
bool rename_file(const std::filesystem::path & old_name, const std::filesystem::path & new_name) noexcept;

// Returns filesystem total size and free space in bytes, or 0, 0 on error
std::pair<uint64_t, uint64_t> fs_space_info(const std::filesystem::path & path);

// Returns `true` if `path` is on FAT filesystem
bool is_on_fat(const std::filesystem::path & path);

}  // namespace netmount_srv

#endif
