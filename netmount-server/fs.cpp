// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2025 Jaroslav Rohel, jaroslav.rohel@gmail.com

#include "fs.hpp"

#include "utils.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifdef __FreeBSD__
  #include <sys/mount.h> /* statfs() */
#else
  #include <linux/msdos_fs.h>
#endif
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#include <format>
#include <string>

namespace netmount_srv {

namespace {

// Tests whether the FCB file name matches the FCB file mask.
bool match_fcb_name_to_mask(const fcb_file_name & mask, const fcb_file_name & name) {
    for (unsigned int i = 0; i < sizeof(name.name_blank_padded); ++i) {
        if ((ascii_to_upper(name.name_blank_padded[i]) != ascii_to_upper(mask.name_blank_padded[i])) &&
            (mask.name_blank_padded[i] != '?')) {
            return false;
        }
    }
    for (unsigned int i = 0; i < sizeof(name.ext_blank_padded); ++i) {
        if ((ascii_to_upper(name.ext_blank_padded[i]) != ascii_to_upper(mask.ext_blank_padded[i])) &&
            (mask.ext_blank_padded[i] != '?')) {
            return false;
        }
    }
    return true;
}


// Converts a time_t into a FAT style timestamp
// 5 bits 00–04: Seconds (0–29, with each unit representing 2 seconds)
// 6 bits 05–10: Minutes (0–59)
// 5 bits 11–15: Hours (0–23)
// 5 bits 16–20: Day (1–31)
// 4 bits 21–24: Month (1–12)
// 7 bits 25–31: Year (since 1980, with 0 representing 1980, 1 representing 1981, and so on).
uint32_t time_to_fat(time_t t) {
    uint32_t res;
    struct tm * ltime;
    ltime = localtime(&t);
    res = ltime->tm_year - 80;  // tm_year is years from 1900, FAT is years from 1980
    res <<= 4;
    res |= ltime->tm_mon + 1;  // tm_mon is in range 0..11 while FAT expects 1..12
    res <<= 5;
    res |= ltime->tm_mday;
    res <<= 5;
    res |= ltime->tm_hour;
    res <<= 6;
    res |= ltime->tm_min;
    res <<= 5;
    res |= ltime->tm_sec / 2;  // DOS stores seconds divided by two
    return res;
}

}  // namespace


uint16_t FilesystemDB::get_handle(const std::filesystem::path & path) {
    uint16_t first_free = items.size();
    uint16_t oldest = 0;
    time_t now = time(NULL);

    // see if not already in cache
    for (uint16_t handle = 0; handle < items.size(); ++handle) {
        auto & cur_item = items[handle];

        if (cur_item.path == path) {
            cur_item.last_used_time = now;
            dbg_print("Found handle {} with path \"{}\" in cache\n", handle, path.native());
            return handle;
        }

        if ((now - cur_item.last_used_time) > 3600) {
            if (!cur_item.directory_list.empty()) {
                // Directory list is too old -> remove it from cache and free memory.
                // It will be re-generated if necessary.
                dbg_print("Remove old directory list for handle {} path \"{}\" from cache\n", handle, path.native());
                cur_item.directory_list = {};
            }
        }

        if (first_free == items.size()) {
            if (cur_item.path.empty()) {
                first_free = handle;
            } else if (items[oldest].last_used_time > cur_item.last_used_time) {
                oldest = handle;
            }
        }
    }

    // not found - if no free slot available, pick the oldest one and replace it
    if (first_free == items.size()) {
        items[oldest].path.clear();
        items[oldest].directory_list = {};
        first_free = oldest;
    }

    // assign item to handle
    items[first_free].path = path;
    items[first_free].last_used_time = now;

    return first_free;
}


const std::filesystem::path & FilesystemDB::get_handle_path(uint16_t handle) const { return items[handle].path; }


int32_t FilesystemDB::read_file(void * buffer, uint16_t handle, uint32_t offset, uint16_t len) {
    long res;
    FILE * fd;
    const auto & fname = items[handle].path;
    if (fname.empty()) {
        throw std::runtime_error(std::format("Handle {} not found", handle));
    }

    fd = fopen(fname.c_str(), "rb");
    if (!fd) {
        throw std::runtime_error(std::format("Cannot open file: {}", strerror(errno)));
    }
    if (fseek(fd, offset, SEEK_SET) != 0) {
        auto orig_errno = errno;
        fclose(fd);
        throw std::runtime_error(std::format("Cannot seek in file: {}", strerror(orig_errno)));
    }
    res = fread(buffer, 1, len, fd);
    fclose(fd);

    return res;
}


int32_t FilesystemDB::write_file(const void * buffer, uint16_t handle, uint32_t offset, uint16_t len) {
    int32_t res;
    FILE * fd;
    const auto & fname = items[handle].path;
    if (fname.empty()) {
        throw std::runtime_error(std::format("Handle {} not found", handle));
    }

    // len 0 means "truncate" or "extend"
    if (len == 0) {
        dbg_print("truncate \"{}\" to {} bytes\n", fname.native(), offset);
        if (truncate(fname.c_str(), offset) != 0) {
            throw std::runtime_error(std::format("Cannot truncate file: {}", strerror(errno)));
        }
        return 0;
    }

    //  write to file
    dbg_print("write {} bytes into file \"{}\" at offset {}\n", len, fname.native(), offset);
    fd = fopen(fname.c_str(), "r+b");
    if (!fd) {
        throw std::runtime_error(std::format("Cannot open file: {}", strerror(errno)));
    }
    if (fseek(fd, offset, SEEK_SET) != 0) {
        auto orig_errno = errno;
        fclose(fd);
        throw std::runtime_error(std::format("Cannot seek in file: {}", strerror(orig_errno)));
    }
    res = fwrite(buffer, 1, len, fd);
    fclose(fd);

    return res;
}


int32_t FilesystemDB::get_file_size(uint16_t handle) {
    if (items[handle].path.empty()) {
        return -1;
    }
    DosFileProperties fprops;
    if (get_path_dos_properties(items[handle].path, &fprops, 0) == FAT_ERROR_ATTR) {
        return -1;
    }
    return fprops.size;
}


bool FilesystemDB::find_file(
    DosFileProperties & properties,
    uint16_t handle,
    const fcb_file_name & tmpl,
    unsigned char attr,
    uint16_t & nth,
    bool is_root_dir,
    bool use_fat_ioctl) {
    // recompute the dir listing if operation is FIND_FIRST (nth == 0) or if no cache found
    if ((nth == 0) || (items[handle].directory_list.empty())) {
        long count = items[handle].create_directory_list(use_fat_ioctl);
        if (count < 0) {
            err_print("ERROR: Failed to scan dir \"{}\"\n", items[handle].path.native());
            return false;
#ifdef DEBUG
        } else {
            dbg_print("Scanned dir \"{}\", found {} items\n", items[handle].path.native(), count);
            for (const auto & item : items[handle].directory_list) {
                dbg_print(
                    "  \"{:>11}\", attr 0x{:02X}, {} bytes\n",
                    reinterpret_cast<const char *>(&item.fcb_name),
                    item.attrs,
                    item.size);
            }
#endif
        }
    }

    DosFileProperties * found_props{nullptr};
    uint16_t n = 0;
    for (auto & item_props : items[handle].directory_list) {
        // forward to where we need to start listing
        if (++n <= nth) {
            continue;
        }

        // skip '.' and '..' items if directory is root
        if (is_root_dir && item_props.fcb_name.name_blank_padded[0] == '.')
            continue;
        if (!match_fcb_name_to_mask(tmpl, item_props.fcb_name))
            continue;

        if (attr == FAT_VOLUME) {
            // look only for VOLUME -> skip if not VOLUME
            if ((item_props.attrs & FAT_VOLUME) == 0) {
                continue;
            }
        } else {
            // return only file with at most the specified combination of hidden, system, and directory attributes
            if ((attr | (item_props.attrs & (FAT_HIDDEN | FAT_SYSTEM | FAT_DIRECTORY))) != attr)
                continue;
        }

        found_props = &item_props;
        break;
    }

    if (found_props) {
        nth = n;
        properties = *found_props;
        return true;
    }

    return false;
}


int32_t FilesystemDB::Item::create_directory_list(bool use_fat_ioctl) {
    directory_list.clear();
    DIR * dp = opendir(path.c_str());
    if (!dp) {
        return -1;
    }
    while (true) {
        auto const * const dir_ent = readdir(dp);
        if (!dir_ent) {
            break;
        }
        auto fullpath = path / dir_ent->d_name;
        DosFileProperties fprops;
        get_path_dos_properties(fullpath, &fprops, use_fat_ioctl);
        directory_list.emplace_back(fprops);
    }
    closedir(dp);
    return directory_list.size();
}


fcb_file_name filename_to_fcb(const char * filename) noexcept {
    fcb_file_name fcb_name;
    unsigned int i;

    // initialize with spaces
    std::fill(std::begin(fcb_name.name_blank_padded), std::end(fcb_name.name_blank_padded), ' ');
    std::fill(std::begin(fcb_name.ext_blank_padded), std::end(fcb_name.ext_blank_padded), ' ');

    // copy initial '.'
    for (i = 0; i < sizeof(fcb_name.name_blank_padded) && filename[i] == '.'; ++i) {
        fcb_name.name_blank_padded[i] = '.';
    }

    // fill in the filename, up to 8 chars or first dot
    for (; i < sizeof(fcb_name.name_blank_padded) && filename[i] != '.' && filename[i] != '\0'; ++i) {
        fcb_name.name_blank_padded[i] = ascii_to_upper(filename[i]);
    }
    filename += i;

    // move to dot
    while (*filename != '.' && *filename != '\0') {
        ++filename;
    }

    if (*filename == '\0') {
        return fcb_name;
    }

    ++filename;  // skip the dot

    // fill in the extension
    for (i = 0; i < sizeof(fcb_name.ext_blank_padded) && filename[i] != '.' && filename[i] != '\0'; ++i) {
        fcb_name.ext_blank_padded[i] = ascii_to_upper(filename[i]);
    }

    return fcb_name;
}


uint8_t get_path_dos_properties(
    const std::filesystem::path & path, DosFileProperties * properties, bool use_fat_ioctl) {
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) != 0) {
        return FAT_ERROR_ATTR;  // error (probably doesn't exist)
    }

    if (properties) {
        // set file fcbname to the file part of path (ignore traling directory separators)
        auto it = path.end();
        while (it != path.begin() && (--it)->empty()) {
        }
        properties->fcb_name = filename_to_fcb(it->c_str());

        properties->time_date = time_to_fat(statbuf.st_mtime);
    }

    if (S_ISDIR(statbuf.st_mode)) {
        if (properties) {
            properties->size = 0;
            properties->attrs = FAT_DIRECTORY;
        }
        return FAT_DIRECTORY;
    }

    // not a directory, set size
    if (properties) {
        properties->size = statbuf.st_size;
    }

    // if not a FAT drive, return a fake attribute archive
    if (!use_fat_ioctl) {
        if (properties) {
            properties->attrs = FAT_ARCHIVE;
        }
        return FAT_ARCHIVE;
    }

    uint32_t attr;
#ifdef __FreeBSD__
    {
        /* map FreeBSD to Linux */
        attr = 0;
        if (statbuf.st_flags & UF_READONLY)
            attr |= 1;  /* ATTR_RO */
        if (statbuf.st_flags & UF_HIDDEN)
            attr |= 2;  /* ATTR_HIDDEN */
        if (statbuf.st_flags & UF_SYSTEM)
            attr |= 4;  /* ATTR_SYS */
        if (statbuf.st_flags & UF_ARCHIVE)
            attr |= 32; /* ATTR_ARCH */
#else
    /* try to fetch DOS attributes by calling the FAT IOCTL API */
    auto fd = open(i, O_RDONLY);
    if (fd == -1) {
        return FAT_ERROR_ATTR;
    }
    if (ioctl(fd, FAT_IOCTL_GET_ATTRIBUTES, &attr) < 0) {
        err_print("Failed to fetch attributes of \"{}\"\n", path.native());
        close(fd);
        return 0;
    } else {
        close(fd);
#endif
        if (properties) {
            properties->attrs = attr;
        }
        return attr;
    }
}


void set_item_attrs(const std::filesystem::path & path, uint8_t attrs) {
    int res;
#ifdef __FreeBSD__
    /* map Linux to FreeBSD */
    unsigned long flags = 0;
    if (attrs & 1)  /* ATTR_RO */
        flags |= UF_READONLY;
    if (attrs & 2)  /* ATTR_HIDDEN */
        flags |= UF_HIDDEN;
    if (attrs & 4)  /* ATTR_SYS */
        flags |= UF_SYSTEM;
    if (attrs & 32) /* ATTR_ARCH */
        flags |= UF_ARCHIVE;
    res = chflags(path.c_str(), flags);
    auto orig_errno = errno;
#else
    int fd;
    fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error(std::format("Cannot open file: {}", strerror(errno)));
    }
    res = ioctl(fd, FAT_IOCTL_SET_ATTRIBUTES, &attrs);
    auto orig_errno = errno;
    close(fd);
#endif
    if (res < 0) {
        throw std::runtime_error(std::format("Cannot set file attributes: {}", strerror(orig_errno)));
    }
}


bool make_dir(const std::filesystem::path & dir) noexcept { return mkdir(dir.c_str(), 0) == 0; }


bool delete_dir(const std::filesystem::path & dir) noexcept { return rmdir(dir.c_str()) == 0; }


bool change_dir(const std::filesystem::path & d) noexcept { return chdir(d.c_str()) == 0; }


DosFileProperties create_or_truncate_file(const std::filesystem::path & path, uint8_t attrs, bool use_fat_ioctl) {
    // try to create/truncate the file
    FILE * const fd = fopen(path.c_str(), "wb");
    if (!fd) {
        throw std::runtime_error(std::format("Cannot open file: {}", strerror(errno)));
    }
    fclose(fd);

    // set FAT attributes
    if (use_fat_ioctl) {
        try {
            set_item_attrs(path, attrs);
        } catch (const std::runtime_error & ex) {
            err_print("Error: Failed to set attribute 0x{:02X} to \"{}\": {}\n", attrs, path.native(), ex.what());
        }
    }

    DosFileProperties properties;
    get_path_dos_properties(path, &properties, use_fat_ioctl);
    return properties;
}


int delete_files(const std::filesystem::path & pattern) {
    // test if pattern contains '?' characters
    bool is_pattern = false;
    const std::string & pattern_string = pattern.native();
    for (auto ch : pattern_string) {
        if (ch == '?') {
            is_pattern = true;
            break;
        }
    }

    // if regular file, delete it right away
    if (!is_pattern) {
        if (unlink(pattern.c_str()) != 0) {
            err_print("Error: failure to delete file \"{}\": {}\n", pattern.native(), strerror(errno));
            return -1;
        }
        return 1;
    }

    // if pattern, get directory and file parts and iterate over all directory
    const std::filesystem::path directory = pattern.parent_path();
    const std::string filemask = pattern.filename();

    const auto filfcb = filename_to_fcb(filemask.c_str());
    // iterate over the directory and delete whatever is matching the pattern
    DIR * const dp = opendir(directory.c_str());
    if (!dp) {
        return -1;
    }
    while (true) {
        auto const * const dir_ent = readdir(dp);
        if (!dir_ent)
            break;
        // skip directories
        if (dir_ent->d_type == DT_DIR)
            continue;
        // if match, delete the file and continue
        auto dirnamefcb = filename_to_fcb(dir_ent->d_name);
        if (match_fcb_name_to_mask(filfcb, dirnamefcb)) {
            auto fname = directory / dir_ent->d_name;
            if (unlink(fname.c_str()) == -1)
                err_print("ERROR: Failed to delete file \"{}\": {}\n", fname.native(), strerror(errno));
        }
    }
    closedir(dp);

    return 0;
}


bool rename_file(const std::filesystem::path & old_name, const std::filesystem::path & new_name) noexcept {
    return rename(old_name.c_str(), new_name.c_str()) == 0;
}


std::pair<uint64_t, uint64_t> fs_space_info(const std::filesystem::path & path) {
    struct statvfs buf;
    if (statvfs(path.c_str(), &buf) != 0) {
        return {0, 0};
    }
    uint64_t size = buf.f_blocks;
    size *= buf.f_frsize;
    uint64_t free = buf.f_bfree;
    free *= buf.f_bsize;
    return {size, free};
}


bool is_on_fat(const std::filesystem::path & path) {
#ifdef __FreeBSD__
    struct statfs buf;
    if (statfs(path.c_str(), &buf) < 0) {
        return false;
    }
    if (strcmp(buf.f_fstypename, "msdosfs"))
        return false;
    return true;
#else
    auto fd = open(path.c_str(), O_RDONLY);
    if (fd == -1)
        return false;
    uint32_t volid;
    // try to get FAT volume id
    if (ioctl(fd, FAT_IOCTL_GET_VOLUME_ID, &volid) < 0) {
        close(fd);
        return false;
    }
    close(fd);
    return true;
#endif
}

}  // namespace netmount_srv
