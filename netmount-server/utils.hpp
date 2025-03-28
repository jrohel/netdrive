// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2025 Jaroslav Rohel, jaroslav.rohel@gmail.com

#ifndef _UTILS_HPP_
#define _UTILS_HPP_

#include <cstdio>
#include <format>

//#define DEBUG

// Enables packet loss simulation (for tests)
//#define SIMULATE_PACKET_LOSS

// The C++23 language provides `std::print`.
// We define a `print` macro with a similar function for C++20.
#define print(stream, fmt, ...)                                                  \
    {                                                                            \
        std::fputs(std::format(fmt __VA_OPT__(, ) __VA_ARGS__).c_str(), stream); \
    }

#define err_print(fmt, ...)                                                      \
    {                                                                            \
        std::fputs(std::format(fmt __VA_OPT__(, ) __VA_ARGS__).c_str(), stderr); \
    }

#ifdef DEBUG
#define dbg_print(fmt, ...)                                                      \
    {                                                                            \
        std::fputs(std::format(fmt __VA_OPT__(, ) __VA_ARGS__).c_str(), stderr); \
    }
#else
#define dbg_print(fmt, ...)
#endif


inline char ascii_to_upper(char c) {
    if ((c >= 'a') && (c <= 'z')) {
        c -= 'a' - 'A';
    }
    return c;
}


inline char ascii_to_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        c += 'a' - 'A';
    }
    return c;
}

#endif
