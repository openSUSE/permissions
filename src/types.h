#pragma once

// local headers
#include "utility.h"

// POSIX / Linux
#include <sys/types.h>

// C++
#include <string>

/// Represents a single permissions profile entry.
struct ProfileEntry {
    std::string file;
    std::string owner;
    std::string group;
    mutable mode_t mode = 0;
    FileCapabilities caps;

    ProfileEntry() = default;

    ProfileEntry(const std::string &p_file, const std::string &p_owner, const std::string &p_group, mode_t p_mode) :
            file(p_file), owner(p_owner), group(p_group), mode(p_mode) {}

    bool hasCaps() const { return caps.hasCaps(); }

    /// Returns whether this profile entry contains a setuid or setgid bit.
    bool hasSetXID() const {
        return (this->mode & (S_ISUID | S_ISGID)) != 0;
    }

    // NOTE: this is currently mutable due to the somewhat unfortunate logic in EntryProcessor::getCapabilities().
    void dropXID() const {
        const mode_t to_drop = (S_ISUID | S_ISGID);
        mode &= ~(to_drop);
    }
};

/// enum to differentiate different /proc availability situations.
enum class ProcMountState {
    /// status was not investigated yet
    UNKNOWN,
    AVAIL,
    UNAVAIL,
};

// vim: et ts=4 sts=4 sw=4 :
