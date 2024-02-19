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

/// Scratch data used while processing an individual ProfileEntry in processEntries().
struct EntryContext {
    /// The resolved user-id corresponding to the active ProfileEntry.
    uid_t uid = (uid_t)-1;
    /// The resolved group-id corresponding to the active ProfileEntry.
    gid_t gid = (gid_t)-1;
    /// The path of the current file to check below a potential m_args.root_path.
    std::string subpath;
    /// A path for safely opening the target file (typically in /proc/self/fd/...).
    std::string fd_path;
    /// The actual capabilities found on on the file.
    FileCapabilities caps;
    /// The actual file status info found on the file.
    FileStatus status;
    /// Indicates whether actual file permissions need to be fixed.
    bool need_fix_perms = false;
    /// Indicates whether actual file capabilities need to be fixed.
    bool need_fix_caps = false;
    /// Indicates whether actual file user:group ownership needs to be fixed.
    bool need_fix_ownership = false;
    /// An insecure ownership constellation was detected in the file's path.
    bool traversed_insecure = false;
    /// An `O_PATH` file descriptor for the target file which is set in safeOpen().
    FileDesc fd;

    /// based on the given `entry` sets `need_fix_*` members as required.
    void check(const ProfileEntry &entry) {
        need_fix_perms = status.getModeBits() != entry.mode;
        need_fix_ownership = !status.matchesOwnership(this->uid, this->gid);
        need_fix_caps = entry.caps != this->caps;
    }

    bool needsFixing() const {
        return need_fix_perms || need_fix_caps || need_fix_ownership;
    }

    bool fetchCapabilities() {
        return caps.setFromFile(fd_path);
    }

    bool needFixPerms() const { return need_fix_perms; }
    bool needFixCaps() const { return need_fix_caps; }
    bool needFixOwnership() const { return need_fix_ownership; }

    bool traversedInsecure() const { return traversed_insecure; }
};

/// enum to differentiate different /proc availability situations.
enum class ProcMountState {
    /// status was not investigated yet
    UNKNOWN,
    AVAIL,
    UNAVAIL,
};

// vim: et ts=4 sts=4 sw=4 :
