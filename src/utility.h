#pragma once

// POSIX
#include <sys/acl.h>
#include <sys/capability.h>
#include <sys/stat.h>

// libacl
#include <acl/libacl.h>

// third party
#include <tclap/CmdLine.h>

// C++
#include <cctype>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

/// `isspace()` has overloads which gives trouble with template argument deduction, therefore provide a wrapper.
inline bool chkspace(char c) { return std::isspace(c); }

inline bool chkslash(char c) { return c == '/'; }

/// Remove certain leading characters from the given string (by default whitespace characters).
template <typename UNARY = bool(char)>
inline void lstrip(std::string &s, UNARY f = chkspace) {
    auto nonmatch_it = s.end();

    for (auto it = s.begin(); it != s.end(); it++) {
        if (!f(*it)) {
            nonmatch_it = it;
            break;
        }
    }

    s = s.substr(static_cast<size_t>(nonmatch_it - s.begin()));
}

/// Remove certain trailing characters from the given string (by default: whitespace characters).
template <typename UNARY = bool(char)>
inline void rstrip(std::string &s, UNARY f = chkspace) {
    while (!s.empty() && f(*s.rbegin()))
        s.pop_back();
}

/// Remove certain leading and trailing characters from the given string (by default: whitespace characters).
template <typename UNARY = bool(char)>
void strip(std::string &s, UNARY f = chkspace) {
    lstrip(s, f);
    rstrip(s, f);
}

template <typename UNARY = bool(char)>
std::string stripped(std::string s, UNARY f = chkspace) {
    strip(s, f);
    return s;
}

inline void stripTrailingSlashes(std::string &s) {
    rstrip(s, [](char c) { return c == '/'; });
}

/// Checks whether the given string has the given prefix.
inline bool hasPrefix(const std::string &s, const std::string &prefix) {
    return s.substr(0, prefix.length()) == prefix;
}

/// Checks whether the given string has the given suffix.
inline bool hasSuffix(const std::string_view &s, const std::string &suffix) {
    if (suffix.length() > s.length())
        return false;

    return s.substr(s.length() - suffix.length()) == suffix;
}

/// Returns whether the given iterable sequence contains the given element `val`.
template <typename T, typename SEQ>
bool matchesAny(const T &val, const SEQ &seq) {
    for (const auto &e: seq) {
        if (val == e)
            return true;
    }

    return false;
}

/// Splits up the `input` string into whitespace separated words and stores them in `words`.
void splitWords(const std::string &input, std::vector<std::string> &words);

template <typename T>
bool stringToUnsigned(const std::string &s, T &out, const int base = 10) {
    char *end = nullptr;
    out = static_cast<T>(std::strtoul(s.c_str(), &end, base));
    if (end && *end != '\0') {
        return false;
    }

    return true;
}

/// Helper class that wraps a plain POSIX file descriptor.
/**
 * This wrapper takes care of closing the file descriptor upon destruction
 * time.
 **/
class FileDesc {
public:

    explicit FileDesc(int fd = -1) :
            m_fd{fd} {
    }

    FileDesc(FileDesc &&other) :
            FileDesc{} {
        // steal the rvalue's file descriptor so we take over ownership, while
        // the other doesn't close it during destruction. This allows to keep
        // this non-copyable type in containers.
        steal(other);
    }

    ~FileDesc() {
        if (valid()) {
            close();
        }
    }

    FileDesc(const FileDesc &other) = delete;
    FileDesc& operator=(const FileDesc &other) = delete;

    int get() const { return m_fd; }

    void set(int fd) {
        if (valid()) {
            close();
        }

        m_fd = fd;
    }

    void steal(FileDesc &other) {
        set(other.get());
        other.invalidate();
    }

    bool valid() const { return m_fd != -1; }
    bool invalid() const { return !valid(); }
    void invalidate() { m_fd = -1; }

    /// Explicitly close and invalidate() the currently stored file descriptor.
    void close();

    /// Resolves the file system path of the file descriptor via /proc/self/fd - for display purposes.
    std::string path() const;

protected:

    int m_fd = -1;
};

/// C++ wrapper around the POSIX struct stat.
class FileStatus :
        public ::stat {
public:

    FileStatus() :
            // zero initialize the `struct stat` using aggregate initialization of the base class
            stat{} {
    }

    FileStatus(const FileStatus &other) {
        *this = other;
    }

    FileStatus& operator=(const FileStatus &other) {
        *static_cast<struct stat*>(this) = other;
        return *this;
    }

    bool isLink() const { return S_ISLNK(this->st_mode); }
    bool isRegular() const { return S_ISREG(this->st_mode); }
    bool isDirectory() const { return S_ISDIR(this->st_mode); }

    /// Returns the file mode bits only.
    /**
     * This includes the permission bits any special bits like setXid but not
     * the file type bits
     **/
    auto getModeBits() const { return this->st_mode & ALLPERMS; }

    bool matchesOwnership(const uid_t uid, const gid_t gid) const {
        return this->st_uid == uid && this->st_gid == gid;
    }

    bool hasNonRootOwner() const {
        return this->st_uid != 0;
    }

    bool hasRootOwner() const {
        return !hasNonRootOwner();
    }

    bool hasNonRootGroup() const {
        return this->st_gid != 0;
    }

    bool hasRootGroup() const {
        return !hasNonRootGroup();
    }

    bool hasSafeOwner(const std::initializer_list<uid_t> &safe_uids) const {
        if (hasRootOwner())
           return true;

        for (const auto &uid: safe_uids) {
            if (matchesOwner(uid))
                return true;
        }

        return false;
    }

    bool hasSafeGroup(const std::initializer_list<gid_t> &safe_gids) const {
        if (!isGroupWritable() || hasRootGroup())
           return true;

        for (const auto &gid: safe_gids) {
            if (matchesGroup(gid))
                return true;
        }

        return false;
    }

    bool matchesOwner(uid_t user) const {
        return this->st_uid == user;
    }

    bool matchesGroup(gid_t group) const {
        return this->st_gid == group;
    }

    /// Checks whether both stat objects refer to the file object.
    /**
     * This compares device and inode identification to determine whether the
     * status refers to the same file system object.
     **/
    bool sameObject(const struct ::stat &other) const {
        return this->st_dev == other.st_dev && this->st_ino == other.st_ino;
    }

    bool isWorldWritable() const {
        return (this->st_mode & S_IWOTH) != 0;
    }

    bool isGroupWritable() const {
        return (this->st_mode & S_IWGRP) != 0;
    }

    bool fstat(const FileDesc &fd) {
        return ::fstat(fd.get(), this) == 0;
    }
};

/// A wrapper around the native `cap_t` type to ease memory management.
class FileCapabilities {
public:

    FileCapabilities();

    FileCapabilities(FileCapabilities &&other) :
            FileCapabilities{} {
        *this = std::move(other);
    }

    FileCapabilities(const FileCapabilities &other) = delete;
    FileCapabilities& operator=(const FileCapabilities &other) = delete;

    FileCapabilities& operator=(FileCapabilities &&other) {
        // steal the rvalue's caps so we take over ownership, while
        // the other doesn't free them during destruction. This allows to keep
        // this non-copyable type in containers.
        m_caps = std::move(other.m_caps);
        return *this;
    }

    bool operator==(const FileCapabilities &other) const;
    bool operator!=(const FileCapabilities &other) const {
        return !(*this == other);
    }

    bool hasCaps() const { return static_cast<bool>(m_caps); }

    cap_t raw() { return m_caps.get(); }

    /// Set new capability data from a textual representation.
    /**
     *  If the operation fails then `false` is returned.
     **/
    bool setFromText(const std::string &text);

    /// Set new capability data from the given file path.
    /**
     *  If the operation fails then `false` is returned. Even if it succeeds
     *  `valid()` can still return `false` if no capabilities are set on the
     *  file (empty data).
     **/
    bool setFromFile(const std::string &path);

    /// Applies the currently stored capability data to the given file descriptors.
    bool applyToFD(int fd) const;

    /// Returns a human readable string describing the current capability data.
    /**
     *  \return The human readable string on success, an empty string on error.
     **/
    std::string toText() const;

    /// Returns a human readable error text for the last error during setFromFile().
    std::string lastErrorText() const;

protected: // types

    // cap_t is a typedef'd pointer type, unique_ptr expects the value type; this is it.
    using CapT = std::remove_pointer<cap_t>::type;

protected: // data

    std::unique_ptr<CapT, int (*)(void*)> m_caps;
    int m_last_errno = 0;
};

/// A wrapper around the `acl_t` type from the libacl library which deals with the POSIX access control list extension.
/**
 * ACLs allow to assign access rights to files that go beyond the basic UNIX
 * user/group/world scheme.
 *
 * An ACL always needs to contain entries matching the basic user/group/world
 * model. If no entries beyond these exist, then it is a basic ACL and the
 * file is treated with traditional UNIX semantics. If further entries exist,
 * then the ACL is called "extended" and the extra access rights are
 * considered by the kernel.
 *
 * An extended ACL needs to adhere to a number of rules like:
 *
 * - the basic entries for user/group/world must exist.
 * - a MASK entry must exist.
 * - no duplicate entries must exist.
 *
 * The mask entry defines the maximum access rights anybody can ever have.
 * Even if an entry grants user X rwx access, a mask of rw- would deny
 * execution rights. For extended ACLs the mask permissions replace the group
 * permission bits returned by `stat()`. This can be confusing, since the
 * actual file group permissions might be different to the mask. The reason
 * for this approach lies in certain file handling patterns found in
 * applications that are unaware of ACLs. For example, applications expect
 * that, when they perform a `chmod(..., 000)` on a file, that nobody will be
 * able to access it anymore. That would no longer hold true in the presence
 * of extended ACL entries. Therefore, since the group bits now refer to the
 * mask entry, the chmod will reduce the mask to zero, denying access also for
 * any existing ACL entries.
 *
 * This class allows basic operations involving ACLs so far as is necessary to
 * implement ACL support in permctl. The actual permissions found in ACLs can
 * largely be treated opaque by permctl, since it only needs to find out
 * differences and apply changes. Most of the complexity comes with the
 * construction of valid ACLs and changes in semantics when ACLs are
 * present/needed on a file.
 *
 * \note There also exist so called default ACLs that can be assigned to
 * directories. They govern the initial access ACL for newly created objects
 * in the directory (similar to setgid/setuid bits on directories).
 * Supporting default ACLs might also be interesting for permctl at some
 * point, but at the moment we limit ourselves to regular access ACLs.
 **/
class FileAcl {
public:
    /// Creates an invalid ACL.
    FileAcl() = default;

    /// Creates an ACL corresponding to the given mode.
    FileAcl(mode_t mode);

    FileAcl(const FileAcl &other) = delete;
    FileAcl& operator=(const FileAcl &other) = delete;

    FileAcl(FileAcl &&other) {
        *this = std::move(other);
    }

    ~FileAcl();

    /// This parses the ACL from a short or long format ACL string.
    /**
     * See `man 5 acl` for the format description. We only use the short
     * format currently, since it fits into a single +extra line.
     *
     * Error conditions are either syntax errors, out of memory or an invalid
     * user / group name. Syntax error and bad user / group cannot be
     * distinguished, both will set errno to EINVAL.
     **/
    bool setFromText(const std::string &text);

    /// This reads the access ACL assigned to the given file.
    /**
     * If the file has not extended ACL then this still succeeds and a basic
     * ACL will be stored in the object, that matches the basic
     * user/group/world permissions. Error conditions are EBADF, ENOMEM and
     * ENOTSUP (if the underlying file system or kernel do not support ACLs at
     * all).
     **/
    bool setFromFile(const std::string &path);

    /// Assigns the currently stored ACL to the given file path.
    /**
     * This can fail for reasons like permission denied, out of space, a
     * read-only file system or lack of ACL support on file system or kernel
     * level.
     **/
    bool applyToFile(const std::string &path) const;

    /// Adds the basic ACL entries that correspond to the given mode.
    /**
     * This call is only allowed if valid() returns `true`, i.e. an ACL must
     * already be allocated.
     *
     * Beyond the extended ACL entries, ACLs also always need to reflect the
     * classical user/group/world permissions. Applying an ACL that doesn't
     * contain these basic entries will fail on kernel level. This means that
     * applying an ACL will always also set the basic mode of the file as is
     * done with `chmod()`, it makes the use of `chmod()` obsolete.
     *
     * This call will *not* replace existing basic entries, but would create
     * duplicate entries in that case, resulting in an invalid ACL.
     **/
    bool setBasicEntries(mode_t mode);

    /// Calculates and adds an entry of type ACL_MASK, if necessary.
    /**
     * If an ACL contains extended entries for user or groups, then an entry
     * of type ACL_MASK is also obligatory. If it doesn't exist already, then
     * it will be automatically calculated by this function, by forming the
     * union of all the extended permissions found in the current ACL and of
     * the basic file group permissions.
     **/
    bool tryCalcMask();

    /// This returns a single line representing the ACLs entries in human readable form.
    /**
     * The returned string will be optimized for readability and won't conform
     * to the ACL library's syntax requirements, i.e. this string cannot be
     * processed again by setFromText().
     **/
    std::string toText() const;

    /// Performs check of the current ACL entries for consistency.
    /**
     * Check the class description for some of the rules that are checked
     * here.
     **/
    bool verify() const;

    /// Returns whether an ACL data structure is allocated in the object.
    bool valid() const { return m_acl != nullptr; }

    /// This checks whether the current ACL data only contains user/group/world base modes.
    /**
     * When obtaining an ACL via setFromFile(), then entries will be returned
     * even if no extended ACL entries exist. These entries represent the
     * traditional user/group/world permissions of the file in ACL form.
     *
     * Use this function to determine whether an ACL only contains such entries.
     **/
    bool isBasicACL() const;

    bool isExtendedACL() const { return !isBasicACL(); };

    FileAcl& operator=(FileAcl &&other) {
        // steal the rvalue's list so we take over ownership, while
        // the other doesn't free them during destruction. This allows to keep
        // this non-copyable type in containers.
        m_acl = other.m_acl;
        other.m_acl = nullptr;
        return *this;
    }

    /// Returns whether the ACL objects are logically equal.
    /**
     * Two invalid FileAcl objects are considered equal. Otherwise two valid
     * FileAcl objects are equal, if for each ACL entry in this object an
     * equal entry exists in the other object.
     **/
    bool operator==(const FileAcl &other) const;

    bool operator!=(const FileAcl &other) const {
        return !(*this == other);
    }

protected: // functions

    /// Frees any memory, if necessary, rendering the object `!valid()`.
    void free();

    acl_t raw() { return m_acl; }

protected: // data

    acl_t m_acl = nullptr;
};

// vim: et ts=4 sts=4 sw=4 :
