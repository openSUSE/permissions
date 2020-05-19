#ifndef CHKSTAT_UTILITY_H
#define CHKSTAT_UTILITY_H

// POSIX
#include <sys/capability.h>
#include <sys/stat.h>

// third party
#include <tclap/CmdLine.h>

// C++
#include <cctype>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

/**
 * \brief
 *     SwitchArg that can be programmatically set
 * \details
 *     TCLAP::SwitchArg doesn't offer a public API to programmatically change
 *     the switch's value. Therefore this specializations provides an
 *     additional method to make this possible.
 **/
class SwitchArgRW :
    public TCLAP::SwitchArg
{
public:
    SwitchArgRW(
        const std::string &flag,
        const std::string &name,
        const std::string &desc,
        TCLAP::CmdLineInterface &parser) :
        TCLAP::SwitchArg(flag, name, desc, parser)
    {}

    void setValue(bool val)
    {
        _value = val;
        // this is used for isSet(), _value only for getValue(), so
        // sync both.
        _alreadySet = val;
    }
};

// isspace has overloads which gives trouble with template argument deduction,
// therefore provide a wrapper
inline bool chkspace(char c) { return std::isspace(c); }

inline bool chkslash(char c) { return c == '/'; }

//! remove certain leading characters from the given string (by default
//! whitespace characters)
template <typename UNARY = bool(char)>
inline void lstrip(std::string &s, UNARY f = chkspace)
{
    auto nonmatch_it = s.end();

    for( auto it = s.begin(); it != s.end(); it++ )
    {
        if( !f(*it) )
        {
            nonmatch_it = it;
            break;
        }
    }

    s = s.substr(static_cast<size_t>(nonmatch_it - s.begin()));
}

//! remove certain trailing characters from the given string (by default
//! whitespace characters)
template <typename UNARY = bool(char)>
inline void rstrip(std::string &s, UNARY f = chkspace)
{
    while( !s.empty() && f(*s.rbegin()) )
        s.pop_back();
}

//! remove certain leading and trailing characters from the given string (by
//! default whitespace characters)
template <typename UNARY = bool(char)>
void strip(std::string &s, UNARY f = chkspace)
{
    lstrip(s, f);
    rstrip(s, f);
}

//! checks whether the given string has the given prefix
inline bool hasPrefix(const std::string &s, const std::string &prefix)
{
    return s.substr(0, prefix.length()) == prefix;
}

//! checks whether the given string has the given suffix
inline bool hasSuffix(const std::string_view &s, const std::string &suffix)
{
    if (suffix.length() > s.length())
        return false;

    return s.substr(s.length() - suffix.length()) == suffix;
}

//! returns whether the given iterable sequence contains the given element \c val
template <typename T, typename SEQ>
bool matchesAny(const T &val, const SEQ &seq)
{
    for (const auto &e: seq)
    {
        if (val == e)
            return true;
    }

    return false;
}

/**
 * \brief
 *  Performs a file existence test for the given path
 * \details
 *  This check only returns \c true if the given file or directory exists and
 *  the current process has read access permissions for it.
 **/
bool existsFile(const std::string &path);

template <typename T1, typename T2>
void appendContainer(T1 &container, const T2 &sequence)
{
    container.insert(container.end(), sequence.begin(), sequence.end());
}

//! splits up the \c input string into whitespace separated words and stores
//! them in \c words
void splitWords(const std::string &input, std::vector<std::string> &words);

template <typename T>
bool stringToUnsigned(const std::string &s, T &out, const int base = 10)
{
    char *end = nullptr;
    out = static_cast<T>(std::strtoul(s.c_str(), &end, base));
    if (end && *end != '\0')
    {
        return false;
    }

    return true;
}

/**
 * \brief
 *  Helper class that wraps a plain POSIX file descriptor
 * \details
 *  This wrapper takes care of closing the file descriptor upon destruction
 *  time.
 **/
class FileDesc
{
public:

    explicit FileDesc(int fd = -1) :
        m_fd(fd)
    {}

    FileDesc(FileDesc &&other) :
        FileDesc()
    {
        // steal the rvalue's file descriptor so we take over ownership, while
        // the other doesn't close it during destruction. This allows to keep
        // this non-copyable type in containers.
        steal(other);
    }

    ~FileDesc()
    {
        if (valid())
        {
            close();
        }
    }

    FileDesc(const FileDesc &other) = delete;
    FileDesc& operator=(const FileDesc &other) = delete;

    int get() const { return m_fd; }

    void set(int fd)
    {
        if (valid())
        {
            close();
        }

        m_fd = fd;
    }

    void steal(FileDesc &other)
    {
        set(other.get());
        other.invalidate();
    }

    bool valid() const { return m_fd != -1; }
    bool invalid() const { return !valid(); }
    void invalidate() { m_fd = -1; }

    //! explicitly close and invalidate() the currently stored file descriptor
    void close();

protected:

    int m_fd = -1;
};

//! C++ wrapper around the POSIX struct stat
class FileStatus :
    public ::stat
{
public:

    FileStatus() :
        // zero initialize the `struct stat` using aggregate initialization
        // of the base class
        ::stat{}
    {}

    FileStatus(const FileStatus &other)
    {
        *this = other;
    }

    FileStatus& operator=(const FileStatus &other)
    {
        *static_cast<struct stat*>(this) = other;
        return *this;
    }

    bool isLink() const { return S_ISLNK(this->st_mode); }
    bool isRegular() const { return S_ISREG(this->st_mode); }
    bool isDirectory() const { return S_ISDIR(this->st_mode); }

    //! returns the file mode bits portion consisting of the permission bits
    //! plus any special bits like setXid but not the file type bits
    auto getModeBits() const { return this->st_mode & ALLPERMS; }

    bool matchesOwnership(const uid_t uid, const gid_t gid) const
    {
        return this->st_uid == uid && this->st_gid == gid;
    }

    //! returns whether this file status and the other file status refer to
    //! the same file object (based on device and inode identification)
    bool sameObject(const struct ::stat &other) const
    {
        return this->st_dev == other.st_dev && this->st_ino == other.st_ino;
    }

    bool isWorldWritable() const
    {
        return (this->st_mode & S_IWOTH) != 0;
    }

    bool fstat(const FileDesc &fd)
    {
        return ::fstat(fd.get(), this) == 0;
    }
};

//! a wrapper around the native cap_t type to ease memory management
class FileCapabilities
{
public:

    explicit FileCapabilities() {}

    ~FileCapabilities();

    FileCapabilities(FileCapabilities &&other)
    {
        // steal the rvalue's caps so we take over ownership, while
        // the other doesn't free them during destruction. This allows to keep
        // this non-copyable type in containers.
        m_caps = other.m_caps;
        other.invalidate();
    }

    FileCapabilities(const FileCapabilities &other) = delete;
    FileCapabilities& operator=(const FileCapabilities &other) = delete;

    bool operator==(const FileCapabilities &other) const;
    bool operator!=(const FileCapabilities &other) const
    {
        return !(*this == other);
    }

    // TODO: the code currently inconsistently uses `valid()` for testing for
    // emptyness in a lot of spots. But `valid()` can mean both: no
    // capabilities existing or an other error occured. `errno` needs to be
    // inspected for this to correctly differentiate.
    // This class's API and the client code should be adjusted to make the
    // difference clear and the logic robust.
    bool valid() const { return m_caps != nullptr; }

    //! explicitly free and invalidate() the currently stored capabilities
    void destroy();

    cap_t raw() { return m_caps; }

    /**
     * \brief
     *  set new capability data from a textual representation
     * \details
     *  If the operation fails then after return valid() will return \c false.
     **/
    void setFromText(const std::string &text);

    /**
     * \brief
     *  set new capability data from the given file path
     * \details
     *  If the operation fails then after return valid() will return \c false.
     **/
    void setFromFile(const std::string &path);

    /**
     * \brief
     *  Applies the currently stored capability data to the given file
     *  descriptors
     **/
    bool applyToFD(int fd) const;

    /**
     * \brief
     *  Returns a human readable string describing the current capability data
     * \return
     *  The human readable string on success, an empty string on error.
     **/
    std::string toText() const;

protected: // functions

    void invalidate() { m_caps = nullptr; }

protected: // data

     cap_t m_caps = nullptr;
};

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
