#ifndef CHKSTAT_UTILITY_H
#define CHKSTAT_UTILITY_H

// POSIX
#include <sys/stat.h>
#include <sys/capability.h>

// third party
#include <tclap/CmdLine.h>

// C++
#include <cctype>
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

//! remove leading characters characters from the given string, by default
//! whitespace characters
template <typename UNARY = bool(char)>
inline std::string& lstrip(std::string &s, UNARY f = chkspace)
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

    return s;
}

//! remove trailing characters from the given string, by default
//! whitespace characters
template <typename UNARY = bool(char)>
inline std::string& rstrip(std::string &s, UNARY f = chkspace)
{
    while( !s.empty() && f(*s.rbegin()) )
        s.pop_back();
    return s;
}

//! remove leading and trailing characters from the given string, by
//! default whitespace characters
template <typename UNARY = bool(char)>
std::string& strip(std::string &s, UNARY f = chkspace)
{
    lstrip(s, f);
    return rstrip(s, f);
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

//! performs a file existence test for the given path
bool existsFile(const std::string &path);

template <typename T1, typename T2>
void appendContainer(T1 &container, const T2 &sequence)
{
    container.insert(container.end(), sequence.begin(), sequence.end());
}

//! splits up the \c input string into whitespace separated words and stores
//! them in \c words
void splitWords(const std::string &input, std::vector<std::string> &words);

//! a helper class that wraps a plain POSIX file descriptor and makes sure it
//! gets closed at descruction/assignment time
class FileDescGuard
{
public:

    explicit FileDescGuard(int fd = -1) :
        m_fd(fd)
    {}

    FileDescGuard(FileDescGuard &&other)
    {
        // steal the rvalue's file descriptor so we take over ownership, while
        // the other doesn't close it during destruction.
        m_fd = other.get();
        other.invalidate();
    }
    FileDescGuard(const FileDescGuard &other) = delete;
    FileDescGuard& operator=(const FileDescGuard &other) = delete;

    ~FileDescGuard()
    {
        if (valid())
        {
            close();
        }
    }

    int get() { return m_fd; }

    void set(int fd)
    {
        if (valid())
        {
            close();
        }

        m_fd = fd;
    }

    bool valid() const { return m_fd != -1; }
    void invalidate() { m_fd = -1; }

    void close();

protected:

    int m_fd = -1;
};

//! C++ wrapper around the POSIX struct stat
class FileStatus :
    public ::stat
{
public:

    bool isLink() const { return S_ISLNK(this->st_mode); }
    bool isRegular() const { return S_ISREG(this->st_mode); }
    bool isDirectory() const { return S_ISDIR(this->st_mode); }

    //! returns the file mode bits portion consisting of the permission bits
    //! plus any special bits like setXid but not the file type bits
    auto getModeBits() const { return this->st_mode & 07777; }

    bool matchesOwnership(const uid_t uid, const gid_t gid) const
    {
        return this->st_uid == uid && this->st_gid == gid;
    }

protected:
};

//! a wrapper around the native cap_t type to ease memory management
class FileCapabilities
{
public:

    ~FileCapabilities();

    explicit FileCapabilities() {}

    FileCapabilities(FileCapabilities &&other)
    {
        // steal the rvalue's caps so we take over ownership, while
        // the other doesn't free them during destruction.
        m_caps = other.m_caps;
        other.invalidate();
    }
    FileCapabilities(const FileCapabilities &other) = delete;
    FileCapabilities& operator=(const FileCapabilities &other) = delete;

    bool operator==(const FileCapabilities &other) const;

    bool valid() const { return m_caps != nullptr; }
    void invalidate() { m_caps = nullptr; }

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
    bool applyToFD(int fd);

    /**
     * \brief
     *  Returns a human readable string describing the current capability data
     * \return
     *  The human readable string on success, an empty string on error.
     **/
    std::string toText() const;

protected:

     cap_t m_caps = nullptr;
};

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
