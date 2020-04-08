#ifndef CHKSTAT_FORMATTING_H
#define CHKSTAT_FORMATTING_H

// local headers
#include "utility.h"

// C++
#include <iosfwd>

enum class NumberBase
{
    OCT,
    DEC,
    HEX
};

//! just a type for wrapping integers for outputting them easily in a
//! formatted manner on std::ostream
class FormattedInt
{
public:

    /**
     * \param[in] val
     *  The actual integer value to output as octal
     * \param[in] width
     *  Minimum field width the number string will be padded to
     **/
    explicit FormattedInt(size_t val) :
        m_val(val)
    {}

    size_t getVal() const { return m_val; }
    size_t getWidth() const { return m_width; }
    char getFill() const { return m_fill; }
    NumberBase getBase() const { return m_base; }

    FormattedInt& setFill(const char c) { m_fill = c; return *this; }
    FormattedInt& setWidth(const size_t w) { m_width = w; return *this; }
    FormattedInt& setBase(const NumberBase &b) { m_base = b; return *this; }

    void applyBase(std::ostream &o) const;

protected:

    size_t m_val = 0;
    size_t m_width = 0;
    char m_fill = '0';
    NumberBase m_base = NumberBase::DEC;
};

//! helper type to output a file mode as octal nicely formatted onto an ostream
class FileModeInt :
    public FormattedInt
{
public:
    explicit FileModeInt(size_t val) :
        FormattedInt(val)
    {
        setBase(NumberBase::OCT);
        setWidth(4);
    }
};

std::ostream& operator<<(std::ostream &o, const FormattedInt &fi);

//! just a helper type for outputting file ownership on a stream
class FileOwnership
{
public:
    FileOwnership(uid_t uid, gid_t gid) :
        m_uid(uid), m_gid(gid)
    {}

    explicit FileOwnership(const FileStatus &fs) :
        m_uid(fs.st_uid), m_gid(fs.st_gid)
    {}

    uid_t getUid() const { return m_uid; }
    gid_t getGid() const { return m_gid; }

protected:

    uid_t m_uid = (uid_t)-1;
    gid_t m_gid = (gid_t)-1;
};

std::ostream& operator<<(std::ostream &o, const FileOwnership &fo);

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
