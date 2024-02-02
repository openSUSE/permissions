// Linux
#include <grp.h>
#include <pwd.h>

// local headers
#include "formatting.h"

// C++
#include <iomanip>
#include <ostream>

void FormattedInt::applyBase(std::ostream &o) const {
    switch(m_base) {
    default:
        break;
    case NumberBase::OCT:
        o << std::oct; return;
    case NumberBase::DEC:
        o << std::dec; return;
    case NumberBase::HEX:
        o << std::hex; return;
    }
}

std::ostream& operator<<(std::ostream &o, const FormattedInt &fi) {
    // NOTE: if a stream has exceptions enabled then this approach can throw
    // exceptions, because the stream has no rdbuf.
    //
    // but std::ostream::flags() does not contain all stream state e.g.
    // setfill() is not part of it.
    std::ios orig_state(nullptr);
    orig_state.copyfmt(o);

    fi.applyBase(o);
    const auto width = static_cast<int>(fi.getWidth());
    o << std::setw(width >= 0 ? width : 0) << std::setfill(fi.getFill()) << fi.getVal();

    o.copyfmt(orig_state);

    return o;
}

std::ostream& operator<<(std::ostream &o, const FileOwnership &fo) {
    const struct passwd *pwd = ::getpwuid(fo.getUid());
    const struct group *grp = ::getgrgid(fo.getGid());;

    if (pwd) {
        o << pwd->pw_name;
    } else {
        o << fo.getUid();
    }

    o << ":";

    if (grp) {
        o << grp->gr_name;
    } else {
        o << fo.getGid();
    }

    return o;
}

// vim: et ts=4 sts=4 sw=4 :
