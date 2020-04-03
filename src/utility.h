#ifndef CHKSTAT_UTILITY_H
#define CHKSTAT_UTILITY_H

// C++
#include <cctype>
#include <string>

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
inline bool hasPrefix(const std::string &s, const std::string prefix)
{
    return s.substr(0, prefix.length()) == prefix;
}

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
