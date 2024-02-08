// Linux
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// local headers
#include "utility.h"

// C++
#include <iostream>
#include <sstream>
#include <string>

void splitWords(const std::string &input, std::vector<std::string> &words) {
    std::stringstream ss;
    std::string word;

    words.clear();
    ss.str(input);

    // read whitespace separated words
    while (!ss.fail()) {
        ss >> word;

        if (!ss.fail()) {
            words.emplace_back(word);
        }
    }
}

void FileDesc::close() {
    if (!valid())
        return;

    if (::close(m_fd) != 0) {
        std::cerr << "Closing FD " << m_fd << ": " << strerror(errno) << std::endl;
    }

    invalidate();
}

FileCapabilities::~FileCapabilities() {
    destroy();
}

bool FileCapabilities::operator==(const FileCapabilities &other) const {
    if (!hasCaps() && !other.hasCaps())
        // if both lack capabilities then compare to true
        return true;

    if (hasCaps() != other.hasCaps())
        // if only one is lacking capabilities then compare to false
        return false;

    // otherwise ask the lib
    return cap_compare(m_caps, other.m_caps) == 0;
}

void FileCapabilities::destroy() {
    if (!hasCaps())
        return;

    if (cap_free(m_caps) != 0) {
        std::cerr << "Freeing file capabilities: " << strerror(errno) << std::endl;
    }

    invalidate();
}

bool FileCapabilities::setFromText(const std::string &text) {
    destroy();

    m_caps = cap_from_text(text.c_str());

    return hasCaps();
}

std::string FileCapabilities::toText() const {
    if (!hasCaps())
        return "";

    auto text = cap_to_text(m_caps, nullptr);

    if (!text)
        return "";

    auto ret = std::string(text);

    cap_free(text);

    return ret;
}

bool FileCapabilities::setFromFile(const std::string &path) {
    destroy();

    m_caps = cap_get_file(path.c_str());

    m_last_errno = m_caps ? 0 : errno;

    return m_caps || m_last_errno == ENODATA;
}

std::string FileCapabilities::lastErrorText() const {
    switch(m_last_errno) {
            default:
                return std::string{"failed to get capabilities: "} + std::strerror(m_last_errno);
            case 0:
                return "no error";
            // we get EBADF for files that don't support capabilities, e.g. sockets or FIFOs
            case EBADF:
                return "cannot assign capabilities for this kind of file";
            case EOPNOTSUPP:
                return "no support for capabilities on kernel or file system";
    }
}

bool FileCapabilities::applyToFD(int fd) const {
    if (cap_set_fd(fd, m_caps) != 0) {
        return false;
    }

    return true;
}

// vim: et ts=4 sts=4 sw=4 :
