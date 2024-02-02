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

bool existsFile(const std::string &path) {
    return access(path.c_str(), R_OK) == 0;
}

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
    if (valid()) {
        destroy();
    }
}

bool FileCapabilities::operator==(const FileCapabilities &other) const {
    if (!valid() && !other.valid())
        // if both are invalid compare to true
        return true;

    if (valid() != other.valid())
        // if only one is invalid then compare to false
        return false;

    return cap_compare(m_caps, other.m_caps) == 0;
}

void FileCapabilities::destroy() {
    if (!valid())
        return;


    if (cap_free(m_caps) != 0) {
        std::cerr << "Freeing file capabilities: " << strerror(errno) << std::endl;
    }

    invalidate();
}

void FileCapabilities::setFromText(const std::string &text) {
    destroy();

    m_caps = cap_from_text(text.c_str());
}

std::string FileCapabilities::toText() const {
    if (!valid())
        return "";

    auto text = cap_to_text(m_caps, nullptr);

    if (!text)
        return "";

    auto ret = std::string(text);

    cap_free(text);

    return ret;
}

void FileCapabilities::setFromFile(const std::string &path) {
    destroy();

    m_caps = cap_get_file(path.c_str());
}

bool FileCapabilities::applyToFD(int fd) const {
    if (cap_set_fd(fd, m_caps) != 0) {
        return false;
    }

    return true;
}

// vim: et ts=4 sts=4 sw=4 :
