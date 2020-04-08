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

bool existsFile(const std::string &path)
{
    int fd = open(path.c_str(), O_RDONLY);

    if (fd != -1)
    {
        close(fd);
        return true;
    }

    return false;
}

void splitWords(const std::string &input, std::vector<std::string> &words)
{
    std::stringstream ss;
    std::string word;

    words.clear();
    ss.str(input);

    // read whitespace separated words
    while (!ss.fail())
    {
        ss >> word;

        if (!ss.fail())
        {
            words.emplace_back(word);
        }
    }
}

void FileDescGuard::close()
{
    if (!valid())
        return;

    if (::close(m_fd) != 0)
    {
        std::cerr << "Closing FD " << m_fd << ": " << strerror(errno) << std::endl;
    }
    
    invalidate();
}

// vim: et ts=4 sts=4 sw=4 :
