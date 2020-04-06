// Linux
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// local headers
#include "utility.h"

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

// vim: et ts=4 sts=4 sw=4 :
