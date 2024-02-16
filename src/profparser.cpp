// local headers
#include "profparser.h"
#include "utility.h"

void ProfileParser::parse(const std::string &path, std::ifstream &fs) {
    size_t linenr = 0;
    std::vector<std::string> active_keys;
    std::string line;
    std::vector<std::string> parts;
    mode_t mode_int;

    auto printBadLine = [path, linenr](const std::string_view context) {
        std::cerr << path << ":" << linenr << ": syntax error in permissions profile (" << context << ")" << std::endl;
    };

    // we're parsing lines of the following format here:
    //
    // # comment
    // <path> <user>:<group> <mode>
    // [+capabilities cap_net_raw=ep]

    while (std::getline(fs, line)) {
        linenr++;
        strip(line);

        // don't know exactly why the dollar is also ignored, probably some
        // dark legacy.
        if (line.empty() || line[0] == '#' || line[0] == '$')
            continue;

        // an extra capability line that belongs to the context of the last
        // profile entry seen.
        if (line[0] == '+') {
            if (active_keys.empty()) {
                printBadLine("lone capability line");
                continue;
            }

            const auto good = parseCapabilityLine(line, active_keys);

            if (!good) {
                printBadLine("bad capability spec or bad +keyword");
            }

            continue;
        }

        // only keep the context for one following non-empty/non-comment line
        // to prevent the context being applied to unintended '+' lines in
        // case of parsing errors later on.
        active_keys.clear();

        splitWords(line, parts);

        if (parts.size() != 3) {
            printBadLine("invalid number of whitespace separated words");
            continue;
        }

        const auto &ownership = parts[1];
        std::string user, group;

        // split up user and group from {user}:{group} string. Two different
        // separator types are allowed like with `chmod`
        for (const auto sep: { ':', '.' }) {
            const auto seppos = ownership.find_first_of(sep);
            if (seppos == ownership.npos)
                continue;

            user = ownership.substr(0, seppos);
            group = ownership.substr(seppos + 1);

            break;
        }

        if (user.empty() || group.empty()) {
            printBadLine("bad user:group specification");
            continue;
        }

        const auto &location = parts[0];
        const auto &mode = parts[2];

        if (!stringToUnsigned(mode, mode_int, 8) || mode_int > ALLPERMS) {
            printBadLine("bad mode specification");
            continue;
        }

        std::vector<std::string> expanded;
        if (!m_expansions.expandPath(location, expanded)) {
            printBadLine("bad variable expansions");
            continue;
        }

        for (const auto &exp_path: expanded) {
            addProfileEntry(exp_path, user, group, mode_int);
            // remember the most recently added entries to allow potential '+'
            // capability lines to be applied to them.
            active_keys.push_back(exp_path);
        }
    }
}

bool ProfileParser::parseCapabilityLine(const std::string &line, const std::vector<std::string> &active_paths) {
    if (!hasPrefix(line, "+capabilities "))
        return false;
    else if (!m_use_fscaps)
        // ignore the content
        return true;

    auto cap_text = line.substr(line.find_first_of(' '));
    if (cap_text.empty())
        // ignore empty capability specification
        return true;

    bool ret = true;

    for (const auto &path: active_paths) {
        auto it = m_entries.find(path);
        if (it == m_entries.end()) {
            std::cerr << "No profile entry for path " << path << "???";
            ret = false;
            continue;
        }

        auto &entry = it->second;

        if (!entry.caps.setFromText(cap_text)) {
            ret = false;
        }
    }

    return ret;
}

ProfileEntry&
ProfileParser::addProfileEntry(const std::string &file, const std::string &owner, const std::string &group, mode_t mode) {
    // use the full path including a potential alternative root directory as map key
    std::string path = m_args.root_path.getValue();
    if (!path.empty()) {
        path += '/';
    }
    path += file;

    // this overwrites a possibly already existing entry
    // this is intended behaviour, hence the order in which profiles are
    // applied is important
    return m_entries[path] = ProfileEntry{path, owner, group, mode};
}

// vim: et ts=4 sts=4 sw=4 :
