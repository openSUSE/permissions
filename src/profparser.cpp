// local headers
#include "profparser.h"
#include "utility.h"

void ProfileParser::parse(const std::string &path, std::ifstream &fs) {
    size_t linenr = 0;
    std::string line;
    std::vector<std::string> parts;

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

        // don't know exactly why the dollar is also ignored, probably some dark legacy.
        if (line.empty() || line[0] == '#' || line[0] == '$')
            continue;

        // an extra capability line that belongs to the context of the last profile entry seen.
        if (line[0] == '+') {
            if (!parseCapabilityLine(line)) {
                printBadLine("bad capability spec or bad +<keyword>");
            }

            continue;
        }

        // only keep the context for the immediately following
        // `+` lines to prevent the context being applied to
        // unintended '+' lines in case of parsing errors later on.
        m_parse_context.clear();

        splitWords(line, parts);

        if (parts.size() != 3) {
            printBadLine("invalid number of whitespace separated words");
            continue;
        }

        if (!parseOwnership(parts[1])) {
            printBadLine("bad user:group specification");
            continue;
        } else if (!parseMode(parts[2])) {
            printBadLine("bad mode specification");
            continue;
        } else if (!m_expansions.expandPath(parts[0], m_parse_context.paths)) {
            printBadLine("bad variable expansions");
            continue;
        }

        addCurrentEntries();
    }
}

bool ProfileParser::parseCapabilityLine(const std::string &line) {

    if (m_parse_context.paths.empty()) {
        std::cerr << "lone capability line or follow-up parsing error\n";
        return false;
    }

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

    for (const auto &path: m_parse_context.paths) {
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

void ProfileParser::addCurrentEntries() {
    // use the full path including a potential alternative root directory as map key
    std::string root = m_args.root_path.getValue();
    if (!root.empty()) {
        root += '/';
    }

    for (auto path: m_parse_context.paths) {
        path = root + path;

        // this overwrites a possibly already existing entry
        // this is intended behaviour, hence the order in which profiles are
        // applied is important
        m_entries[path] = ProfileEntry{
                path, m_parse_context.user,
                m_parse_context.group, m_parse_context.mode};
    }
}

bool ProfileParser::parseOwnership(const std::string &ownership) {

        // split up user and group from {user}:{group} string. Two different
        // separator types are allowed like with `chmod`
        for (const auto sep: {':', '.' }) {
            const auto seppos = ownership.find_first_of(sep);
            if (seppos == ownership.npos)
                continue;

            m_parse_context.user = ownership.substr(0, seppos);
            m_parse_context.group = ownership.substr(seppos + 1);

            break;
        }

        return !m_parse_context.user.empty() && !m_parse_context.group.empty();
}

bool ProfileParser::parseMode(const std::string &mode) {
    auto &mode_int = m_parse_context.mode;

    if (!stringToUnsigned(mode, mode_int, 8) || mode_int > ALLPERMS) {
        return false;
    }

    return true;
}

// vim: et ts=4 sts=4 sw=4 :
