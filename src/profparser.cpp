// local headers
#include "profparser.h"
#include "utility.h"

ProfileEntry::ProfileEntry(const std::string &p_file, const std::string &p_owner,
            const std::string &p_group, mode_t p_mode) :
            file(p_file), owner(p_owner), group(p_group), mode(p_mode) {
    // By default make the ACL equal to the basic mode, this way the ACL
    // object can be used for assigning ACLs, even if no ACL is configured in
    // the profile.
    // This is necessary for being able to remove existing ACL entries in case
    // none are configured in the profile. A chmod() won't remove existing
    // ACL entries, we need to explicitly apply a basic ACL to get rid of
    // them.
    acl = FileAcl{mode};
}

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
    // [+acl user:nobody:rw-,mask::rw-]

    while (std::getline(fs, line)) {
        linenr++;
        strip(line);

        // don't know exactly why the dollar is also ignored, probably some dark legacy.
        if (line.empty() || line[0] == '#' || line[0] == '$')
            continue;

        if (line[0] == '+') {
            parseExtraLine(line, printBadLine);
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

void ProfileParser::parseExtraLine(const std::string &line, std::function<void(const std::string_view)> printBadLine) {
        if (m_parse_context.paths.empty() || m_active_entries.empty()) {
            std::cerr << "lone +<keyword> line or follow-up parsing error\n";
            return;
        }

        // an extra capability line that belongs to the context of the last profile entry seen.
        if (hasPrefix(line, "+capabilities ")) {
            if (!parseCapabilityLine(line)) {
                printBadLine("bad capability spec");
            }
        } else if (hasPrefix(line, "+acl ")) {
            if (!parseAclLine(line)) {
                printBadLine("bad ACL spec");
            }
        } else {
            printBadLine("bad +<keyword> line");
        }
}

bool ProfileParser::parseCapabilityLine(const std::string &line) {

    if (!m_use_fscaps)
        // ignore the content
        return true;

    auto cap_text = line.substr(line.find_first_of(' '));
    if (cap_text.empty())
        // ignore empty capability specification
        return true;

    FileCapabilities caps;

    if (!caps.setFromText(cap_text)) {
        std::cerr << "Failed to parse capability string: " << caps.lastErrorText() << std::endl;
        return false;
    }

    for (auto it: m_active_entries) {
        auto &entry = it->second;
        entry.caps = caps.copy();
    }

    return true;
}

bool ProfileParser::parseAclLine(const std::string &line) {
    auto acl_text = line.substr(line.find_first_of(' '));
    if (acl_text.empty())
        // ignore empty ACL specification
        return true;

    FileAcl acl;

    if (!acl.setFromText(acl_text)) {
        std::cerr << "Bad ACL specification or invalid user/group name\n";
        return false;
    }

    if (!acl.isExtendedACL()) {
        // we set a basic ACL entry by default, see ProfileEntry() constructor.
        std::cerr << "This ACL entry does not contain extended privileges. Permctl does not support this, this ACL will be ignored\n";
        return false;
    }

    if (!acl.setBasicEntries(m_parse_context.mode)) {
        std::cerr << "Failed to add basic mode entries to ACL\n";
        return false;
    }

    if (!acl.tryCalcMask()) {
        std::cerr << "Failed to calculate mask entry for ACL\n";
        return false;
    }

    if (!acl.verify()) {
        std::cerr << "Resulting ACL failed verification, it has logical errors\n";
        return false;
    }

    for (auto it: m_active_entries) {
        auto &entry = it->second;
        entry.acl = acl.copy();
    }

    return true;
}

void ProfileParser::addCurrentEntries() {
    m_active_entries.clear();

    for (auto path: m_parse_context.paths) {
        path = fullPath(path);

        // this overwrites a possibly already existing entry
        // this is intended behaviour, hence the order in which profiles are
        // applied is important
        auto res = m_entries.insert_or_assign(path, ProfileEntry{
                path, m_parse_context.user,
                m_parse_context.group, m_parse_context.mode});

        m_active_entries.push_back(res.first);
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

std::string ProfileParser::fullPath(const std::string &path) const {
    // use the full path including a potential alternative root directory as map key
    std::string root = m_args.root_path.getValue();

    if (root.empty())
        return path;

    return root + '/' + path;
}

// vim: et ts=4 sts=4 sw=4 :
