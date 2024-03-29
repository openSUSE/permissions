#pragma once

// local headers
#include "cmdline.h"
#include "utility.h"
#include "varexp.h"

// C++
#include <fstream>
#include <map>
#include <string>

/// Represents a single permissions profile entry.
struct ProfileEntry {
    std::string file;
    std::string owner;
    std::string group;
    // NOTE: this is mutable to allow for a const dropXID() due to the somewhat unfortunate logic in EntryProcessor::getCapabilities().
    mutable mode_t mode = 0;
    FileCapabilities caps;

    ProfileEntry() = default;

    ProfileEntry(const std::string &p_file, const std::string &p_owner, const std::string &p_group, mode_t p_mode) :
            file(p_file), owner(p_owner), group(p_group), mode(p_mode) {}

    bool hasCaps() const { return caps.hasCaps(); }

    /// Returns whether this profile entry contains a setuid or setgid bit.
    bool hasSetXID() const {
        return (this->mode & (S_ISUID | S_ISGID)) != 0;
    }

    void dropXID() const {
        const mode_t to_drop = (S_ISUID | S_ISGID);
        mode &= ~(to_drop);
    }
};

/// Parses ProfileEntry structures out of permissions profile configuration files.
class ProfileParser {
public: // functions

    ProfileParser(const CmdlineArgs &args, const VariableExpansions &expansions) :
            m_args{args},
            m_expansions{expansions} {}

    /// Parses the given profile file and stores the according entries.
    /**
     * \param[in] path The path of the profile for displaying purposes.
     * \param[in-out] fs The open input stream for parsing the profile.
     **/
    void parse(const std::string &path, std::ifstream &fs);

    /// Whether to process capability settings or to discard them.
    void setUseFsCaps(bool use) {
        m_use_fscaps = use;
    }

    const auto& entries() const {
        return m_entries;
    }

    bool existsEntry(const std::string &path) const {
        return m_entries.find(fullPath(path)) != m_entries.end();
    }

protected: // functions

    /// Parses extra "+capabilities" lines in permission profiles.
    /**
     * \param[in] line
     *      The input line from a profile file that starts with "+"
     * \return
     *      Whether the line could be successfully parsed
     **/
    bool parseCapabilityLine(const std::string &line);

    /// Adds a ProfileEntry to m_entries from the current m_parse_context.
    void addCurrentEntries();

    bool parseOwnership(const std::string &ownership);

    bool parseMode(const std::string &mode);

    /// Returns the full path for `path` considering any configured root path
    std::string fullPath(const std::string &path) const;

protected: // data

    /// Whether to touch file based capabilities.
    /**
     * This is influenced by command line parameters and the sysconfig
     * configuration file.
     **/
    bool m_use_fscaps = true;

    const CmdlineArgs &m_args;

    const VariableExpansions &m_expansions;

    struct {
        std::string user;
        std::string group;
        mode_t mode;
        std::vector<std::string> paths;

        void clear() {
            user.clear();
            group.clear();
            paths.clear();
            mode = 0;
        }
    } m_parse_context;

    /// A mapping of file paths to ProfileEntry, denotes the entry to apply for each path.
    std::map<std::string, ProfileEntry> m_entries;
};

// vim: et ts=4 sts=4 sw=4 :
