#pragma once

// local headers
#include "cmdline.h"
#include "types.h"
#include "varexp.h"

// C++
#include <fstream>
#include <map>
#include <string>

/// Parses ProfileEntry structures out of permissions profile configuration files.
class ProfileParser {
public: // functions

    ProfileParser(const CmdlineArgs &args, const VariableExpansions &expansions) :
            m_args{args},
            m_expansions{expansions} {}

    /// Parses the given profile file and stores the according entries.
    void parse(const std::string &path, std::ifstream &fs);

    /// Whether to process capability settings or to discard them.
    void setUseFsCaps(bool use) {
        m_use_fscaps = use;
    }

    const auto& entries() const {
        return m_entries;
    }

    bool existsEntry(const std::string &path) const {
        return m_entries.find(path) != m_entries.end();
    }

protected: // functions

    /// Parses extra "+capabilities" lines in permission profiles.
    /**
     * \param[in] line
     *      The input line from a profile file that starts with "+"
     * \param[input] active_paths
     *      The paths that the capability line applies to. It is expected that
     *      these paths already have entries in m_profile_entries.
     * \return
     *      Whether the line could successfully be parsed
     **/
    bool parseCapabilityLine(const std::string &line, const std::vector<std::string> &active_paths);

    /// Adds a ProfileEntry to m_entries for the given set of parameters.
    ProfileEntry&
    addProfileEntry(const std::string &file, const std::string &owner, const std::string &group, mode_t mode);

protected: // data

    /// Whether to touch file based capabilities.
    /**
     * This is influenced by command line parameters and the sysconfig
     * configuration file.
     **/
    bool m_use_fscaps = true;

    const CmdlineArgs &m_args;

    const VariableExpansions &m_expansions;

    /// A mapping of file paths to ProfileEntry, denotes the entry to apply for each path.
    std::map<std::string, ProfileEntry> m_entries;
};

// vim: et ts=4 sts=4 sw=4 :
