#pragma once

// local headers
#include "cmdline.h"
#include "profparser.h"
#include "utility.h"
#include "varexp.h"

// C++
#include <fstream>
#include <set>
#include <string>
#include <utility>
#include <vector>

/// Main application class for Chkstat.
class Chkstat {
public: // functions

    Chkstat(const CmdlineArgs &args);

    int run();

protected: // functions

    /// Process the already validated command line arguments.
    bool processArguments();

    bool needToCheck(const std::string &path) const {
        if (m_files_to_check.empty())
            // all paths should be checked
            return true;

        // otherwise only if the path is explicitly listed
        return m_files_to_check.find(path) != m_files_to_check.end();
    }

    std::string getUsrRoot() const {
        return m_args.config_root_path.getValue() + "/usr/share/permissions";
    }

    std::string getEtcRoot() const {
        return m_args.config_root_path.getValue() + "/etc";
    }

    bool parseSysconfig();

    /// Adds the given profile (suffix) to the list of profiles to be processed.
    void addProfile(const std::string &name);

    /// Collects all configured profiles.
    /**
     * Collects all profiles configured in m_profiles from /usr and /etc
     * system directories and stores their paths and streams in
     * m_profile_streams.
     **/
    void collectProfilePaths();

    /// Collects configured per-package profiles from the given directory.
    void collectPackageProfilePaths(const std::string &dir);

    /// The main profile entry traversal algorithm that carries out required file system operations.
    int processEntries();

    /// Checks whether /proc is mounted and returns the result.
    bool isProcMounted() const;

    /// Checks if changes are allowed to be applied without /proc filesystem
    bool allowNoProc() const;

    /// Prints an introductory text describing the active configuration.
    void printHeader();

    /// Attempt to open the given profile path and add it to m_profile_streams.
    bool tryOpenProfile(const std::string &path);

protected: // data

    const CmdlineArgs &m_args;

    /// Whether a /proc mount has been detected.
    const bool m_have_proc;

    /// Optional explicit set of files to check.
    std::set<std::string> m_files_to_check;

    /// Whether to actually apply changes.
    /**
     * This is basically defined by command line parameters but can be
     * overridden by runtime context e.g. a missing /proc or sysconfig.
     **/
    bool m_apply_changes = false;

    /// Allow operation without mounted /proc file system.
    /**
     * In normal operation we fall back to a read only mode if /proc is not
     * available because securely operating on arbitrary filesystems is not
     * possible then. In some configurations /proc is not available (e.g.
     * container setups) but changes should be applied anyway.
     * The caller needs to ensure that no unpriviled user can influence the
     * operation in nefarious ways
     **/
    const bool m_allow_no_proc = false;

    /// The predefined profile names shipped with permissions.
    static constexpr const char * const PREDEFINED_PROFILES[] = {"easy", "secure", "paranoid"};

    /// Permission profile names in the order they should be applied.
    std::vector<std::string> m_profiles;

    /// Permission profile paths and their opened streams in the order they should be applied.
    std::vector<std::pair<std::string, std::ifstream>> m_profile_streams;

    /// A collection of the basenames of packages that have already been processed by collectPackageProfilePaths().
    std::set<std::string> m_package_profiles_seen;

    /// Access to variable expansion mappings from the variables.conf file.
    VariableExpansions m_variable_expansions;

    ProfileParser m_profile_parser;
};

// vim: et ts=4 sts=4 sw=4 :
