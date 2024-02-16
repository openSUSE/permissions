#pragma once

// local headers
#include "cmdline.h"
#include "types.h"
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

    bool checkFsCapsSupport() const;

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

    /// Parses the given profile file and stores the according entries in m_profile_entries.
    void parseProfile(const std::string &path, std::ifstream &fs);

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

    /// Adds a ProfileEntry to m_profile_entries for the given set of parameters.
    ProfileEntry&
    addProfileEntry(const std::string &file, const std::string &owner, const std::string &group, mode_t mode);

    /// The main profile entry traversal algorithm that carries out required file system operations.
    int processEntries();

    /// Resolves the textual user:group in `entry` and stores the result in `ctx`.
    bool resolveEntryOwnership(const ProfileEntry &entry, EntryContext &ctx);

    /// Tests whether /proc is available in a caching manner.
    bool checkHaveProc() const;

    /// Prints an introductory text describing the active configuration.
    void printHeader();

    /// Print differences between configuration and reality.
    /**
     * This outputs the operations that will (or should) be performed to
     * arrive at the ProfileEntry configuration.
     **/
    void printEntryDifferences(const ProfileEntry &entry, const EntryContext &ctx) const;

    /// Check whether it is safe to adjust the actual file given the collected information.
    bool isSafeToApply(const ProfileEntry &entry, const EntryContext &ctx) const;

    /// Actually apply changes to `ctx` according to `entry`.
    bool applyChanges(const ProfileEntry &entry, const EntryContext &ctx) const;

    /// Gets the currently set capabilities from `ctx.fd_path` and stores them in `ctx.caps`.
    /**
     * `entry` is potentially modified if capabilities can't be applied. The
     * return value indicates if an operational error occurred but it doesn't
     * indicate whether a capability value could be assigned. Check
     * `ctx.caps.valid()` for this.
     **/
    bool getCapabilities(ProfileEntry &entry, EntryContext &ctx);

    /// Safely open the target file taking symlinks and insecure constellations into account.
    /**
     * On success the file descriptor will be stored in ctx.fd.
     *
     * \return
     *      An indication whether the file could be successfully opened
     **/
    bool safeOpen(EntryContext &ctx);

    /// Resolves the file system path for the given file descriptor via /proc/self/fd.
    std::string getPathFromProc(const FileDesc &fd) const;

    /// Expand possible variables in profile path specifications.
    /**
     * Profile paths can contain %{variable} syntax that will expand to one or
     * more alternative values. This function performs this expansion and
     * returns the individual paths the profile entry corresponds to. It is
     * possible that only a single entry results from the expansion or that no
     * expansion is necessary at all, in which case only a single entry will
     * be returned in `paths`.
     *
     * \return
     *      In case any unrecoverable parsing error is encountered `false` is
     *      returned and the profile entry should be ignored entirely.
     **/
    bool expandProfilePaths(const std::string &path, std::vector<std::string> &expansions);

    /// Attempt to open the given profile path and add it to m_profile_streams.
    bool tryOpenProfile(const std::string &path);

protected: // data

    const CmdlineArgs &m_args;

    /// Optional explicit set of files to check.
    std::set<std::string> m_files_to_check;
    /// Whether to touch file based capabilities.
    /**
     * This is influenced by command line parameters and the sysconfig
     * configuration file
     **/
    bool m_use_fscaps = true;

    /// Whether to actually apply changes.
    /**
     * This basically defined by command line parameters but can be overridden
     * by runtime context.
     **/
    bool m_apply_changes = false;

    /// The predefined profile names shipped with permissions.
    static constexpr const char * const PREDEFINED_PROFILES[] = {"easy", "secure", "paranoid"};

    /// Permission profile names in the order they should be applied.
    std::vector<std::string> m_profiles;

    /// Permission profile paths and their opened streams in the order they should be applied.
    std::vector<std::pair<std::string, std::ifstream>> m_profile_streams;

    /// A mapping of file paths to ProfileEntry, denotes the entry to apply for each path.
    std::map<std::string, ProfileEntry> m_profile_entries;

    /// A collection of the basenames of packages that have already been processed by collectPackageProfilePaths().
    std::set<std::string> m_package_profiles_seen;

    /// Access to variable expansion mappings from the variables.conf file.
    VariableExpansions m_variable_expansions;

    /// The effective user ID we're running as.
    const uid_t m_euid;
    /// The effective group ID we're running as.
    const gid_t m_egid;

    mutable ProcMountState m_proc_mount_avail = ProcMountState::UNKNOWN;
};

// vim: et ts=4 sts=4 sw=4 :
