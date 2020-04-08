#ifndef CHKSTAT_H
#define CHKSTAT_H

// local headers
#include "utility.h"

// POSIX / Linux
#include <sys/types.h>

// third party
#include <tclap/CmdLine.h>

// C++
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

struct ProfileEntry
{
    std::string file;
    std::string owner;
    std::string group;
    mode_t mode;
    FileCapabilities caps;

    bool hasCaps() const { return caps.valid(); }

    //! returns whether this profile entry contains a setuid or setgid bit
    bool hasSetXID() const
    {
        return (this->mode & (S_ISUID | S_ISGID)) != 0;
    }
};

/**
 * \brief
 *  scratch data used while processing individual profile entries in
 *  processEntries()
 **/
struct EntryContext
{
    //! the resolved user-id corresponding to the active ProfileEntry
    uid_t uid;
    //! the resolved group-id corresponding to the active ProfileEntry
    gid_t gid;
    //! the path of the current file to check below a potential m_root_path
    std::string subpath;
    //! a path for safely opening the target file (typically in ///proc/self/fd/...)
    std::string fd_path;
    //! the actual capabilities found on on the file
    FileCapabilities caps;
    //! the actual file status info found on the file
    FileStatus status;
    //! indicates whether actual file permissions need to be fixed
    bool need_fix_perms;
    //! indicates whether actual file capabilities need to be fixed
    bool need_fix_caps;
    //! indicates whether actual file user:group ownership needs to be fixed
    bool need_fix_ownership;

    explicit EntryContext()
    {
        reset();
    }

    void reset()
    {
        uid = (uid_t)-1;
        gid = (gid_t)-1;
        subpath.clear();
        fd_path.clear();
        if (caps.valid())
        {
            caps.destroy();
        }
        need_fix_perms = false;
        need_fix_caps = false;
        need_fix_ownership = false;
    }

    //! based on the given \c entry sets need_fix_* members as required
    void checkNeedFixed(const ProfileEntry &entry)
    {
        need_fix_perms = status.getModeBits() != entry.mode;
        need_fix_ownership = !status.matchesOwnership(this->uid, this->gid);
        need_fix_caps = entry.caps != this->caps;
    }

    bool needsFixing() const
    {
        return need_fix_perms || need_fix_caps || need_fix_ownership;
    }

    bool needFixPerms() const { return need_fix_perms; }
    bool needFixCaps() const { return need_fix_caps; }
    bool needFixOwnership() const { return need_fix_ownership; }
};

//! enum to differentiate different /proc availibility situations
enum class ProcMountState
{
    //! status was not investigated yet
    PROC_MOUNT_STATE_UNKNOWN,
    PROC_MOUNT_STATE_AVAIL,
    PROC_MOUNT_STATE_UNAVAIL,
};

/**
 * \brief
 *     Main application class for Chkstat
 **/
class Chkstat
{
public: // functions

    Chkstat(int argc, const char **argv);

    int run();

protected: // functions

    /**
     * \brief
     *     Validates command line arguments on syntactical and logical level
     **/
    bool validateArguments();

    /**
     * \brief
     *      Process the already validated command line arguments
     **/
    bool processArguments();

    bool needToCheck(const std::string &path) const
    {
        if (m_checklist.empty())
            // all paths should be checked
            return true;

        // otherwise only if the path is explicitly listed
        return m_checklist.find(path) != m_checklist.end();
    }

    bool parseSysconfig();

    bool checkFsCapsSupport() const;

    /**
     * \brief
     *      Adds the given profile (suffix) to the list of profiles to be
     *      processed
     **/
    void addProfile(const std::string &name);

    /**
     * \brief
     *      Collects all configured profiles
     *  \details
     *      Collects all profiles configured in m_profiles from /usr and /etc
     *      system directories and stores their paths in m_profile_paths.
     **/
    void collectProfiles();

    /**
     * \brief
     *      Collects configured per-package profiles from the given directory
     **/
    void collectPackageProfiles(const std::string &dir);

    /**
     * \brief
     *      Parses the given profile file and stores the according entries in
     *      m_profile_entries
     **/
    void parseProfile(const std::string &path);

    /**
     * \brief
     *      Parses extra "+capabilities" lines in permission profiles
     * \param[in] line 
     *      The input line from a profile file that starts with "+"
     * \param[inout] entry
     *      The last ProfileEntry that was previously parsed from the profile
     *      file. Can be nullptr for corrupt files.
     * \return
     *      Whether the line could successfully be parsed
     **/
    bool parseExtraProfileLine(const std::string &line, ProfileEntry *entry);

    /**
     * \brief
     *      Adds a ProfileEntry to m_profile_entries for the given set of
     *      parameters
     **/
    ProfileEntry&
    addProfileEntry(const std::string &file, const std::string &owner, const std::string &group, mode_t mode);

    /**
     * \brief
     *      This function contains the actual profile entry traversal
     *      algorithm that carries out required file system operations
     **/
    int processEntries();

    /**
     * \brief
     *      Resolves the textual user:group in \c entry and stores the result
     *      in \c ctx
     **/
    bool resolveEntryOwnership(const ProfileEntry &entry, EntryContext &ctx);

    //! tests whether /proc is available in a caching manner
    bool checkHaveProc() const;

    //! prints an introductory text describing the active configuration
    void printHeader();

    //! outputs the difference that will (or should) be performed to arrived
    //! at the ProfileEntry configuration
    void printEntryDifferences(const ProfileEntry &entry, const EntryContext &ctx) const;

    /**
     * \brief
     *      Gets the currently set capabilities from ctx.fd_path and stores
     *      them in \c ctx.caps
     * \details
     *      \c entry is potentially modified if capabilities can't be applied.
     *      The return value indicates if an operational error occured but it
     *      doesn't indicate whether a capability valoue could be assigned.
     *      Check ctx.caps.valid() for this.
     **/
    bool getCapabilities(ProfileEntry &entry, EntryContext &ctx);

    // intermediate member functions in the process of refactoring global
    // functions
    int safe_open(const char *path, struct stat *stb, uid_t target_uid, bool *traversed_insecure);

protected: // data

    const int m_argc = 0;
    const char **m_argv = nullptr;

    TCLAP::CmdLine m_parser;

    TCLAP::SwitchArg m_system_mode;
    TCLAP::SwitchArg m_force_fscaps;
    TCLAP::SwitchArg m_disable_fscaps;
    SwitchArgRW m_apply_changes;
    TCLAP::SwitchArg m_only_warn;
    SwitchArgRW m_no_header;

    // NOTE: previously chkstat allowed multiple specifications of value
    // switches like --level and --root but actually only used the last
    // occurence on the command line. In theory this is a backward
    // compatiblity break, but it's also kind of a bug.

    TCLAP::MultiArg<std::string> m_examine_paths;
    TCLAP::ValueArg<std::string> m_force_level_list;
    TCLAP::MultiArg<std::string> m_file_lists;

    TCLAP::ValueArg<std::string> m_root_path;
    //! alternate config root directory relative to which config files are
    //! looked up
    TCLAP::ValueArg<std::string> m_config_root_path;

    //! positional input arguments: either the files to check for --system
    //! mode or the profiles to parse for non-system mode.
    TCLAP::UnlabeledMultiArg<std::string> m_input_args;

    //! optional explicit set of files to check
    std::set<std::string> m_checklist;
    //! whether to touch file based capabilities. influenced by command line
    //! and sysconfig configuration file
    bool m_use_fscaps = true;

    //! the default, predefined profile names shipped with permissions
    static constexpr const char * const PREDEFINED_PROFILES[] = {"easy", "secure", "paranoid"};

    //! permission profile names in the order they should be applied
    std::vector<std::string> m_profiles;

    //! permission profile paths in the order they should be applied
    std::vector<std::string> m_profile_paths;

    //! a mapping of file paths to ProfileEntry, denotes the entry to apply
    //! for each path
    std::map<std::string, ProfileEntry> m_profile_entries;

    //! the effective user ID we're running as
    const uid_t m_euid;

    mutable ProcMountState m_proc_mount_avail = ProcMountState::PROC_MOUNT_STATE_UNKNOWN;
};

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
