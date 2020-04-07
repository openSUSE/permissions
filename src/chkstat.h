#ifndef CHKSTAT_H
#define CHKSTAT_H

// POSIX / Linux
#include <sys/capability.h>
#include <sys/types.h>

// third party
#include <tclap/CmdLine.h>

// C++
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

/**
 * \brief
 *     SwitchArg that can be programmatically set
 * \details
 *     TCLAP::SwitchArg doesn't offer a public API to programmatically change
 *     the switch's value. Therefore this specializations provides an
 *     additional method to make this possible.
 **/
class SwitchArgRW :
    public TCLAP::SwitchArg
{
public:
    SwitchArgRW(
        const std::string &flag,
        const std::string &name,
        const std::string &desc,
        TCLAP::CmdLineInterface &parser) :
        TCLAP::SwitchArg(flag, name, desc, parser)
    {}

    void setValue(bool val)
    {
        _value = val;
        // this is used for isSet(), _value only for getValue(), so
        // sync both.
        _alreadySet = val;
    }
};

struct ProfileEntry
{
    std::string file;
    std::string owner;
    std::string group;
    mode_t mode;
    cap_t caps = nullptr;

    ~ProfileEntry()
    {
        freeCaps();
    }

    void freeCaps()
    {
        if (caps)
        {
            cap_free(caps);
        }

        caps = nullptr;
    }

    void setCaps(cap_t new_caps)
    {
        freeCaps();
        caps = new_caps;
    }
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
};

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
