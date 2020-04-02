#ifndef CHKSTAT_H
#define CHKSTAT_H

// third party
#include <tclap/CmdLine.h>

// C++
#include <string>

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
    TCLAP::ValueArg<std::string> m_config_root_path;

    //! positional input arguments: either the files to check for --system
    //! mode or the profiles to parse for non-system mode.
    TCLAP::UnlabeledMultiArg<std::string> m_input_args;
};

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
