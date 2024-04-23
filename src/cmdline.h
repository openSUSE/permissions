#pragma once

// third party
#include <tclap/CmdLine.h>

class CmdlineArgs {
protected: // data
    TCLAP::CmdLine m_parser;

public: // data

    TCLAP::SwitchArg system_mode;
    TCLAP::SwitchArg force_fscaps;
    TCLAP::SwitchArg disable_fscaps;
    TCLAP::SwitchArg apply_changes;
    TCLAP::SwitchArg only_warn;
    TCLAP::SwitchArg no_header;
    TCLAP::SwitchArg verbose;
    TCLAP::SwitchArg print_variables;

    // NOTE: old chkstat allowed multiple specifications of value
    // switches like --level and --root but actually only used the last
    // occurrence on the command line. In theory this is a backward
    // compatibility break, but it's also kind of a bug.

    TCLAP::MultiArg<std::string> examine_paths;
    TCLAP::ValueArg<std::string> force_level_list;
    TCLAP::MultiArg<std::string> file_lists;

    TCLAP::ValueArg<std::string> root_path;
    /// Alternate config root directory relative to which config files are looked up.
    TCLAP::ValueArg<std::string> config_root_path;

    /// Positional input arguments
    /**
     * Either the files to check for --system mode or the profiles to parse
     * for non-system mode.
     **/
    TCLAP::UnlabeledMultiArg<std::string> input_args;
public: // functions

    CmdlineArgs();

    int parse(const int argc, const char **argv);

protected: // functions

    /// Validates command line arguments on syntactical and logical level.
    bool validateArguments();
};

// vim: et ts=4 sts=4 sw=4 :
