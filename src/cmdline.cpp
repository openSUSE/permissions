// local headers
#include "cmdline.h"
#include "utility.h"

CmdlineArgs::CmdlineArgs() :
    m_parser{"Tool to check and set file permissions"},
    system_mode{"", "system", "system mode, act according to /etc/sysconfig/security", m_parser},
    force_fscaps{"", "fscaps", "force use of file system capabilities", m_parser},
    disable_fscaps{"", "no-fscaps", "disable use of file system capabilities", m_parser},
    apply_changes{"s", "set", "actually apply changes (--system mode may imply this depending on file based configuration)", m_parser},
    only_warn{"", "warn", "only inform about which changes would be performed but don't actually apply them (which is the default, except in --system mode)", m_parser},
    no_header{"n", "noheader", "don't print intro message", m_parser},
    verbose{"v", "verbose", "print additional output that might be useful for diagnosis", m_parser},
    print_variables{"", "print-variables", "print supported profile variable mappings then exit", m_parser},
    examine_paths{"e", "examine", "operate only on the specified path(s)", false, "PATH", m_parser},
    force_level_list{"", "level", "force application of the specified space-separated list of security levels (only supported in --system mode)", false, "", "e.g. \"local paranoid\"", m_parser},
    file_lists{"f", "files", "read newline separated list of files to check (see --examine) from the specified path", false, "PATH", m_parser},
    root_path{"r", "root", "check files relative to the given root directory", false, "", "PATH", m_parser},
    config_root_path{"", "config-root", "lookup configuration files relative to the given root directory", false, "", "PATH", m_parser},
    input_args{"args", "in --system mode a list of paths to check, otherwise a list of profiles to parse", false, "PATH", m_parser} {

    }

int CmdlineArgs::parse(const int argc, const char **argv) {
    m_parser.parse(argc, argv);

    return validateArguments() ? 0 : 2;
}

bool CmdlineArgs::validateArguments() {
    // in this case ignore all the rest, we'll just print the variables
    if (print_variables.isSet())
        return true;

    // check all parameters and only then return to provide full diagnostic to
    // the user, not just bit by bit complaining.
    bool ret = true;

    // check for mutually exclusive command line arguments
    const auto xor_args = {
        std::make_pair(&force_fscaps, &disable_fscaps),
        {&apply_changes, &only_warn}
    };

    for (const auto &args: xor_args) {
        auto &arg1 = *args.first;
        auto &arg2 = *args.second;

        if (arg1.isSet() && arg2.isSet()) {
            std::cerr << arg1.getName() << " and " << arg2.getName()
                << " cannot be set at the same time\n";
            ret = false;
        }
    }

    if (!system_mode.isSet() && input_args.getValue().empty()) {
        std::cerr << "one or more permission file paths to use are required\n";
        ret = false;
    }

    for (const auto arg: {&root_path, &config_root_path}) {
        if (!arg->isSet())
            continue;

        auto &path = arg->getValue();

        if (path.empty() || path[0] != '/') {
            std::cerr << arg->getName() << " must begin with '/'" << std::endl;
            ret = false;
        }

        // remove trailing slashes to normalize arguments
        stripTrailingSlashes(path);
    }

    return ret;
}

// vim: et ts=4 sts=4 sw=4 :
