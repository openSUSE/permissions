// C++
#include <fstream>
#include <string_view>

// local headers
#include "utility.h"
#include "varexp.h"

void VariableExpansions::load(const std::string &root) {
    const auto conf_path = root + "/variables.conf";

    std::ifstream fs(conf_path);

    if (!fs) {
        std::cerr << "warning: couldn't find variable mapping configuration in " << conf_path << ": " << std::strerror(errno) << std::endl;
        return;
    }

    std::vector<std::string> words;
    size_t linenr = 0;
    std::string line;

    auto printBadLine = [conf_path, linenr](const std::string_view context) {
        std::cerr << conf_path << ":" << linenr <<
            ": syntax error in variable configuration (" << context << ")" << std::endl;
    };

    while (std::getline(fs, line)) {
        linenr++;
        strip(line);

        if (line.empty() || line[0] == '#')
            continue;

        const auto equal_pos = line.find('=');

        if (equal_pos == line.npos) {
            printBadLine("missing '=' assignment");
            continue;
        }

        const auto varname = stripped(line.substr(0, equal_pos));
        if (!checkValidIdentifier(varname)) {
            printBadLine("bad variable identifier");
            continue;
        }

        const auto values = stripped(line.substr(equal_pos + 1));
        splitWords(values, words);

        if (words.empty()) {
            printBadLine("empty assignment");
            continue;
        }

        normalizeValues(words);

        // tolerate words.size() == 1, we could emit a warning, but it could
        // be a valid use case.

        if (m_expansions.find(varname) != m_expansions.end()) {
            printBadLine("duplicate variable entry, ignoring");
            continue;
        }

        m_expansions[varname] = words;
    }
}

bool VariableExpansions::checkValidIdentifier(const std::string &ident) {
    for (auto ch: ident) {
        if (std::isalnum(ch))
            continue;
        else if (ch == '_')
            continue;

        std::cerr << "Invalid characters encountered in variable name '" << ident << "': '" << ch << "'" << std::endl;

        return false;
    }

    return true;
}

void VariableExpansions::normalizeValues(std::vector<std::string> &values) {
    for (auto &value: values) {
        // remove leading/trailing separators
        strip(value, chkslash);

        // remove consecutive slashes in two passes:
        // - identify indices of repeated slashes
        // - remove indices starting from the end of the string to avoid
        //   shifting index positions.
        char prev_char = 0;
        size_t pos = 0;
        std::vector<size_t> del_indices;

        for (auto ch: value) {
            if (ch == '/' && prev_char == '/')
                del_indices.push_back(pos);
            else
                prev_char = ch;

            pos++;
        }

        for (auto it = del_indices.rbegin(); it != del_indices.rend(); it++) {
            value.erase(*it, 1);
        }
    }
}

bool VariableExpansions::expandPath(const std::string &path, std::vector<std::string> &expanded) const {
    std::stringstream ss;
    ss.str(path);
    std::string part;

    // the initial entry
    expanded.clear();
    expanded.push_back("");

    // we support variables only as individual
    // path components i.e. something like %{myvar}stuff/suffix is not
    // allowed, only %{myvar}/suffix.
    //
    // multiple variable components in the same path are supported

    // process each path component.
    // we add fixed strings plainly to each entry in `expanded` and for each
    // variable we encounter we add new path variants to `expanded` as
    // necessary.
    while (std::getline(ss, part, '/')) {
        if (hasPrefix(part, "%{") && hasSuffix(part, "}")) {
            // variable found
            const auto variable = part.substr(2, part.length() - 3);
            auto it = m_expansions.find(variable);

            if (it == m_expansions.end()) {
                expanded.clear();
                std::cerr << "Undeclared variable %{" << variable << "} encountered." << std::endl;
                return false;
            }

            // now we need to create additional entries for each possible value of the variable
            std::vector<std::string> new_expanded;

            for (const auto &element: expanded) {
                for (const auto &var_value: it->second) {
                    new_expanded.push_back(element + "/" + var_value);
                }
            }

            expanded = new_expanded;
        } else if (part.empty()) {
            // leading slash, ignore
            continue;
        } else {
            // regular fixed string
            for (auto &element: expanded) {
                element = element + "/" + part;
            }
        }
    }

    return true;
}

// vim: et ts=4 sts=4 sw=4 :
