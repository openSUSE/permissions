#pragma once

// C++
#include <map>
#include <string>

/// Processing of variables.conf
class VariableExpansions {
public: // functions

    /// Parses the variables.conf file and fills m_expansions.
    void load(const std::string &root);

    /// Access the variable expansions from the last load() operation.
    const auto& expansions() const {
        return m_expansions;
    }

protected: // functions

    /// Checks that a path variable identifier contains only valid characters.
    bool checkValidIdentifier(const std::string &ident);

    /// Normalizes the given list of path variable values.
    /**
     *  Unnecessary path separators will be removed from each value.
     **/
    void normalizeValues(std::vector<std::string> &values);

protected: // data

    /// Collected variable expansion mappings from the variables.conf file.
    std::map<std::string, std::vector<std::string>> m_expansions;
};

// vim: et ts=4 sts=4 sw=4 :
