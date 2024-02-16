#pragma once

// C++
#include <map>
#include <string>

/// Processing of variables.conf and handling of profile path expansions.
/**
 * Profile paths can contain %{variable} syntax that will expand to one or
 * more alternative values. This class parses the variable configuration file
 * and performs necessary expansions on individual profile entry paths.
 **/
class VariableExpansions {
public: // functions

    /// Parses the variables.conf file and fills m_expansions.
    void load(const std::string &root);

    /// Access the variable expansions from the last load() operation.
    const auto& expansions() const {
        return m_expansions;
    }

    /// Expand possible variables in profile path specifications.
    /**
     * Returns the expanded paths for the given profile entry path. It is
     * possible that only a single entry results from the expansion or that no
     * expansion is necessary at all, in which case only a single entry will
     * be returned in `expanded`.
     *
     * \return In case any unrecoverable parsing error is encountered `false` is
     *         returned and the profile entry should be ignored entirely.
     **/
    bool expandPath(const std::string &path, std::vector<std::string> &expanded) const;

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
