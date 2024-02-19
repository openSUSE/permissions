#pragma once

// system headers
#include <unistd.h>

// local headers
#include "cmdline.h"
#include "types.h"

/// Process a single permissions profile entry performing operations on the file system.
/**
 * This class actually compares configuration data with file state found on
 * disk. It can act in a read-only mode where it only prints what changes
 * would be performed. Or it can actually apply necessary changes.
 **/
class EntryProcessor {
public: // functions

    EntryProcessor(const ProfileEntry &entry, const CmdlineArgs &args, const bool apply_changes);

    /// Returns the path relative to the altroot that this entry is concerned with
    const auto& path() const {
        return m_ctx.subpath;
    }

    bool process(const bool have_proc);

protected: // functions

    /// Resolves the textual user:group in `m_entry` and stores the result in `m_ctx`.
    bool resolveOwnership();

    /// Safely open the target file taking symlinks and insecure constellations into account.
    /**
     * On success the file descriptor will be stored in m_ctx.fd.
     *
     * \return
     *      An indication whether the file could be successfully opened
     **/
    bool safeOpen();

    /// Gets the currently set capabilities from `m_ctx.fd_path` and stores them in `m_ctx.caps`.
    /**
     * `m_entry` is potentially modified if capabilities can't be applied. The
     * return value indicates if an operational error occurred but it doesn't
     * indicate whether a capability value could be assigned. Check
     * `m_ctx.caps.valid()` for this.
     **/
    bool getCapabilities();

    /// Print differences between configuration and reality.
    /**
     * This outputs the operations that will (or should) be performed to
     * arrive at the ProfileEntry configuration.
     **/
    void printDifferences() const;

    /// Check whether it is safe to adjust the actual file given the collected information.
    bool isSafeToApply() const;

    /// Actually apply changes to `m_ctx` according to `m_entry`.
    bool applyChanges() const;

protected: // data

    EntryContext m_ctx;
    const ProfileEntry &m_entry;
    const CmdlineArgs &m_args;
    const bool m_apply_changes;
    static const uid_t m_euid; ///< The effective user ID we're running as.
    static const gid_t m_egid; ///< The effective group ID we're running as.
};

// vim: et ts=4 sts=4 sw=4 :
