#pragma once

#include <array>

// for backward compatibility still support the CHKSTAT prefix
constexpr std::array<const char*, 2> ENVVARS_ALLOW_NO_PROC{{
        "PERMCTL_ALLOW_INSECURE_MODE_IF_NO_PROC",
        "CHKSTAT_ALLOW_INSECURE_MODE_IF_NO_PROC"}};
constexpr const char *ENVVAR_PRETEND_NO_PROC = "PERMCTL_PRETEND_NO_PROC";

// vim: et ts=4 sts=4 sw=4 :
