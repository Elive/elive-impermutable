# /lib/bilibop/rules.sh
# vim: set et sw=4 sts=4 ts=4 fdm=marker fcl=all:

# The bilibop-rules functions need those of bilibop-common:
. /lib/bilibop/common.sh
get_bilibop_variables

# See bilibop.conf(5) and udisks(7) manpage for details.

# _udisks_system_internal() ================================================={{{
# What we want is: forbid user applications to (auto)mount listed filesystems.
_udisks_system_internal() {
    ${DEBUG} && echo "> udisks_system_internal $@" >&2
    local   skip
    for skip in ${BILIBOP_RULES_SYSTEM_INTERNAL_WHITELIST}
    do
        case    "${skip}" in
            UUID=${ID_FS_UUID}|LABEL=${ID_FS_LABEL}|TYPE=${ID_FS_TYPE}|USAGE=${ID_FS_USAGE})
                return 1
                ;;
        esac
    done
    return 0
}
# ===========================================================================}}}
# _udisks_presentation_hide() ==============================================={{{
# What we want is: hide bilibop partitions to the desktop applications
# (especially the file managers) based on Udisks: this includes Nautilus,
# Thunar, PCManFM and Konkeror. Only the whitelisted filesystems will be
# shown to the user.
# NOTE: this function must be called from /lib/udev/bilibop_disk. The ID_FS_*
# variables should be exported by udev, and so this functions don't need an
# argument. The same rule applies to the two following functions.
_udisks_presentation_hide() {
    ${DEBUG} && echo "> udisks_presentation_hide $@" >&2
    local   skip
    for skip in ${BILIBOP_RULES_PRESENTATION_HIDE_WHITELIST}
    do
        case    "${skip}" in
            UUID=${ID_FS_UUID}|LABEL=${ID_FS_LABEL}|TYPE=${ID_FS_TYPE}|USAGE=${ID_FS_USAGE})
                return 1
                ;;
        esac
    done
    return 0
}
# ===========================================================================}}}
# _udisks_presentation_icon() ==============================================={{{
# What we want is: use another icon than the default one to show a device to
# the user.
_udisks_presentation_icon() {
    ${DEBUG} && echo "> udisks_presentation_icon $@" >&2
    local   icon
    for icon in ${BILIBOP_RULES_PRESENTATION_ICON}
    do
        case    "${icon}" in
            UUID=${ID_FS_UUID}:*|LABEL=${ID_FS_LABEL}:*|TYPE=${ID_FS_TYPE}:*|USAGE=${ID_FS_USAGE}:*)
                echo "${icon##*:}"
                return 0
                ;;
        esac
    done
    return 1
}
# ===========================================================================}}}
# _udisks_presentation_name() ==============================================={{{
# What we want is: use another icon than the default one to show a device to
# the user.
_udisks_presentation_name() {
    ${DEBUG} && echo "> udisks_presentation_name $@" >&2
    local   name
    for name in ${BILIBOP_RULES_PRESENTATION_NAME}
    do
        case    "${name}" in
            UUID=${ID_FS_UUID}:*|LABEL=${ID_FS_LABEL}:*|TYPE=${ID_FS_TYPE}:*|USAGE=${ID_FS_USAGE}:*)
                echo "${name##*:}"
                return 0
                ;;
        esac
    done
    return 1
}
# ===========================================================================}}}

