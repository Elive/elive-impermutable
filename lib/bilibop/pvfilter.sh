# /lib/bilibop/pvfilter.sh
# vim: set et sw=4 sts=4 ts=4 fdm=marker fcl=all:

# The pvfilter functions need those of bilibop-common:
. /lib/bilibop/common.sh

# See lvm.conf(5) and pvfilter(8) manpages for details.

# _pvfilter_delimiter() ====================================================={{{
# What we want is: set a valid (objective) and readable (subjective) delimiter.
# Pipes can be used as delimiters between alternatives into the string, and
# slashes are used as delimiters in the paths of the files. Given that we
# already use a delimiter in the sed's subtitute commands, we have to choose
# something else, that is not a metacharacter (i.e. must not be interpreted by
# the shell, sed or lvm parser) and should not be encountered in the string to
# build. Some valid delimiters can be used as is from the shell, some others
# must be escaped or quoted... Use at your own risk.
# And the question is... What is the most readable?
_pvfilter_delimiter() {
    ${DEBUG} && echo "> _pvfilter_delimiter $@" >&2
    case "${1}" in
        "!"|"#"|"%"|"+"|","|"."|":"|";"|"="|"@"|"|"|"/")
            B="${1}"
            E="${1}"
            ;;
        "()"|"[]"|"{}")
            B="${1%?}"
            E="${1#?}"
            ;;
        *)
            B="|"
            E="|"
            ;;
    esac
}
# ===========================================================================}}}
# _pvfilter_find_dev_links() ================================================{{{
# What we want is: output the symlinks to a device node given as argument. Note
# that 'udevadm info --query symlink --name DEVICE can give a different result,
# some links being 'omitted' (not managed by udev, even if it has created them).
_pvfilter_find_dev_links() {
    ${DEBUG} && echo "> _pvfilter_find_dev_links $@" >&2
    if  eval ${udev} ; then
        udevadm info --query symlink --name ${1} |
        sed 's, ,\n,g'
    else
        cd ${udev_root}
        find * -type l -ls |
        awk "/ (\.\.\/)*${1}$/ {print \$11}"
        cd ${OLDPWD}
    fi
}
# ===========================================================================}}}
# _pvfilter_accept_string() ================================================={{{
# What we want is: output a string in a valid format to be used directly inside
# the square brackets in the 'filter' array. First argument is a directory
# where to find symlinks to a device node, second argument is a basename of a
# symlink in this directory, or a list of basenames, separated by pipes (|).
_pvfilter_accept_string() {
    ${DEBUG} && echo "> _pvfilter_accept_string $@" >&2
    [ -n "${2}" ] || return 1
    [ "${B}" = "/" -o "${E}" = "/" ] && local B="|" E="|"
    if      echo "${2}" | grep -q '|'
    then    echo "a${B}${1:+^${1}}/(${2})\$${E}"
    else    echo "a${B}${1:+^${1}}/${2}\$${E}"
    fi
}
# ===========================================================================}}}
# _pvfilter_reject_string() ================================================={{{
# What we want is: output a string in a valid format to be used directly inside
# the square brackets in the 'filter' array. First argument is a directory
# where to find symlinks to a device node, second argument can be a basename of
# a symlink in this directory or the basename of a subdirectory; or a list of
# basenames, separated by pipes (|). The third argument, if it exists, can be
# -f or -d, and says how to suffix the string.
_pvfilter_reject_string() {
    ${DEBUG} && echo "> _pvfilter_reject_string $@" >&2
    [ -n "${2}" ] || return 1
    [ "${3}" = "-d" ] && local end="/.*" || local end="$"
    [ "${B}" = "/" -o "${E}" = "/" ] && local B="|" E="|"
    if      echo "${2}" | grep -q '|'
    then    echo "r${B}${1:+^${1}}/(${2})${end}${E}"
    else    echo "r${B}${1:+^${1}}/${2}${end}${E}"
    fi
}
# ===========================================================================}}}
# _pvfilter_list_tagged_devices() ==========================================={{{
# What we want is: output the list of the block devices that have been tagged
# by udev with the tag given as argument (In Bilibop, this should be BILIBOP or
# INSIDEV).
_pvfilter_list_tagged_devices() {
    ${DEBUG} && echo "> _pvfilter_list_tagged_devices $@" >&2
    grep '[[:digit:]]' /proc/partitions |
    while read major minor size node ; do
        [ -e "/run/udev/tags/${1}/b${major}:${minor}" ] &&
        echo "${node}"
    done
}
# ===========================================================================}}}
# _pvfilter_list_other_devices() ============================================{{{
# What we want is: output the list of physical and virtual block devices not
# inside the computer nor on the same disk than the root filesystem. This is
# based on udev tags.
_pvfilter_list_other_devices() {
    ${DEBUG} && echo "> _pvfilter_list_other_devices $@" >&2
    grep '[[:digit:]]' /proc/partitions |
    while read major minor size node ; do
        [ "${major}" = "11" ] && continue
        for TAG in $@ ; do
            [ -e "/run/udev/tags/${TAG}/b${major}:${minor}" ] && continue 2
        done
        echo "${node}"
    done
}
# ===========================================================================}}}
# _pvfilter_list_devices() =================================================={{{
# What we want is: output a list of devices that can be given as arguments;
# otherwise the argument is a keyword.
_pvfilter_list_devices() {
    ${DEBUG} && echo "> _pvfilter_list_devices $@" >&2
    case "${1}" in
        all)
            device_nodes ;;
        insidev)
            _pvfilter_list_tagged_devices "INSIDEV" ;;
        bilibop)
            _pvfilter_list_tagged_devices "BILIBOP" ;;
        other)
            _pvfilter_list_other_devices "BILIBOP" "INSIDEV" ;;
        ${udev_root}/*)
            for i in ${*} ; do readlink -f ${i} ; done ;;
    esac
}
# ===========================================================================}}}
# _pvfilter_list_filter_devices() ==========================================={{{
# What we want is: build a string usable in the lvm.conf 'filter' array for
# accepted devices (can be a single device, or a class: bilibop, insidev, other)
# We don't want to use device names, because they are dynamically assigned. But
# some symlinks are dynamic too (as in /dev/block) or not managed by udev.
# Finally, the only ones we can use are /dev/disk/by-id/* for physical devices
# and /dev/mapper/* for dm devices.
_pvfilter_list_filter_devices() {
    ${DEBUG} && echo "> _pvfilter_list_filter_devices $@" >&2
    diskid=
    dmname=
    lvname=
    for dev in $(_pvfilter_list_devices ${1}) ; do
        dev=${dev##*/}
        echo "${ALREADY_DONE}" | grep -q "\<${dev}\>" && continue
        ALREADY_DONE="${ALREADY_DONE:+${ALREADY_DONE} }${dev}"
        ID_FS_TYPE=
        DM_LV_NAME=
        DM_VG_NAME=
        eval $(query_udev_envvar ${dev})
        [ "${ID_FS_TYPE}" = "LVM2_member" ] || continue

        case "${dev}" in
            dm-*)
                for link in $(_pvfilter_find_dev_links ${dev}) ; do
                    # A LV can also be used as PV for another VG
                    if  [ -n "${DM_VG_NAME}" -a -n "${DM_LV_NAME}" ] ; then
                        [ "${link}" = "${DM_VG_NAME}/${DM_LV_NAME}" ] &&
                        lvname="${lvname:+${lvname}|}${link}" &&
                        break
                    fi

                    case "${link}" in
                        mapper/*)
                            dmname="${dmname:+${dmname}|}${link##*/}"
                            break
                            ;;
                        disk/by-id/*)
                            diskid="${diskid:+${diskid}|}${link##*/}"
                            break
                            ;;
                        *)
                            continue
                            ;;
                    esac
                done
                ;;
            *)
                for link in $(_pvfilter_find_dev_links ${dev}) ; do
                    case "${link}" in
                        disk/by-id/*)
                            diskid="${diskid:+${diskid}|}${link##*/}"
                            break
                            ;;
                        *)
                            continue
                            ;;
                    esac
                done
                ;;
        esac
    done

    dmname="$(echo ${dmname} | sed 's,|,\n,g')"
    dmname="$(echo ${dmname} | sed 's, ,|,g')"
    diskid="$(echo ${diskid} | sed 's,|,\n,g')"
    diskid="$(echo ${diskid} | sed 's, ,|,g')"
}
# ===========================================================================}}}
# _pvfilter_list_exclude_devices() =========================================={{{
# What we want is: build a string usable in the lvm.conf 'filter' array for
# rejected devices (can be a single device, or a class: bilibop, insidev, other)
# For the acceptance behaviour, only one device/symlink can be used, but to
# ignore a device, we have to ignore all its symlinks, some of them being
# dynamically attributed (as in /dev/block or /dev/disk/by-path). What we know
# is that a PV has no symlink in /dev/disk/by-label and /dev/disk/by-uuid, and
# links as /dev/disk/by-id/dm-uuid-* are static. Only physical block devices
# can have a symlink in /dev/disk/by-path. The dmname of a dm device being
# arbitrarly fixed by the user, links such as /dev/disk/by-id/dm-name-* and
# /dev/mapper/* can be considered as static but are subject to changes. The
# same can be said for a PV using a LV instead of a partition as its underlying
# device: there can be symlinks to manage in /dev/<VG_NAME>. Arrrgh! And it
# would be nice, for readability, to avoid duplicates.
_pvfilter_list_exclude_devices() {
    ${DEBUG} && echo "> _pvfilter_list_exclude_devices $@" >&2
    devlist=
    dirlist=
    for dev in $(_pvfilter_list_devices ${1}) ; do
        dev=${dev##*/}
        echo "${ALREADY_DONE}" | grep -q "\<${dev}\>" && continue
        ALREADY_DONE="${ALREADY_DONE:+${ALREADY_DONE} }${dev}"
        ID_FS_TYPE=
        eval $(query_udev_envvar ${dev})
        [ "${ID_FS_TYPE}" = "LVM2_member" ] || continue
        devlist="${devlist:+${devlist}|}${dev}"

        for link in $(_pvfilter_find_dev_links ${dev}) ; do
            case "${link}" in
                block/*)
                    [ -z "${reject_block}" ] &&
                    dirlist="${dirlist:+${dirlist}|}${link%/*}" &&
                    reject_block="done"
                    ;;
                disk/by-path/*)
                    [ -z "${reject_path}" ] &&
                    dirlist="${dirlist:+${dirlist}|}${link%/*}" &&
                    reject_path="done"
                    ;;
                disk/by-id/*)
                    devlist="${devlist:+${devlist}|}${link##*/}"
                    ;;
                *)
                    devlist="${devlist:+${devlist}|}${link}"
                    ;;
            esac
        done
    done

    devlist="$(echo ${devlist} | sed 's,|,\n,g')"
    devlist="$(echo ${devlist} | sed 's, ,|,g')"
    dirlist="$(echo ${dirlist} | sed 's,|,\n,g')"
    dirlist="$(echo ${dirlist} | sed 's, ,|,g')"
}
# ===========================================================================}}}
# _pvfilter_list_pv() ======================================================={{{
# What we want is: bypass the lvm.conf settings and list all possible Physical
# Volumes (in fact, block devices with the LVM2_member fstype) and optionally
# their symlinks: all symlinks (--show) or only those actually managed by udev
# (--udev).
_pvfilter_list_pv() {
    ${DEBUG} && echo "> _pvfilter_list_pv $@" >&2
    local node
    for node in $(device_nodes) ; do
        ID_FS_TYPE=
        eval $(query_udev_envvar ${node})
        [ "${ID_FS_TYPE}" = "LVM2_member" ] || continue
        echo ${udev_root}/${node}
        eval ${show} || eval ${udev} &&
            _pvfilter_find_dev_links ${node} | grep -v '^$' |
            sed "s,^,\t${udev_root}/,"
    done
}
# ===========================================================================}}}
# _pvfilter_init_lvm_configfile() ==========================================={{{
# What we want is: have valid 'obtain_device_list_from_udev' and 'filter'
# variables in a valid 'devices' section in lvm.conf; all is missing (the file,
# the section, the variables) must be created if necessary and possible.
_pvfilter_init_lvm_configfile() {
    ${DEBUG} && echo "> _pvfilter_init_lvm_configfile $@" >&2
    if  [ ! -f "${LVM_CONF}" ] ; then
        if  eval ${init} ; then
            if  ! mkdir -p ${LVM_CONF%/*} 2>/dev/null ; then
                echo "${PROG}: unable to create ${LVM_CONF%/*}." >&2
                return 10
            fi

            if  [ ! -w "${LVM_CONF%/*}" ] ; then
                echo "${PROG}: unable to create ${LVM_CONF}: no write permission on ${LVM_CONF%/*}." >&2
                return 10

            else
                cat >${LVM_CONF} <<EOF
# ${LVM_CONF}
# See lvm.conf(5)

devices {
    obtain_device_list_from_udev = 1
    filter = [ "a|.*|" ]
}
EOF
                chmod 644 ${LVM_CONF}
            fi

        else
            echo "${PROG}: ${LVM_CONF} does not exist." >&2
            echo "Use '--init' option to create it." >&2
            return 10
        fi
    else
        if  eval ${init} ; then
            echo "${PROG}: what's the need to use '--init' option ?" >&2
            return 1
        else
            return 0
        fi
    fi
}
# ===========================================================================}}}
# _pvfilter_init_device_filters() ==========================================={{{
# What we want is: have a valid 'filter' variable in a valid 'devices' section
# in lvm.conf; all is missing (the file, the section, the variable) must be
# created if necessary and possible.
_pvfilter_init_device_filters() {
    ${DEBUG} && echo "> _pvfilter_init_device_filters $@" >&2
    grep -q '^[[:blank:]]*obtain_device_list_from_udev[[:blank:]]*=' ${LVM_CONF}
    local have_obtain="$?"
    grep -q '^[[:blank:]]*filter[[:blank:]]*=' ${LVM_CONF}
    local have_filter="$?"
    grep -q '^[[:blank:]]*devices[[:blank:]]*{' ${LVM_CONF}
    local have_devices="$?"

    if  [ "${have_devices}" = "1" ] &&
        [ "${have_filter}" = "0" -o "${have_obtain}" = "0" ] ; then
        # Inconsistency
        echo "${PROG}: ${LVM_CONF} seems to be inconsistent." >&2
        return 13

    elif [ "${have_devices}" = "1" ] ; then
        # Add devices section with minimal content
        if  eval ${init} ; then
            if  [ ! -w "${LVM_CONF}" ] ; then
                echo "${PROG}: no write permission on ${LVM_CONF}" >&2
                return 10
            else
                cat >>${LVM_CONF} <<EOF

devices {
    obtain_device_list_from_udev = 1
    filter = [ "a|.*|" ]
}
EOF
            fi

        else
            echo "${PROG}: 'devices' section is missing in ${LVM_CONF}." >&2
            echo "Use '--init' option to create it." >&2
            return 10
        fi

    elif [ "${have_filter}" = "0" -a "${have_obtain}" = "0" ] ; then
        if  eval ${init} ; then
            echo "${PROG}: what's the need to use '--init' option ?" >&2
            return 1
        else
            return 0
        fi

    else
        if  eval ${init} && [ ! -w "${LVM_CONF}" ] ; then
            echo "${PROG}: no write permission on ${LVM_CONF}" >&2
            return 10
        fi
        [ "${have_filter}" = "1" ] &&
        # Add 'filter' variable
        if  eval ${init} ; then
            sed -i 's,^[[:blank:]]*devices[[:blank:]]*{.*,&\n    filter = [ "a|.*|" ],' ${LVM_CONF}
        else
            echo "${PROG}: 'filter' variable is missing in ${LVM_CONF}." >&2
            echo "Use '--init' option to create it." >&2
            return 10
        fi
        [ "${have_obtain}" = "1" ] &&
        # Add 'obtain_device_list_from_udev' variable
        if  eval ${init} ; then
            sed -i 's,^[[:blank:]]*devices[[:blank:]]*{.*,&\n    obtain_device_list_from_udev = 1,' ${LVM_CONF}
        else
            echo "${PROG}: 'obtain_device_list_from_udev' variable is missing in ${LVM_CONF}." >&2
            echo "Use '--init' option to create it." >&2
            return 10
        fi
    fi
}
# ===========================================================================}}}

