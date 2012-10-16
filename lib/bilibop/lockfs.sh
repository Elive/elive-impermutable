# /lib/bilibop/lockfs.sh
# vim: set et sw=4 sts=4 ts=4 fdm=marker fcl=all:

# The bilibop-lockfs functions need those of bilibop-common:
. /lib/bilibop/common.sh
get_bilibop_variables ${rootmnt}

# lock_file() ==============================================================={{{
# What we want is: add a filename to the list of files that have been modified
# by the 'bilibop-lockfs' local-bottom initramfs script.
lock_file() {
    ${DEBUG} && echo "> lock_file $@" >&2
    grep -q "^${1}$" ${BILIBOP_RUNDIR}/lock ||
    echo "${1}" >>${BILIBOP_RUNDIR}/lock
}
# ===========================================================================}}}
# remount_ro() =============================================================={{{
# What we want is: remount as readonly the lower branch of an aufs mountpoint
# given as argument.
remount_ro() {
    ${DEBUG} && echo "> remount_ro $@" >&2
    is_aufs_mountpoint -q "${1}" || return 1
    mount -o remount,ro $(aufs_readonly_branch "${1}")
}
# ===========================================================================}}}
# remount_rw() =============================================================={{{
# What we want is: remount as writable the lower branch of an aufs mountpoint
# given as argument.
remount_rw() {
    ${DEBUG} && echo "> remount_rw $@" >&2
    is_aufs_mountpoint -q "${1}" || return 1
    mount -o remount,rw $(aufs_readonly_branch "${1}")
}
# ===========================================================================}}}
# blockdev_root_subtree() ==================================================={{{
# What we want is: set 'ro' or 'rw' the filesystem and its hosting disk given
# as arguments, and all other devices between them. For example, if the first
# one is a Logical Volume (/dev/dm-3) onto a LUKS partition (/dev/sdb1), this
# will modify settings for /dev/dm-3, /dev/sdb, /dev/dm-0 and /dev/sdb1. The
# main option (--setro or --setrw) must be the first argument, and the disk
# node the last one.
blockdev_root_subtree() {
    ${DEBUG} && echo "> blockdev_root_subtree $@" >&2
    local   dev="${2}"
    # Here blockdev must be called two times (give the two arguments in the
    # same command line don't work with the busybox's blockdev implementation).
    blockdev --set"${1}" "${2}"
    blockdev --set"${1}" "${3}"
    while   true
    do
        case    "${dev##*/}" in
                dm-*)
                    dev="$(parent_device_from_dm ${dev})"
                    ;;
                loop*)
                    dev="$(underlying_device_from_loop "${dev}")"
                    ;;
                *)
                    # If a logical partition has to be locked, lock the
                    # primary extended partition too. Only for ms-dos
                    # partition tables.
                    extended="$(extended_partition "${3}")" ||
                        return 0
                    [ $(cat /sys/class/block/${dev##*/}/partition) -gt 4 ] &&
                        dev="${extended}" ||
                        return 0
                    ;;
        esac
        blockdev --set"${1}" "${dev}"
    done
}
# ===========================================================================}}}
# get_swap_policy() ========================================================={{{
# What we want is: output the policy to apply for swap devices. If it is set in
# bilibop.conf, apply it; otherwise, the fallback depends on the 'removable'
# flag in the sysfs attributes.
get_swap_policy() {
    ${DEBUG} && echo "> get_swap_policy $@" >&2
    case    "${BILIBOP_LOCKFS_SWAP_POLICY}" in
        soft|hard|noauto|crypt)
            echo "${BILIBOP_LOCKFS_SWAP_POLICY}"
            ;;
        *)
            # If BILIBOP_LOCKFS_SWAP_POLICY is not set to
            # a known value, use a heuristic to know what
            # to do:
            is_removable "${BILIBOP_DISK}" &&
            echo "hard" ||
            echo "crypt"
            ;;
    esac
}
# ===========================================================================}}}
# is_a_crypt_target() ======================================================={{{
# What we want is: parse /etc/crypttab and if the device (/dev/mapper/*) is
# encountered as being the target, return 0; otherwise, return 1.
is_a_crypt_target() {
    ${DEBUG} && echo "> is_a_crypt_target $@" >&2
    while   read TARGET SOURCE KEY_FILE CRYPT_OPTS
    do
            if      [ "${TARGET}" != "${1##*/}" ]
            then    unset TARGET SOURCE KEY_FILE CRYPT_OPTS
            else    return 0
            fi
    done <${CRYPTTAB}
    return 1
}
# ===========================================================================}}}
# is_encrypted() ============================================================{{{
# What we want is: know if a mapped device name (/dev/mapper/something) given
# as argument is or will be encrypted with cryptsetup (we don't manage other
# programs such as cryptmount or mount.crypt).
is_encrypted() {
    ${DEBUG} && echo "> is_encrypted $@" >&2
    [ -f "${CRYPTTAB}" ] || return 1

    case    "${1}" in
        ${UDEV_ROOT}/*)
            dev="$(echo "${1}" | sed "s,^${UDEV_ROOT},${udev_root},")"
            ;;
        LABEL=*)
            dev="${udev_root}/disk/by-label/${1#LABEL=}"
            ;;
        UUID=*)
            dev="${udev_root}/disk/by-uuid/${1#UUID=}"
            ;;
        *)
            return 1
            ;;
    esac

    dev="$(readlink -f "${dev}")"

    while   true
    do
        case    "${dev}" in
            ${udev_root}/dm-*)
                # This may be an encrypted swap device, but also a Logical Volume
                # containing a swap filesystem. In the last case, is the Volume
                # Group inside an encrypted container?
                is_a_crypt_target "$(mapper_name_from_dm_node "${dev}")" && return 0
                dev="$(parent_device_from_dm ${dev})"
                ;;
            *)
                # This is not an encrypted swap device, or we don't know how to
                # manage it.
                return 1
                ;;
        esac
    done
    return 1
}
# ===========================================================================}}}
# apply_swap_policy() ======================================================={{{
# What we want is: modify temporary /etc/fstab and /etc/crypttab by commenting
# swap entries or modifying their options.
apply_swap_policy() {
    ${DEBUG} && echo "> apply_swap_policy $@" >&2
    case    "$(get_swap_policy)" in
        soft)
            # Nothing to do
            ;;
        hard)
            sed -i "s|^\s*${1}\s\+none\s\+swap\s.*|${comment}\n#&\n|" ${FSTAB}

            CRYPTTAB="${rootmnt}/etc/crypttab"
            if      is_encrypted "${1}"
            then
                    sed -i "s|^\s*${TARGET}\s\+${SOURCE}.*|${comment}\n#&\n|" ${CRYPTTAB}
                    lock_file "/etc/crypttab"
            fi
            ;;
        noauto)
            noauto="${1} none swap noauto 0 0"
            sed -i "s|^\s*${1}\s\+none\s\+swap\s.*|${comment}\n#&\n${replace}\n${noauto}\n|" ${FSTAB}

            CRYPTTAB="${rootmnt}/etc/crypttab"
            if      is_encrypted "${1}"
            then
                    noauto="${TARGET} ${SOURCE} ${KEY_FILE} ${CRYPT_OPTS},noauto"
                    sed -i "s|^\s*${TARGET}\s\+${SOURCE}.*|${comment}\n#&\n${replace}\n${noauto}\n|" ${CRYPTTAB} &&
                    lock_file "/etc/crypttab"
            fi
            ;;
        crypt)
            CRYPTTAB="${rootmnt}/etc/crypttab"
            is_encrypted "${1}" ||
            sed -i "s|^\s*${1}\s\+none\s\+swap\s.*|${comment}\n#&\n|" ${FSTAB}
            ;;
    esac
}
# ===========================================================================}}}
# parse_and_modify_fstab() =================================================={{{
# What we want is: modify some entries in /etc/fstab and optionally in
# /etc/crypttab. This should apply only on block devices, and only on those
# that have not been whitelisted in bilibop.conf(5). Replace the fstype by
# 'lockfs', and modify options to remember the original fstype. This will be
# used by the mount.lockfs helper.
parse_and_modify_fstab() {
    ${DEBUG} && echo "> parse_and_modify_fstab $@" >&2
    grep -v '^\s*\(#\|$\)' ${FSTAB} |
    while   read device mntpnt fstype option dump pass
    do
        # Due to the pipe (|) before the 'while' loop, we are now in a
        # subshell. The variables just previously set (device, mntpnt,
        # fstype, option, dump, pass) have no sense outside of this loop.
        # Don't use them later (after the 'done').

        case    "${fstype}" in
            swap)
                # Special settings for swap devices
                grep -q '\<noswap\>' /proc/cmdline ||
                apply_swap_policy "${device}"
                continue
                ;;
            none|ignore|tmpfs)
                # Don't modify some entries
                continue
                ;;
        esac

        # Don't modify the "noauto" mount lines:
        echo "${option}" | grep -q '\<noauto\>' && continue

        # Skip what we are sure that it is not a local block device:
        case	"${device}" in
            UUID=*|LABEL=*|${UDEV_ROOT}/*)
                ;;
            *)
                continue
                ;;
        esac

        # Skip locking device if whitelisted by the sysadmin. Three formats
        # are accepted: the mountpoint itself, a (symlink to a) device name,
        # or a metadata about the filesystem (allowing to use something like
        # TYPE=vfat for any mountpoint).
        for skip in ${BILIBOP_LOCKFS_WHITELIST}
        do
            case    "${skip}" in
                ${device})
                    continue 2
                    ;;
                ${mntpnt})
                    continue 2
                    ;;
                TYPE=${fstype})
                    continue 2
                    ;;
            esac
        done

        # For each filesystem to lock, modify the line in fstab. A mount
        # helper script will manage it later:
        #log_warning_msg "${0##*/}: Preparing to lock: ${mntpnt}."

        sed -i "s|^\s*${device}\s\+${mntpnt}\s.*|${comment}\n#&\n${replace}\n${device} ${mntpnt} lockfs fstype=${fstype},${option} ${dump} ${pass}\n|" ${FSTAB}

    done
}
# ===========================================================================}}}
# add_lockfs_mount_helper() ================================================={{{
# What we want is: add a mount helper script (or a symlink to it) to an aufs
# mountpoint given as argument (this should be the next root of the system from
# the point of view of the initramfs).
add_lockfs_mount_helper() {
    ${DEBUG} && echo "> add_lockfs_mount_helper $@" >&2
    if      [ -x ${1}/lib/bilibop/lockfs_mount_helper ]
    then
            # lockfs_mount_helper is usable as is, so symlink it:
            ln -s /lib/bilibop/lockfs_mount_helper ${1}/sbin/mount.lockfs

    elif    [ -f ${1}/lib/bilibop/lockfs_mount_helper ]
    then
            # lockfs_mount_helper is not executable
            cp ${1}/lib/bilibop/lockfs_mount_helper ${1}/sbin/mount.lockfs
            chmod +x ${1}/sbin/mount.lockfs

    else    # lockfs_mount_helper is missing. Create a fallback script.
            # It will not set an aufs and its lower and upper branches,
            # but only recalls 'mount' with valid options.
            cat >${1}/sbin/mount.lockfs <<EOF
#!/bin/sh
# THIS IS A FALLBACK; IT DON'T LOCK FS BUT JUST RECALLS /bin/mount WITH VALID FSTYPE AND OPTIONS.
PATH="/bin"
[ "\$(readlink -f /proc/\${PPID}/exe)" = "/bin/mount" ] || exit 3
for opt in \$(IFS=',' ; echo \${4}) ; do
    case "\${opt}" in
        fstype=*) eval "\${opt}" ;;
        *) mntopt="\${mntopt:+\${mntopt},}\${opt}" ;;
    esac
done
exec mount \${1} \${2} \${fstype:+-t \${fstype}} \${mntopt:+-o \${mntopt}}
EOF
            chmod +x ${1}/sbin/mount.lockfs
    fi
    lock_file "/sbin/mount.lockfs"
}
# ===========================================================================}}}
# check_mount_lockfs() ======================================================{{{
# What we want is: check if /sbin/mount.lockfs exists in the future root
# filesystem given as argument, and if it is executable. If not, add it.
check_mount_lockfs() {
    ${DEBUG} && echo "> check_mount_lockfs $@" >&2
    if      [ -h ${1}/sbin/mount.lockfs ]
    then
            # /sbin/mount.lockfs already exist and is a symlink.
            # Is it absolute or relative ?
            helper="$(readlink ${1}/sbin/mount.lockfs)"
            case    "${helper}" in
                /*)
                    helper="${1}${helper}"
                    ;;
                ?*)
                    helper="${1}/sbin/${helper}"
                    ;;
            esac

            if      [ ! -f "${helper}" -o ! -x "${helper}" ]
            then
                    # There is a problem with the target. So, remove the
                    # symlink and add a new lockfs mount helper.
                    rm -rf ${1}/sbin/mount.lockfs
                    add_lockfs_mount_helper "${1}"
            fi

    elif    [ -f ${1}/sbin/mount.lockfs -a -x ${1}/sbin/mount.lockfs ]
    then
            # This probably means the sysadmin has written its own helper
            # program. Don't modify this.
            :

    else    rm -rf ${1}/sbin/mount.lockfs
            add_lockfs_mount_helper "${1}"
    fi
}
# ===========================================================================}}}
# mount_fallback() =========================================================={{{
# What we want is: mount a device on its original mountpoint and rewrite the
# fstab entry to keep it coherent. This function should be called in case of
# error or if the device is whitelisted. Device, mountpoint, type and options
# must be given as argument (in this order), each of them being inserted
# between double quotes.
mount_fallback() {
    ${DEBUG} && echo "> mount_fallback $@" >&2
    sed -i "s;^\s*[^#][^ ]\+\s\+${2}\s\+lockfs\s.*;${1} ${2} ${3:-auto} ${4:-defaults} 0 0;" /etc/fstab
    exec mount ${1} ${2} ${3:+-t ${3}} ${4:+-o ${4}}
}
# ===========================================================================}}}
# initialize_lvm_conf() ====================================================={{{
# What we want is: create lvm.conf or modify it if one of the file itself, the
# 'devices' section or the 'filter' array is missing.
initialize_lvm_conf() {
    ${DEBUG} && echo "> overwrite_lvm_conf $@" >&2
    eval $(grep '^\s*LVM_SYSTEM_DIR=' ${rootmnt}/etc/environment)
    LVM_CONF="${rootmnt}${LVM_SYSTEM_DIR:=/etc/lvm}/lvm.conf"

    if      [ ! -f "${LVM_CONF}" ]
    then
            mkdir -p ${LVM_CONF%/*}
            cat >${LVM_CONF} <<EOF
# ${LVM_SYSTEM_DIR}/lvm.conf
# Build on the fly by ${0##*/} from the initramfs.
# See lvm.conf(5) and bilibop(7) for details.
devices {
    dir = "${1}"
    scan = [ "${1}" ]
    obtain_device_list_from_udev = 1
    filter = [ "a#.*#" ]
    sysfs_scan = 1
}
EOF
            return 0
    fi

    >>${LVM_CONF}
    lock_file "${LVM_SYSTEM_DIR}/lvm.conf"

    if      ! grep -q '^\s*devices\s*{' ${LVM_CONF}
    then
            cat >>${LVM_CONF} <<EOF
# Added on the fly by ${0##*/} from the initramfs.
# See lvm.conf(5) and bilibop(7) for details.
devices {
    dir = "${1}"
    scan = [ "${1}" ]
    obtain_device_list_from_udev = 1
    filter = [ "a#.*#" ]
    sysfs_scan = 1
}
EOF
    elif    ! grep -q '^\s*filter\s*=' ${LVM_CONF}
    then
            sed -i "s;^\s*devices\s*{;&\n    filter = [ \"a#.*#\" ]\n;" ${LVM_CONF}
    fi
}
# ===========================================================================}}}
# blacklist_bilibop_devices() ==============================================={{{
# What we want is: avoid breakage of readonly settings by lvm tools, especially
# 'vgchange -ay'. This command usually bypasses the 'ro' attribute of a block
# device (obtained with 'blockdev --setro DEVICE' or 'hdparm -r1 DEVICE'), and
# silently unmounts it. If this device contains the root filesystem, it can
# happen that all is mounted on / is silently unmounted (/boot, /home, /proc,
# /sys, /dev, /tmp and more) and becomes unmountable until the next reboot.
# So, we need to blacklist all known bilibop Physical Volumes by setting the
# 'filter' array in lvm.conf(5).
blacklist_bilibop_devices() {
    ${DEBUG} && echo "> blacklist_bilibop_devices $@" >&2
    [ -x "${rootmnt}/sbin/lvm" -a -x "/sbin/lvm" ] || return 0

    local   node
    initialize_lvm_conf "${UDEV_ROOT}"

    for node in $(device_nodes)
    do
        [ "${udev_root}/${node}" = "${BILIBOP_DISK}" ] &&
            continue
        [ "$(physical_hard_disk ${udev_root}/${node})" != "${BILIBOP_DISK}" ] &&
            continue

        blacklist=
        ID_FS_TYPE=
        DEVLINKS=
        eval $(query_udev_envvar ${node})
        [ "${ID_FS_TYPE}" = "LVM2_member" ] ||
            continue

        DEVLINKS="$(echo ${DEVLINKS} | sed "s,${udev_root}/,,g")"
        [ "${udev_root}/${node}" = "${BILIBOP_PART}" ] &&
            DEVLINKS="${BILIBOP_COMMON_BASENAME}/part ${DEVLINKS}"
        blacklist="$(echo ${node} ${DEVLINKS} | sed 's, \+,|,g')"

        sed -i "s;^\s*filter\s*=\s*\[\s*;&\"r#^${1}/(${blacklist})\$#\", ;" ${LVM_CONF}
    done
}
# ===========================================================================}}}

