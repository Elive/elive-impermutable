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
# blockdev_rootdev_tree() ==================================================={{{
# What we want is: set 'ro' or 'rw' the filesystem and its hosting disk given
# as arguments, and all other devices between them. For example, if the first
# one is a Logical Volume (/dev/dm-3) onto a LUKS partition (/dev/sdb1), this
# will modify settings for /dev/dm-3, /dev/sdb, /dev/dm-0 and /dev/sdb1. The
# main option (--setro or --setrw) must be the first argument, and the disk
# node the last one.
blockdev_rootdev_tree() {
    ${DEBUG} && echo "> blockdev_rootdev_tree $@" >&2
    local   dev="${2}"
    # I don't know why, but here blockdev must be called two times (give the
    # two arguments in the same command line seem to not work in initramfs).
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
            # a known value, use an heuristic to know what
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
        ${UDEV_ROOT}/mapper/*)
            # This may be an encrypted swap device, but also a Logical Volume
            # containing a swap filesystem. In the last case, is the Volume
            # Group inside an encrypted container?
            ;;
        *)
            # This is not an encrypted swap device, or we don't know how to
            # manage it.
            return 1
            ;;
    esac

    is_a_crypt_target "${1}" && return 0

    # At this step, we know that the device is not directly mapped by
    # cryptsetup. But we know that /etc/crypttab exists, so we can try
    # something like: if the device already exixts, find its parent
    # device, and check if it is a cryptsetup target, and so on.

    # For the moment we have just parsed files without knowledge about
    # devices. Now we need to work on them:
    local   name
    local   dev="$(readlink -f ${udev_root}/mapper/${1##*/})"

    [ -b "${dev}" ] || return 1
    dev="$(parent_device_from_dm ${dev})"

    while   true
    do
            case    "${dev##*/}" in
                dm-*)
                    is_a_crypt_target "$(mapper_name_from_dm_node ${dev})" && return 0
                    dev="$(parent_device_from_dm ${dev})"
                    ;;
                *)
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
