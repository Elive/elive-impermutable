# /lib/bilibop/lockfs.sh
# vim: set et sw=4 sts=4 ts=4 fdm=marker fcl=all:

# The bilibop-lockfs functions need those of bilibop-common:
. /lib/bilibop/common.sh

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
# See also the NOTE in 'set_readonly_lvm_settings()' about why we don't use
# 'lvm lvchange --permission r' to set a LV as readonly.
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
# get_device_node() ========================================================={{{
# What we want is: output the device node from a given argument of the form
# /dev/*, LABEL=* or UUID=* such as they can be found in fstab. This means
# the LABEL may contain '/' characters that need to be translated to their
# hex value, but cannot contain space characters, as they are not managed by
# fstab parsers (i.e. mount).
get_device_node() {
    ${DEBUG} && echo "> get_device_node $@" >&2
    local symlink
    case "${1}" in
        ${UDEV_ROOT}/*)
            symlink="$(echo "${1}" | sed "s,^${UDEV_ROOT},${udev_root},")"
            ;;
        UUID=*)
            symlink="${udev_root}/disk/by-uuid/${1#UUID=}"
            ;;
        LABEL=*)
            symlink="${udev_root}/disk/by-label/$(echo "${1#LABEL=}" | sed -e 's,/,\\x2f,g')"
            ;;
    esac
    if [ -e "${symlink}" ]; then
        readlink -f ${symlink}
    else
        return 1
    fi
}
# ===========================================================================}}}
# get_swap_policy() ========================================================={{{
# What we want is: output the policy to apply for swap devices. If it is set in
# bilibop.conf, apply it; otherwise, the fallback depends on the 'removable'
# flag in the sysfs attributes.
get_swap_policy() {
    ${DEBUG} && echo "> get_swap_policy $@" >&2
    case    "${BILIBOP_LOCKFS_SWAP_POLICY}" in
        soft|hard|noauto|crypt|random)
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
    local dev="$(get_device_node "${1}")"

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
# is_randomly_encrypted() ==================================================={{{
# What we want is: parse /etc/crypttab and if the device (/dev/mapper/*) is
# encountered as being the target with a random key, return 0; otherwise,
# return 1.
is_randomly_encrypted() {
    ${DEBUG} && echo "> is_randomly_encrypted $@" >&2
    while   read TARGET SOURCE KEY_FILE CRYPT_OPTS
    do
            if      [ "${TARGET}" != "${1##*/}" ]
            then    unset TARGET SOURCE KEY_FILE CRYPT_OPTS
            else
                    case "${KEY_FILE}" in
                        ${UDEV_ROOT}/random|${UDEV_ROOT}/urandom)
                            return 0
                            ;;
                        *)
                            ;;
                    esac
            fi
    done <${CRYPTTAB}
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
        random)
            CRYPTTAB="${rootmnt}/etc/crypttab"
            is_randomly_encrypted "${1}" ||
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
    grep -v '^[[:blank:]]*\(#\|$\)' ${FSTAB} |
    while   read device mntpnt fstype option dump pass
    do
        # Due to the pipe (|) before the 'while' loop, we are now in a
        # subshell. The variables just previously set (device, mntpnt,
        # fstype, option, dump, pass) have no sense outside of this loop.
        # Don't use them later (after the 'done').

        case    "${fstype}" in
            swap)
                # Special settings for swap devices
                apply_swap_policy "${device}"
                continue
                ;;
            none|ignore|tmpfs|lockfs)
                # Don't modify some entries
                continue
                ;;
        esac

        # Don't modify the "noauto" mount lines nor the binded mounts:
        echo "${option}" | grep -q '\<\(noauto\|r\?bind\)\>' && continue

        # Skip what we are sure that it is not a local block device (or a
        # local file):
        case	"${device}" in
            UUID=*|LABEL=*|/*)
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
                ${device}|${mntpnt}|TYPE=${fstype})
                    [ -f "/etc/lvm/bilibop" ] &&
                    unlock_logical_volume ${device}
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
[ "\$(readlink -f /proc/\${PPID}/exe)" = "/usr/bin/mount" ] ||
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
# initialize_lvm_conf() ====================================================={{{
# What we want is: create lvm.conf or modify it if the file itself, or a
# required (for our purpose) section, or a required (for our purpose)
# variable/array is missing.
initialize_lvm_conf() {
    ${DEBUG} && echo "> initialize_lvm_conf $@" >&2

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
    filter = [ "a|.*|" ]
    global_filter = [ "a|.*|" ]
    sysfs_scan = 1
}

global {
    locking_type = 1
    metadata_read_only = 0
}

activation {
}
EOF
            return 0
    fi

    ##
    if      ! grep -q '^[[:blank:]]*devices[[:blank:]]*{' ${LVM_CONF}
    then    cat >>${LVM_CONF} <<EOF
# Added on the fly by ${0##*/} from the initramfs.
# See lvm.conf(5) and bilibop(7) for details.
devices {
    dir = "${1}"
    scan = [ "${1}" ]
    obtain_device_list_from_udev = 1
    filter = [ "a|.*|" ]
    global_filter = [ "a|.*|" ]
    sysfs_scan = 1
}
EOF
    else
            grep -q '^[[:blank:]]*dir[[:blank:]]*=' ${LVM_CONF} ||
            sed -i "s;^\s*devices\s*{;&\n\tdir = \"${1}\"\n;" ${LVM_CONF}
            grep -q '^[[:blank:]]*scan[[:blank:]]*=' ${LVM_CONF} ||
            sed -i "s;^\s*devices\s*{;&\n\tscan = [ \"${1}\" ]\n;" ${LVM_CONF}
            grep -q '^[[:blank:]]*obtain_device_list_from_udev[[:blank:]]*=' ${LVM_CONF} ||
            sed -i 's;^\s*devices\s*{;&\n\tobtain_device_list_form_udev = 1\n;' ${LVM_CONF}
            grep -q '^[[:blank:]]*filter[[:blank:]]*=' ${LVM_CONF} ||
            sed -i 's;^\s*devices\s*{;&\n\tfilter = [ "a|.*|" ]\n;' ${LVM_CONF}
            grep -q '^[[:blank:]]*global_filter[[:blank:]]*=' ${LVM_CONF} ||
            sed -i 's;^\s*devices\s*{;&\n\tglobal_filter = [ "a|.*|" ]\n;' ${LVM_CONF}
            grep -q '^[[:blank:]]*sysfs_scan[[:blank:]]*=' ${LVM_CONF} ||
            sed -i 's;^\s*devices\s*{;&\n\tsysfs_scan = 1\n;' ${LVM_CONF}
    fi

    ##
    if      ! grep -q '^[[:blank:]]*global[[:blank:]]*{' ${LVM_CONF}
    then    cat >>${LVM_CONF} <<EOF
# Added on the fly by ${0##*/} from the initramfs.
# See lvm.conf(5) and bilibop(7) for details.
global {
    locking_type = 1
    metadata_read_only = 0
}
EOF
    else
            grep -q '^[[:blank:]]*locking_type[[:blank:]]*=' ${LVM_CONF} ||
            sed -i 's;^\s*global\s*{;&\n\tlocking_type = 1\n;' ${LVM_CONF}
            grep -q '^[[:blank:]]*metadata_read_only[[:blank:]]*=' ${LVM_CONF} ||
            sed -i 's;^\s*global\s*{;&\n\tmetadata_read_only = 0\n;' ${LVM_CONF}
    fi

    ##
    if      ! grep -q '^[[:blank:]]*activation[[:blank:]]*{' ${LVM_CONF}
    then    cat >>${LVM_CONF} <<EOF
# Added on the fly by ${0##*/} from the initramfs.
# See lvm.conf(5) and bilibop(7) for details.
activation {
}
EOF
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
# 'filter' and 'global_filter' arrays in lvm.conf(5). 'bilibop/part' and
# 'disk/by-id/lvm-pv-uuid-*' must be added manually because they do not exist
# yet (udev rules creating them are not included in the initramdisk).
blacklist_bilibop_devices() {
    ${DEBUG} && echo "> blacklist_bilibop_devices $@" >&2

    local   node
    for node in $(device_nodes)
    do
        [ "${udev_root}/${node}" = "${BILIBOP_DISK}" ] &&
            continue
        [ "$(physical_hard_disk ${udev_root}/${node})" != "${BILIBOP_DISK}" ] &&
            continue

        blacklist=
        ID_FS_TYPE=
        ID_FS_UUID_ENC=
        DEVLINKS=
        eval $(query_udev_envvar ${node})
        [ "${ID_FS_TYPE}" = "LVM2_member" ] ||
            continue

        DEVLINKS="$(echo ${DEVLINKS} | sed "s,${udev_root}/,,g")"
        [ "${udev_root}/${node}" = "${BILIBOP_PART}" ] &&
            DEVLINKS="${BILIBOP_COMMON_BASENAME}/part ${DEVLINKS}"
        [ -n "${ID_FS_UUID_ENC}" ] &&
            if ! echo ${DEVLINKS} | grep -q "/lvm-pv-uuid-${ID_FS_UUID_ENC}\>"; then
                DEVLINKS="${DEVLINKS} disk/by-id/lvm-pv-uuid-${ID_FS_UUID_ENC}"
            fi
        blacklist="$(echo ${node} ${DEVLINKS} | sed 's, \+,|,g')"

        sed -i "s;^\s*\(global_\)\?filter\s*=\s*\[\s*;&\"r#^${UDEV_ROOT}/(${blacklist})\$#\", ;" ${LVM_CONF}
    done
}
# ===========================================================================}}}
# set_readonly_lvm_settings() ==============================================={{{
# What we want is: overwrite temporary lvm.conf (into initrd or on aufs) and
# set some variables to make VG and LV read-only (content + metadata).
# In 'global' section:
#   locking_type = 4
#   metadata_read_only = 1
# In 'activation' section:
#   read_only_volume_list = [ "vg0/lv0", "vg0/lv1", "vg1/lv0", "vg1/lv1", "vg1/lv2" ]
#
# NOTE: we cannot use 'lvchange --permission r' here or elsewhere, because
# (unlike 'blockdev --setro'), this makes the readonly setup persistent, and
# this would need additional stuff to undo that at the good time by running
# 'lvchange --permission rw'. Additionally, this changes LV metadata, and this
# is exactly what we want to avoid.
set_readonly_lvm_settings() {
    ${DEBUG} && echo "> set_readonly_lvm_settings $@" >&2

    cp ${LVM_CONF} ${LVM_CONF}.bak

    sed -i 's|^\(\s*locking_type\s*=\s*\).*|\14|' ${LVM_CONF}
    # This prohibits execution of commands such as vgchange or lvchange in new
    # releases of lvm2, so don't do that:
    #sed -i 's|^\(\s*metadata_read_only\s*=\s*\).*|\11|' ${LVM_CONF}

    for lvm in $(cat /etc/lvm/bilibop)
    do
        ROVL="${ROVL:+${ROVL}, }\"${lvm}\""
    done
    [ -n "${ROVL}" ] || return 0

    if  grep -q '^[[:blank:]]*read_only_volume_list[[:blank:]]*=' ${LVM_CONF} ; then
        sed -i "s|^\s*read_only_volume_list\s*=\s*[|& ${ROVL},|" ${LVM_CONF}
    else
        sed -i "s|^\s*activation\s*{.*|&\n\tread_only_volume_list = [ ${ROVL} ]|" ${LVM_CONF}
    fi
}
# ===========================================================================}}}
# undo_readonly_dm_settings() ==============================================={{{
# What we want is: undo the readonly settings that have been done from the
# init-top initramfs script. At first, we have to restore lvm.conf in the
# initrd environment, and make Logical Volumes and dm-crypt devices writable.
undo_readonly_dm_settings() {
    ${DEBUG} && echo "> undo_readonly_dm_settings $@" >&2
    [ -f /etc/lvm/bilibop ] || return 0
    [ -f /etc/lvm/lvm.conf.bak ] || return 0
    mv /etc/lvm/lvm.conf.bak /etc/lvm/lvm.conf
    for dev in ${udev_root}/dm-*; do
        [ -b ${dev} ] &&
        blockdev --setrw ${dev}
    done
}
# ===========================================================================}}}
# activate_bilibop_lv() ====================================================={{{
# What we want is: activate Logical Volumes listed in /etc/lvm/bilibop. It can
# happen that some LV are not yet activated at this point: the initramfs lvm2
# script activates $ROOT and $resume only (the initramfs cryptroot script is
# less selective). After 'blacklist_bilibop_devices()', there will be no way
# for the lvm init script to activate missing LV, and mount (between others)
# will fail.
activate_bilibop_lv() {
    ${DEBUG} && echo "> activate_bilibop_lv $@" >&2
    [ -f /etc/lvm/bilibop ] || return 0
    local vg_lv
    for vg_lv in $(cat /etc/lvm/bilibop); do
        if [ ! -e "${udev_root}/${vg_lv}" ]; then
            lvm lvchange -a y --sysinit ${vg_lv}
        fi
    done
}
# ===========================================================================}}}
# unlock_logical_volume() ==================================================={{{
# What we want is: avoid mount errors for whitelisted devices/mountpoints. For
# that, we have to override, from the local-bottom script, some settings done
# from the init-top script: reset readonly attribute of a whitelisted Logical
# Volume, and remove it from the list of the Logical Volumes to set read-only.
# This function is called from parse_and_modify_fstab().
unlock_logical_volume() {
    ${DEBUG} && echo "> unlock_logical_volume $@" >&2
    local dev="$(get_device_node ${1})"

    for lvm in $(cat /etc/lvm/bilibop)
    do
        [ -e "${udev_root}/${lvm}" ] || continue
        if [ "$(readlink -f ${udev_root}/${lvm})" = "${dev}" ]
        then
            sed -i "s,^${lvm}$,," /etc/lvm/bilibop
            blockdev --setrw ${dev}
            break
        fi
    done
}
# ===========================================================================}}}
# plymouth_message() ========================================================{{{
# What we want is: tell plymouth daemon to display a message. (Plymouth is the
# name of the standard graphical boot splash on Linux)
plymouth_message() {
    ${DEBUG} && echo "> plymouth_message $@" >&2
	if      [ -x /bin/plymouth ] && plymouth --ping
    then    plymouth message --text="$@"
    fi
}
# ===========================================================================}}}
# is_physically_locked() ===================================================={{{
# What we want is: return 0 if a drive given as argument (generally a USB key
# or a SD/MMC card) is write-protected, i.e. physically locked by a switch,
# and 1 otherwise. Since this function relies on the output of dmesg, it must
# be called very early (or it may happen that the relevant info is flushed or
# unbuffered). As far as I know, only USB keys and Flash memory cards may have
# a switch to lock them; there are two 'syntaxes', depending on the media type.
is_physically_locked() {
    ${DEBUG} && echo "> is_physically_locked $@" >&2
    case "${1}" in
        sd?)
            if dmesg | grep -q "\[${1}\] [Ww]rite [Pp]rotect [Ii]s [Oo]n$"; then
                return 0
            fi
            ;;
        mmcblk?|mspblk?)
            if dmesg | grep -q "[[:blank:]]${1}: .* [1-9][0-9]*\(\.[0-9]\+\)\? [GM]i\?B (ro)$"; then
                return 0
            fi
            ;;
    esac
    return 1
}
# ===========================================================================}}}

