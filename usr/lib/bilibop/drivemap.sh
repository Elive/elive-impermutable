# /lib/bilibop/drivemap.sh
# vim: set et sw=4 sts=4 ts=4 fdm=marker fcl=all:

# The _drivemap_* functions need some more common functions:
. /lib/bilibop/common.sh
get_udev_root

### DRIVEMAP FUNCTIONS ###

# _drivemap_initial_indent() ================================================{{{
# What we want is: initialize the indentation values to show the disk map as
# a tree. We use the length of the $udev_root string to align indentations on
# the path separator (/). We will have to consider two types of indentation:
# the absolute one is N times the indent unit, N being the indentation level;
# the relative one is the addition of an indent unit to the previous
# indentation string, without knowledge of its level. Here we want the absolute
# form. The relative indentations will be set using local variables (local
# indent="${indent}${I}") in some functions. By this way we will go back to
# the previous indentation level after the function (and sub-functions) has
# terminated.
_drivemap_initial_indent() {
    ${DEBUG} && echo "> _drivemap_initial_indent $@" >&2
    I="$(echo ${udev_root} | sed 's;.; ;g')"
    indent=""
}
# ===========================================================================}}}
# _drivemap_max_mp_length() ================================================={{{
# What we want is: define the length of the longest mountpoint string to use it
# in a formated output (with a fixed width), but with aligned paths.
_drivemap_max_mp_length() {
    ${DEBUG} && echo "> _drivemap_max_mp_length $@" >&2
    local   length=1
    for	mp in $(grep "^${udev_root}/" /proc/mounts | sed 's,^[^ ]\+ \([^ ]\+\) .*,\1,')
    do  [ ${#mp} -gt ${length} ] && length=${#mp}
    done
    echo ${length}
}
# ===========================================================================}}}
# _drivemap_volume_size() ==================================================={{{
# What we want is: output the size of a device given as argument. This size
# will be added to the informations about the device, and must be human
# readable. To avoid some kind of confusion, we use the same units than the
# vendors, i.e powers of 10 instead of powers of 2 (factor 1000 instead of
# factor 1024). This size string is formated to be right-aligned into a six
# columns space, including the size unit. Sizes into /sys/class/block/*/size
# seem to be given in 512 bytes units, even when /sys/block/*/queue/*_size
# give something different. This can be verified with CDROMs, having a sector
# size of 2048 bytes.
_drivemap_volume_size() {
    ${DEBUG} && echo "> _drivemap_volume_size $@" >&2
    local   dev="${1}"
    local   size="$(cat /sys/class/block/${dev##*/}/size)"
    if      [ $((size*512/1000/1000/1000/1000)) -gt 1 ]
    then    printf "%6s" "$((size*512/1000/1000/1000/1000))TB"
    elif    [ $((size*512/1000/1000/1000)) -ge 10 ]
    then    printf "%6s" "$((size*512/1000/1000/1000))GB"
    elif    [ $((size*512/1000/1000)) -gt 10 ]
    then    printf "%6s" "$((size*512/1000/1000))MB"
    elif    [ $((size*512/1000)) -gt 10 ]
    then    printf "%6s" "$((size*512/1000))KB"
    else    printf "%6s" "$((size*512))B"
    fi
}
# ===========================================================================}}}
# _drivemap_mount_point() ==================================================={{{
# What we want is: output the mountpoint of a device given as argument. If the
# argument is a regular file, we assume the corresponding block device is a
# loopback device.
_drivemap_mount_point() {
    ${DEBUG} && echo "> _drivemap_mount_point $@" >&2
    local   dev mnt opt

    [ -f "${1}" ] &&
    for dev in /sys/block/loop?*/loop/backing_file
    do
        if      [ "${1}" = "$(cat ${dev})" ]
        then
                dev="${dev%/loop/backing_file}"
                dev="${udev_root}/${dev##*/}"
                eval set -- ${dev}
                break
        fi
    done

    grep '^/' /proc/mounts |
    while   read dev mnt opt
    do
        [ "$(readlink -f ${dev})" = "$(readlink -f ${1})" ] &&
        echo "${mnt}" &&
        return 0
    done

    grep '^/' /proc/swaps |
    while   read dev opt
    do
        [ "$(readlink -f ${dev})" = "$(readlink -f ${1})" ] &&
        echo "<SWAP>" &&
        return 0
    done
}
# ===========================================================================}}}
# _drivemap_whole_disk_id() ================================================={{{
# What we want is: output a string identifying the disk given as argument as
# surely as possible for a common user. If possible, this string should begin
# by the bus type, that says where the disk is connected to the computer, and
# include the vendor|manufacturer|product|model name.
_drivemap_whole_disk_id() {
    ${DEBUG} && echo "> _drivemap_whole_disk_id $@" >&2
    local   DRIVE_ID devlink bus

    # Some device id are not very comprehensive for the standard user. Try to
    # use the most explicit if possible...
    for bus in usb ieee1394 memstick scsi
    do
        for devlink in ${DEVLINKS}
        do
            case    "${devlink}" in
                /dev/disk/by-id/${bus}-*)
                    DRIVE_ID="${devlink#/dev/disk/by-id/}"
                    break 2
                    ;;
            esac
        done
    done

    # ...or fallback to the first one, except if it is the obscur wwn-0x*:
    # what to do with an hexadecimal number?
    [ -z "${DRIVE_ID}" ] &&
    for devlink in ${DEVLINKS}
    do
        case    "${devlink}" in
            /dev/disk/by-id/wwn-*)
                break
                ;;
            /dev/disk/by-id/*)
                DRIVE_ID="${devlink#/dev/disk/by-id/}"
                break
                ;;
        esac
    done

    # If not sufficient, try something else
    [ -z "${DRIVE_ID}" ] &&
    DRIVE_ID="${ID_SERIAL}"

    echo "${DRIVE_ID}"
}
# ===========================================================================}}}
# _drivemap_whole_disk_fs() ================================================={{{
_drivemap_whole_disk_fs() {
    ${DEBUG} && echo "> _drivemap_whole_disk_fs $@" >&2
    local   DRIVE_SIZE DRIVE_INFO

    if	    [ "${ID_CDROM}" = "1" ]
    then
            if      [ "${_info_}" = "true" ]
            then    DRIVE_SIZE="$(_drivemap_volume_size ${1})"
                    DRIVE_INFO="${ID_FS_TYPE:+${ID_FS_TYPE} | }${DRIVE_SIZE}"
            else    DRIVE_INFO=
            fi
            _drivemap_print_line "${I}${ID_FS_LABEL:-${1}}" "${DRIVE_INFO:+[ ${DRIVE_INFO} ]}" fill

    else
            if      [ "${_info_}" = "true" ]
            then    DRIVE_SIZE="$(_drivemap_volume_size ${1})"
                    DRIVE_INFO="${ID_FS_TYPE:+${ID_FS_TYPE} | }${DRIVE_SIZE}"
            else    DRIVE_INFO=
            fi
            _drivemap_print_line "${1}" "${DRIVE_INFO:+[ ${DRIVE_INFO} ]}" fill
    fi
}
# ===========================================================================}}}
# _drivemap_whole_disk() ===================================================={{{
# What we want is: generate the elements of a line about the whole disk given
# as argument
_drivemap_whole_disk() {
    ${DEBUG} && echo "> _drivemap_whole_disk $@" >&2
    local   DRIVE_ID DRIVE_SIZE DRIVE_INFO
    if      [ "${_info_}" = "true" ]
    then
            eval $(query_udev_envvar "${1}")

            DRIVE_ID="$(_drivemap_whole_disk_id ${1})"
            DRIVE_SIZE="$(_drivemap_volume_size ${1})"

            # No sense to attribute a size to an optical drive. Only the
            # inserted medium, if it exists, can have a size.
            [ "${ID_CDROM}" = "1" ] && DRIVE_SIZE="    --"

            # Catenate id and size and with a separator between them.
            DRIVE_INFO="${DRIVE_ID:+${DRIVE_ID} | }${DRIVE_SIZE}"
    fi

    # Print the result, but never fill the line with dots:
    _drivemap_print_line "${1}" "${DRIVE_INFO:+[ ${DRIVE_INFO} ]}" #fill
}
# ===========================================================================}}}
# _drivemap_dotline() ======================================================={{{
# What we want is: output a line of dots with a length depending of two numbers
# given as arguments.
_drivemap_dotline() {
    ${DEBUG} && echo "> _drivemap_dotline $@" >&2
    [ $((${_width_}-2-${1}-${2})) -gt 0 ] &&
    echo "........................................................................................................................................................................................................" |
    sed "s;^\(\.\{$((${_width_}-2-${1}-${2}))\}\).*;\1;"
}
# ===========================================================================}}}
# _drivemap_print_line() ===================================================={{{
# What we want is: output a device name and optionally information about
# it. The line can be indented, formated for 70 columns, and filled with
# dots to make it more readable. The first argument is the indentation
# string and the device name. It is mandatory. The second argument consists
# in informations about the device (device id and size, or fstype and size)
# between square brackets. It can be empty. If not, this information will
# be right-aligned. The last argument, optional, is a flag to say: fill
# the line between the device name and the informations with dots. Of
# course, this flag is ignored if the information block is not provided.
_drivemap_print_line() {
    ${DEBUG} && echo "> _drivemap_print_line $@" >&2
    [ "${_mountpoint_}" = "true" ] &&
    local   mntpnt="$(_drivemap_mount_point ${1%(\*)})"

    if      [ -n "${2}" -a "${3}" = "fill" ]
    then
            local   dotline="$(_drivemap_dotline ${#1} ${#2})"
            printf "${1} ${dotline} ${2}${mntpnt:+ ${mntpnt}}\n"

    elif    [ -n "${mntpnt}" -a "${3}" = "fill" ]
    then
            local   dotline="$(_drivemap_dotline ${#1} ${length})"
            printf "${1} ${dotline} ${mntpnt}\n"

    elif    [ -n "${2}" ]
    then
            printf "%s%*s\n" "${1}" $((${_width_}-${#1})) "${2}"

    else    printf "${1}\n"
    fi
}
# ===========================================================================}}}
# _drivemap_loopback_device() ==============================================={{{
# What we want is: print a line about a loop device associated to a file hosted
# on the device given as argument. After what we can check if there is some
# dm device or another loop device hosted on the loop device.
_drivemap_loopback_device() {
    ${DEBUG} && echo "> _drivemap_loopback_device $@" >&2
    local   dev loop lofile LOOP_SIZE LOOP_INFO
    # Set the indentation string relatively to the previous one, as this:
    # local indent="${indent}${I}"
    #        ^^^^      ^^^^
    #       local     global or at least inherited from the calling function.
    # The new (local) indent variable will be inherited by any function called
    # by this one.
    local   indent="${indent}${I}"

    # Check only associated loop devices (listed in /proc/partitions)
    for loop in $(grep '\sloop[0-9]\+$' /proc/partitions | sed 's,.*\s\([^ ]\+\)$,\1,')
    do
        # Reset dev - this is mandatory:
        dev=
        lofile=

        # Avoid infinite loops between loopback and dm devices, because each
        # of _drivemap_loopback_device and _drivemap_dmdevice_holder calls the
        # other:
        echo "${ALREADY_DONE}" | grep -qw "${loop}" && continue

        if      [ "$(underlying_device_from_loop ${udev_root}/${loop})" = "${udev_root}/${1}" ]
        then
                dev="${udev_root}/${loop}"
        fi
        [ -b "${dev}" ] || continue
        ALREADY_DONE="${ALREADY_DONE:+${ALREADY_DONE} }${loop}"

        [ "${_backing_file_}" = "true" ] &&
            lofile="$(backing_file_from_loop ${dev})"
        [ -e "${lofile}" ] ||
            lofile="${dev}"

        if      [ "${_info_}" = "true" ]
        then
                # ID_FS_* are not local; so reset it here:
                ID_FS_TYPE=
                eval "$(query_udev_envvar ${dev})"
                LOOP_SIZE="$(_drivemap_volume_size ${dev})"
                LOOP_INFO="${ID_FS_TYPE:+${ID_FS_TYPE} | }${LOOP_SIZE}"
        fi

        [ "${DEVICE}" = "${udev_root}/${loop}" ] &&
            [ "${_mark_}" = "true" ] &&
            device="${lofile}(*)" ||
            device="${lofile}"

        _drivemap_print_line "${indent}${device}" "${LOOP_INFO:+[ ${LOOP_INFO} ]}" fill
        _drivemap_loopback_device "${loop}"
        _drivemap_dmdevice_holder "${loop}"
    done
}
# ===========================================================================}}}
# _drivemap_dmdevice_holder() ==============================================={{{
# What we want is: find the dm devices hosted by the dm device or the partition
# given as argument, query informations about it (optional), output the result
# and continue by calling this function from inside itself.
_drivemap_dmdevice_holder() {
    ${DEBUG} && echo "> _drivemap_dmdevice_holder $@" >&2
    local   device holder mapped DEVICE_SIZE DEVICE_INFO
    # Set the indentation string relatively to the previous one:
    local   indent="${indent}${I}"
    [ "$(echo /sys/class/block/${1}/holders/*)" != "/sys/class/block/${1}/holders/*" ] ||
    return 1

    for	holder in /sys/class/block/${1}/holders/*
    do
        holder="${holder##*/}"
        device="${udev_root}/${holder}"
        if      [ "${_info_}" = "true" ]
        then
                ID_FS_TYPE=
                eval $(query_udev_envvar "${device}")
                DEVICE_SIZE="$(_drivemap_volume_size ${device})"
                DEVICE_INFO="${ID_FS_TYPE:+${ID_FS_TYPE} | }${DEVICE_SIZE}"
        fi
        [ "${_dm_name_}" = "true" ] &&
        case "${holder}" in
            dm-*)
                device="${udev_root}/mapper/$(mapper_name_from_dm_node ${holder})"
                ;;
        esac

        [ "${DEVICE}" = "${udev_root}/${holder}" ] &&
            [ "${_mark_}" = "true" ] &&
            device="${device}(*)"

        _drivemap_print_line "${indent}${device}" "${DEVICE_INFO:+[ ${DEVICE_INFO} ]}" fill
        _drivemap_loopback_device "${holder}"
        _drivemap_dmdevice_holder "${holder}"
    done
}
# ===========================================================================}}}
# _drivemap_primary_partitions() ============================================{{{
# What we want is: print a line about each primary partition. If there is an
# extended primary partition, we have to deal with an MBR partition scheme;
# partitions from number 5 to N are logical partitions, and included onto the
# extended one. Or, if there is no extended partition but partitions with a
# number greater than 4, we have to deal with a GPT partition table: this
# means all partitions will be on the same level (no more indent in the tree).
_drivemap_primary_partitions() {
    ${DEBUG} && echo "> _drivemap_primary_partitions $@" >&2
    local   n PART PART_SIZE PART_INFO

    # At first, find if there is an extended partition on the disk, to treat
    # logical partitions as subdevices of this extended one in the tree of
    # devices instead of sequentially.
    local   extended="$(extended_partition "${1}" | sed 's,.*\([1-4]\)$,\1,')"

    for	PART in ${1}?*
    do
        # Partition number:
        n="$(cat /sys/class/block/${PART##*/}/partition)"

        # Absolute indentation, first level:
        indent="${I}"

        ID_FS_TYPE=
        ID_PART_ENTRY_TYPE=

        [ -n "${extended}" ] &&
        case	"${n}" in
            [1-4])  ;;
            *)  continue ;;
        esac

        if      [ "${_info_}" = "true" ]
        then
                eval $(query_udev_envvar "${PART}")
                [ "${n}" = "${extended}" ] &&
                case    "${ID_PART_ENTRY_TYPE}" in
                    0x5)    ID_FS_TYPE="Extended" ;;
                    0xf)    ID_FS_TYPE="Extended W95 (LBA)" ;;
                    0x85)   ID_FS_TYPE="Linux Extended" ;;
                esac

                PART_SIZE="$(_drivemap_volume_size ${PART})"
                PART_INFO="${ID_FS_TYPE:+${ID_FS_TYPE} | }${PART_SIZE}"
        fi

        [ "${DEVICE}" = "${PART}" ] &&
            [ "${_mark_}" = "true" ] &&
            device="${PART}(*)" ||
            device="${PART}"

        _drivemap_print_line "${indent}${device}" "${PART_INFO:+[ ${PART_INFO} ]}" fill

        if      [ "${n}" = "${extended}" ]
        then	_drivemap_logical_partitions "${1}"
        else    _drivemap_loopback_device "${PART##*/}"
                _drivemap_dmdevice_holder "${PART##*/}"
        fi
done
}
# ===========================================================================}}}
# _drivemap_logical_partitions() ============================================{{{
# What we want is: the same than in the previous function, except that this one
# is called only if it exists an extended partition. In that case, partition
# with a number greater than 4 will be treated as logical partitions, and so
# will be shown as subdevices of the extended partition. If there is no
# extended partition but partition numbers greater than 4, we assume we have
# to deal with a GPT partition table.
_drivemap_logical_partitions() {
    ${DEBUG} && echo "> _drivemap_logical_partitions $@" >&2
    local   n PART PART_SIZE PART_INFO
    for	PART in ${1}?*
    do
        # Partition number:
        n="$(cat /sys/class/block/${PART##*/}/partition)"

        # Absolute indentation, second level (we consider a logical partition is
        # a subdevice of an extended one).
        indent="${I}${I}"
        case    "${n}" in
            [1-4])
                continue
                ;;
        esac

        if      [ "${_info_}" = "true" ]
        then
                ID_FS_TYPE=
                eval $(query_udev_envvar "${PART}")
                PART_SIZE="$(_drivemap_volume_size ${PART})"
                PART_INFO="${ID_FS_TYPE:+${ID_FS_TYPE} | }${PART_SIZE}"
        fi

        [ "${DEVICE}" = "${PART}" ] &&
            [ "${_mark_}" = "true" ] &&
            device="${PART}(*)" ||
            device="${PART}"

        _drivemap_print_line "${indent}${device}" "${PART_INFO:+[ ${PART_INFO} ]}" fill
        _drivemap_loopback_device "${PART##*/}"
        _drivemap_dmdevice_holder "${PART##*/}"
    done
}
# ===========================================================================}}}

