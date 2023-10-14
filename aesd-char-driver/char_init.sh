#!/bin/sh

module=aesdchar
device=aesdchar
group="staff"
mode="664"

case "$1" in
	start)
		echo "Loading ${module} driver"
		insmod /lib/modules/$(uname -r)/extra/${module}.ko || exit 1 
		echo "Creating ${module} device node"
		major=$(awk "\$2==\"$module\" {print \$1}" /proc/devices)
        if [ ! -z ${major} ]; then
            rm -f /dev/${device}
            mknod /dev/${device} c $major 0
            chgrp $group /dev/${device}
            chmod $mode /dev/${device}
        else
		    echo "No device found in /proc/devices for driver \"${module}\""
            exit 1
	    fi
		;;
	stop)
		echo "Removing ${module} driver"
		rmmod $module || exit 1
		echo "Deleting ${module} device node"
		rm -f /dev/${device}
		;;
	*)
		echo "Usage: $0 {start|stop}"
		exit 1
		;;
esac

exit 0
