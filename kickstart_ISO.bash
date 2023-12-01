#!/usr/bin/bash -xv
kscfg="$1"
isodir="$2"
outdir="$3"

function PREPISO {
	if [ -z "$kscfg" ]; then
		printf "\n\n\nYou need state the kickstart config to be used.\n\n\n"
		exit 1
	elif [ ! -f "$kscfg" ]; then
		printf "\n\n\nKickstart file %s does not exist.\n\n\n" "$kscfg"
		exit 1
	fi
	if [ -z "$isodir" ]; then
		printf "\n\n\nYou need to state the directory to be used to generate the ISO.\n\n\n"
		exit 1
	elif [ ! -d "$isodir" ]; then
		printf "\n\n\nThe directory %s does not exist.\n\n\n" "$isodir"
		exit 1
	fi
	if [ -z "$outdir" ]; then
		printf "\n\n\nYou need to state the directory to output the ISO to.\n\n\n"
		exit 1
	elif [ ! -d "$outdir" ]; then
		printf "\n\n\nThe directroy %s does not exist\n\n\n" "$outdir"
		exit 1
	fi
	if [ "$USER" != "root" ]; then
		printf "\n\n\nYou need to have root permissions to run this script.\n\n\n"
		exit 1
	fi
	volid="$(awk -F= '$1 == "VOLID"{print $NF}' $kscfg | dos2unix | tr -d [:blank:] )"
}
function GENISOCFG {
cat << EOF
default vesamenu.c32
timeout 100

display boot.msg

# Clear the screen when exiting the menu, instead of leaving the menu displayed.
# For vesamenu, this means the graphical background is still displayed without
# the menu itself for as long as the screen remains in graphics mode.
menu clear
menu background splash.png
menu title $volid
menu vshift 8
menu rows 18
menu margin 8
#menu hidden
menu helpmsgrow 15
menu tabmsgrow 13

# Border Area
menu color border * #00000000 #00000000 none

# Selected item
menu color sel 0 #ffffffff #00000000 none

# Title bar
menu color title 0 #ff7ba3d0 #00000000 none

# Press [Tab] message
menu color tabmsg 0 #ff3a6496 #00000000 none

# Unselected menu item
menu color unsel 0 #84b8ffff #00000000 none

# Selected hotkey
menu color hotsel 0 #84b8ffff #00000000 none

# Unselected hotkey
menu color hotkey 0 #ffffffff #00000000 none

# Help text
menu color help 0 #ffffffff #00000000 none

# A scrollbar of some type? Not sure.
menu color scrollbar 0 #ffffffff #ff355594 none

# Timeout msg
menu color timeout 0 #ffffffff #00000000 none
menu color timeout_msg 0 #ffffffff #00000000 none

# Command prompt text
menu color cmdmark 0 #84b8ffff #00000000 none
menu color cmdline 0 #ffffffff #00000000 none

# Do not display the actual menu unless the user presses a key. All that is displayed is a timeout message.

menu tabmsg Press Tab for full configuration options on menu items.

menu separator # insert an empty line
menu separator # insert an empty line

label linux
  menu label ^Install $volid
  menu default
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=$volid inst.ks=cdrom:/$(basename $kscfg)

menu end
EOF
}

function GENGRUBCFG {
cat << EOF
set default="1"

function load_video {
  insmod efi_gop
  insmod efi_uga
  insmod video_bochs
  insmod video_cirrus
  insmod all_video
}

load_video
set gfxpayload=keep
insmod gzio
insmod part_gpt
insmod ext2

set timeout=60
### END /etc/grub.d/00_header ###

search --no-floppy --set=root -l 'RHEL-8-4-0-BaseOS-x86_64'

### BEGIN /etc/grub.d/10_linux ###
menuentry 'Install $volid' --class fedora --class gnu-linux --class gnu --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=$volid inst.ks=cdrom:/$(basename $kscfg)
        initrdefi /images/pxeboot/initrd.img
}

EOF
}
function GENKICKSTARTISO {
	PREPISO
	cp -f $kscfg $isodir/
	GENISOCFG
	for isocfg in $(find $isodir -type f -name isolinux.cfg); do
		chmod +w $isocfg
		GENISOCFG > $isocfg
	done
	GENGRUBCFG
	for grubcfg in $(find $isodir -type f -name grub.cfg); do
		chmod +w $grubcfg
		GENGRUBCFG > $grubcfg
	done
	cd $isodir
	if [ -f "../$volid.iso" ]; then
		rm -f ../$volid.iso
	fi
	outiso="$outdir/$volid-$(date +%F-%H%M%S).iso"
	if [ -f "$outiso" ]; then
		rm -f $outiso
	fi
	#mkisofs -o ../$volid.iso -b isolinux/isolinux.bin -J -R -l -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e images/efiboot.img -no-emul-boot -graft-points -V "$volid" .
	mkisofs -o $outiso -b isolinux/isolinux.bin -J -joliet-long -R -l -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e images/efiboot.img -no-emul-boot -graft-points -V "$volid" .

	printf "\n\n\nISO created at %s\n\n\n" "$outiso" 


}
GENKICKSTARTISO
