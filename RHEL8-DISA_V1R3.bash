#!/usr/bin/bash
host="$(echo $HOSTNAME | tr [:upper:] [:lower:])"

function V-230235 {
	funcname="${FUNCNAME[0]}"
	if [ ! -f "/boot/grub2/grub.cfg" ]; then
		printf "%s:Not Applicable. %s is using UEFI.\n" "$funcname" "$host"
	elif [ -f "/boot/grub2/user.cfg" ]; then
		printf "%s:%s requires manual review for %s. Automated correction is too risky.\n" "$funcname" "$funcname" "$host"
		grep -iw grub2_password /boot/grub2/user.cfg
	elif [ ! -f "/boot/grub2/user.cfg" ]; then
		printf "%s: Manual action will be required to fix this vulnerability.\n" "$funcname"
	fi
}
function V-230264 {
	funcname="${FUNCNAME[0]}"
	let startline="$(yum repolist | egrep -n -e "^repo id" | awk -F: '{print $1}') + 1"
	for repoid in $(yum repolist | tail -n +$startline | awk '{print $1}'); do
		printf "%s: Enabling GPG Check for %s.\n" "$funcname" "$repoid"
		dnf config-manager --save --setopt=$repoid.gpgcheck=1 $repoid >/dev/null
	done
	egrep '^\[.*\]|gpgcheck' /etc/yum.repos.d/*.repo
}
function V-230329 {
	funcname="${FUNCNAME[0]}"
	if [ ! -d "/etc/gdm" ]; then
		printf "%s: Not Applicable. %s does not hame GNOME installed.\n" "$funcname" "$host"
	fi
}
function V-230529 {
	funcname="${FUNCNAME[0]}"
	systemctl mask ctrl-alt-del.target
	systemctl daemon-reload
	printf "%s: Not A Finding. Status for ctrl-alt-del is below...\n" "$funcname"
	systemctl status ctrl-alt-del.target
}
function V-230530 {
	funcname="${FUNCNAME[0]}"
	if [ ! -d "/etc/gdm" ]; then
		printf "%s: Not Applicable. %s does not hame GNOME installed.\n" "$funcname" "$host"
	fi
}
function V-244540 {
	funcname="${FUNCNAME[0]}"
	if [ "$(grep -i nullok /etc/pam.d/system-auth | wc -l)" -ge "1" ]; then
		printf "%s: There is a finding...\n%s\n" "$funcname" "$(grep -i nullok /etc/pam.d/system-auth)"
	else
		printf "%s: Not A Finding. No output.\n" "$funcname"
	fi
}
function V-244541 {
	funcname="${FUNCNAME[0]}"
	if [ "$(grep -i nullok /etc/pam.d/password-auth | wc -l)" -ge "1" ]; then
		printf "%s: There is a finding...\n%s\n" "$funcname" "$(grep -i nullok /etc/pam.d/password-auth)"
	else
		printf "%s: Not A Finding. No output.\n" "$funcname"
	fi
}
function V-230494 {
	funcname="${FUNCNAME[0]}"
	grep -ri ATM /etc/modprobe.d/* | grep -i "/bin/true"
}
function APPLYSTIGS {
	if [ "$USER" != "root" ]; then
		printf "\n\nNeed to be root to run this script.\n\n\n"
		exit 1
	fi
	V-230235
	V-230264
	V-230329
	V-230529
	V-230530
	V-244540
	V-244541
	V-230494
}
APPLYSTIGS
