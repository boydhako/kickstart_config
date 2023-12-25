#!/bin/bash -xv
stig="$1"

if [ "$USER" != "root" ]; then
	printf "You are %s. This script needs to be run as root.\n\n" "$USER"
	exit 1
fi
#function v230221 {
#	printf "> Running %s...\n" "$FUNCNAME"
#	printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Bull feces test"
#}

function v230221 {
	printf "> Running %s...\n" "$FUNCNAME"
	dnf upgrade
	printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Bull feces test"
}
function v230233 {
	printf "> Running %s...\n" "$FUNCNAME"
	rounds="$(awk '$1 == "password" && $2 == "sufficient" && $3 == "pam_unix.so" {print $0}' /etc/pam.d/password-auth | sed 's/ /\n/g' | awk -F= '$1 == "rounds" {print $NF}')"
	if [ -z "$rounds" ]; then
		printf "Null rounds\n"
		str="$(awk '$1 == "password" && $2 == "sufficient" && $3 == "pam_unix.so" {print $0}' /etc/pam.d/password-auth)"
		sed -i "s#$str#$str rounds=5000#g" /etc/pam.d/password-auth
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added rounds"
	elif [ "$rounds" -lt "5000" ]; then
		printf "Less than 5000\n"
		sed -i "s#rounds=$rounds#rounds=5000#g" /etc/pam.d/password-auth
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Changed rounds to 5000"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	fi
	unset rounds
}
function v230336 {
	printf "> Running %s...\n" "$FUNCNAME"
	unlocktime="$(awk '$1 == "auth" && $2 == "required" && $3 == "pam_faillock.so" {print $0}' /etc/pam.d/password-auth | sed 's# #\n#g' | awk -F= '$1 == "unlock_time" {print $NF}')"
	if [ -z "$unlocktime" ]; then
		str="$(awk '$1 == "auth" && $2 == "required" && $3 == "pam_faillock.so" {print $0}' /etc/pam.d/password-auth)"
		sed -i "s#$str#$str unlock_time=0#" /etc/pam.d/password-auth
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added Unlock Time"
	elif [ "$unlocktime" != "0" -a "$unlocktime" != "preauth" -a "$unlocktime" != "authfail" ]; then
		sed -i "s#unlock_time=$unlocktime#unlock_time=0#g" /etc/pam.d/password-auth
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Changed Unlock Time"
	fi
}
function v230342 {
	printf "> Running %s...\n" "$FUNCNAME"
	if [ "$(awk '$1 == "auth" && $2 == "required" && $3 == "pam_faillock.so" && $4 == "preauth" {print $0}' /etc/pam.d/password-auth | egrep -e " audit " | wc -l)" -lt "1" ]; then
		str="$(awk '$1 == "auth" && $2 == "required" && $3 == "pam_faillock.so" && $4 == "preauth" {print $0}' /etc/pam.d/password-auth | head -n 1)"
		sed -i "s#$str#$str audit#" /etc/pam.d/password-auth
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added audit to preauth line"
	fi
}
function v230332 {
	printf "> Running %s...\n" "$FUNCNAME"
	denies="$(awk '$1 == "auth" && $2 == "required" && $3 == "pam_faillock.so" && $4 == "preauth" {print $0}' /etc/pam.d/password-auth | sed 's# #\n#g' | awk -F= '$1 == "deny" {printf $NF}')"
	if [ "$denies" -gt "3" -o "$denies" == "0" ]; then
		str="$(awk '$1 == "auth" && $2 == "required" && $3 == "pam_faillock.so" && $4 == "preauth" {print $0}' /etc/pam.d/password-auth)"
		fix="$(echo $str | sed "s#deny=$denies#deny=3#g")"
		sed -i "s#$str#$fix#" /etc/pam.d/password-auth
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Changed deny count in preauth line"
	elif [ -z "$denies" ]; then
		str="$(awk '$1 == "auth" && $2 == "required" && $3 == "pam_faillock.so" && $4 == "preauth" {print $0}' /etc/pam.d/password-auth)"
		sed -i "s#$str#$str deny=3#" /etc/pam.d/password-auth
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added deny count in preauth line"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	fi
}
function v230343 {
	printf "> Running %s...\n" "$FUNCNAME"
	FAILLOCKCFG "$FUNCNAME" "audit" "NULL"
}
function v230438 {
	printf "> Running %s...\n" "$FUNCNAME"
	if [ "$(grep -e "init_module" /etc/audit/audit.rules | egrep -v -e "^#" -e " finit_module " | wc -l)" -lt "1" ]; then
		printf "# %s %s\n" "$FUNCNAME" "$(date)" >> /etc/audit/audit.rules
		for arch in b32 b64; do
			printf "%s always,exit -F arch=%s -S init_module -F auid>=1000 -F auid!=unset -k module_chng\n" "-a" "$arch" >> /etc/audit/audit.rules
		done
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added init_module lines to /etc/audit/audit.rules"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	fi
}
function v230445 {
	printf "> Running %s...\n" "$FUNCNAME"
	if [ "$(grep -e "finit_module" /etc/audit/audit.rules | egrep -v -e "^#" -e " init_module "| wc -l)" -lt "1" ]; then
		printf "# %s %s\n" "$FUNCNAME" "$(date)" >> /etc/audit/audit.rules
		for arch in b32 b64; do
			printf "%s always,exit -F arch=%s -S finit_module -F auid>=1000 -F auid!=unset -k module_chng\n" "-a" "$arch" >> /etc/audit/audit.rules
		done
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added finit_module lines to /etc/audit/audit.rules"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	fi
}
function v230446 {
	printf "> Running %s...\n" "$FUNCNAME"
	if [ "$(grep -e " delete_module " /etc/audit/audit.rules | egrep -e "module_chng" | wc -l)" -lt "1" ]; then
		printf "# %s %s\n" "$FUNCNAME" "$(date)" >> /etc/audit/audit.rules
		for arch in b32 b64; do
			printf "%s always,exit -F arch=%s -S delete_module -F auid>=1000 -F auid!=unset -k module_chng\n" "-a" "$arch" >> /etc/audit/audit.rules
		done
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added delete_module lines to /etc/audit/audit.rules"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	fi
}
function v230267 {
	printf "> Running %s...\n" "$FUNCNAME"
	CFGSYSCTL "$FUNCNAME" "fs.protected_symlinks" "1"
}
function v230268 {
	printf "> Running %s...\n" "$FUNCNAME"
	CFGSYSCTL "$FUNCNAME" "fs.protected_hardlinks" "1"
}
function v230540 {
	printf "> Running %s...\n" "$FUNCNAME"
	CFGSYSCTL "$FUNCNAME" "net.ipv6.conf.all.forwarding" "0"
}
function v230547 {
	printf "> Running %s...\n" "$FUNCNAME"
	CFGSYSCTL "$FUNCNAME" "kernel.kptr_restrict" "1"
}
function v230549 {
	printf "> Running %s...\n" "$FUNCNAME"
	CFGSYSCTL "$FUNCNAME" "net.ipv4.conf.all.rp_filter" "1"
}
function v230244 {
	printf "> Running %s...\n" "$FUNCNAME"
	SSHDCFG "$FUNCNAME" "ClientAliveCountMax" "0"
}
function v230288 {
	printf "> Running %s...\n" "$FUNCNAME"
	SSHDCFG "$FUNCNAME" "StrictModes" "yes"
}
function v230289 {
	printf "> Running %s...\n" "$FUNCNAME"
	SSHDCFG "$FUNCNAME" "Compression" "no"
}
function v230291 {
	printf "> Running %s...\n" "$FUNCNAME"
	SSHDCFG "$FUNCNAME" "KerberosAuthentication" "no"
}
function v230330 {
	printf "> Running %s...\n" "$FUNCNAME"
	SSHDCFG "$FUNCNAME" "PermitUserEnvironment" "no"
}
function v230382 {
	printf "> Running %s...\n" "$FUNCNAME"
	SSHDCFG "$FUNCNAME" "PrintLastLog" "yes"
}
function v230556 {
	printf "> Running %s...\n" "$FUNCNAME"
	SSHDCFG "$FUNCNAME" "X11UseLocalhost" "yes"
}
function v230287 {
	printf "> Running %s...\n" "$FUNCNAME"
	find /etc/ssh -type f -name "ssh_host*key" -exec chmod 0600 {} \;
	files="$(find /etc/ssh -type f -name "ssh_host*key" | awk '{printf $0", "}' | sed 's#, $##g')"
	printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Changed file mode to 0600 for $files"
}
function v230333 {
	printf "> Running %s...\n" "$FUNCNAME"
	FAILLOCKCFG "$FUNCNAME" "deny" "3"
}
function v230335 {
	printf "> Running %s...\n" "$FUNCNAME"
	FAILLOCKCFG "$FUNCNAME" "fail_interval" "900"
}
function v230337 {
	printf "> Running %s...\n" "$FUNCNAME"
	FAILLOCKCFG "$FUNCNAME" "unlock_time" "0"
}
function v230341 {
	printf "> Running %s...\n" "$FUNCNAME"
	FAILLOCKCFG "$FUNCNAME" "silent" "NULL"
}
function v230345 {
	printf "> Running %s...\n" "$FUNCNAME"
	FAILLOCKCFG "$FUNCNAME" "even_deny_root" "NULL"
}
function v230364 {
	printf "> Running %s...\n" "$FUNCNAME"
	setenforce 0
	let uidmin="$(awk '$1 == "UID_MIN" {print $2}' /etc/login.defs)"
	let uidmax="$(awk '$1 == "UID_MAX" {print $2}' /etc/login.defs)"
	export userlist=""
	for user in $(awk -F: '$4 < 1 {print $1}' /etc/shadow); do
		validuser="$(awk -v user="$user" -v uidmin="$uidmin" -v uidmax="$uidmax" -F: '$1 == user && $3 >= uidmin && $3 <= uidmax {print $1}' /etc/passwd)"
		if [ ! -z "$validuser" ]; then
			chage -m 1 $validuser
			userlist="$validuser $userlist"
		fi
	done
	setenforce 1
	if [ -z "$userlist" ]; then
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Changed the following users: $userlist"
	fi
}
function v230367 {
	printf "> Running %s...\n" "$FUNCNAME"
	setenforce 0
	let uidmin="$(awk '$1 == "UID_MIN" {print $2}' /etc/login.defs)"
	let uidmax="$(awk '$1 == "UID_MAX" {print $2}' /etc/login.defs)"
	export userlist=""
	for user in $(awk -F: '$5 > 60 || $5 <= 0 {print $1}' /etc/shadow); do
		validuser="$(awk -v user="$user" -v uidmin="$uidmin" -v uidmax="$uidmax" -F: '$1 == user && $3 >= uidmin && $3 <= uidmax {print $1}' /etc/passwd)"
		if [ ! -z "$validuser" ]; then
			chage -M 60 $validuser
			userlist="$validuser $userlist"
		fi
	done
	setenforce 1
	if [ -z "$userlist" ]; then
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Changed the following users: $userlist"
	fi
}
function v230255 {
	printf "> Running %s...\n" "$FUNCNAME"
	cryptocfg="/etc/crypto-policies/back-ends/opensslcnf.config"
	if [ "$(egrep -e "^MinProtocol" $cryptocfg | wc -l)" -lt "1" ]; then
		printf "\nMinProtocol = TLSv1.2\n" >> $cryptocfg
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Added MinProtocol = TLSv1.2"
	else
		currentminprotocol="$(awk '$1 == "MinProtocol" {print $NF}' $cryptocfg)"
		if [ "$currentminprotocol" != "TLSv1.2" ]; then
			str="$(awk '$1 == "MinProtocol" {print $0}' $cryptocfg)"
			sed -i "s#^$str#MinProtocol = TLSv1.2#g" $cryptocfg
			printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Changed MinProtocol to TLSv1.2"
		else
			printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
		fi
	fi
}
function v230301 {
	printf "> Running %s...\n" "$FUNCNAME"
	partlist=""
	for part in $(mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev' | awk '{print $3}'); do
		dev="$(awk -v part="$part" '$2 == part {print $1}' /etc/fstab)"
		mountpnt="$(awk -v part="$part" '$2 == part {print $2}' /etc/fstab)"
		fs="$(awk -v part="$part" '$2 == part {print $3}' /etc/fstab)"
		mntopts="$(awk -v part="$part" '$2 == part {print $4}' /etc/fstab)"
		dump="$(awk -v part="$part" '$2 == part {print $5}' /etc/fstab)"
		fsckorder="$(awk -v part="$part" '$2 == part {print $6}' /etc/fstab)"
		str="$(awk -v part="$part" '$2 == part {print $0}' /etc/fstab)"
		sed -i "s#^$str#$dev\t$mountpnt\t$fs\t$mntopts,nodev\t$dump\t$fsckorder#g" /etc/fstab
		mount -o remount $part
		partlist="$part $partlist"
	done
	if [ -z "$partlist" ]; then
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Changed /etc/fstab for the following partitions: $partlist"
	fi
}
function v230349 {
	printf "> Running %s...\n" "$FUNCNAME"
	if [ "$(grep -e '[ -n "$PS1" -a -z "$TMUX" ] && exec tmux' /etc/bashrc | wc -l)" -lt "1" ]; then
		printf "\n\n# %s %s\n[ -n \"\$PS1\" -a -z \"\$TMUX\" ] && exec tmux\n\n" "$FUNCNAME" "$(date)" >> /etc/bashrc
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "Enabled use of TMUX in /etc/bashrc"
	else
		printf "Status:%s:%s:%s\n" "$FUNCNAME" "NF" "No changes"
	fi
}
function v230494 {
	printf "> Running %s...\n" "$FUNCNAME"
	KERNELMOD "$FUNCNAME" "atm" "install" "/bin/true" "yes"
}
function v230495 {
	printf "> Running %s...\n" "$FUNCNAME"
	KERNELMOD "$FUNCNAME" "can" "install" "/bin/true" "yes"
}
function v230496 {
	printf "> Running %s...\n" "$FUNCNAME"
	KERNELMOD "$FUNCNAME" "sctp" "install" "/bin/true" "yes"
}
function v230497 {
	printf "> Running %s...\n" "$FUNCNAME"
	KERNELMOD "$FUNCNAME" "tipc" "install" "/bin/true" "yes"
}
function v230498 {
	printf "> Running %s...\n" "$FUNCNAME"
	KERNELMOD "$FUNCNAME" "cramfs" "install" "/bin/true" "yes"
}
function v230499 {
	printf "> Running %s...\n" "$FUNCNAME"
	KERNELMOD "$FUNCNAME" "firewire-core" "install" "/bin/true" "yes"
}
function v230503 {
	printf "> Running %s...\n" "$FUNCNAME"
	KERNELMOD "$FUNCNAME" "usb-storage" "install" "/bin/true" "yes"
}
function KERNELMOD () {
	vulnid="$1"
	kernelmodule="$2"
	modaction="$3"
	modactionsetting="$4"
	blmod="$5"
	if [ -z "$vulnid" -o -z "$kernelmodule" -o -z "$modaction" -o -z "$modactionsetting" -o -z "$blmod" ]; then
		printf "Need more info..."
		exit 1
	fi
	if [ "$blmod" != "yes" -a "$blmod" != "no" ]; then
		printf "Need more info...\n"
		exit 1
	fi
	function ENABLEKERNELMOD {
		sed -i "s#^$modaction $kernelmodule#\#$modaction $kernelmodule#g" $file
		printf "\n# %s - Requires ability to load \"%s\" kernel module - %s\n%s %s %s\n\n" "$vulnid" "$kernelmodule" "$(date)" "$modaction" "$kernelmodule" "$modactionsetting" >> $file
		#printf "\n# %s - Requires ability to load \"%s\" kernel module\n%s %s %s\n\n" "$vulnid" "$kernelmodule" "$modaction" "$kernelmodule" "$modactionsetting"

		}
	if [ "$(grep -r $kernelmodule /etc/modprobe.d/* | awk -F: '{print $1}' | sort | uniq | wc -l)" -ge "1" ]; then
		for file in $(grep -r $kernelmodule /etc/modprobe.d/* | awk -F: '{print $1}' | sort | uniq); do
			if [ "$(awk -v kernelmodule="$kernelmodule" -v modaction="$modaction" -v modactionsetting="$modactionsetting" '$1 == modaction && $2 == kernelmodule && $3 == modactionsetting {print $0}' $file | wc -l)" -lt "1" ]; then
				ENABLEKERNELMOD
				modactionstatus="changed"
			fi
		done
	else
		file="/etc/modprobe.d/$vulnid.conf"
		ENABLEKERNELMOD
		modactionstatus="added"
	fi
	if [ "$blmod" == "yes" ]; then
		if [ "$(egrep -r -e "^blacklist" /etc/modprobe.d/* | awk -v kernelmodule="$kernelmodule" '$2 == kernelmodule {print $0}' | wc -l)" -lt "1" ]; then
			printf "\n# %s - Requires blacklisting of \"%s\" kernel module - %s\nblacklist %s\n\n" "$vulnid" "$kernelmodule" "$(date)" "$kernelmodule" >> /etc/modprobe.d/$vulnid.conf
			modblstatus="added"
		fi
	fi
	if [ "$modblstatus" == "added" ]; then
		if [ "$modactionstatus" == "added" ]; then
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Added blacklist and module enablement for $kernelmodule."
		elif [ "$modactionstatus" == "changed" ]; then
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Added blacklist and changed module enablement for $kernelmodule."
		else
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "No Changes."
		fi
	else
		if [ "$modactionstatus" == "added" ]; then
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Set module enablement for $kernelmodule."
		elif [ "$modactionstatus" == "changed" ]; then
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Changed module enablement for $kernelmodule."
		else
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "No Changes."
		fi
	fi
}
function FAILLOCKCFG () {
	vulnid="$1"
	flsetting="$2"
	flvalue="$3"
	flcfg="/etc/security/faillock.conf"
	if [ -z "$vulnid" -o -z "$flsetting" -o -z "$flvalue" ]; then
		printf "Need more info..."
		exit 1
	fi
	if [ ! -f "$flcfg" ]; then
		printf "%s does not exist. Check that faillock is installed.\n" "$flcfg"
		exit 1
	fi
	if [ "$flvalue" == "NULL" ]; then
		flvalue=""
	fi
	if [ "$(egrep -ve "^#" $flcfg | egrep -e "^$flsetting" | wc -l)" -lt "1" ]; then
		printf "\n# %s Adding %s setting - %s\n" "$vulnid" "$flsetting" "$(date)" >> $flcfg
		if [ -z "$flvalue" ]; then
			printf "%s\n\n" "$flsetting" >> $flcfg
		else
			printf "%s = %s\n\n" "$flsetting" "$flvalue" >> $flcfg
		fi
		printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Added $flsetting to $flcfg"
	else
		if [ ! -z "$flvalue" ]; then
			flcurrentvalue="$(awk -v flsetting="$flsetting" '$1 == flsetting {print $NF}' $flcfg)"
			if [ "$flcurrentvalue" != "$flvalue" ]; then
				str="$(awk -v flsetting="$flsetting" '$1 == flsetting {print $0}' $flcfg)"
				sed -i "s#^$str#\# $vulnid Changing $flsetting to $flvalue - $(date)\n$flsetting = $flvalue\n\n#g" $flcfg
				printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Changed $flsetting in $flcfg"
			else
				printf "Status:%s:%s:%s\n" "$vulnid" "NF" "No changes"
			fi
		else
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "No changes"
		fi
	fi
}
function SSHDCFG () {
	vulnid="$1"
	sshsetting="$2"
	sshvalue="$3"
	sshdcfg="/etc/ssh/sshd_config"
	if [ -z "$vulnid" -o -z "$sshsetting" -o -z "$sshvalue" ]; then
		printf "Need more info..."
		exit 1
	fi
	if [ ! -f "$sshdcfg" ]; then
		printf "\n\n%s not found.\n\n" "$sshdcfg"
		exit 1
	fi
	if [ "$(egrep -ve "^#" $sshdcfg | egrep -i -e "$sshsetting" | wc -l)" -lt "1" ]; then
		printf "\n# %s Adding \"%s %s\" %s\n%s %s\n" "$vulnid" "$sshsetting" "$sshvalue" "$(date)" "$sshsetting" "$sshvalue" >> $sshdcfg
		printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Adding \"$sshsetting $sshvalue\" in $sshdcfg"
	else
		currentsshvalue="$(awk -v sshsetting="$sshsetting" '$1 == sshsetting {print $NF}' $sshdcfg)"
		if [ "$currentsshvalue" != "$sshvalue" ]; then
			str="$(awk -v sshsetting="$sshsetting" '$1 == sshsetting {print $0}' $sshdcfg)"
			sed -i "s#^$str#\# $vulnid Changed $sshsetting to $sshvalue - $(date)\n$sshsetting $sshvalue\n#g" $sshdcfg
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Set $sshsetting to $sshvalue in $sshdcfg"
		else
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "No changes"
		fi
	fi
}
function CFGSYSCTL () {
	vulnid="$1"
	syssetting="$2"
	sysvalue="$3"
	if [ -z "$vulnid" -o -z "$syssetting" -o -z "$sysvalue" ]; then
		printf "Need more info...\n"
		exit 1
	fi
	syscfgfile="/etc/sysctl.d/99-$vulnid.conf"
	setsysvalue="$(sysctl $syssetting | awk '{print $NF}')"
	if [ ! -f "$syscfgfile" ]; then
		printf "# %s Created %s\n%s = %s\n\n" "$vulnid" "$(date)" "$syssetting" "$sysvalue" > $syscfgfile
	fi
	for file in $(egrep -Hre "^$syssetting" /etc/sysctl.d/*.conf /etc/sysctl.conf| awk -F: '{print $1}' | sort | uniq); do
		if [ "$(awk -v syssetting="$syssetting" '$1 == syssetting {print $NF}' $file)" != "$sysvalue" ]; then
			sed -i "s#^$syssetting.*#$syssetting = $sysvalue#g" $file
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "Changed $syssetting = $sysvalue in $file"
		else
			printf "Status:%s:%s:%s\n" "$vulnid" "NF" "No changes"
		fi
	done
}
function APPLYSTIGS {
	if [ -z "$stig" ]; then
		v230221
		v230233
		v230336
		v230342
		v230332
		v230438
		v230445
		v230446
		v230267
		v230268
		v230540
		v230547
		v230549
	elif [ "$stig" == "test" ]; then
		KERNELMOD "v-230494" "atm" "install" "/bin/true" "yes"
	else
		$stig
	fi
}
APPLYSTIGS
