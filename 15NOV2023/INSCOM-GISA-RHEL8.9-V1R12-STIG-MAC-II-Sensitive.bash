#!/bin/bash -xv
aidecfg="/etc/aide.conf"
sshhostkeys="$(sshd -T | awk '$1 == "hostkey" {print $NF}')"
selinuxenforce="$(getenforce)"

function GETHOMEMNT {
	homemnt=""
	for homedir in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $6}' /etc/passwd); do
		homemnt="$homemnt $(df -h $homedir | awk '{print $NF}' | tail -n 1)"
	done
}

function AIDEVAL {
	val="$1"
	for var in $(grep -v -e "^#" $aidecfg | grep -e "=" | tr -d [:blank:] | awk -F= '{print $1}'); do
		case $var in
			database)
			;;
			database_out)
			;;
			gzip_dbout)
			;;
			verbose)
			;;
			report_url)
			;;
			*)
				if [ "$(grep -e "^$var" $aidecfg | grep -i -e $val | wc -l)" -lt "1" ]; then
					str="$(grep -e "^$var" $aidecfg)"
					sed -i "s#^$str#$str+$val#" $aidecfg
				fi
			;;
		esac
	done
}

function SSHCRYPTO {
	opt="$1"
	str="$2"
	cfg="/etc/crypto-policies/back-ends/opensshserver.config"
	set="$(sed -e "s#-o#\n#g" $cfg | awk -F= -v opt="$opt" '$1 == opt {print $2}' | tr -d [:blank:])"
	if [ "$set" != "$str" ]; then
		sed -i "s#-o$opt=$set #-o$opt=$str #" $cfg
	fi
}

function SSHDCFG {
	setting="$1"
	value="$2"
	cfg="/etc/ssh/sshd_config"
	cfgdir="$(dirname $cfg)"
	cfgfile="$(basename $cfg)"
	for file in $(find $cfgdir -type f -iname "$cfgfile*"); do
		if [ "$(egrep -v -e "^#" $file | grep $setting | wc -l)" -lt "1" ]; then
			printf "\n# %s - Adding \"%s %s\"\n%s %s\n\n" "$(date)" "$setting" "$value" "$setting" "$value" >> $file
		else
			if [ "$(awk -v setting="$setting" '$1 == setting {print $2}' $file)" != "$value" ]; then
				sed -i "s#^$setting.*#\# $(date) - Modified $setting to $value\n$setting $value ---#g" $file
			fi
		fi
	done
}

function SELINUXCFG {
	setting="$1"
	value="$2"
	cfg="/etc/selinux/config"
	currentvalue="$(awk -F= -v setting="$setting" '$1 == setting {print $2}' $cfg)"

	if [ -z "$currentvalue" ]; then
		printf "\n\n# Added %s\n%s=%s\n\n" "$(date)" "$setting" "$value" >> $cfg
	elif [ "$currentvalue" != "$value" ]; then
		sed -i "s#^$setting=.*#\n\n\# $setting set to \"$value\" on $(date)\n$setting=$value\n\n#g" $cfg
	fi
}

function FAILLOCKCFG {
	setting="$1"
	value="$2"
	cfg="/etc/security/faillock.conf"
	currentvalue="$(egrep -v -e "^#" $cfg | tr -d [:blank:] | awk -F= -v setting="$setting" '$1 == setting {print $2}')"

	if [ -z "$currentvalue" ]; then
		printf "\n\n# Adding %s with %s - %s\n%s = %s\n\n" "$setting" "$value" "$(date)" "$setting" "$value"
	elif [ "$currentvalue" != "$value" ]; then
		str="$(egrep -e "^$setting.*$currentvalue" $cfg)"
		sed "s#^$str.*#\n\n\# Changed $setting to \"$value\" on $(date)\n$setting = $value\n\n#g" $cfg
	fi
}

function YUMCFG {
	setting="$1"
	value="$2"
	for yumrepodir in $(dnf config-manager --dump | tr -d [:blank:] | awk -F= '$1 == "reposdir" {print $2}' | sed 's/,/\n/g'); do
		if [ -d "$yumrepodir" ]; then
			for cfg in $(find $yumrepodir -type f -iname "*.repo"); do
				for repoid in $(grep -e "^\[" $cfg | sed -e 's/\[//g' -e 's/\]//g'); do
					currentvalue="$(dnf config-manager $repoid --dump | tr -d [:blank:] |awk -F= -v setting="$setting" '$1 == setting {print $2}')"
					if [ "$currentvalue" != "$value" ]; then
						sed -i "s#^$setting=.*#$setting=$value#g" $cfg
					fi
				done
			done
		fi
	done
}


function V230475 {
	for pkg in audit rsyslog; do
		for bin in $(rpm -ql $pkg | grep bin); do
			if [ "$(grep $bin $aidecfg | wc -l)" -lt "1" ]; then
				printf "\n# %s - %s\n%s p+i+n+u+g+s+b+acl+xattrs+sha512\n" "$FUNCNAME" "$(date)" "$bin" >> $aidecfg
			fi
		done
	done
}

function V230551 {
	AIDEVAL xattrs
}

function V230552 {
	AIDEVAL acl
}

function V230263 {
	if [ "$(find /etc/cron.* -type f -exec grep aide {} \; | wc -l)" -lt "1" ]; then
		if [ "$(grep aide /etc/crontab /var/spool/cron/root 2>/dev/null | wc -l)" -lt "1" ]; then
			printf "#!%s\n%s --check | mailx -s \"$HOSTNAME - Daily AIDE integrity check run\" root@localhost\n\n" "$(which bash)" "$(which aide)" > /etc/cron.daily/$FUNCNAME
			chmod a+rx /etc/cron.daily/$FUNCNAME
		fi
	fi
}

function V230252 {
	SSHCRYPTO Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com
}

function V255924 {
	SSHCRYPTO KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
}

function V244525 {
	SSHDCFG ClientAliveInterval 600
}

function V230553 {
	for pkg in $(rpm -qa | grep -i xorg | grep -i server); do
		dnf -y autoremove $pkg
	done
}

function V230240 {
	SELINUXCFG SELINUX enforcing
}

function V250315 {
	faildir="/var/log/faillock"
	FAILLOCKCFG dir $faildir
	semanage fcontext -a -t faillog_t "$faildir(/.*)?"
	restorecon -R -v $faildir
}

function V254520 {
	for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
		seuser="$(semanage login -l | awk -v user="$user" '$1 == user {print $2}')"
		if [ "$(id $user | grep -e "(wheel)" | wc -l)" -ge "1" ]; then
			isadmin="1"
		else
			isadmin="0"
		fi
		if [ -z "$seuser" ]; then
			case $isadmin in
				1)
				semanage login -a -s staff_u $user
				;;
				*)
				semanage login -a -s user_u $user
				;;
			esac
		fi
		unset isadmin
	done
}

function V230264 {
	YUMCFG gpgcheck 1
}

function V251710 {
	dbdir="$(awk '$2 == "DBDIR" {print $3}' $aidecfg)"
	dbfile="$(awk -F= '$1 == "database" {print $2}' $aidecfg | sed "s#file:@@{DBDIR}#$dbdir#")"
	if [ ! -f "$dbfile" ]; then
		aide --init
	fi
}

function V250315 {
	printf "%swheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL\n" "%" > /etc/sudoers.d/$FUNCNAME
}

function V230309 {
	for fs in $(cat /proc/filesystems | awk '$1 != "nodev" {print $1}'); do
		for mntpnt in $(mount | grep -e " $fs " | awk '{print $3}'); do
			for file in $(find $mntpnt -xdev -type f -perm -0002 -print); do
				for homemnt in $homemnt; do
					if [ "$(grep -H $file $homemnt/*/.* | awk -F: '{print $1}' | wc -l)" -ge "1" ]; then
						chmod 0755 $file
					fi
				done
			done
		done
	done
}

function STIG {
	GETHOMEMNT
	#V250315
	#V230475
	#V230551
	#V230552
	#V230263
	#V230252
	#V255924
	#V244525
	#V230553
	#V230240
	#V250315
	#V254520
	#V230264
	#V251710
	#V230309
}
STIG
