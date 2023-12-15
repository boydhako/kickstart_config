#!/bin/bash -xv
aidecfg="/etc/aide.conf"

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

function STIG {
	#V230475
	#V230551
	#V230552
	#V230263
	#V230252
	#V255924
	V244525
}
STIG
