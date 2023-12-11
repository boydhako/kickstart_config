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

function STIG {
	V230475
	V230551
	V230552
	V230263
}
STIG
