#!/bin/bash
date="$(date +%F)"
nmcfg="/etc/NetworkManager/NetworkManager.conf"
sshdcfg="/etc/ssh/sshd_config"
fipscryptodir="/usr/share/crypto-policies/FIPS"
cryptodir="/etc/crypto-policies/back-ends"

function PAMDCFG {
	cfgdir="/etc/pam.d"
	rule="$1"
	cfg="$cfgdir/$2"
	type="$3"
	ctrl="$4"
	lib="$5"
	opt="$6"
	value="$7"
	optvalue="$opt=$value"

	if [ -z "$value" ]; then
		optvalue="$opt"
	fi

	if [ ! -f "$cfg" ]; then
		printf "# %s - Creating %s with \"%s %s %s\" - %s\n%s\t%s\t%s\n" "$rule" "$cfg" "$type" "$ctrl" "$optvalue" "$date" "$type" "$ctrl" "$optvalue" > $cfg
	elif [ "$(awk -v type="$type" -v ctrl="$ctrl" -v lib="$lib" '$3 == lib {print $0}' $cfg | wc -l)" -lt "1" ]; then
		str="$(awk -v type="$type" -v ctrl="$ctrl" -v lib="$lib" '$1 == type {print $0}' $cfg | head -n 1)"
		sed -i "s#^$str#$type\t$ctrl\t$lib\t$optvalue\n$str#" $cfg
	elif [ "$(echo $optvalue | grep -e "=" | wc -l)" -ge "1" ]; then

		if [ "$(awk -v type="$type" -v ctrl="$ctrl" -v lib="$lib" '$1 == type && $3 == lib {print $0}' $cfg | grep -e "$opt" | wc -l)" -lt "1" ]; then
			str="$(awk -v type="$type" -v ctrl="$ctrl" -v lib="$lib" '$1 == type && $3 == lib {print $0}' $cfg)"
			sed -i "s#^$str#$str $optvalue#" $cfg
		fi

		for currentvalue in $(cat $cfg | sed 's/ /\n/g' | awk -v opt="$opt" -F= '$1 == opt {print $2}'); do
			if [ "$currentvalue" != "$value" ]; then
				str="$(awk -v type="$type" -v ctrl="$ctrl" -v lib="$lib" '$1 == type && $3 == lib {print $0}' $cfg | grep -e "$opt=$currentvalue" | head -n 1)"
				newstr="$(echo $str | sed "s# $opt=$currentvalue# $opt=$value#")"
				sed -i "s#^$str#$newstr#g" $cfg
			fi
		done
	fi
}

function AUDITCFG {
	cfgdir="/etc/audit"
	rule="$1"
	cfg="$cfgdir/$2"
	setting="$3"
	value="$4"

	if [ ! -f "$cfg" ]; then
		printf "# %s - Created %s with \"%s=%s\" - %s\n%s=%s\n" "$rule" "$cfg" "$setting" "$value" "$date" "$setting" "$value" > $cfg
	else
		currentvalue="$(cat $cfg | tr -d [:blank:] | awk -F= -v setting="$setting" '$1 == setting {print $2}' | tail -n 1)"

		if [ -z "$currentvalue" ]; then
			printf "# %s - Adding \"%s=%s\" - %s\n%s=%s\n" "$rule" "$setting" "$value" "$date" "$setting" "$value" >> $cfg
		elif [ "$currentvalue" != "$value" ]; then
			str="$(egrep -e "^$setting" $cfg)"
			sed -i "s#^$str#\# $rule - Modifying \"$setting\" from \"$currentvalue\" to \"$value\" - $date\n$setting=$value#" $cfg
		fi
	fi
}

function AUDITPLUGINCFG {
	cfgdir="/etc/audit/plugins.d"
	rule="$1"
	cfg="$cfgdir/$2"
	setting="$3"
	value="$4"

	if [ ! -f "$cfg" ]; then
		printf "# %s - Creating %s - %s\n%s=%s\n" "$rule" "$cfg" "$date" "$setting" "$value" > $cfg
	else
		if [ "$(grep -e "^$setting" $cfg | wc -l)" -lt "1" ]; then
			printf "# %s - Adding \"%s=%s\" - %s\n%s=%s\n" "$rule" "$setting" "$value" "$date" "$setting" "$value" >> $cfg
		else
			currentvalue="$(cat $cfg | tr -d [:blank:] | awk -F= -v setting="$setting" '$1 == setting {print $2}')"

			if [ "$currentvalue" != "$value" ]; then
				str="$(grep -e "^$setting" $cfg | tail -n 1)"
				sed -i "s#^$str#\# $rule - Modifying \"$setting\" from \"$currentvalue\" to \"$value\" - $date\n$setting=$value#g" $cfg
			fi
		fi
	fi
}

function AIDEATTRCFG {
	cfg="/etc/aide.conf"
	rule="$1"
	setting="$2"

	for var in $(grep -v -e "^#" $cfg | grep -e "=" | tr -d [:blank:] | awk -F= '{print $1}' | sort | uniq); do
		case $var in
			database*)
			;;
			gzip_dbout)
			;;
			verbose)
			;;
			report_url)
			;;
			*)
				if [ "$(grep -e "^$var" $cfg | grep -e "$setting" | wc -l)" -lt "1" ]; then
					str="$(grep -e "^$var" $cfg)"
					sed -i "s#^$str#$str+$setting#g" $cfg
				fi
			;;
		esac
	done
}

function LOGINDEFSCFG {
	cfg="/etc/login.defs"
	rule="$1"
	setting="$2"
	value="$3"

	currentvalue="$(grep -e "^$setting" $cfg | awk '{print $2}')"

	if [ -z "$currentvalue" ]; then
		printf "# %s - Adding \"%s\" as \"%s\"\n%s %s\n" "$rule" "$setting" "$value" "$setting" "$value" >> $cfg
	elif [ "$currentvalue" != "$value" ]; then
		sed -i "s#^$setting.*#\# $rule - Modifying \"$setting\" to \"$value\"\n$setting $value#g" $cfg
	fi
}

function SYSTEMDCFG {
	sysdir="/etc/systemd"
	rule="$1"
	cfg="$sysdir/$2"
	section="$3"
	setting="$4"
	value="$5"

	if [ ! -f "$cfg" ]; then
		printf "# Creating %s %s with \"%s=%s\" - %s\n[%s]\n%s=%s\n" "$rule" "$cfg" "$setting" "$value" "$date" "$section" "$setting" "$value" > $cfg
	else
		if [ "$(grep -e "^\[$section\]" $cfg | wc -l)" -lt "1" ]; then
			printf "# Adding %s %s section with \"%s=%s\" - %s\n[%s]\n%s=%s\n" "$rule" "$section" "$setting" "$value" "$date" "$section" "$setting" "$value" >> $cfg
		else
			if [ -z "$(grep -e "^$setting" $cfg)" ]; then
				sed -i "s#^\[$section\]#\[$section\]\n\# Adding $rule \"$setting=$value\" - $date\n$setting=$value#" $cfg
			else
				currentvalue="$(grep -e "^$setting" $cfg | awk -F= '{print $2}')"
				if [ "$currentvalue" != "$value" ]; then
					sed -i "s#^$setting.*#\# $rule Modifying \"$setting\" to \"$value\" - $date\n$setting=$value#" $cfg
				fi
			fi
		fi
	fi
	systemctl restart systemd-logind
}

function SYSCTLCFG {
	rule="$1"
	setting="$2"
	value="$3"

	runningvalue="$(sysctl $setting | tr -d [:blank:] | awk -F= '{print $2}')"
	setvalue="$(/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F $setting | tail -n 1 | tr -d [:blank:] | awk -F= '{print $2}')"

	if [ -z "$runningvalue" -o -z "$setvalue" ]; then
		printf "%s=%s\n" "$setting" "$value" > /etc/sysctl.d/99-$rule.conf
		sysctl --system > /dev/null
	else
		for cfgvalue in $runningvalue $setvalue; do
			if [ "$cfgvalue" != "$value" ]; then
				for file in $(grep -e "^$setting" /etc/sysctl.conf /etc/sysctl.d/* | awk -F: '{print $1}' | sort | uniq); do
					str="$(egrep -e "^$setting" $file)"
					sed -i "s#^$str#$setting=$value#g" $file
					sysctl --system > /dev/null
				done
			fi
		done
	fi
}

function MODPROBECFG {
	module="$1"
	install="$2"

	if [ "$(grep -r -e $module /etc/modprobe.conf /etc/modprobe.d/* 2>/dev/null | wc -l)" -ge "1" ]; then
		for file in $(grep -r -e $module /etc/modprobe.conf /etc/modprobe.d/* 2>/dev/null | awk -F: '{print $1}' | sort | uniq); do
			currentinstall="$(egrep -e "^install $module" $file | awk '{print $3}')"
			blacklist="$(egrep -e "^blacklist $module$" $file | wc -l)"

			if [ "$install" != "$currentinstall" ]; then
				sed -i "s#^install $module.*#\# Modifying \"$module\" install to \"$install\" - $date\ninstall $module $install#g" $file
			fi
			if [ "$blacklist" != "1" ]; then
				printf "# Adding %s to blacklist - %s\nblacklist %s\n" "$module" "$date" "$module" >> $file
			fi
		done
	else
		modcfg="/etc/modprobe.d/$module.conf"
		printf "# Creating %s module config - %s\n" "$module" "$date" > $modcfg
		printf "install %s %s\n" "$module" "$install" >> $modcfg
		printf "blacklist %s\n" "$module" >> $modcfg
	fi
}

function SSHDCFG {
	setting="$1"
	value1="$2"
	value2="$3"

	if [ "$(egrep -e "^$setting" $sshdcfg | wc -l)" -lt "1" ]; then
		printf "# Adding \"$setting $value1 $value2\" - $date\n%s %s %s\n" "$setting" "$value1" "$value2" >> $sshdcfg
		systemctl restart sshd.service
	else
		current1="$(awk -v setting="$setting" '$1 == setting {print $2}' $sshdcfg)"
		current2="$(awk -v setting="$setting" '$1 == setting {print $3}' $sshdcfg)"
		if [ -z "$value2"  -a "$value1" != "$current1" ]; then
			str="$(grep -e "^$setting" $sshdcfg)"
			sed -i "s/^$str/# Modifying $setting to $value1 - $date\n$setting $value1/g" $sshdcfg
			systemctl restart sshd.service
		else
			if [ "$value2" != "$current2" ]; then
				str="$(grep -e "^$setting" $sshdcfg)"
				sed -i "s/^$str.*/# Modifying $setting to \"$value1 $value2\" - $date\n$setting $value1 $value2/g" $sshdcfg
				systemctl restart sshd.service
			fi
			if [ "$value1" != "$current1" ]; then
				str="$(grep -e "^$setting" $sshdcfg)"
				sed -i "s/^$str.*/# Modifying $setting to \"$value1 $value2\" - $date\n$setting $value1 $value2/g" $sshdcfg
				systemctl restart sshd.service
			fi
		fi
	fi
}

function SSHCRYPTO {
	rule="$1"
	file="$cryptodir/$2"
	fipsfile="$fipscryptodir/$(basename --suffix .config $2).txt"
	setting="$3"
	value="$4"

    for file in $fipsfile $file; do
        if [ -f "$file" ]; then
            if [ "$(grep -e "^$setting " $file | wc -l)" -ge "1" ]; then
                currentvalue="$(grep -e "^$setting " $file | sed "s#^$setting #$setting:#g" | tr -d [:blank:] | awk -F: '{print $2}')"
                if [ "$value" != "$currentvalue" ]; then
                    str="$(egrep -e "^$setting " $file)"
                    sed -i "s#^$str#$setting $value#g" $file
                    systemctl restart sshd.service
                fi
            else
                printf "%s %s\n" "$setting" "$value" >> $file
            fi
        fi
    done

	V258236
}

function V257779 {
cat > /etc/issue << EOF
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
}

function V257782 {
	sed 's/.*fips=1.*//g' /usr/lib/systemd/system/rngd.service > /etc/systemd/system/rngd.service
	systemctl daemon-reload
	systemctl start rngd
}

function V257949 {
	if [ "$(NetworkManager --print-config | grep -v -e "^#" | grep -e "^dns" | wc -l)" -lt "1" ]; then
		sed -i "s/\[main\]/\[main\]\n\n# Added $FUNCNAME $date - \"dns=none\"\ndns=none\n/g" $nmcfg
		systemctl reload NetworkManager
	else
		value="$(awk -F= '$1 == "dns" {print $2}' $nmcfg)"
		case $value in
			main)
			;;
			none)
			;;
			*)
				sed "s/^dns.*/# Modified $FUNCNAME $date - \"dns=none\"\ndns=none\n/g" $nmcfg
				systemctl reload NetworkManager
			;;
		esac
	fi
}

function V257982 {
	SSHDCFG LogLevel VERBOSE
}

function V257981 {
	SSHDCFG banner /etc/issue
}

function V257983 {
	SSHDCFG PubkeyAuthentication yes
}

function V257984 {
	SSHDCFG PermitEmptyPasswords no
}

function V257985 {
	SSHDCFG PermitRootLogin no
}

function V257986 {
	SSHDCFG UsePAM yes
}

function V257992 {
	SSHDCFG HostbasedAuthentication no
}

function V257993 {
	SSHDCFG PermitUserEnvironment no
}

function V257995 {
	SSHDCFG ClientAliveCountMax 1
}

function V257996 {
	SSHDCFG ClientAliveInterval 600
}

function V258010 {
	SSHDCFG UsePrivilegeSeparation sandbox
}

function V258011 {
	SSHDCFG X11UseLocalhost yes
}

function V257994 {
	SSHDCFG RekeyLimit 1G 1h
}

function V257804 {
	MODPROBECFG atm /bin/false
}

function V257805 {
	MODPROBECFG can /bin/false
}

function V257806 {
	MODPROBECFG firewire-core /bin/true
}

function V257807 {
	MODPROBECFG sctp /bin/false
}

function V257808 {
	MODPROBECFG tipc /bin/false
}

function V257880 {
	MODPROBECFG cramfs /bin/false
}

function V258034 {
	MODPROBECFG usb-storage /bin/false
}

function V258039 {
	MODPROBECFG bluetooth /bin/false
}

function V257937 {
	fwstate="$(firewall-cmd --state)"

	if [ "$fwstate" == "running" ]; then
		for fwzone in $(firewall-cmd --get-active-zones | grep -ve "^ "); do
			fwtarget="$(firewall-cmd --info-zone=$fwzone | grep target | awk '{print $NF}')"
			pfwtarget="$(firewall-cmd --permanent --info-zone=$fwzone | grep target | awk '{print $NF}')"

			for target in $fwtarget $pfwtarget; do
				if [ "$target" != "DROP" ]; then
					firewall-cmd --permanent --zone=$fwzone --set-target="DROP"
					firewall-cmd --complete-reload
				fi
			done
		done
	else
		printf "### %s: FirewallD isn't running correctly ###\n" "$FUNCNAME"
		systemctl restart firewalld.service
		sleep 10s
		V257937
	fi
}

function V257960 {
	SYSCTLCFG $FUNCNAME net.ipv4.conf.all.log_martians 1
}

function V257961 {
	SYSCTLCFG $FUNCNAME net.ipv4.conf.default.log_martians 1
}

function V257967 {
	SYSCTLCFG $FUNCNAME net.ipv4.icmp_ignore_bogus_error_responses 1
}

function V257970 {
	SYSCTLCFG $FUNCNAME net.ipv4.conf.all.forwarding 0
}

function V257989 {
	SSHCRYPTO $FUNCNAME openssh.config Ciphers aes-256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
}

function V257990 {
    printf "Per DISA, %s is to be used.\n" "V-257991"
}

function V257991 {
	SSHCRYPTO $FUNCNAME openssh.config MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512
}

function V258236 {
	for file in $(find $cryptodir -type f); do
		name="$(basename --suffix .config $file)"
		if [ "$(find $fipscryptodir -name "$name.txt" | wc -l)" -ge "1" ]; then
			cfgtxt="$(find $fipscryptodir -name "$name.txt" | head -n 1)"
			mv $file /root/$name-crypto-back-end-$date.bck
			ln -s $cfgtxt $cryptodir/$name.config
		fi
	done
	for link in $(find $cryptodir -type l); do
		file="$(file $link | awk '{print $NF}')"
		if [ "$(dirname $file)" != "$fipscryptodir" ]; then
			name="$(basename --suffix .txt $file)"
			cfg="$(find $fipscryptodir -name "$name.txt")"
			unlink $link
			ln -s $cfg $cryptodir/$name.config
		fi
	done

	for file in $(find $fipscryptodir -type f); do
		name="$(basename --suffix .txt $file)"
		cfg="$cryptodir/$name.config"
		if [ ! -f "$cfg" ]; then
			ln -s $file $cfg
		fi
	done
}

function V258065 {
	tmuxcfg="/etc/tmux.conf"
	for setting in lock-command lock-session; do
		if [ "$(grep -Ei $setting $tmuxcfg | wc -l)" -lt "1" ]; then
			case $setting in
				lock-command)
					printf "set -g lock-command vlock\n" >> $tmuxcfg
				;;
				lock-session)
					printf "bind X lock-session\n" >> $tmuxcfg
				;;
			esac
			tmux source $tmuxcfg
		fi
	done
}

function V258077 {
	SYSTEMDCFG $FUNCNAME logind.conf Login StopIdleSessionSec 900
}

function V258108 {
	LOGINDEFSCFG $FUNCNAME PASS_MIN_LEN 15
}

function V258119 {
	LOGINDEFSCFG $FUNCNAME SHA_CRYPT_MIN_ROUNDS 5000
	LOGINDEFSCFG $FUNCNAME SHA_CRYPT_MAX_ROUNDS 5000
}

function V258136 {
	AIDEATTRCFG $FUNCNAME sha512
}

function V258145 {
	AUDITPLUGINCFG $FUNCNAME syslog.conf active yes
}

function V258168 {
	AUDITCFG $FUNCNAME auditd.conf freq 100
}

function V258091 {
	PAMDCFG $FUNCNAME system-auth password required pam_pwquality.so retry 3
}

function V258092 {
	PAMDCFG $FUNCNAME password-auth password required pam_pwhistory.so remember 5
}

function V258093 {
	PAMDCFG $FUNCNAME system-auth password required pam_pwhistory.so remember 5
}

function V258099 {
	PAMDCFG $FUNCNAME password-auth password sufficient pam_unix.so  rounds 5000
}

function V258100 {
	PAMDCFG $FUNCNAME system-auth password sufficient pam_unix.so  rounds 5000
}

function V258125 {
	dnf list installed pcsc-lite >/dev/null
	if [ "$?" == "0" ]; then
		active="$(systemctl is-active pcscd)"
		if [ "$active" != "active" ]; then
			systemctl enable --now pcscd
		fi
	fi
}

function V257823 {
        function GETPKGS {
                for file in $(rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"' | awk '{print $NF}'); do
                        dnf provides $file | egrep -B 1 -e "^Repo" | head -n 1
                done
        }
        for pkg in $(GETPKGS | sort | uniq | awk '{print $1}'); do
                dnf reinstall -y $pkg
                if [ "$?" != "0" ]; then
                        printf "\n\n!!! Unable to do fix action for %s. !!!\n\nMight need to check YUM configuration to reinstall [%s].\n\n" "$FUNCNAME" "$pkg"
                        read -p "==== PRESS ANY KEY TO CONTINUE ===="
                fi
        done
}

function STIGIMPLEMENT {
	V258236
	V258125
	V258100
	V258099
	V258093
	V258092
	V258091
	V258168
	V258145
	V258136
	V258119
	V258108
	V258077
	V258065
	V257990
	V257989
	V257970
	V257967
	V257961
	V257960
	V257937
	V257779
	V257782
	V257949
	V257982
	V257981
	V257983
	V257984
	V257985
	V257986
	V257992
	V257993
	V257995
	V257996
	V258010
	V258011
	V257994
	V257804
	V257805
	V257806
	V257807
	V257808
	V257880
	V258034
	V258039
    V257823
}

STIGIMPLEMENT
