#!/bin/bash -xv
date="$(date +%F)"
nmcfg="/etc/NetworkManager/NetworkManager.conf"
sshdcfg="/etc/ssh/sshd_config"

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

function STIGIMPLEMENT {
	V257937
	#V257779
	#V257782
	#V257949
	#V257982
	#V257981
	#V257983
	#V257984
	#V257985
	#V257986
	#V257992
	#V257993
	#V257995
	#V257996
	#V258010
	#V258011
	#V257994
	#V257804
	#V257805
	#V257806
	#V257807
	#V257808
	#V257880
	#V258034
	#V258039
}

STIGIMPLEMENT
