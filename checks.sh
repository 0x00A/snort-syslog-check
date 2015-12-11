#!/bin/bash
# Script to perform the snort daily checks

# Grep commands to display the Snort events by classification as variables
# Several classifications are grouped together as it's just for use as a summary

#Dates
today=$(date +%a_%d-%m-%y)
yesterday=$(date --date=yesterday +%a_%d-%m-%y)

#Number of Priority 1 events
p1_yesterday () {
sudo zcat dailychecks.gz |
egrep -c "Priority: 1"
}
p1_today () {
sudo cat todayevents |
egrep -c "Priority: 1"
}

# Total events
class_total () {
sudo zcat dailychecks.gz |
egrep -c "Classification: "
}
class_total_today () {
sudo cat todayevents |
egrep -c "Classification: "
}

# Traffic related
class_traffic () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Not Suspicious Traffic|\
Classification: Unknown Traffic|\
Classification: Potentially Bad Traffic"
}
class_traffic_today () {
sudo cat todayevents | 
egrep -c "Classification: Not Suspicious Traffic|\
Classification: Unknown Traffic|\
Classification: Potentially Bad Traffic"
}

# Information leaks
class_leaks () {
sudo zcat dailychecks.gz |
egrep -c "Classification: Attempted Information Leak|\
Classification: Information Leak|\
Classification: Large Scale Information Leak"
}
class_leaks_today () {
sudo cat todayevents |
egrep -c "Classification: Attempted Information Leak|\
Classification: Information Leak|\
Classification: Large Scale Information Leak"
}


# Denial of service
class_dos () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Attempted Denial of Service|\
Classification: Denial of Service|\
Classification: Detection of a Denial of Service Attack"
}
class_dos_today () {
sudo cat todayevents | 
egrep -c "Classification: Attempted Denial of Service|\
Classification: Denial of Service|\
Classification: Detection of a Denial of Service Attack"
}

# Privilege Gain
class_privgain () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Attempted User Privilege Gain|\
Classification: Unsuccessful User Privilege Gain|\
Classification: Successful User Privilege Gain|\
Classification: Attempted Admin|\
Classification: Attempted Administrator Privilege Gain|\
Classification: Successful Administrator Privilege Gain"
}
class_privgain_today () {
sudo cat todayevents | 
egrep -c "Classification: Attempted User Privilege Gain|\
Classification: Unsuccessful User Privilege Gain|\
Classification: Successful User Privilege Gain|\
Classification: Attempted Admin|\
Classification: Attempted Administrator Privilege Gain|\
Classification: Successful Administrator Privilege Gain"
}

# Web app attacks
class_webapp () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: access to a potentially vulnerable web application|\
Classification: Web Application Attack"
}
class_webapp_today () {
sudo cat todayevents | 
egrep -c "Classification: access to a potentially vulnerable web application|\
Classification: Web Application Attack"
}

# Malware
class_malware () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Known malicious file or file based exploit|\
Classification: Known malware command and control traffic|\
Classification: A Network Trojan was detected"
}
class_malware_today () {
sudo cat todayevents | 
egrep -c "Classification: Known malicious file or file based exploit|\
Classification: Known malware command and control traffic|\
Classification: A Network Trojan was detected"
}

# Suspicious activity
class_suspicious () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: A suspicious string was detected|\
Classification: A suspicious filename was detected|\
Classification: An attempted login using a suspicious username was detected|\
Classification: A client was using an unusual port|\
Classification: Detection of a non-standard protocol or event"
}
class_suspicious_today () {
sudo cat todayevents | 
egrep -c "Classification: A suspicious string was detected|\
Classification: A suspicious filename was detected|\
Classification: An attempted login using a suspicious username was detected|\
Classification: A client was using an unusual port|\
Classification: Detection of a non-standard protocol or event"
}

# Policy violation
class_policy () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Inappropriate Content was Detected|\
Classification: Potential Corporate Privacy Violation"
}
class_policy_today () {
sudo cat todayevents | 
egrep -c "Classification: Inappropriate Content was Detected|\
Classification: Potential Corporate Privacy Violation"
}

#Exploits
class_exploit () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Known client side exploit attempt"
}
class_exploit_today () {
sudo cat todayevents | 
egrep -c "Classification: Known client side exploit attempt"
}

# Sensitive Data
class_sensitive () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Senstive Data"
}
class_sensitive_today () {
sudo cat todayevents | 
egrep -c "Classification: Senstive Data"
}

# Default credentials
class_default () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Attempt to login by a default username and password"
}
class_default_today () {
sudo cat todayevents | 
egrep -c "Classification: Attempt to login by a default username and password"
}

# Shellcode
class_shellcode () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Executable code was detected"
}
class_shellcode_today () {
sudo cat todayevents | 
egrep -c "Classification: Executable code was detected"
}

# Calls
class_call () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Decode of an RPC Query|\
Classification: A system call was detected"
}
class_call_today () {
sudo cat todayevents | 
egrep -c "Classification: Decode of an RPC Query|\
Classification: A system call was detected"
}

#General network
class_network () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: A TCP connection was detected|\
Classification: Generic Protocol Command Decode|\
Classification: Generic ICMP event"
}
class_network_today () {
sudo cat todayevents | 
egrep -c "Classification: A TCP connection was detected|\
Classification: Generic Protocol Command Decode|\
Classification: Generic ICMP event"
}

#Network scan
class_scan () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Detection of a Network Scan"
}
class_scan_today () {
sudo cat todayevents | 
egrep -c "Classification: Detection of a Network Scan"
}

# Misc activity
class_misc () {
sudo zcat dailychecks.gz | 
egrep -c "Classification: Misc activity|\
Classification: Misc Attack"
}
class_misc_today () {
sudo cat todayevents | 
egrep -c "Classification: Misc activity|\
Classification: Misc Attack"
}

clear

echo
tput smul
tput bold
echo Snort Status Page
tput sgr0
echo -e "\n\n"
echo If the following Snort processes are not displayed beneath the \'Currently Running Snort Processes\' heading then they are not running:
echo 
echo /usr/sbin/snort -b -d -D -I -i eth6 -u snort -g snort -c /etc/snort/snort.conf -l /data/messages/snort/eth6
echo /usr/sbin/snort -b -d -D -I -i eth7 -u snort -g snort -c /etc/snort/snort.conf -l /data/messages/snort/eth7
echo -e "\n\n"
tput smul
tput bold
echo Currently Running Snort Processes
tput sgr0
echo -e "\n\n"

# Make sure that snort is running
ps -efa | grep snort | grep -v 'grep' | awk '{ s = ""; for (i = 8; i <= NF; i++) s = s $i " "; print s }'

echo -e "\n\n"
tput smul
tput bold
echo Interface Checks
tput sgr0
echo -e "\n\n"
echo Check that both eth6 and eth7 show as \'UP\'.
echo -e "\n\n"
ifconfig eth6
ifconfig eth7

echo -e "\n\n"
echo Press any key to continue...
echo 
# Wait for the user input to continue
read -n 1 -s

# Copy the previous days' logs to a file named 'dailychecks.gz'
ls -rt /var/log/messages-2* | tail -1 | xargs -i sudo cp {} ~/dailychecks.gz

# Put the 'dailychecks.gz' file into the 'users' group
sudo chgrp users dailychecks.gz

clear

echo
tput smul
tput bold
echo Snort Events Summary Yesterday - $yesterday
echo
tput sgr0

# Begin summary of yesterday's events

if [[ $(class_total) -ge 1 ]]; then

	echo There were a total of $(class_total) Snort events broken down into the following categories:
	echo
	echo

		if [[ $(class_leaks) -ge 2 ]];then
			echo Information Leaks - $(class_leaks) events
			echo
		elif [[ $(class_leaks) -eq 1 ]];then
			echo Information Leaks - $(class_leaks) event
			echo
		fi

		if [[ $(class_traffic) -ge 2 ]];then
			echo Unusual Traffic - $(class_traffic) events
			echo
		elif [[ $(class_traffic) -eq 1 ]];then
			echo Unusual Traffic - $(class_traffic) event
			echo
		fi

		if [[ $(class_dos) -ge 2 ]];then
			echo Denial of Service - $(class_dos) events
			echo
		elif [[ $(class_dos) -eq 1 ]];then
			echo Denial of Service - $(class_dos) event
			echo
		fi

		if [[ $(class_privgain) -ge 2 ]];then
			echo Privilage Escalation - $(class_privgain) events
			echo
		elif [[ $(class_privgain) -eq 1 ]];then
			echo Privilage Escalation - $(class_privgain) event
			echo
		fi

		if [[ $(class_webapp) -ge 2 ]];then
			echo Wep Application Attacks - $(class_webapp) events
			echo
		elif [[ $(class_webapp) -eq 1 ]];then
			echo Web Application Attacks - $(class_webapp) event
			echo
		fi

		if [[ $(class_malware) -ge 2 ]];then
			echo Malware = $(class_malware) events
			echo
		elif [[ $(class_malware) -eq 1 ]];then
			echo Malware = $(class_malware) event
			echo
		fi

		if [[ $(class_suspicious) -ge 2 ]];then
			echo Suspicious Activity - $(class_suspicious) events
			echo
		elif [[ $(class_suspicious) -eq 1 ]];then
			echo Suspicious Activity - $(class_suspicious) event
			echo
		fi

		if [[ $(class_policy) -ge 2 ]];then
			echo Policy Violation - $(class_policy) events
			echo
		elif [[ $(class_policy) -eq 1 ]];then
			echo Policy Violation - $(class_policy) event
			echo
		fi

		if [[ $(class_exploit) -ge 2 ]];then 
			echo Exploit - $(class_exploit) events
			echo
		elif [[ $(class_exploit) -eq 1 ]];then
			echo Exploit - $(class_exploit) event
			echo
		fi

		if [[ $(class_sensitive) -ge 2 ]];then
			echo Sensitive - $(class_sensitive) events
			echo
		elif [[ $(class_sensitive) -eq 1 ]];then
			echo Sensitive - $(class_sensitive) event
			echo
		fi

		if [[ $(class_default) -ge 2 ]];then
			echo Default Credentials in Use - $(class_default) events
			echo
		elif [[ $(class_default) -eq 1 ]];then
			echo Default Credentials in Use - $(class_default) event
			echo
		fi

		if [[ $(class_shellcode) -ge 2 ]];then
			echo Shellcode - $(class_shellcode) events
			echo
		elif [[ $(class_default) -eq 1 ]];then
			echo Shellcode - $(class_shellcode) event
			echo
		fi

		if [[ $(class_call) -ge 2 ]];then
	 		echo System/Remote Procedure Call $(class_call) events
			echo
		elif [[ $(class_call) -eq 1 ]];then
			echo System/Remote Procedure Call $(class_call) event
			echo
		fi

		if [[ $(class_network) -ge 2 ]];then
			echo General Network - $(class_network) events
			echo
		elif [[ $(class_network) -eq 1 ]];then
			echo General Network - $(class_network) event
			echo
		fi

		if [[ $(class_scan) -ge 2 ]];then
			echo Network Scan - $(class_scan) events
			echo
		elif [[ $(class_scan) -eq 1 ]];then 
			echo Network Scan - $(class_scan) event
			echo
		fi

		if [[  $(class_misc) -ge 2 ]];then
			echo Misc - $(class_misc) events
			echo
		elif [[  $(class_misc) -eq 1 ]];then 
			echo General Network - $(class_misc) event
			echo
		fi
	echo
	echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	echo The next page will display the events in detail.
	echo
	echo Press any key to continue...
	echo
	read -n 1 -s

	# End of summary

	zcat dailychecks.gz | grep -E 'Priority: 2|Priority: 3|Priority: 4|Priority: 5' | less

	clear

	# Allow the user to write the logs to a text file
	echo
	read -p "Do you wish to write these logs to a file? (y/n) " RESP
	if [[  "$RESP" = "y"  ]]; then
		sudo zcat dailychecks.gz | grep -E 'Priority: 2|Priority: 3|Priority: 4|Priority: 5' > ~/yesterdays_snort_events.txt
			echo -e "\n\n"
		echo Written to '~/yesterdays_snort_events.txt'
	tput sgr0
	echo
	echo Press any key to continue...
	echo
	read -n 1 -s

	else
		echo
	fi

	clear
	
	if [[  $(p1_yesterday) -ge 1 ]];then
 	 	echo
		tput smul
		tput bold
		echo Priority 1 Events Yesterday - $yesterday
		tput sgr0
		echo 
		echo Press any key to continue...
		echo
		read -n 1 -s

		zcat dailychecks.gz | grep --color=always 'Priority: 1' | less -R

		clear

		echo
		read -p "Do you wish to write these logs to a file? This will append '~/yesterdays_snort_events' if it exists. (y/n) " RESP
		if [[  "$RESP" = "y"  ]]; then
			sudo zcat dailychecks.gz | grep -E 'Priority: 1' >> ~/yesterdays_snort_events.txt
				echo -e "\n\n"
			echo Appended '~/yesterdays_snort_events'
		echo
		echo Press any key to continue...
		echo
		read -n 1 -s

		else
			echo
		fi

		clear

	else
	tput sgr0
	echo
	echo There were no priority 1 events yesterday.
	echo
	echo Press any key to continue...
	echo
	read -n 1 -s
	fi
else 
echo There were no Snort events yesterday.
echo
echo Press any key to continue...
echo
read -n 1 -s

fi

clear

echo
tput smul
tput bold
echo Snort Events Summary Today - $today
echo
tput sgr0

# Begin summary of today's events

sudo cat /var/log/messages | grep -E 'Priority: 2|Priority: 3|Priority: 4|Priority: 5' > ~/todayevents

if [[ $(class_total_today) -ge 1 ]]; then

	echo There were a total of $(class_total_today) Snort events broken down into the following categories:
	echo
	echo

		if [[ $(class_leaks_today) -ge 2 ]];then
			echo Information Leaks - $(class_leaks_today) events
			echo
		elif [[ $(class_leaks_today) -eq 1 ]];then
			echo Information Leaks - $(class_leaks_today) event
			echo
		fi

		if [[ $(class_traffic_today) -ge 2 ]];then
			echo Unusual Traffic - $(class_traffic_today) events
			echo
		elif [[ $(class_traffic_today) -eq 1 ]];then
			echo Unusual Traffic - $(class_traffic_today) event
			echo
		fi

		if [[ $(class_dos_today) -ge 2 ]];then
			echo Denial of Service - $(class_dos_today) events
			echo
		elif [[ $(class_dos_today) -eq 1 ]];then
			echo Denial of Service - $(class_dos_today) event
			echo
		fi

		if [[ $(class_privgain_today) -ge 2 ]];then
			echo Privilage Escalation - $(class_privgain_today) events
			echo
		elif [[ $(class_privgain_today) -eq 1 ]];then
			echo Privilage Escalation - $(class_privgain_today) event
			echo
		fi

		if [[ $(class_webapp_today) -ge 2 ]];then
			echo Wep Application Attacks - $(class_webapp_today) events
			echo
		elif [[ $(class_webapp_today) -eq 1 ]];then
			echo Web Application Attacks - $(class_webapp_today) event
			echo
		fi

		if [[ $(class_malware_today) -ge 2 ]];then
			echo Malware = $(class_malware_today) events
			echo
		elif [[ $(class_malware_today) -eq 1 ]];then
			echo Malware = $(class_malware_today) event
			echo
		fi

		if [[ $(class_suspicious_today) -ge 2 ]];then
			echo Suspicious Activity - $(class_suspicious_today) events
			echo
		elif [[ $(class_suspicious_today) -eq 1 ]];then
			echo Suspicious Activity - $(class_suspicious_today) event
			echo
		fi

		if [[ $(class_policy_today) -ge 2 ]];then
			echo Policy Violation - $(class_policy_today) events
			echo
		elif [[ $(class_policy_today) -eq 1 ]];then
			echo Policy Violation - $(class_policy_today) event
			echo
		fi

		if [[ $(class_exploit_today) -ge 2 ]];then 
			echo Exploit - $(class_exploit_today) events
			echo
		elif [[ $(class_exploit_today) -eq 1 ]];then
			echo Exploit - $(class_exploit_today) event
			echo
		fi

		if [[ $(class_sensitive_today) -ge 2 ]];then
			echo Sensitive - $(class_sensitive_today) events
			echo
		elif [[ $(class_sensitive_today) -eq 1 ]];then
			echo Sensitive - $(class_sensitive_today) event
			echo
		fi

		if [[ $(class_default_today) -ge 2 ]];then
			echo Default Credentials in Use - $(class_default_today) events
			echo
		elif [[ $(class_default_today) -eq 1 ]];then
			echo Default Credentials in Use - $(class_default_today) event
			echo
		fi

		if [[ $(class_shellcode_today) -ge 2 ]];then
			echo Shellcode - $(class_shellcode_today) events
			echo
		elif [[ $(class_default_today) -eq 1 ]];then
			echo Shellcode - $(class_shellcode_today) event
			echo
		fi

		if [[ $(class_call_today) -ge 2 ]];then
	 		echo System/Remote Procedure Call $(class_call_today) events
			echo
		elif [[ $(class_call_today) -eq 1 ]];then
			echo System/Remote Procedure Call $(class_call_today) event
			echo
		fi

		if [[ $(class_network_today) -ge 2 ]];then
			echo General Network - $(class_network_today) events
			echo
		elif [[ $(class_network_today) -eq 1 ]];then
			echo General Network - $(class_network_today) event
			echo
		fi

		if [[ $(class_scan_today) -ge 2 ]];then
			echo Network Scan - $(class_scan_today) events
			echo
		elif [[ $(class_scan_today) -eq 1 ]];then 
			echo Network Scan - $(class_scan_today) event
			echo
		fi

		if [[  $(class_misc_today) -ge 2 ]];then
			echo Misc - $(class_misc_today) events
			echo
		elif [[  $(class_misc_today) -eq 1 ]];then 
			echo General Network - $(class_misc_today) event
			echo
		fi
	echo 
	echo ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	echo The next page will display the events in detail.
	echo
	echo Press any key to continue...
	echo	
	read -n 1 -s

	# End of summary

	sudo cat todayevents | grep -E 'Priority: 2|Priority: 3|Priority: 4|Priority: 5' | less

	clear

	echo

	read -p "Do you wish to write these logs to a file? (y/n) " RESP
	if [[  "$RESP" = "y"  ]]; then
		sudo cat /var/log/messages | grep -E 'Priority: 2|Priority: 3|Priority: 4|Priority: 5' > ~/todays_snort_events.txt
			echo -e "\n\n"
		echo Written to '~/todays_snort_events'
	tput sgr0

	echo 
	echo Press any key to continue...
	echo
	read -n 1 -s

	else
		echo
	fi

	clear
	
	if [[  "p1_today" -ge 1  ]]; then
		echo 
		tput smul
		tput bold
		echo Priority 1 Events Today - $today
		echo
		tput sgr0
		echo Press any key to continue...
		echo
		read -n 1 -s
	
		sudo cat messages | grep --colour=always 'Priority: 1' | less -R

		clear

		echo

		read -p "Do you wish to write these logs to a file? This will append '~/todays_snort_events' if it exists. (y/n) " RESP
		if [[  "$RESP" = "y"  ]]; then
			sudo cat /var/log/messages | grep -E 'Priority: 1' >> ~/todays_snort_events.txt
				echo -e "\n\n"
			echo Appended '~/todays_snort_events'
		
		echo
		echo Press any key to exit...
		echo
		read -n 1 -s
		clear
		sudo rm dailychecks.gz
		rm todayevents
		exit
		else
		tput sgr0
			clear
		fi
	else
	tput sgr0
	echo
	echo There are currently no priority 1 events today.
	echo
	echo Press any key to exit...
	echo
	read -n 1 -s
	clear
	fi
	sudo rm dailychecks.gz
	rm todayevents
	exit
else
echo There are currently no Snort events today.
echo
echo Press any key to exit...
echo
read -n 1 -s
clear
fi
sudo rm dailychecks.gz
rm todayevents
exit
# Written by Scott Pendlebury 12/2013
