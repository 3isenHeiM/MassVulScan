#!/bin/bash

#############################################################################################################################
#
# Script Name    : MassVulScan.sh
# Description    : This script combines the high processing speed to find open ports (MassScan), the effectiveness
#                  to identify open services versions (Nmap).
#                  A beautiful report (nmap-bootstrap.xsl) is generated containing all hosts found with open ports,
#                  and finally a text file including specifically the potential vulnerables hosts is created.
# Author         : https://github.com/3isenHeiM
# Site           : https://hack2know.how/
# Date           : 2020-12-08
# Version        : 1.9.0
# Usage          : ./MassVulScan.sh [[-f file] + [-e file] [-i] [-a] [-c] [-k] [-ns] | [-h] [-v]]
# Prerequisites  : Install MassScan (>=1.0.5) & Nmap to use this script.
#                  Xsltproc package is also necessary.
#                  Please, read the file "requirements.txt" if you need some help.
#                  With a popular OS from Debian OS family (e.g. Debian, Ubuntu, Linux Mint or Elementary),
#                  the installation of these prerequisites is automatic.
#
#############################################################################################################################

version="2.0.0"
yellow_color="\033[1;33m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"
source_installation="./sources/installation.sh"
source_top_tcp="./sources/top-ports-tcp-100.txt"
source_top_udp="./sources/top-ports-udp-100.txt"
top_ports="100"
script_start="$SECONDS"
report_folder="$(pwd)/reports/"
date="$(date +%F_%H-%M-%S)"


##### FILES THAT WILL BE CREATED
file_only_IP="MVS_only_IPs.txt"
file_IP_and_hostnames="MVS_IPs_and_hostnames.txt"
file_hosts_to_dig="MVS_hosts_to_convert.txt"
file_DNS_answers="MVS_DNS_answers.txt"
file_hosts_resolved="MVS_hosts_resolved.txt"
file_duplicate_IP="MVS_duplicate_IPs.txt"
file_unique_IP="MVS_unique_IPs.txt"
file_unsorted_IP="MVS_unsorted_IP.txt"
masscan_output="MVS_masscan_output.txt"
file_nmap_check_result="MVS_nmap_check_result.txt"
file_nmap_temp="MVS_nmap_input_temp.txt"
file_nmap_input="MVS_nmap_input.txt"
file_IP_and_hostnames_merged="MVS_IPs_and_hostnames_merged.txt"
file_nmap_output="MVS_nmap_output.xml"
file_nmap_process="MVS_process_nmap.txt"

# Time elapsed
time_elapsed(){
script_end="$SECONDS"
script_duration="$((script_end-script_start))"

printf 'Duration: %02dh:%02dm:%02ds\n' $((${script_duration}/3600)) $((${script_duration}%3600/60)) $((${script_duration}%60))
}

# Logo
banner(){
	if [[ $(which figlet) ]]; then
		my_logo="$(figlet -w 50 -c -f maxiwi MassVulScan)"
		echo -e "${end_color}"
		echo -e "${red_color}${my_logo}${end_color}"
	else
		echo -e "${end_color}"
		echo -e "${red_color}  █   █                 █ █            ███                "
		echo -e "${red_color}  ██ ██  ███  ███  ███  █ █  █ █  █    █    ███  ███  ███ "
		echo -e "${red_color}  █ █ █    █  █    █    █ █  █ █  █     █   █      █  █ █ "
		echo -e "${red_color}  █   █  ███    █    █  █ █  █ █  █      █  █    ███  █ █ "
		echo -e "${red_color}  █   █  ███  ███  ███   █   ███  ███  ███  ███  ███  █ █ "
		echo -e "${end_color}"
	fi
	echo -e "${yellow_color}                                        Version ${version}"

}

# Usage of script
usage(){
  echo -e "${red_color}${bold_color}$(date +"[%H:%M]")${end_color}${blue_color} Usage: Root user or sudo${end_color} ./$(basename "$0") [[-f file] + [-e file] [-i] [-a] [-c] [-k] [-ns] | [-v] [-h]]"
	echo -e "${red_color}${bold_color}$(date +"[%H:%M]")${end_color}${blue_color} Information: Bash script which identifies open network ports and any associated vulnerabilities."
	echo -e "${end_color}"
	echo -e "${bold_color}    * Mandatory parameter:"
	echo -e "${yellow_color}        -f | --include-file${end_color}"
	echo "          Input file including IPv4 addresses and/or hostnames to scan, compatible with subnet mask."
	echo "          Example:"
	echo "                  # You can add a comment in the file"
	echo "                  10.66.0.0/24"
	echo "                  webmail.acme.corp"
	echo -e "${end_color}"
	echo -e "${bold_color}          By default, the top ${top_ports} TCP/UDP ports are scanned, the rate is fix to 2.5K pkts/sec."
	echo -e "${end_color}"
	echo -e "${bold_color}    * Optional parameters (must be used in addition of \"-f\" parameter):"
	echo -e "${yellow_color}        -e | --exclude-file${end_color}"
	echo "          Exclude file including IPv4 addresses (NO hostname) to NOT scan, compatible with subnet mask."
	echo "          Example:"
	echo "                  # You can add a comment in the file"
	echo "                  10.66.0.128/25"
	echo "                  10.66.6.225"
	echo -e "${end_color}"
	echo -e "${yellow_color}        -a | --all-ports${end_color}"
	echo "          Scan all 65535 ports (TCP + UDP), the maximum rate is fix to 5K pkts/sec."
	echo -e "${end_color}"
	echo -e "${yellow_color}        -c | --check${end_color}"
	echo "          Perform a Nmap pre-scanning to identify online hosts and scan only them."
	echo "          By default, all the IPs addresses will be tested, even if the host is unreachable."
	echo -e "${end_color}"
	echo -e "${yellow_color}        -k | --keep-ips${end_color}"
	echo "          Keep IPs scanned with and without open ports and protocols in two files (same exiting file is overwritten)"
	echo "          By default, all the files used are deleted at the end of the script."
	echo "          Example:"
	echo "                  All_IPs_scanned_with_ports.txt:    tcp:10.66.6.11:25,443 webmail.acme.corp,smtp.acme.corp"
	echo "                                                     udp:10.66.6.12:53,137"
	echo "                  All_IPs_scanned_without_ports.txt: 10.66.6.11"
	echo -e "${end_color}"
	echo -e "${yellow_color}        -ns | --no-nmap-scan${end_color}"
	echo "          Use only the script to detect the hosts with open ports (no reports provided)."
	echo -e "${end_color}"
	echo -e "${yellow_color}        -h | --help${end_color}"
	echo "          This help menu."
	echo -e "${end_color}"
	echo -e "${yellow_color}        -v | --version${end_color}"
	echo "          Script version."
	echo ""
}



# Root user?
check_root(){
if [[ $(id -u) != "0" ]]; then
	echo -e "${red_color}${bold_color}$(date +"[%H:%M]") You are not root.${end_color}"
	echo "    Assuming your are in the sudoers list, please launch the script with \"sudo\"."
	exit 1
fi
}

# Verifying if installation source file exist
source_file(){
if [[ -z ${source_installation} ]] || [[ ! -s ${source_installation} ]]; then
	echo -e "${red_color}${bold_color}$(date +"[%H:%M]") Source file \"${source_installation}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}    This script can install the prerequisites for you.${end_color}"
	echo "    Please, download the source from Github and try again: git clone https://github.com/3isenHeiM/MassVulScan.git"
	exit 1
fi
}

# Verifying if top-ports source files exist
source_file_top(){
if [[ -z ${source_top_tcp} ]] || [[ ! -s ${source_top_tcp} ]]; then
	echo -e "${red_color}$(date +"[%H:%M]") Source file \"${source_top_tcp}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}    This file is a prerequisite to scan TCP top ports.${end_color}"
	echo "    Please, download the source from Github and try again: git clone https://github.com/3isenHeiM/MassVulScan.git"
	exit 1
elif [[ -z ${source_top_udp} ]] || [[ ! -s ${source_top_udp} ]]; then
	echo -e "${red_color}$(date +"[%H:%M]") Source file \"${source_top_udp}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}    This file is a prerequisite to scan UDP top ports.${end_color}"
	echo "    Please, download the source from Github and try again: git clone https://github.com/3isenHeiM/MassVulScan.git"
	exit 1
fi
}

# Checking prerequisites
if [[ ! $(which masscan) ]] || [[ ! $(which nmap) ]] || [[ ! $(which xsltproc) ]]; then
	echo -e "${red_color}$(date +"[%H:%M]") There are some prerequisites to install before to launch this script.${end_color}"
	echo -e "${yellow_color}    Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):${end_color}"
	echo "$(grep ^-- "requirements.txt")"
	# Automatic installation for Debian OS family
	source_file
	source "${source_installation}"
else
	masscan_version="$(masscan -V | grep "Masscan version" | cut -d" " -f3)"
	nmap_version="$(nmap -V | grep "Nmap version" | cut -d" " -f3)"
	if [[ ${masscan_version} < "1.0.5" ]]; then
		echo -e "${red_color}$(date +"[%H:%M]") Masscan is not up to date.${end_color}"
		echo "    Be sure to have the last Masscan version >= 1.0.5."
		echo "    Your current version is: ${masscan_version}"
		# Automatic installation for Debian OS family
		source_file
		source "${source_installation}"
	fi
	if [[ ${nmap_version} < "7.60" ]]; then
		echo -e "${red_color}$(date +"[%H:%M]") Nmap is not up to date.${end_color}"
		echo "    Be sure to have Nmap version >= 7.60."
		echo "    Your current version is: ${nmap_version}"
		# Automatic installation for Debian OS family
		source_file
		source "${source_installation}"
	fi
fi

hosts="$1"
exclude_file=""
check="off"

banner

# No paramaters
if [[ "$1" == "" ]]; then
	usage
	exit 1
fi

# Available parameters
while [[ "$1" != "" ]]; do
        case "$1" in
                -f | --include-file )
                        shift
                        hosts="$1"
                        ;;
                -e | --exclude-file )
                        file_to_exclude="yes"
                        shift
                        exclude_file="$1"
                        ;;
                -a | --all-ports )
                        all_ports="on"
                       ;;
                -c | --check )
                        check="on"
                        ;;
                -k | --keep-ips )
                        keep="on"
                        ;;
                -ns | --no-nmap-scan )
                        no_nmap_scan="on"
                        ;;
                -h | --help )
                        usage
                        exit 0
                        ;;
                -v | --version )
                        echo -e "${yellow_color}$(date +"[%H:%M]") Script version is: ${bold_color}${version}${end_color}"
                        exit 0
                        ;;
                * )
                        usage
                        exit 1
        esac
        shift
done

check_root

# Checking if process already running
check_proc="$(ps -C "MassVulScan.sh" | grep -c "MassVulScan\.sh")"

if [[ ${check_proc} -gt "2" ]]; then
	echo -e "${red_color}$(date +"[%H:%M]") A process \"MassVulScan.sh\" is already running.${end_color}"
	exit 1
fi

# Valid input file?
if [[ -z ${hosts} ]] || [[ ! -s ${hosts} ]]; then
	echo -e "${red_color}$(date +"[%H:%M]") Input file \"${hosts}\" does not exist or is empty.${end_color}"
	echo "    Please, try again."
	exit 1
fi

# Valid exclude file?
if [[ ${file_to_exclude} = "yes" ]]; then
        if [[ -z ${exclude_file} ]] || [[ ! -s ${exclude_file} ]]; then
                echo -e "${red_color}$(date +"[%H:%M]") Exclude file \"${exclude_file}\" does not exist or is empty.${end_color}"
                echo "    Please, try again."
                exit 1
        fi
fi

# Cleaning old files
rm -rf MVS_* "${nmap_temp}" /tmp/nmap_temp-* 2>/dev/null

# Folder for temporary Nmap file(s)
nmap_temp="$(mktemp -d /tmp/nmap_temp-XXXXXXXX)"


##########################
# Parsing the input file #
##########################

echo -e "${blue_color}${bold_color}$(date +"[%H:%M]") Parsing the input file... ${end_color}"

# First parsing to translate the hostnames to IPs
# This will extract the number of non-IP entries in the file
num_hosts=$(grep -v "^#" ${hosts} | grep "\S" | grep -vEoc '([0-9]{1,3}\.){3}[0-9]{1,3}')

# If hostnames are present in the file
if [[ ${num_hosts} != "0" ]]; then
	echo -e "${blue_color}${bold_color}    ${num_hosts} hostname(s) has been detected, we will try to translate them to IPv4.${end_color}"

	# Saving IPs first
	# Extracting the IPs from the file
	if [[ $(grep -v "^#" ${hosts} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}') ]]; then
		grep -v "^#" ${hosts} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' > $file_IP_and_hostnames
	fi

	# Filtering on the hosts only
	grep -v "^#" ${hosts} | grep "\S" | grep -vE '([0-9]{1,3}\.){3}[0-9]{1,3}' > $file_hosts_to_dig

	# Crawl $file_hosts_to_dig and request the corresponding IP
	# Results will be stored in $file_DNS_answers
	echo -n -e "    Asking the DNS server..."
	while IFS=, read -r host_to_dig; do
		# Get the IP via a dig request
		host_ip=$(dig ${host_to_dig} +short | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
		# Store <IP> <hostname> in the file $file_DNS_answers
		echo $host_ip ${host_to_dig} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' >> $file_DNS_answers
  done < $file_hosts_to_dig

	echo -e "done."

	num_resolved_hosts=$(sort -u $file_DNS_answers | wc -l)

	# Check if all the hostnames have been resolved
	if [[ ${num_resolved_hosts} -ne ${num_hosts} ]]; then
		echo -e "${red_color}${bold_color}$(date +"[%H:%M]") ${num_resolved_hosts}/${num_hosts} hostname(s) have been resolved.${end_color}"
		# Build the list of hostname resolved
		cat $file_DNS_answers | cut -d " " -f 2 > $file_hosts_resolved

		echo -e "${blue_color}    Hostnames not resolved :${end_color}"
		not_resolved=$(diff --new-line-format="" --unchanged-line-format=""  $file_hosts_to_dig $file_hosts_resolved)
		for line in "${not_resolved}"; do echo "      ${line}"; done
		echo -e ""
	else
		echo -e "${blue_color}${bold_color}$(date +"[%H:%M]") All hostnames have been resolved.${end_color}"
	fi
fi
# echo -e "done."

# Second parsing to detect multiple IPs for the same hostname
echo -n -e "${blue_color}${bold_color}$(date +"[%H:%M]") Eliminating duplicates...${end_color}"

if [[ -s $file_DNS_answers ]]; then
	# Read the file containing <IP> <hostname>
	while read line; do
		num_ips=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)

		if [[ ${num_ips} -gt "1" ]]; then
			# Filtering on the multiple IPs only
			hostname=$(echo ${line} | grep -oE '[^ ]+$')
			ips_list=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
			ips_tab=(${ips_list})
			ips_loop="$(for index in "${!ips_tab[@]}"; do echo "${ips_tab[${index}]} ${hostname}"; done)"

			echo "${ips_loop}" >> $file_IP_and_hostnames
		else
			# Saving uniq IP
			echo ${line} >> $file_IP_and_hostnames
		fi
	done < $file_DNS_answers


	# Third parsing to detect duplicate IPs and keep the multiple hostnames
	# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html

	cat $file_IP_and_hostnames | awk '/.+/ { \
				if (!($1 in ips_list)) { \
				value[++i] = $1 } ips_list[$1] = ips_list[$1] $2 "," } END { \
				for (j = 1; j <= i; j++) { \
				printf("%s %s\n%s", value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' > $file_unsorted_IP
fi

# Get the target filename only
hosts_sorted_filename="${hosts%.*}"
# Extract its extension
hosts_sorted_extension="${hosts##*.}"
# Append "_sorted" to the input filename
hosts_sorted="${hosts_sorted_filename}_sorted.${hosts_sorted_extension}"

if [[ -s $file_unsorted_IP ]]; then
	# There are hostnames, so use the file $file_unsorted_IP
	cut -d" " -f1 $file_unsorted_IP | sort -u | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts_sorted}
else
	# No hostnames, we can directly use the input file
	cut -d" " -f1 ${hosts} | sort -u | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts_sorted}
fi

echo -e " done."


echo -e "${red_color}${bold_color}$(date +"[%H:%M]") Here are the IPs that will be scanned.${end_color}"
if [[ ${exclude_file} != "" ]] ; then
	echo -e "    Don't worry, the exlude_file will be taken into account when giving these to masscan and nmap !"
fi
for line in $(cat $hosts_sorted); do echo "    ${line}"; done

# From now on, the input file is the sorted input file
hosts="${hosts_sorted}"

# Get all the ports
top_ports_tcp="$(grep -v ^"#" ${source_top_tcp})"
top_ports_udp="$(grep -v ^"#" ${source_top_tcp})"

source_file_top
ports="-p${top_ports_tcp},U:${top_ports_udp}"
rate="2500"
echo -e ""
echo -e "${yellow_color}$(date +"[%H:%M]") Default parameters: --top-ports ${top_ports} (TCP/UDP) and --max-rate 2500.${end_color}"


################################################
# Checking if there are more than 2 interfaces #
################################################

interface="$(ip route | grep default | cut -d" " -f5)"
nb_interfaces="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -co "^[[:alnum:]]*")"

if [[ ${nb_interfaces} -gt "2" ]]; then
	interfaces_list="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -o "^[[:alnum:]]*")"
	interfaces_tab=(${interfaces_list})
	echo -e "${blue_color}${bold_color}$(date +"[%H:%M]") Warning: multiple network interfaces have been detected:${end_color}"
	interfaces_loop="$(for index in "${!interfaces_tab[@]}"; do echo "    ${index}) ${interfaces_tab[${index}]}"; done)"
	echo -e "${blue_color}${interfaces_loop}${end_color}"
	echo -e "${blue_color}${bold_color}Which one do you want to use? [choose the corresponding number to the interface name]${end_color}"
	echo -e "${blue_color}${bold_color}Or typing \"Enter|Return\" key to use the one corresponding to the default route${end_color}"
  read -p "Interface number? >> " -r -t 60 interface_number
  if [[ -z ${interface_number} ]];then
		echo -e "\n${red_color}$(date +"[%H:%M]") No interface chosen, we will use the one with the default route.${end_color}"
  else
		interface="${interfaces_tab[${interface_number}]}"
  fi
  echo -e "${yellow_color}$(date +"[%H:%M]") Network interface chosen: ${interface}${end_color}"
fi

##################################################
##################################################
## Okay, serious matters start there! Let's go! ##
##################################################
##################################################

###################################################
# 1/4 First analysis with Nmap to find live hosts #
###################################################

if [[ ${check} = "on" ]]; then

	echo -e "${blue_color}$(date +"[%H:%M]") Checking LIVE hosts...${end_color}"
	if [[ ${exclude_file} = "" ]] ; then
		nmap -sP -T5 --min-parallelism 100 --max-parallelism 256 -iL "${hosts}" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > $file_nmap_check_result
	else
		nmap -sP -T5 --min-parallelism 100 --max-parallelism 256 -iL "${hosts}" --excludefile ${exclude_file}  | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > $file_nmap_check_result
	fi

	if [[ $? != "0" ]]; then
			echo -e "${error_color}$(date +"[%H:%M]") ERROR! Please verify parameters or input/exclude file format.${end_color}"
			echo -e "${error_color}    Maybe there is no host detected online. Exiting.${end_color}"
			rm -rf $file_nmap_check_result
			time_elapsed
			exit 1
	fi

  echo -e "${green_color}$(date +"[%H:%M]") Pre-scanning phase is ended.${end_color}"
  hosts="$file_nmap_check_result"
  nb_hosts_nmap="$(< "${hosts}" wc -l)"
  echo -e "${yellow_color}$(date +"[%H:%M]")    ${nb_hosts_nmap} IP address(es) to check.${end_color}"

fi

########################################
# 2/4 Using Masscan to find open ports #
########################################

echo -e "${blue_color}$(date +"[%H:%M]") Running Masscan...${end_color}"

if [[ ${exclude_file} = "" ]] ; then
	echo "masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL ${masscan_output}"
	masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL $masscan_output

else
	echo "masscan --open ${ports} --source-port 40000 -iL "${hosts}" --excludefile "${exclude_file}" -e "${interface}" --max-rate "${rate}" -oL ${masscan_output}"
	masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL $masscan_output
fi

if [[ $? != "0" ]]; then
	echo -e "${error_color}$(date +"[%H:%M]") ERROR. Something went wrong with masscan.${end_color}"
	echo -e "    Please verify parameters or input/exclude file format. Exiting."
	rm -rf $masscan_output
	exit 1
fi

echo -e "${green_color}$(date +"[%H:%M]") Masscan phase has ended.${end_color}"

if [[ -z $masscan_output ]]; then
	echo -e "${error_color}$(date +"[%H:%M]") ERROR. File \"${masscan_output}\" disappeared! Exiting.${end_color}"
	exit 1
fi

if [[ ! -s $masscan_output ]]; then
        echo -e "${green_color}$(date +"[%H:%M]") No IP with open TCP/UDP ports found. Exiting.${end_color}"
	rm -rf $masscan_output
	time_elapsed
	exit 0
else
	tcp_ports="$(grep -c "^open tcp" $masscan_output)"
	udp_ports="$(grep -c "^open udp" $masscan_output)"
	nb_ports="$(grep -c ^open $masscan_output)"
	nb_hosts_nmap="$(grep ^open $masscan_output | cut -d" " -f4 | sort | uniq -c | wc -l)"
	echo -e "${yellow_color}$(date +"[%H:%M]") ${nb_hosts_nmap} host(s) concerning ${nb_ports} open ports.${end_color}"
fi

###########################################
# 3/4 Identifying open services with Nmap #
###########################################

# Output file with hostnames
merge_ip_hostname(){
	cat $file_nmap_input | while IFS=, read -r line; do
		search_ip=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

		if [[ $(grep "${search_ip}" $file_unsorted_IP) ]] 2>/dev/null; then

			if [[ $(grep "${search_ip}" $file_unsorted_IP | awk -F" " '{print $2}') ]]; then
				search_hostname=$(grep "${search_ip}" $file_unsorted_IPt | awk -F" " '{print $2}')
				echo "${line} ${search_hostname}" >> $file_IP_and_hostnames_merged
			else
				echo "${line}" >> $file_IP_and_hostnames_merged
			fi
		else
			echo "${line}" >> $file_IP_and_hostnames_merged
		fi
	done
}

# Hosts list scanned
hosts_scanned(){
	echo -e "${yellow_color}${bold_color}$(date +"[%H:%M]") Host(s) discovered with an open port(s):${end_color}"
	grep ^open $masscan_output | awk '{ip[$4]++} END{for (i in ip) {print "  " i " has " ip[i] " open port(s)"}}' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4
}

# Preparing the input file for Nmap
# This will create the file $file_nmap_temp with the conversion of the Masscan output
nmap_file(){
	proto="$1"
	# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html
	grep "^open ${proto}" $masscan_output | awk '/.+/ { \
					if (!($4 in ips_list)) { \
					value[++i] = $4 } ips_list[$4] = ips_list[$4] $3 "," } END { \
					for (j = 1; j <= i; j++) { \
					printf("%s:%s:%s\n%s", $2, value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' >> $file_nmap_temp
}

# Preparing input file for Nmap
if [[ ${tcp_ports} -gt "0" ]]; then
	nmap_file tcp
fi

# Preparing input file for Nmap
if [[ ${udp_ports} -gt "0" ]]; then
	nmap_file udp
fi

# Sort the file
sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 $file_nmap_temp > $file_nmap_input

if [[ ${no_nmap_scan} != "on" ]]; then

	nb_nmap_process="$(sort -n $file_nmap_input | wc -l)"

	# Keep the nmap input file?
	if [[ ${keep} == "on" ]]; then
		hosts_scanned
		merge_ip_hostname
		mv $file_IP_and_hostnames_merged ${report_folder}All_IPs_scanned_with_ports.txt
		grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' $file_nmap_input | sort -u > ${report_folder}All_IPs_scanned_without_ports.txt
		echo -e "${yellow_color}$(date +"[%H:%M]") All the IPs scanned are in these 2 files:${end_color}"
		echo -e "${blue_color}        -> ${report_folder}All_IPs_scanned_with_ports.txt${end_color}"
		echo -e "${blue_color}        -> ${report_folder}All_IPs_scanned_without_ports.txt${end_color}"
	fi

	function progress_bar {
		# Get the line of the terminal length
		linelength=$(tput cols)
		let _barsize=($linelength-35) # 30 is approx the number of chars dispalyed
		# Inspired from https://github.com/fearside/ProgressBar/
		# Process data
    let _progress=(${1}*100/${2}*100)/100	# _progress is the percentage
    let _done=(${_progress}*${_barsize})/100
    let _left=${_barsize}-$_done

		# echo "${_progress} ${_done} ${_left}"
		# Build progressbar string lengths
    _fill=$(printf "%${_done}s")
    _empty=$(printf "%${_left}s")

		# 1.2 Build progressbar strings and print the ProgressBar line
		# 1.2.1 Output example:
		# 1.2.1.1 Progress : [########################################] 100%
		echo -n -e "\r        Nmap scan ${1}/${2} |${_fill// /█}${_empty// / }| ${_progress}%"

	}

	# Function for parallel Nmap scans
	parallels_scans(){
		proto="$(echo "$1" | cut -d":" -f1)"
		ip="$(echo "$1" | cut -d":" -f2)"
		port="$(echo "$1" | cut -d":" -f3)"

		if [[ $proto == "tcp" ]]; then
			nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sT -sV -n  -oA "${nmap_temp}/${ip}"_tcp_nmap-output "${ip}" > /dev/null 2>&1
			echo "${ip} (${proto}): Done" >> $file_nmap_process
			else
				nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sU -sV -n  -oA "${nmap_temp}/${ip}"_udp_nmap-output "${ip}" > /dev/null 2>&1
				echo "${ip} (${proto}): Done" >> $file_nmap_process
		fi

		nmap_proc_ended="$(grep "$Done" -co $file_nmap_process)"
		percent="$(awk "BEGIN {printf \"%.2f\n\", "${nmap_proc_ended}/${nb_nmap_process}*100"}")"
		# Clear the line
		linelength=$(tput cols)
	  _fill=$(printf "%${linelength}s")
		echo -n -e "\r${_fill// / }"
		# Add the new line
		echo -e "\r${yellow_color}${bold_color}$(date +"[%H:%M]") Scan is done for ${ip} (${proto})${end_color}"
		# Print current progress par
		progress_bar ${nmap_proc_ended} ${nb_nmap_process}
	}

	# Controlling the number of Nmap scanner to launch
	if [[ ${nb_nmap_process} -ge "50" ]]; then
		max_job="50"
		echo -e "${blue_color}${bold_color}$(date +"[%H:%M]") Warning: A lot of Nmap process to launch: ${nb_nmap_process}${end_color}"
		echo -e "${blue_color}    So, to no disturb your system, I will only launch ${max_job} Nmap process at time.${end_color}"
		else
			echo -e "${blue_color}${bold_color}$(date +"[%H:%M]") Launching ${nb_nmap_process} Nmap scanner(s) in the same time...${end_color}"
			max_job="${nb_nmap_process}"
	fi

	# Queue files
	new_job(){
	job_act="$(jobs | wc -l)"
	while ((job_act >= ${max_job})); do
		job_act="$(jobs | wc -l)"
	done
	parallels_scans "${ip_to_scan}" &
	}

	# We are launching all the Nmap scanners in the same time
	count="1"

	rm -rf $file_nmap_process

	while IFS=, read -r ip_to_scan; do
		new_job $i
		count="$(expr $count + 1)"
	done < $file_nmap_input

	wait

	sleep 2 && tset

	echo -e "\n${green_color}$(date +"[%H:%M]") Nmap phase is ended.${end_color}"

elif [[ ${no_nmap_scan} == "on" ]] && [[ ${keep} == "on" ]]; then
	echo -e "${yellow_color}$(date +"[%H:%M]") No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat $file_IP_and_hostnames_merged)${end_color}"
	mv IPs_hostnames_merged.txt ${report_folder}All_IPs_scanned_with_ports.txt
	grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' $file_nmap_input | sort -u > ${report_folder}All_IPs_scanned_without_ports.txt
	echo -e "${yellow_color}$(date +"[%H:%M]") All the IPs scanned are in these 2 files:${end_color}"
	echo -e "${blue_color}        -> ${report_folder}All_IPs_scanned_with_ports.txt${end_color}"
	echo -e "${blue_color}        -> ${report_folder}All_IPs_scanned_without_ports.txt${end_color}"

else
	echo -e "${yellow_color}$(date +"[%H:%M]") No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat $file_IP_and_hostnames_merged)${end_color}"
fi

##########################
# 4/4 Generating reports #
##########################

if [[ ${no_nmap_scan} != "on" ]]; then
	nmap_bootstrap="./stylesheet/nmap-bootstrap.xsl"

	global_report_name="Global-Report"


	# Merging all the Nmap XML files to one big XML file
	echo "<?xml version=\"1.0\"?>" > $file_nmap_output
	echo "<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">" >> $file_nmap_output
	echo "<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl\" type="text/xsl\"?>" >> $file_nmap_output
	echo "<!-- nmap results file generated by MassVulScan.sh -->" >> $file_nmap_output
	echo "<nmaprun args=\"nmap --max-retries 2 --max-rtt-timeout 500ms -p[port(s)] -Pn -s(T|U) -sV -n [ip(s)]\" scanner=\"Nmap\" start=\"\" version=\"${nmap_version}\" xmloutputversion=\"1.04\">" >> $file_nmap_output
	echo "<!--Generated by MassVulScan.sh--><verbose level=\"0\" /><debug level=\"0\" />" >> $file_nmap_output

	for i in ${nmap_temp}/*.xml; do
		sed -n -e '/<host /,/<\/host>/p' "$i" >> $file_nmap_output
	done

	echo "<runstats><finished elapsed=\"\" exit=\"success\" summary=\"Nmap XML merge done at $(date); ${vuln_hosts_count} vulnerable host(s) found\" \
	      time=\"\" timestr=\"\" /><hosts down=\"0\" total=\"${nb_hosts_nmap}\" up=\"${nb_hosts_nmap}\" /></runstats></nmaprun>" >> $file_nmap_output

	# Using bootstrap to generate a beautiful HTML file (report)
	xsltproc -o "${date}_${global_report_name}.html" "${nmap_bootstrap}" $file_nmap_output 2>/dev/null

	# End of script
	echo -e "${yellow_color}$(date +"[%H:%M]") Global HTML report generated:"
	echo -e "${blue_color}           -> ${report_folder}${date}_${global_report_name}.html${end_color}"

	# Moving Nmap raw output to report folder
	mv ${nmap_temp}/*.nmap "${report_folder}"

	echo -e "${green_color}$(date +"[%H:%M]") Report phase is ended, bye!${end_color}"
else
	echo -e "${yellow_color}$(date +"[%H:%M]") No reports to produce with --no-nmap-scan parameter.${end_color}"

fi

# Remove old files
#rm -rf MVS_* "${nmap_temp}" /tmp/nmap_temp-* 2>/dev/null


time_elapsed

exit 0
