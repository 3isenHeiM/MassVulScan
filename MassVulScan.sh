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
source_top_tcp="./sources/top-ports-tcp-1000.txt"
source_top_udp="./sources/top-ports-udp-1000.txt"
script_start="$SECONDS"
report_folder="$(pwd)/reports/"
date="$(date +%F_%H-%M-%S)"

# Time elapsed
time_elapsed(){
script_end="$SECONDS"
script_duration="$((script_end-script_start))"

printf 'Duration: %02dh:%02dm:%02ds\n' $((${script_duration}/3600)) $((${script_duration}%3600/60)) $((${script_duration}%60))
}

# Root user?
check_root(){
if [[ $(id -u) != "0" ]]; then
	echo -e "${red_color}[X] You are not the root.${end_color}"
	echo "Assuming your are in the sudoers list, please launch the script with \"sudo\"."
	exit 1
fi
}

# Verifying if installation source file exist
source_file(){
if [[ -z ${source_installation} ]] || [[ ! -s ${source_installation} ]]; then
	echo -e "${red_color}[X] Source file \"${source_installation}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}[I] This script can install the prerequisites for you.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/3isenHeiM/MassVulScan.git"
	exit 1
fi
}

# Verifying if top-ports source files exist
source_file_top(){
if [[ -z ${source_top_tcp} ]] || [[ ! -s ${source_top_tcp} ]]; then
	echo -e "${red_color}[X] Source file \"${source_top_tcp}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}[I] This file is a prerequisite to scan TCP top ports.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/3isenHeiM/MassVulScan.git"
	exit 1
elif [[ -z ${source_top_udp} ]] || [[ ! -s ${source_top_udp} ]]; then
	echo -e "${red_color}[X] Source file \"${source_top_udp}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}[I] This file is a prerequisite to scan UDP top ports.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/3isenHeiM/MassVulScan.git"
	exit 1
fi
}

# Checking prerequisites
if [[ ! $(which masscan) ]] || [[ ! $(which nmap) ]] || [[ ! $(which xsltproc) ]]; then
	echo -e "${red_color}[X] There are some prerequisites to install before to launch this script.${end_color}"
	echo -e "${yellow_color}[I] Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):${end_color}"
	echo "$(grep ^-- "requirements.txt")"
	# Automatic installation for Debian OS family
	source_file
	source "${source_installation}"
else
	masscan_version="$(masscan -V | grep "Masscan version" | cut -d" " -f3)"
	nmap_version="$(nmap -V | grep "Nmap version" | cut -d" " -f3)"
	if [[ ${masscan_version} < "1.0.5" ]]; then
		echo -e "${red_color}[X] Masscan is not up to date.${end_color}"
		echo "Please. Be sure to have the last Masscan version >= 1.0.5."
		echo "Your current version is: ${masscan_version}"
		# Automatic installation for Debian OS family
		source_file
		source "${source_installation}"
	fi
	if [[ ${nmap_version} < "7.60" ]]; then
		echo -e "${red_color}[X] Nmap is not up to date.${end_color}"
		echo "Please. Be sure to have Nmap version >= 7.60."
		echo "Your current version is: ${nmap_version}"
		# Automatic installation for Debian OS family
		source_file
		source "${source_installation}"
	fi
fi

hosts="$1"
exclude_file=""
check="off"

# Logo
logo(){
	if [[ $(which figlet) ]]; then
		my_logo="$(figlet -w 50 -c -f maxiwi MassVulScan)"
		echo -e "${end_color}"
		echo -e "${red_color}${my_logo}${end_color}"
		echo -e "${yellow_color}[I] Version ${version}"
	else
		echo -e "${end_color}"
		echo -e "${red_color}  █   █                 █ █            ███                "
		echo -e "${red_color}  ██ ██  ███  ███  ███  █ █  █ █  █    █    ███  ███  ███ "
		echo -e "${red_color}  █ █ █    █  █    █    █ █  █ █  █     █   █      █  █ █ "
		echo -e "${red_color}  █   █  ███    █    █  █ █  █ █  █      █  █    ███  █ █ "
		echo -e "${red_color}  █   █  ███  ███  ███   █   ███  ███  ███  ███  ███  █ █ "
		echo -e "${end_color}"
		echo -e "${yellow_color}[I] Version ${version}"
	fi
}

# Usage of script
usage(){
  logo
	echo -e "${blue_color}${bold_color}[-] Usage: Root user or sudo${end_color} ./$(basename "$0") [[-f file] + [-e file] [-i] [-a] [-c] [-k] [-ns] | [-v] [-h]]"
	echo -e "${blue_color}${bold_color}[-] Information: Bash script which identifies open network ports and any associated vulnerabilities."
	echo -e "${end_color}"
	echo -e "${bold_color}    * Mandatory parameter:"
	echo -e "${yellow_color}        -f | --include-file${end_color}"
	echo "          Input file including IPv4 addresses and/or hostnames to scan, compatible with subnet mask."
	echo "          Example:"
	echo "                  # You can add a comment in the file"
	echo "                  10.66.0.0/24"
	echo "                  webmail.acme.corp"
	echo -e "${end_color}"
	echo -e "${bold_color}          By default: the top 100 TCP/UDP ports are scanned, the rate is fix to 2.5K pkts/sec."
	echo -e "${end_color}"
	echo -e "${bold_color}    * Optional parameters (must be used in addition of \"-f\" parameter):"
	echo -e "${yellow_color}        -e | --exclude-file${end_color}"
	echo "          Exclude file including IPv4 addresses (NO hostname) to NOT scan, compatible with subnet mask."
	echo "          Example:"
	echo "                  # You can add a comment in the file"
	echo "                  10.66.0.128/25"
	echo "                  10.66.6.225"
	echo -e "${yellow_color}        -i | --interactive${end_color}"
	echo "          Interactive menu with extra parameters:"
	echo "                  1) Ports to scan (e.g. -p1-65535 = all TCP ports)"
	echo "                  2) Rate level (pkts/sec)"
	echo "                  3) Nmap Scripting Engine (NSE) to use (default is vulners.nse)"
	echo -e "${yellow_color}        -a | --all-ports${end_color}"
	echo "          Scan all 65535 ports (TCP + UDP), the maximum rate is fix to 5K pkts/sec, and"
	echo "          the NSE vulners.nse script is used."
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
                -i | --interactive )
                        interactive="on"
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
                        echo -e "${yellow_color}[I] Script version is: ${bold_color}${version}${end_color}"
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
	echo -e "${red_color}[X] A process \"MassVulScan.sh\" is already running.${end_color}"
	exit 1
fi

# Valid input file?
if [[ -z ${hosts} ]] || [[ ! -s ${hosts} ]]; then
	echo -e "${red_color}[X] Input file \"${hosts}\" does not exist or is empty.${end_color}"
	echo "Please, try again."
	exit 1
fi

# Valid exclude file?
if [[ ${file_to_exclude} = "yes" ]]; then
        if [[ -z ${exclude_file} ]] || [[ ! -s ${exclude_file} ]]; then
                echo -e "${red_color}[X] Exclude file \"${exclude_file}\" does not exist or is empty.${end_color}"
                echo "Please, try again."
                exit 1
        fi
fi

# Cleaning old files
rm -rf IPs_hostnames_merged.txt file_with_IPs_and_hostnames.txt hosts_to_convert.txt \
hosts_converted.txt file_with_IPs_sorted temp-nmap-output nmap-input.temp.txt \
nmap-input.txt masscan-output.txt process_nmap_done.txt vulnerable_hosts.txt \
file_with_uniq_IP_only.txt file_with_multiple_IPs_only.txt nmap-output.xml file_with_IPs_unsorted.txt \
All_IPs_scanned_without_ports_temp.txt /tmp/nmap_temp-* *_sorted 2>/dev/null

# Folder for temporary Nmap file(s)
nmap_temp="$(mktemp -d /tmp/nmap_temp-XXXXXXXX)"


##########################
# Parsing the input file #
##########################

echo -n -e "${blue_color}${bold_color}\r[-] Parsing the input file..."

# First parsing to translate the hostnames to IPs
num_hosts=$(grep -v "^#" ${hosts} | grep "\S" | grep -vEoc '([0-9]{1,3}\.){3}[0-9]{1,3}')

if [[ ${num_hosts} != "0" ]]; then

    # Saving IPs first
	if [[ $(grep -v "^#" ${hosts} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}') ]]; then
		grep -v "^#" ${hosts} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' > file_with_IPs_only.txt
	fi

        # Filtering on the hosts only
        grep -v "^#" ${hosts} | grep "\S" | grep -vE '([0-9]{1,3}\.){3}[0-9]{1,3}' > hosts_to_convert.txt

        while IFS=, read -r host_to_convert; do
		host_ip=$(dig ${host_to_convert} +short | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
		echo $host_ip ${host_to_convert} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' >> hosts_converted.txt
        done < hosts_to_convert.txt

fi

if [[ -s hosts_converted.txt ]]; then
	num_valid_hosts=$(sort -u hosts_converted.txt | wc -l)
	echo -n -e "${blue_color}${bold_color}\r${num_valid_hosts} Valid hostname(s) has been detected, we will translate them to IPv4 format:\n${end_color}"
fi

if [[ -s file_with_IPs_only.txt ]]; then
	mv file_with_IPs_only.txt file_with_IPs_and_hostnames.txt
fi

# Second parsing to detect multiple IPs for the same hostname
if [[ -s hosts_converted.txt ]]; then
	while read line; do
		num_ips=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)

		if [[ ${num_ips} -gt "1" ]]; then
			# Filtering on the multiple IPs only
			hostname=$(echo ${line} | grep -oE '[^ ]+$')
			ips_list=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
			ips_tab=(${ips_list})
			ips_loop="$(for index in "${!ips_tab[@]}"; do echo "${ips_tab[${index}]} ${hostname}"; done)"

			echo "${ips_loop}" >> file_with_multiple_IPs_only.txt

		elif [[ ${num_ips} -eq "1" ]]; then
			# Saving uniq IP
			echo ${line} >> file_with_uniq_IP_only.txt
		fi
	done < hosts_converted.txt

	if [[ -s file_with_uniq_IP_only.txt ]]; then
		cat file_with_uniq_IP_only.txt >> file_with_IPs_and_hostnames.txt
	fi

	if [[ -s file_with_multiple_IPs_only.txt ]]; then
		cat file_with_multiple_IPs_only.txt >> file_with_IPs_and_hostnames.txt
	fi

	# Third parsing to detect duplicate IPs and keep the multiple hostnames
	# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html

	cat file_with_IPs_and_hostnames.txt | awk '/.+/ { \
				if (!($1 in ips_list)) { \
				value[++i] = $1 } ips_list[$1] = ips_list[$1] $2 "," } END { \
				for (j = 1; j <= i; j++) { \
				printf("%s %s\n%s", value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' > file_with_IPs_unsorted.txt
fi

hosts_sorted_filename="${hosts%.*}"
hosts_sorted_extension="${hosts##*.}"
hosts_sorted="${hosts_sorted_filename}_sorted.${hosts_sorted_extension}"

if [[ -s file_with_IPs_unsorted.txt ]]; then
	echo -e "${bold_color}$(cat file_with_IPs_unsorted.txt)${end_color}"
	cut -d" " -f1 file_with_IPs_unsorted.txt | sort -u | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts_sorted}
else
        echo -n -e "${blue_color}${bold_color}\rOnly IPs has been detected in the input file.\n${end_color}"
	cut -d" " -f1 ${hosts} | sort -u | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts_sorted}
fi

hosts="${hosts_sorted}"

# Interactive mode "on" or "off"?
top_ports_tcp="$(grep -v ^"#" sources/top-ports-tcp-1000.txt)"
top_ports_udp="$(grep -v ^"#" sources/top-ports-udp-1000.txt)"

source_file_top
ports="-p${top_ports_tcp},U:${top_ports_udp}"
rate="2500"
echo -e "${yellow_color}[I] Default parameters: --top-ports 100 (TCP/UDP) and --max-rate 2500.${end_color}"


################################################
# Checking if there are more than 2 interfaces #
################################################

interface="$(ip route | grep default | cut -d" " -f5)"
nb_interfaces="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -co "^[[:alnum:]]*")"

if [[ ${nb_interfaces} -gt "2" ]]; then
	interfaces_list="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -o "^[[:alnum:]]*")"
	interfaces_tab=(${interfaces_list})
	echo -e "${blue_color}${bold_color}Warning: multiple network interfaces have been detected:${end_color}"
	interfaces_loop="$(for index in "${!interfaces_tab[@]}"; do echo "   ${index}) ${interfaces_tab[${index}]}"; done)"
	echo -e "${blue_color}${interfaces_loop}${end_color}"
	echo -e "${blue_color}${bold_color}Which one do you want to use? [choose the corresponding number to the interface name]${end_color}"
	echo -e "${blue_color}${bold_color}Or typing \"Enter|Return\" key to use the one corresponding to the default route${end_color}"
        read -p "Interface number? >> " -r -t 60 interface_number
                if [[ -z ${interface_number} ]];then
        		echo -e "${yellow_color}[I] No interface chosen, we will use the one with the default route.${end_color}"
                        else
                                interface="${interfaces_tab[${interface_number}]}"
                fi
        echo -e "${yellow_color}[I] Network interface chosen: ${interface}${end_color}"
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

	echo -e "${blue_color}[-] Checking LIVE hosts...${end_color}"
	nmap -sP -T5 --min-parallelism 100 --max-parallelism 256 -iL "${hosts}" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > temp-nmap-output
		if [[ $? != "0" ]]; then
			echo -e "${error_color}[X] ERROR! Please verify parameters or input/exclude file format.${end_color}"
			echo -e "${error_color}    Maybe there is no host detected online. Exiting.${end_color}"
			rm -rf temp-nmap-output
			time_elapsed
			exit 1
		fi

    echo -e "${green_color}[V] Pre-scanning phase is ended.${end_color}"
    hosts="temp-nmap-output"
    nb_hosts_nmap="$(< "${hosts}" wc -l)"
    echo -e "${yellow_color}[I] ${nb_hosts_nmap} IP address(es) to check.${end_color}"

fi

########################################
# 2/4 Using Masscan to find open ports #
########################################

echo -e "${blue_color}[-] Running Masscan...${end_color}"

if [[ ${exclude_file} = "" ]] && [[ $(id -u) = "0" ]]; then
	masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt
elif [[ ${exclude_file} = "" ]] && [[ $(id -u) != "0" ]]; then
	sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt
elif [[ ${exclude_file} != "" ]] && [[ $(id -u) = "0" ]]; then
	masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL masscan-output.txt
else
	sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL masscan-output.txt
fi

if [[ $? != "0" ]]; then
	echo -e "${error_color}[X] ERROR! Please verify parameters or input/exclude file format. Exiting.${end_color}"
	rm -rf masscan-output.txt
	exit 1
fi

echo -e "${green_color}[V] Masscan phase has ended.${end_color}"

if [[ -z masscan-output.txt ]]; then
	echo -e "${error_color}[X] ERROR! File \"masscan-output.txt\" disappeared! Exiting.${end_color}"
	exit 1
fi

if [[ ! -s masscan-output.txt ]]; then
        echo -e "${green_color}[!] No IP with open TCP/UDP ports found. Exiting.${end_color}"
	rm -rf masscan-output.txt
	time_elapsed
	exit 0
else
	tcp_ports="$(grep -c "^open tcp" masscan-output.txt)"
	udp_ports="$(grep -c "^open udp" masscan-output.txt)"
	nb_ports="$(grep -c ^open masscan-output.txt)"
	nb_hosts_nmap="$(grep ^open masscan-output.txt | cut -d" " -f4 | sort | uniq -c | wc -l)"
	echo -e "${yellow_color}[I] ${nb_hosts_nmap} host(s) concerning ${nb_ports} open ports.${end_color}"
fi

###########################################################################################
# 3/4 Identifying open services with Nmap and if they are vulnerable with vulners script  #
###########################################################################################

# Output file with hostnames
merge_ip_hostname(){
	cat nmap-input.txt | while IFS=, read -r line; do
		search_ip=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

		if [[ $(grep "${search_ip}" file_with_IPs_unsorted.txt) ]] 2>/dev/null; then

			if [[ $(grep "${search_ip}" file_with_IPs_unsorted.txt | awk -F" " '{print $2}') ]]; then
				search_hostname=$(grep "${search_ip}" file_with_IPs_unsorted.txt | awk -F" " '{print $2}')
				echo "${line} ${search_hostname}" >> IPs_hostnames_merged.txt
			else
				echo "${line}" >> IPs_hostnames_merged.txt
			fi
		else
			echo "${line}" >> IPs_hostnames_merged.txt
		fi
	done
}

# Hosts list scanned
hosts_scanned(){
	echo -e "${bold_color}Host(s) discovered with an open port(s):${end_color}"
	grep ^open masscan-output.txt | awk '{ip[$4]++} END{for (i in ip) {print "  " i " has " ip[i] " open port(s)"}}' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4
}

# Preparing the input file for Nmap
nmap_file(){
	proto="$1"
	# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html
	grep "^open ${proto}" masscan-output.txt | awk '/.+/ { \
					if (!($4 in ips_list)) { \
					value[++i] = $4 } ips_list[$4] = ips_list[$4] $3 "," } END { \
					for (j = 1; j <= i; j++) { \
					printf("%s:%s:%s\n%s", $2, value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' >> nmap-input.temp.txt
}

if [[ ${tcp_ports} -gt "0" ]]; then
	nmap_file tcp
fi

if [[ ${udp_ports} -gt "0" ]]; then
	nmap_file udp
fi

sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 nmap-input.temp.txt > nmap-input.txt

if [[ ${no_nmap_scan} != "on" ]]; then

	nb_nmap_process="$(sort -n nmap-input.txt | wc -l)"

	# Keep the nmap input file?
	if [[ ${keep} == "on" ]]; then
		hosts_scanned
		merge_ip_hostname
		mv IPs_hostnames_merged.txt ${report_folder}All_IPs_scanned_with_ports.txt
		grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' nmap-input.txt | sort -u > ${report_folder}All_IPs_scanned_without_ports.txt
		echo -e "${yellow_color}[I] All the IPs scanned are in these 2 files:${end_color}"
		echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_with_ports.txt${end_color}"
		echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_without_ports.txt${end_color}"
	fi

	# Function for parallel Nmap scans
	parallels_scans(){
		proto="$(echo "$1" | cut -d":" -f1)"
		ip="$(echo "$1" | cut -d":" -f2)"
		port="$(echo "$1" | cut -d":" -f3)"

		if [[ $proto == "tcp" ]]; then
			nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sT -sV -n  -oA "${nmap_temp}/${ip}"_tcp_nmap-output "${ip}" > /dev/null 2>&1
			echo "${ip} (${proto}): Done" >> process_nmap_done.txt
			else
				nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sU -sV -n  -oA "${nmap_temp}/${ip}"_udp_nmap-output "${ip}" > /dev/null 2>&1
				echo "${ip} (${proto}): Done" >> process_nmap_done.txt
		fi

		nmap_proc_ended="$(grep "$Done" -co process_nmap_done.txt)"
		pourcentage="$(awk "BEGIN {printf \"%.2f\n\", "${nmap_proc_ended}/${nb_nmap_process}*100"}")"
		echo -n -e "\r                                                                                                         "
		echo -n -e "${yellow_color}${bold_color}\r[I] Scan is done for ${ip} (${proto}) -> ${nmap_proc_ended}/${nb_nmap_process} Nmap process launched...(${pourcentage}%)${end_color}"
	}

	# Controlling the number of Nmap scanner to launch
	if [[ ${nb_nmap_process} -ge "50" ]]; then
		max_job="50"
		echo -e "${blue_color}${bold_color}Warning: A lot of Nmap process to launch: ${nb_nmap_process}${end_color}"
		echo -e "${blue_color}[-] So, to no disturb your system, I will only launch ${max_job} Nmap process at time.${end_color}"
		else
			echo -e "${blue_color}${bold_color}[-] Launching ${nb_nmap_process} Nmap scanner(s) in the same time...${end_color}"
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

	rm -rf process_nmap_done.txt

	while IFS=, read -r ip_to_scan; do
		new_job $i
		count="$(expr $count + 1)"
	done < nmap-input.txt

	wait

	sleep 2 && tset

	echo -e "\n${green_color}[V] Nmap phase is ended.${end_color}"


elif [[ ${no_nmap_scan} == "on" ]] && [[ ${keep} == "on" ]]; then
	echo -e "${yellow_color}[I] No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat IPs_hostnames_merged.txt)${end_color}"
	mv IPs_hostnames_merged.txt ${report_folder}All_IPs_scanned_with_ports.txt
	grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' nmap-input.txt | sort -u > ${report_folder}All_IPs_scanned_without_ports.txt
	echo -e "${yellow_color}[I] All the IPs scanned are in these 2 files:${end_color}"
	echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_with_ports.txt${end_color}"
	echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_without_ports.txt${end_color}"

else
	echo -e "${yellow_color}[I] No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat IPs_hostnames_merged.txt)${end_color}"
fi

##########################
# 4/4 Generating reports #
##########################

if [[ ${no_nmap_scan} != "on" ]]; then
	nmap_bootstrap="./stylesheet/nmap-bootstrap.xsl"

	global_report_name="global-report"
	# vulnerable_report_name="vulnerable_hosts_details"
	#
	# if [[ -s ${report_folder}${date}_vulnerable_hosts_details.txt ]] && [[ ${report_folder}${date}_vulnerable_hosts_details.txt != ${report_folder}${date}_${vulnerable_report_name}.txt ]]; then
	# 	mv ${report_folder}${date}_vulnerable_hosts_details.txt ${report_folder}${date}_${vulnerable_report_name}.txt
	# 	echo -e "${yellow_color}[I] All details on the vulnerabilities:"
	# 	echo -e "${blue_color}-> ${report_folder}${date}_${vulnerable_report_name}.txt${end_color}"
	# elif [[ -s ${report_folder}${date}_vulnerable_hosts_details.txt ]] && [[ ${report_folder}${date}_vulnerable_hosts_details.txt == ${report_folder}${date}_${vulnerable_report_name}.txt ]]; then
	# 	echo -e "${yellow_color}[I] All details on the vulnerabilities:"
	# 	echo -e "${blue_color}-> ${report_folder}${date}_vulnerable_hosts_details.txt${end_color}"
	# fi

	# Merging all the Nmap XML files to one big XML file
	echo "<?xml version=\"1.0\"?>" > nmap-output.xml
	echo "<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">" >> nmap-output.xml
	echo "<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl\" type="text/xsl\"?>" >> nmap-output.xml
	echo "<!-- nmap results file generated by MassVulScan.sh -->" >> nmap-output.xml
	echo "<nmaprun args=\"nmap --max-retries 2 --max-rtt-timeout 500ms -p[port(s)] -Pn -s(T|U) -sV -n [ip(s)]\" scanner=\"Nmap\" start=\"\" version=\"${nmap_version}\" xmloutputversion=\"1.04\">" >> nmap-output.xml
	echo "<!--Generated by MassVulScan.sh--><verbose level=\"0\" /><debug level=\"0\" />" >> nmap-output.xml

	for i in ${nmap_temp}/*.xml; do
		sed -n -e '/<host /,/<\/host>/p' "$i" >> nmap-output.xml
	done

	echo "<runstats><finished elapsed=\"\" exit=\"success\" summary=\"Nmap XML merge done at $(date); ${vuln_hosts_count} vulnerable host(s) found\" \
	      time=\"\" timestr=\"\" /><hosts down=\"0\" total=\"${nb_hosts_nmap}\" up=\"${nb_hosts_nmap}\" /></runstats></nmaprun>" >> nmap-output.xml

	# Using bootstrap to generate a beautiful HTML file (report)
	xsltproc -o "${report_folder}${date}_${global_report_name}.html" "${nmap_bootstrap}" nmap-output.xml 2>/dev/null

	# End of script
	echo -e "${yellow_color}[I] Global HTML report generated:"
	echo -e "${blue_color}-> ${report_folder}${date}_${global_report_name}.html${end_color}"

	# Moving Nmap raw output to report folder
	mv ${nmap_temp}/*.nmap "${report_folder}"

	echo -e "${green_color}[V] Report phase is ended, bye!${end_color}"
else
	echo -e "${yellow_color}[I] No reports to produce with --no-nmap-scan parameter.${end_color}"

fi

rm -rf IPs_hostnames_merged.txt file_with_IPs_and_hostnames.txt hosts_to_convert.txt \
hosts_converted.txt file_with_IPs_sorted temp-nmap-output nmap-input.temp.txt \
nmap-input.txt masscan-output.txt process_nmap_done.txt vulnerable_hosts.txt \
file_with_uniq_IP_only.txt file_with_multiple_IPs_only.txt nmap-output.xml file_with_IPs_unsorted.txt \
All_IPs_scanned_without_ports_temp.txt "${nmap_temp}" ${hosts} 2>/dev/null

time_elapsed

exit 0
