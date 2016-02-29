#!/bin/bash
### BEGIN INIT INFO
# Provides:          advwall
# Required-Start:    $network
# Required-Stop:     
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Netfilter firewall layer 3 script
# Description:       Version 0.99 beta1
#                    Writed by Romain Meillon (r.meillon@servitics.fr), distributed under GPL Licence.
### END INIT INFO

# Debug config (1 = yes, 0 = no)
DEBUG="1"

# Global config file of advwall
CONFIG_PATH="/etc/advwall"

# Temp file path used to revert changes
tempfile="/tmp/advwall.$$.tmp"

currentDate=`date +%Y%m%d%H%M%S`

debug() {
	[ "$DEBUG" = "1" ] && echo "Debug: $*"
}

error() {
	echo "Error: $*" #>1 2>&1
}

checkLoadConfig() { 
	debug "Checking and loading global files..."
	if [ -r ${CONFIG_PATH}/advwall.conf ] 
	then
		debug "Loading ${CONFIG_PATH}/advwall.conf"
		source ${CONFIG_PATH}/advwall.conf
	else
		error "${CONFIG_PATH}/advwall.conf missing or not readable."
		exit 1
	fi
	
	# Checking some vars in the config file
	if [ -z "$enabledPoolPath" ] || [ -z "$LOG_FREQ" ] ; then
		echo "You must set config options in ${CONFIG_PATH}/advwall.conf"
		exit 1
	fi
}

executeAction() {
	debug "$*"
	if [[ -n ${timer} && ${timer} -gt 0 ]]
	# With timer
	then
		# If dump arg is passed to non null, we dump into ${dump} where ${dump} is a file
		[ -n "${dump}" ] && echo "$*" >> ${dump} && return 0
		
		# or execute real command
		eval $*		
		if [ $? -ne 0 ]
		then
			error "$*"
			return 1
		else
			# and write it to the temp file
			echo "$*" >> ${tempfile}
			return 0
		fi

	# or with dump
	else
		# If dump arg is passed to non null, we dump into ${dump} where ${dump} is a file
		[ -n "${dump}" ] && echo "$*" >> ${dump} && return 0
		# or execute real command
		eval $*
		if [ $? -ne 0 ]
		then
			error "$*"
			return 1
		fi
	fi
}

# Revert iptables command
revertLine() {
	local originalCmd="$*"
	#debug "Original command = ${originalCmd}"

	# Reverse -A -I and -N iptables commands
	revertedCmd=`echo ${originalCmd} | awk '/-I.* [0-1] -/ {$4=""} { print $0 };' | sed 's/-[AI]/-D/' | sed 's/-N/-X/'`

	# replace by previous policy in main chains (-P), only if the previous commands changed something in main chains policies
	if echo ${revertedCmd} | egrep "\-P INPUT" >> /dev/null 2>&1
	then
		revertedCmd=`echo "${IPTBIN} -P INPUT ${INPUT_PREV_POL}"`
	elif echo ${revertedCmd} | egrep "\-P OUTPUT" >> /dev/null 2>&1
	then
		revertedCmd=`echo "${IPTBIN} -P OUTPUT ${OUTPUT_PREV_POL}"`
	elif echo ${revertedCmd} | egrep "\-P FORWARD" >> /dev/null 2>&1
	then
		revertedCmd=`echo "${IPTBIN} -P FORWARD ${FORWARD_PREV_POL}"`
	fi

	#debug "Reverted command = ${revertedCmd}"
}

# reverts actions in ${tempfile}
revertActions () {
	if [[ -n ${timer} && ${timer} -gt 0 ]]
	then
		echo -n "Waiting ${timer} seconds before reverting changes : "
		for sec in `seq 1 ${timer}`
		do
		echo -n "${sec} "
		sleep 1
	done
		echo "Reverting changes..."
		debug "Temp file used : ${tempfile}"
		tac ${tempfile} | while read line
		do
			revertLine ${line}			
			# Revert previous reverted actions.
			executeAction ${revertedCmd}
		done

		# remove temp file
		rm -f ${tempfile}
	fi
}

startAllFiles() {
	debug "Executing all rules files in  ${enabledPoolPath}"
	findPreviousPolicies
	for ruleFile in `ls ${enabledPoolPath}` ; do
		debug "-----------------"
		debug "Processing ${ruleFile}..."
		cat ${enabledPoolPath}/${ruleFile} | grep "^iptables.*" | while read filterLine ; do
			executeAction ${filterLine}
		done
	done
}

startFile() {
	local fileNum=${1}

	# Check if number exists, and is unique
	local numbersOfFiles=`ls ${enabledPoolPath} | egrep "^${fileNum}-.*" | grep -c ""`
	[ "${numbersOfFiles}" -ne "1" ] && error "Number not found, or more than one file found (${numbersOfFiles}), exiting." && exit 1
	
	local fileName=`ls ${enabledPoolPath} | egrep "^${fileNum}-.*"`

	local chainName=`echo ${fileName} | egrep -o "\-.*" | sed s/-//g`
	
	# Checking if tables already exists before touching anything.
	for i in IN OUT FWD
	do
		chainCheck ${chainName}_${i}
		if [ "$?" = "0" ] ; then
			error "Chain ${chainName}_${i} found, exiting."
			exit 1
		fi
	done

	findPreviousPolicies
	debug "Starting file rule number ${fileNum}, dedicated chain suffixes will be \"${chainName}\"..."
	cat ${enabledPoolPath}/${fileName} | grep "^iptables.*" | while read filterLine ; do
		executeAction ${filterLine}
	done
}

stopFile() {
	local fileNum=${1}

	# Check if number exists, and is unique
	local numbersOfFiles=`ls ${enabledPoolPath} | egrep "^${fileNum}-.*" | grep -c ""`
	[ "${numbersOfFiles}" -ne "1" ] && error "Number not found, or more than one file found (${numbersOfFiles}), exiting." && exit 1
	
	local fileName=`ls ${enabledPoolPath} | egrep "^${fileNum}-.*"`

	local chainName=`echo ${fileName} | egrep -o "\-.*" | sed s/-//g`

	# checking if reference tables in the file already exists.
	for refChain in `tac ${enabledPoolPath}/${fileName} | grep "^iptables.*" | egrep -o "${chainName}_(IN|OUT|FWD)" | sort --unique` ; do
		chainCheck ${refChain}
		if [ "$?" -ne "0" ] ; then
			error "The chain ${refChain} in file ${fileName} not found, exiting."
			exit 1
		fi
	done
	
	debug "Stopping file rule number ${fileNum}, dedicated chain suffixes must be \"${chainName}\"..."
	tac ${enabledPoolPath}/${fileName} | grep "^iptables.*" | while read filterLine ; do
		revertLine ${filterLine}
		
		# Revert previous reverted actions.
		executeAction ${revertedCmd}
	done
}

chainCheck() {
	local chainToCheck=$1
	#debug "Checking for existing chain ${chainToCheck} ..."
	iptables -L ${chainToCheck} >> /dev/null 2>&1
	return $?
}

# Check if the firewall is already started or not (test if there is more than 2 lines in iptables -vnL)
checkInit () {
	INIT=`iptables -vnL | grep -c ""`
	if [ ${INIT} -gt 8 ]
	then
		return 0
	else
		return 1
	fi
}

findPreviousPolicies() {
	# Grab previous policies of main chains for reverting actions
	INPUT_PREV_POL=""
	OUTPUT_PREV_POL=""
	FORWARD_PREV_POL=""
	INPUT_PREV_POL=`iptables -L INPUT | egrep "policy" | egrep -o "ACCEPT|DROP|REJECT"`
	OUTPUT_PREV_POL=`iptables -L OUTPUT | egrep "policy" | egrep -o "ACCEPT|DROP|REJECT"`
	FORWARD_PREV_POL=`iptables -L FORWARD | egrep "policy" | egrep -o "ACCEPT|DROP|REJECT"`
	debug "Previous main chains policies were INPUT : ${INPUT_PREV_POL} - OUTPUT : ${OUTPUT_PREV_POL} - FORWARD : ${FORWARD_PREV_POL}"
}

flushTables() { 
	debug "Flushing tables and deleting custom chains..."
	executeAction iptables -F
	executeAction iptables -X
	executeAction iptables -t nat -F
	executeAction iptables -t mangle -F

	debug "Setting up defaults chains policies to ACCEPT."
	executeAction iptables -P INPUT 	ACCEPT
	executeAction iptables -P OUTPUT 	ACCEPT
	executeAction iptables -P FORWARD 	ACCEPT
}

backupNF() {
	debug "Backuping Netfilter in ${backupPath}/nf_save_${currentDate}"
	iptables-save >> ${backupPath}/nf_save_${currentDate}
	if [ $? -ne 0 ] ; then 
		error "Error during Backup, exiting."
		exit 1
	fi
}

restoreNF() {
	flushTables
	debug "Restoring Netfilter from ${backupPath}/${1}"
	iptables-restore < ${backupPath}/${1}
	if [ $? -ne 0 ] ; then 
		error "Error during restore, exiting."
		exit 1
	fi
}

printUsage() {
	echo "Usage: ${0} <action> <file number> <options>"
	echo ""
	echo "Available actions :"
	echo "start			Start the script. If a file number is specified, it will start the specified one."
	echo "stop			Stop the script. If a file number is specified, it will stop the specified one."
	echo "restart			Restart the script. If a file number is specified, it will restart the specified one."
	echo "backup			Backup the current Netfilter configuration."
	echo "restore <file>		Restore the config file specified (in the folder : ${backupPath})"
	echo "status			Print status"
	echo ""
	echo "Available options :"
	echo "-d dumpfile.txt		Dump all iptables commands to the specified file instead of executing them."
	echo "-t <second>		Used with : start. Wait X seconds before reverting changes, canceled if used with -d option."
}

# ARGUMENTS CAN BE :
# advwall	Action	Number	Option1 Option2
#	0			1		2		3		4
# advwall	Action	Option1  Option2
#	0			1		2		3		4

case ${1} in
	start)
		checkLoadConfig		
		#debug "Arguments are 1: ${1}, 2: ${2}, 3: ${3}, 4: ${4}"
		# File number can be 1 to 4 digits ($2)
		if [[ -n ${2} && ${2}  =~ ^[[:digit:]]{1,4}$ ]] ; then
			# File number 00 or 99 can't be started once
			[[ ${2} = "00" || ${2} = "99" ]] && error "00-INIT or 99-CLOSE can't be started or stopped once, exiting." && exit 1
			# Dump argument ?
			if [[ "${3}" = "-d" && -n "${4}" ]] ; then 
				debug "Dumping all commands to file $PWD/${4}"
				dump="$PWD/${4}"
				backupNF
				startFile ${2}
			# Timer argument ?
			elif [[ "${3}" = "-t" && ${4} -gt 0 ]] ; then
				debug "Set reset timer to ${4} seconds."
				timer="${4}"
				touch ${tempfile}
				backupNF
				startFile ${2}
				revertActions
			else
				backupNF
				startFile ${2}
			fi
		# in case of "advwall start -d <file>" without file number
		# Dump argument ?
		elif [[ "${2}" = "-d" && -n "${3}" ]] ; then
			debug "Dumping all commands to file $PWD/${3}"
			dump="$PWD/${3}"
			# Checking if the firewall has already been started.
			checkInit
			if [ "$?" != "0" ]
			then
				debug "Firewall has not been started yet, processing all files."
				backupNF
				startAllFiles
			else
				error "Firewall base already started, exiting."
				exit 1
			fi
		# Timer argument ?
		elif [[ "${2}" = "-t" && ${3} -gt 0 ]] ; then
			debug "Set reset timer to ${3} seconds."
			timer="${3}"
			touch ${tempfile}
			# Checking if the firewall has already been started.
			checkInit
			if [ "$?" != "0" ]
			then
				debug "Firewall has not been started yet, processing all files."
				backupNF
				startAllFiles
				revertActions
			else
				error "Firewall base already started, exiting."
				exit 1
			fi
		# in case of no file number or dump or timer options
		else
			# Checking if the firewall has already been started.
			checkInit
			if [ "$?" != "0" ]
			then
				debug "Firewall has not been started yet, processing all files."
				backupNF
				startAllFiles
			else
				error "Firewall base already started, exiting."
				exit 1
			fi
		fi
	;;

	stop)
		checkLoadConfig
		#debug "Arguments are 1: ${1}, 2: ${2}, 3: ${3}, 4: ${4}"
		# File number can be 1 to 4 digits ($2)
		if [[ -n ${2} && ${2}  =~ ^[[:digit:]]{1,4}$ ]] ; then
			# File number 00 or 99 can't be started once
			[[ ${2} = "00" || ${2} = "99" ]] && error "00-INIT or 99-CLOSE can't be started or stopped once, exiting." && exit 1
			# Dump argument ?
			if [[ "${3}" = "-d" && -n "${4}" ]] ; then 
				debug "Dumping all commands to file $PWD/${4}"
				dump="$PWD/${4}"
				backupNF
				stopFile ${2}
			# Timer argument ?
			elif [[ "${3}" = "-t" && ${4} -gt 0 ]] ; then
				error "Timer can't be used with stop action, please use backup/restore"
				exit 1
			else
				backupNF
				stopFile ${2}
			fi
		# in case of "advwall start -d <file>" without file number
		# Dump argument ?
		elif [[ "${2}" = "-d" && -n "${3}" ]] ; then
			debug "Dumping all commands to file $PWD/${3}"
			dump="$PWD/${3}"
			# Checking if the firewall has already been started.
			checkInit
			if [ "$?" != "0" ]
			then
				error "Firewall has not been started yet, exiting."
				exit 1
			else
				debug "Firewall is started."
				backupNF
				flushTables
			fi
		# Timer argument ?
		elif [[ "${2}" = "-t" && ${3} -gt 0 ]] ; then
			error "Timer can't be used with stop action, please use backup/restore"
			exit 1
		# in case of no file number or dump or timer options
		else
			# Checking if the firewall has already been started.
			checkInit
			if [ "$?" != "0" ]
			then
				error "Firewall has not been started yet, exiting."
				exit 1
			else
				debug "Firewall is started."
				backupNF
				flushTables
			fi
		fi
	;;
	
	backup)
		checkLoadConfig
		backupNF
	;;
	
	restore)
		checkLoadConfig
		#debug "Arguments are 1: ${1}, 2: ${2}, 3: ${3}, 4: ${4}"
		if [ -r "${backupPath}/${2}" ] ; then
			backupNF
			restoreNF ${2}
		else
			error "A valid file name must be specified, exiting."
			exit 1
		fi
	;;

	status)
		checkLoadConfig
		echo "#"
		echo "# Regular Tables"
		echo "#"
		executeAction iptables -vnL
		echo
		echo "#"
		echo "# NAT Tables"
		echo "#"
		executeAction iptables -vnL -t nat
		echo 
		echo "#"
		echo "# Mangle Tables"
		echo "#"
		executeAction iptables -vnL -t mangle
	;;
	
	*)
	printUsage
	exit 1
	;;
esac
