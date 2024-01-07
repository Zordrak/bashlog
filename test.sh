#!/bin/bash

set -uo pipefail

# Interactive debug testing is off by default.
# To turn it on, pass TEST_INTERACTIVE=1
# Correct exit code from this test script
# will then be '1' instead of '0'
script_name=$(basename "${0}")
readonly script_name

declare interactive="${TEST_INTERACTIVE:-0}"

readonly logfile="/tmp/${script_name}.log"
readonly logfile_json="/tmp/${script_name}.log.json"
touch "${logfile}"
touch "${logfile_json}"

if [ -f "/var/log/messages" ]; then
	syslogoutfile=/var/log/messages
elif [ -f "/var/log/syslog" ]; then
	syslogoutfile=/var/log/syslog
else
	exit 1
fi

if [ -f "/var/log/debug" ]; then
	syslogdebugoutfile=/var/log/debug
elif [ -f "/var/log/syslog" ]; then
	syslogdebugoutfile=/var/log/syslog
else
	exit 1
fi

readonly syslogoutfile

delete_temp_logfiles() {
	rm -f "${logfile}"
	rm -f "${logfile_json}"
}

trap 'delete_temp_logfiles' EXIT

function result() {
	local level="${1}"
	shift
	local line="${@}"

	case "${level}" in
		ok)
			echo -e "\t\033[32mOK: ${line}\033[0m"
			;;
		fail)
			echo -e "\t\033[31mFAIL: ${line}\033[0m"
			echo -e "Test failed, continuing remaining tests"
			return 1
			;;
		*)
			echo "UWOTM8?!"
			exit 1
			;;
	esac
}

# shellcheck source-path=SCRIPTDIR
source log.sh

declare random_string
# shellcheck disable=SC2002
random_string="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"
readonly random_string
declare stdout
declare fileout
declare jsonout
declare syslogout

declare BASHLOG_FILE=1
declare BASHLOG_JSON=1
declare BASHLOG_SYSLOG=1

##
# INFO
##

echo "Testing 'info'"

BASHLOG_FILE=1
BASHLOG_JSON=1
BASHLOG_SYSLOG=1
DEBUG=0

stdout="$(log 'info' "${random_string}")"
fileout="$(tail -n1 "${logfile}")"
jsonout="$(tail -n1 "${logfile_json}")"
syslogout="$(sudo tail -n1 "${syslogoutfile}")"

grep -q -E $'^\033\[32m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" &&
	result ok 'info -> stdout' ||
	result fail 'info -> stdout'

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] ${random_string}$" <<<"${fileout}" &&
	result ok 'info -> file' ||
	result fail 'info -> file'

grep -q -E '^{"timestamp":"[0-9]{10}","level":"info","message":"'"${random_string}"'"}$' <<<"${jsonout}" &&
	result ok 'info -> json file' ||
	result fail 'info -> json file'

grep -q -E "${script_name}\[${$}\]: INFO: ${random_string}$" <<<"${syslogout}" &&
	result ok "info -> syslog (\"${syslogoutfile}\")" ||
	result fail "info -> syslog (\"${syslogoutfile}\")"

##
# WARN
##

echo "Testing 'warn'"

delete_temp_logfiles

BASHLOG_FILE=1
BASHLOG_JSON=1
BASHLOG_SYSLOG=1
DEBUG=0

stdout="$(log 'warn' "${random_string}")"
fileout="$(tail -n1 "${logfile}")"
jsonout="$(tail -n1 "${logfile_json}")"
syslogout="$(sudo tail -n1 /var/log/syslog)"

grep -q -E $'^\033\[33m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[WARN\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" &&
	result ok 'warn -> stdout' ||
	result fail 'warn -> stdout'

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[WARN\] ${random_string}$" <<<"${fileout}" &&
	result ok 'warn -> file' ||
	result fail 'warn -> file'

grep -q -E '^{"timestamp":"[0-9]{10}","level":"warn","message":"'"${random_string}"'"}$' <<<"${jsonout}" &&
	result ok 'warn -> json file' ||
	result fail 'warn -> json file'

grep -q -E "${script_name}\[${$}\]: WARN: ${random_string}$" <<<"${syslogout}" &&
	result ok 'warn -> syslog (/var/log/syslog)' ||
	result fail 'warn -> syslog (/var/log/syslog)'

##
# ERROR
##

echo "Testing: 'error'"

delete_temp_logfiles

BASHLOG_FILE=1
BASHLOG_JSON=1
BASHLOG_SYSLOG=1
DEBUG=0

stderr="$(log 'error' "${random_string}" 2>&1 1>/dev/null)"
fileout="$(tail -n1 "${logfile}")"
jsonout="$(tail -n1 "${logfile_json}")"
syslogout="$(sudo tail -n1 /var/log/syslog)"

grep -q -E $'^\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] '"${random_string}"$'\033\[0m$' <<<"${stderr}" &&
	result ok 'error -> stderr' ||
	result fail 'error -> stderr'

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] ${random_string}$" <<<"${fileout}" &&
	result ok 'error -> file' ||
	result fail 'error -> file'

grep -q -E '^{"timestamp":"[0-9]{10}","level":"error","message":"'"${random_string}"'"}$' <<<"${jsonout}" &&
	result ok 'error -> json file' ||
	result fail 'error -> json file'

grep -q -E "${script_name}\[${$}\]: ERROR: ${random_string}$" <<<"${syslogout}" &&
	result ok 'error -> syslog (/var/log/syslog)' ||
	result fail 'error -> syslog (/var/log/syslog)'

##
# DEBUG OFF
##

echo "Testing 'debug', DEBUG=0"

delete_temp_logfiles

BASHLOG_FILE=1
BASHLOG_JSON=1
BASHLOG_SYSLOG=1
DEBUG=0

# If there's no output, there'll be no file
touch "${logfile}"
touch "${logfile_json}"

stdout="$(log 'debug' "${random_string}")"
fileout="$(tail -n1 "${logfile}")"
jsonout="$(tail -n1 "${logfile_json}")"
syslogout="$(sudo tail -n1 "${syslogdebugoutfile}")"

grep -q -E $'^\033\[34m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" &&
	result fail 'debug -> stdout' ||
	result ok 'debug -> stdout'

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] ${random_string}$" <<<"${fileout}" &&
	result fail 'debug -> file' ||
	result ok 'debug -> file'

grep -q -E '^{"timestamp":"[0-9]{10}","level":"debug","message":"'"${random_string}"'"}$' <<<"${jsonout}" &&
	result fail 'debug -> json file' ||
	result ok 'debug -> json file'

grep -q -E "${script_name}\[${$}\]: DEBUG: ${random_string}$" <<<"${syslogout}" &&
	result fail "debug -> syslog (\"${syslogoutfile}\")" ||
	result ok "debug -> syslog (\"${syslogdebugoutfile}\")"

##
# DEBUG ON
##

echo "Testing 'debug', DEBUG=1"

delete_temp_logfiles

BASHLOG_FILE=1
BASHLOG_JSON=1
BASHLOG_SYSLOG=1
DEBUG=1

stdout="$(log 'debug' "${random_string}")"
fileout="$(tail -n1 "${logfile}")"
jsonout="$(tail -n1 "${logfile_json}")"
syslogout="$(sudo tail -n1 "${syslogdebugoutfile}")"

grep -q -E $'^\033\[34m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" &&
	result ok 'debug -> stdout' ||
	result fail 'debug -> stdout'

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] ${random_string}$" <<<"${fileout}" &&
	result ok 'debug -> file' ||
	result fail 'debug -> file'

grep -q -E '^{"timestamp":"[0-9]{10}","level":"debug","message":"'"${random_string}"'"}$' <<<"${jsonout}" &&
	result ok 'debug -> json file' ||
	result fail 'debug -> json file'

grep -q -E "${script_name}\[${$}\]: DEBUG: ${random_string}$" <<<"${syslogout}" &&
	result ok "debug -> syslog (\"${syslogoutfile}\")" ||
	result fail "debug -> syslog (\"${syslogoutfile}\")"

##
# BAD LEVEL, DEBUG OFF
##

echo "Testing: BAD LEVEL ('snooch'), DEBUG=0"

delete_temp_logfiles

BASHLOG_FILE=1
BASHLOG_JSON=1
BASHLOG_SYSLOG=1
DEBUG=0

stderr="$(log 'snooch' "${random_string}" 2>&1 1>/dev/null)"
fileout="$(tail -n1 "${logfile}")"
jsonout="$(tail -n1 "${logfile_json}")"
syslogout="$(sudo tail -n1 /var/log/syslog)"

grep -q -E $'^\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: '"${random_string}"$'\033\[0m$' <<<"${stderr}" &&
	result ok 'snooch -> stderr' ||
	result fail 'snooch -> stderr'

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: ${random_string}$" <<<"${fileout}" &&
	result ok 'snooch -> file' ||
	result fail 'snooch -> file'

grep -q -E '^{"timestamp":"[0-9]{10}","level":"error","message":"Undefined log level trying to log: '"${random_string}"'"}$' <<<"${jsonout}" &&
	result ok 'snooch -> json file' ||
	result fail 'snooch -> json file'

grep -q -E "${script_name}\[${$}\]: ERROR: Undefined log level trying to log: ${random_string}$" <<<"${syslogout}" &&
	result ok 'snooch -> syslog (/var/log/syslog)' ||
	result fail 'snooch -> syslog (/var/log/syslog)'

##
# BAD LEVEL, DEBUG ON
##

echo "Testing: BAD LEVEL ('snooch'), DEBUG=1"

delete_temp_logfiles

BASHLOG_FILE=1
BASHLOG_JSON=1
BASHLOG_SYSLOG=1
DEBUG=1

stderr="$(echo | log 'snooch' "${random_string}" 2>&1 1>/dev/null)"
fileout="$(tail -n1 "${logfile}")"
jsonout="$(tail -n1 "${logfile_json}")"
syslogout="$(sudo tail -n1 /var/log/syslog)"

grep -q -E $'^\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: '"${random_string}"$'\033\[0m$' <<<"${stderr}" &&
	result ok 'snooch -> stderr' ||
	result fail 'snooch -> stderr'

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: ${random_string}$" <<<"${fileout}" &&
	result ok 'snooch -> file' ||
	result fail 'snooch -> file'

grep -q -E '^{"timestamp":"[0-9]{10}","level":"error","message":"Undefined log level trying to log: '"${random_string}"'"}$' <<<"${jsonout}" &&
	result ok 'snooch -> json file' ||
	result fail 'snooch -> json file'

grep -q -E "${script_name}\[${$}\]: ERROR: Undefined log level trying to log: ${random_string}$" <<<"${syslogout}" &&
	result ok 'snooch -> syslog (/var/log/syslog)' ||
	result fail 'snooch -> syslog (/var/log/syslog)'

##
# INFO, FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'info', IO Exception (file), DEBUG=0"

rm -f "${logfile}"

BASHLOG_FILE=1
BASHLOG_JSON=0
BASHLOG_SYSLOG=0
DEBUG=0

sudo touch "${logfile}"

stderr="$(log 'info' "${random_string}" 2>&1 1>/dev/null)"

sudo rm -f "${logfile}"

grep -q -E $"^*log.sh: line [0-9]+: ${logfile}: Permission denied" <<<"${stderr}" &&
	grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] '"${random_string}"'" >> "/tmp/'"${script_name}"$'.log"\033\[0m$' <<<"${stderr}" &&
	result ok 'info -> file, Permission denied -> stderr' ||
	result fail 'info -> file, Permission denied -> stderr'

##
# INFO, FILE IO EXCEPTION, DEBUG ON
##

echo "Testing: 'info', IO Exception (file), DEBUG=1"

rm -f "${logfile}"

BASHLOG_FILE=1
BASHLOG_JSON=0
BASHLOG_SYSLOG=0
DEBUG=1

sudo touch "${logfile}"

stderr="$(echo | log 'info' "${random_string}" 2>&1 1>/dev/null)"

sudo rm -f "${logfile}"

grep -q -E $"^*log.sh: line [0-9]+: ${logfile}: Permission denied" <<<"${stderr}" &&
	grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] '"${random_string}"'" >> "/tmp/'"${script_name}"$'.log"\033\[0m$' <<<"${stderr}" &&
	result ok 'info -> file, Permission denied -> stderr' ||
	result fail 'info -> file, Permission denied -> stderr'

##
# INFO, JSON FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'info', IO Exception (json), DEBUG=0"

rm -f "${logfile_json}"

BASHLOG_FILE=0
BASHLOG_JSON=1
BASHLOG_SYSLOG=0
DEBUG=0

sudo touch "${logfile_json}"

stderr="$(log 'info' "${random_string}" 2>&1 1>/dev/null)"

sudo rm -f "${logfile_json}"

grep -q -E $"^*log.sh: line [0-9]+: ${logfile_json}: Permission denied" <<<"${stderr}" &&
	grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "{"timestamp":"[0-9]{10}","level":"info","message":"'"${random_string}"'"}" >> "/tmp/'"${script_name}"$'.log.json"\033\[0m$' <<<"${stderr}" &&
	result ok 'info -> file, Permission denied -> stderr' ||
	result fail 'info -> file, Permission denied -> stderr'

##
# INFO, JSON FILE IO EXCEPTION, DEBUG ON
##

echo "Testing: 'info', IO Exception (json), DEBUG=1"

rm -f "${logfile_json}"

BASHLOG_FILE=0
BASHLOG_JSON=1
BASHLOG_SYSLOG=0
DEBUG=1

sudo touch "${logfile_json}"

stderr="$(echo | log 'info' "${random_string}" 2>&1 1>/dev/null)"

sudo rm -f "${logfile_json}"

grep -q -E $"^*log.sh: line [0-9]+: ${logfile_json}: Permission denied" <<<"${stderr}" &&
	grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "{"timestamp":"[0-9]{10}","level":"info","message":"'"${random_string}"'"}" >> "/tmp/'"${script_name}"$'.log.json"\033\[0m$' <<<"${stderr}" &&
	result ok 'info -> file, Permission denied -> stderr' ||
	result fail 'info -> file, Permission denied -> stderr'

##
# WARN, FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'warn', IO Exception (file), DEBUG=0"

rm -f "${logfile}"

BASHLOG_FILE=1
BASHLOG_JSON=0
BASHLOG_SYSLOG=0
DEBUG=0

sudo touch "${logfile}"

stderr="$(log 'warn' "${random_string}" 2>&1 1>/dev/null)"

sudo rm -f "${logfile}"

grep -q -E $"^*log.sh: line [0-9]+: ${logfile}: Permission denied" <<<"${stderr}" &&
	grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[WARN\] '"${random_string}"'" >> "/tmp/'"${script_name}"$'.log"\033\[0m$' <<<"${stderr}" &&
	result ok 'warn -> file, Permission denied -> stderr' ||
	result fail 'warn -> file, Permission denied -> stderr'

##
# ERROR, FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'error', IO Exception (file), DEBUG=0"

rm -f "${logfile}"

BASHLOG_FILE=1
BASHLOG_JSON=0
BASHLOG_SYSLOG=0
DEBUG=0

sudo touch "${logfile}"

stderr="$(log 'error' "${random_string}" 2>&1 1>/dev/null)"

sudo rm -f "${logfile}"

grep -q -E $"^*log.sh: line [0-9]+: ${logfile}: Permission denied" <<<"${stderr}" &&
	grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] '"${random_string}"'" >> "/tmp/'"${script_name}"$'.log"\033\[0m$' <<<"${stderr}" &&
	result ok 'error -> file, Permission denied -> stderr' ||
	result fail 'error -> file, Permission denied -> stderr'

##
# INTERACTIVE DEBUG
##

if [ "${interactive}" -eq 1 ]; then

	echo "Testing: Debug Interaction, DEBUG=1"

	BASHLOG_FILE=0
	BASHLOG_JSON=0
	BASHLOG_SYSLOG=0
	DEBUG=1

	echo -e "\n\t\033[32mLogging a normal successful debug message to stdout\033[0m"
	log 'debug' 'A normal successful debug message'

	echo -e "\n\t\033[32mLogging an error message to stdout that should provide a debug shell\n\tExit the shell with ^D, 'exit 0' or 'exit'.\n\tIf you exit with a non-zero code, testing will be abandoned, this script will exit without further warning.\033[0m"
	log 'error' 'An error message'

	result ok 'Interactive Shell. We have errored and continued.'

	echo -e "\n\t\033[32mLogging an error message to stdout that should provide a debug shell\n\tExit the shell with 'exit 1' or a non-zero code of your choice.\n\tThe test is successful if this script exits with the same code\033[0m"
	log 'error' 'An error message'

	result fail 'Interactive Shell. This script should have exited with a non-zero code'

fi

exit 0
