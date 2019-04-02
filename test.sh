#!/bin/bash

set -uo pipefail;

# Interactive debug testing is off by default.
# To turn it on, pass TEST_INTERACTIVE=1
# Correct exit code from this test script
# will then be '1' instead of '0'
declare interactive="${TEST_INTERACTIVE:-0}";

function result() {
  local level="${1}";
  shift;
  local line="${@}"; 

  case "${level}" in
    ok)
      echo -e "\t\033[32mOK: ${line}\033[0m";
      ;;
    fail)
      echo -e "\t\033[31mFAIL: ${line}\033[0m";
      echo -e "Abandoning tests due to failure";
      exit 1;
      ;;
    *)
      echo "UWOTM8?!";
      exit 1;
      ;;
  esac;
}

sudo rm -f "/tmp/${0}.log";
sudo rm -f "/tmp/${0}.log.json";

source log.sh;

declare random_string="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)";
declare stdout;
declare fileout;
declare jsonout;
declare syslogout;

declare BASHLOG_FILE=1;
declare BASHLOG_JSON=1;
declare BASHLOG_SYSLOG=1;

##
# INFO
##

echo "Testing 'info'";

rm -f "/tmp/${0}.log";
rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=1;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=1;
DEBUG=0;

stdout="$(log 'info' "${random_string}")";
fileout="$(tail -n1 /tmp/${0}.log)";
jsonout="$(tail -n1 /tmp/${0}.log.json)";
syslogout="$(sudo tail -n1 /var/log/messages)";

grep -q -E $'^\033\[32m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" \
  && result ok 'info -> stdout' \
  || result fail 'info -> stdout';

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] ${random_string}$" <<<"${fileout}" \
  && result ok 'info -> file' \
  || result fail 'info -> file';

grep -q -E '^{"timestamp":"[0-9]{10}","level":"info","message":"'"${random_string}"'"}$' <<<"${jsonout}" \
  && result ok 'info -> json file' \
  || result fail 'info -> json file';

grep -q -E "$(basename ${0})\[${$}\]: INFO: ${random_string}$" <<<"${syslogout}" \
  && result ok 'info -> syslog (/var/log/messages)' \
  || result fail 'info -> syslog (/var/log/messages)';

##
# WARN
##

echo "Testing 'warn'";

rm -f "/tmp/${0}.log";
rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=1;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=1;
DEBUG=0;

stdout="$(log 'warn' "${random_string}")";
fileout="$(tail -n1 /tmp/${0}.log)";
jsonout="$(tail -n1 /tmp/${0}.log.json)";
syslogout="$(sudo tail -n1 /var/log/syslog)";

grep -q -E $'^\033\[33m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[WARN\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" \
  && result ok 'warn -> stdout' \
  || result fail 'warn -> stdout';

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[WARN\] ${random_string}$" <<<"${fileout}" \
  && result ok 'warn -> file' \
  || result fail 'warn -> file';

grep -q -E '^{"timestamp":"[0-9]{10}","level":"warn","message":"'"${random_string}"'"}$' <<<"${jsonout}" \
  && result ok 'warn -> json file' \
  || result fail 'warn -> json file';

grep -q -E "$(basename ${0})\[${$}\]: WARN: ${random_string}$" <<<"${syslogout}" \
  && result ok 'warn -> syslog (/var/log/syslog)' \
  || result fail 'warn -> syslog (/var/log/syslog)';

##
# ERROR
##

echo "Testing: 'error'";

rm -f "/tmp/${0}.log";
rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=1;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=1;
DEBUG=0;

stderr="$(log 'error' "${random_string}" 2>&1 1>/dev/null)";
fileout="$(tail -n1 /tmp/${0}.log)";
jsonout="$(tail -n1 /tmp/${0}.log.json)";
syslogout="$(sudo tail -n1 /var/log/syslog)";

grep -q -E $'^\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] '"${random_string}"$'\033\[0m$' <<<"${stderr}" \
  && result ok 'error -> stderr' \
  || result fail 'error -> stderr';

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] ${random_string}$" <<<"${fileout}" \
  && result ok 'error -> file' \
  || result fail 'error -> file';

grep -q -E '^{"timestamp":"[0-9]{10}","level":"error","message":"'"${random_string}"'"}$' <<<"${jsonout}" \
  && result ok 'error -> json file' \
  || result fail 'error -> json file';

grep -q -E "$(basename ${0})\[${$}\]: ERROR: ${random_string}$" <<<"${syslogout}" \
  && result ok 'error -> syslog (/var/log/syslog)' \
  || result fail 'error -> syslog (/var/log/syslog)';

##
# DEBUG OFF
##

echo "Testing 'debug', DEBUG=0";

rm -f "/tmp/${0}.log";
rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=1;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=1;
DEBUG=0;

# If there's no output, there'll be no file
touch "/tmp/${0}.log";
touch "/tmp/${0}.log.json";

stdout="$(log 'debug' "${random_string}")";
fileout="$(tail -n1 /tmp/${0}.log)";
jsonout="$(tail -n1 /tmp/${0}.log.json)";
syslogout="$(sudo tail -n1 /var/log/debug)";

grep -q -E $'^\033\[34m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" \
  && result fail 'debug -> stdout' \
  || result ok 'debug -> stdout';

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] ${random_string}$" <<<"${fileout}" \
  && result fail 'debug -> file' \
  || result ok 'debug -> file';

grep -q -E '^{"timestamp":"[0-9]{10}","level":"debug","message":"'"${random_string}"'"}$' <<<"${jsonout}" \
  && result fail 'debug -> json file' \
  || result ok 'debug -> json file';

grep -q -E "$(basename ${0})\[${$}\]: DEBUG: ${random_string}$" <<<"${syslogout}" \
  && result fail 'debug -> syslog (/var/log/debug)' \
  || result ok 'debug -> syslog (/var/log/debug)';

##
# DEBUG ON
##

echo "Testing 'debug', DEBUG=1";

rm -f "/tmp/${0}.log";
rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=1;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=1;
DEBUG=1;

stdout="$(log 'debug' "${random_string}")";
fileout="$(tail -n1 /tmp/${0}.log)";
jsonout="$(tail -n1 /tmp/${0}.log.json)";
syslogout="$(sudo tail -n1 /var/log/debug)";

grep -q -E $'^\033\[34m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] '"${random_string}"$'\033\[0m$' <<<"${stdout}" \
  && result ok 'debug -> stdout' \
  || result fail 'debug -> stdout';

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[DEBUG\] ${random_string}$" <<<"${fileout}" \
  && result ok 'debug -> file' \
  || result fail 'debug -> file';

grep -q -E '^{"timestamp":"[0-9]{10}","level":"debug","message":"'"${random_string}"'"}$' <<<"${jsonout}" \
  && result ok 'debug -> json file' \
  || result fail 'debug -> json file';

grep -q -E "$(basename ${0})\[${$}\]: DEBUG: ${random_string}$" <<<"${syslogout}" \
  && result ok 'debug -> syslog (/var/log/debug)' \
  || result fail 'debug -> syslog (/var/log/debug)';

##
# BAD LEVEL, DEBUG OFF
##

echo "Testing: BAD LEVEL ('snooch'), DEBUG=0";

rm -f "/tmp/${0}.log";
rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=1;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=1;
DEBUG=0;

stderr="$(log 'snooch' "${random_string}" 2>&1 1>/dev/null)";
fileout="$(tail -n1 /tmp/${0}.log)";
jsonout="$(tail -n1 /tmp/${0}.log.json)";
syslogout="$(sudo tail -n1 /var/log/syslog)";

grep -q -E $'^\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: '"${random_string}"$'\033\[0m$' <<<"${stderr}" \
  && result ok 'snooch -> stderr' \
  || result fail 'snooch -> stderr';

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: ${random_string}$" <<<"${fileout}" \
  && result ok 'snooch -> file' \
  || result fail 'snooch -> file';

grep -q -E '^{"timestamp":"[0-9]{10}","level":"error","message":"Undefined log level trying to log: '"${random_string}"'"}$' <<<"${jsonout}" \
  && result ok 'snooch -> json file' \
  || result fail 'snooch -> json file';

grep -q -E "$(basename ${0})\[${$}\]: ERROR: Undefined log level trying to log: ${random_string}$" <<<"${syslogout}" \
  && result ok 'snooch -> syslog (/var/log/syslog)' \
  || result fail 'snooch -> syslog (/var/log/syslog)';

##
# BAD LEVEL, DEBUG ON
##

echo "Testing: BAD LEVEL ('snooch'), DEBUG=1";

rm -f "/tmp/${0}.log";
rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=1;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=1;
DEBUG=1;

stderr="$(echo | log 'snooch' "${random_string}" 2>&1 1>/dev/null)";
fileout="$(tail -n1 /tmp/${0}.log)";
jsonout="$(tail -n1 /tmp/${0}.log.json)";
syslogout="$(sudo tail -n1 /var/log/syslog)";

grep -q -E $'^\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: '"${random_string}"$'\033\[0m$' <<<"${stderr}" \
  && result ok 'snooch -> stderr' \
  || result fail 'snooch -> stderr';

grep -q -E "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Undefined log level trying to log: ${random_string}$" <<<"${fileout}" \
  && result ok 'snooch -> file' \
  || result fail 'snooch -> file';

grep -q -E '^{"timestamp":"[0-9]{10}","level":"error","message":"Undefined log level trying to log: '"${random_string}"'"}$' <<<"${jsonout}" \
  && result ok 'snooch -> json file' \
  || result fail 'snooch -> json file';

grep -q -E "$(basename ${0})\[${$}\]: ERROR: Undefined log level trying to log: ${random_string}$" <<<"${syslogout}" \
  && result ok 'snooch -> syslog (/var/log/syslog)' \
  || result fail 'snooch -> syslog (/var/log/syslog)';

##
# INFO, FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'info', IO Exception (file), DEBUG=0";

rm -f "/tmp/${0}.log";

BASHLOG_FILE=1;
BASHLOG_JSON=0;
BASHLOG_SYSLOG=0;
DEBUG=0;

sudo touch "/tmp/${0}.log";

stderr="$(log 'info' "${random_string}" 2>&1 1>/dev/null)";

sudo rm -f "/tmp/${0}.log";

grep -q -E $'^./log.sh: line [0-9]+: /tmp/'"$(basename ${0})"'.log: Permission denied' <<<"${stderr}" \
  && grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] '"${random_string}"'" >> "/tmp/'"$(basename ${0})"$'.log"\033\[0m$' <<<"${stderr}" \
  && result ok 'info -> file, Permission denied -> stderr' \
  || result fail 'info -> file, Permission denied -> stderr';

##
# INFO, FILE IO EXCEPTION, DEBUG ON
##

echo "Testing: 'info', IO Exception (file), DEBUG=1";

rm -f "/tmp/${0}.log";

BASHLOG_FILE=1;
BASHLOG_JSON=0;
BASHLOG_SYSLOG=0;
DEBUG=1;

sudo touch "/tmp/${0}.log";

stderr="$(echo | log 'info' "${random_string}" 2>&1 1>/dev/null)";

sudo rm -f "/tmp/${0}.log";

grep -q -E $'^./log.sh: line [0-9]+: /tmp/'"$(basename ${0})"'.log: Permission denied' <<<"${stderr}" \
  && grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[INFO\] '"${random_string}"'" >> "/tmp/'"$(basename ${0})"$'.log"\033\[0m$' <<<"${stderr}" \
  && result ok 'info -> file, Permission denied -> stderr' \
  || result fail 'info -> file, Permission denied -> stderr';

##
# INFO, JSON FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'info', IO Exception (json), DEBUG=0";

rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=0;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=0;
DEBUG=0;

sudo touch "/tmp/${0}.log.json";

stderr="$(log 'info' "${random_string}" 2>&1 1>/dev/null)";

sudo rm -f "/tmp/${0}.log.json";

grep -q -E $'^./log.sh: line [0-9]+: /tmp/'"$(basename ${0})"'.log.json: Permission denied' <<<"${stderr}" \
  && grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "{"timestamp":"[0-9]{10}","level":"info","message":"'"${random_string}"'"}" >> "/tmp/'"$(basename ${0})"$'.log.json"\033\[0m$' <<<"${stderr}" \
  && result ok 'info -> file, Permission denied -> stderr' \
  || result fail 'info -> file, Permission denied -> stderr';

##
# INFO, JSON FILE IO EXCEPTION, DEBUG ON
##

echo "Testing: 'info', IO Exception (json), DEBUG=1";

rm -f "/tmp/${0}.log.json";

BASHLOG_FILE=0;
BASHLOG_JSON=1;
BASHLOG_SYSLOG=0;
DEBUG=1;

sudo touch "/tmp/${0}.log.json";

stderr="$(echo | log 'info' "${random_string}" 2>&1 1>/dev/null)";

sudo rm -f "/tmp/${0}.log.json";

grep -q -E $'^./log.sh: line [0-9]+: /tmp/'"$(basename ${0})"'.log.json: Permission denied' <<<"${stderr}" \
  && grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "{"timestamp":"[0-9]{10}","level":"info","message":"'"${random_string}"'"}" >> "/tmp/'"$(basename ${0})"$'.log.json"\033\[0m$' <<<"${stderr}" \
  && result ok 'info -> file, Permission denied -> stderr' \
  || result fail 'info -> file, Permission denied -> stderr';

##
# WARN, FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'warn', IO Exception (file), DEBUG=0";

rm -f "/tmp/${0}.log";

BASHLOG_FILE=1;
BASHLOG_JSON=0;
BASHLOG_SYSLOG=0;
DEBUG=0;

sudo touch "/tmp/${0}.log";

stderr="$(log 'warn' "${random_string}" 2>&1 1>/dev/null)";

sudo rm -f "/tmp/${0}.log";

grep -q -E $'^./log.sh: line [0-9]+: /tmp/'"$(basename ${0})"'.log: Permission denied' <<<"${stderr}" \
  && grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[WARN\] '"${random_string}"'" >> "/tmp/'"$(basename ${0})"$'.log"\033\[0m$' <<<"${stderr}" \
  && result ok 'warn -> file, Permission denied -> stderr' \
  || result fail 'warn -> file, Permission denied -> stderr';

##
# ERROR, FILE IO EXCEPTION, DEBUG OFF
##

echo "Testing: 'error', IO Exception (file), DEBUG=0";

rm -f "/tmp/${0}.log";

BASHLOG_FILE=1;
BASHLOG_JSON=0;
BASHLOG_SYSLOG=0;
DEBUG=0;

sudo touch "/tmp/${0}.log";

stderr="$(log 'error' "${random_string}" 2>&1 1>/dev/null)";

sudo rm -f "/tmp/${0}.log";

grep -q -E $'^./log.sh: line [0-9]+: /tmp/'"$(basename ${0})"'.log: Permission denied' <<<"${stderr}" \
  && grep -q -E $'\033\[31m[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] Logging Exception: echo -e "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[ERROR\] '"${random_string}"'" >> "/tmp/'"$(basename ${0})"$'.log"\033\[0m$' <<<"${stderr}" \
  && result ok 'error -> file, Permission denied -> stderr' \
  || result fail 'error -> file, Permission denied -> stderr';

##
# INTERACTIVE DEBUG
##

if [ "${interactive}" -eq 1 ]; then

  echo "Testing: Debug Interaction, DEBUG=1";

  BASHLOG_FILE=0;
  BASHLOG_JSON=0;
  BASHLOG_SYSLOG=0;
  DEBUG=1;

  echo -e "\n\t\033[32mLogging a normal successful debug message to stdout\033[0m";
  log 'debug' 'A normal successful debug message';

  echo -e "\n\t\033[32mLogging an error message to stdout that should provide a debug shell\n\tExit the shell with ^D, 'exit 0' or 'exit'.\n\tIf you exit with a non-zero code, testing will be abandoned, this script will exit without further warning.\033[0m";
  log 'error' 'An error message';

  result ok 'Interactive Shell. We have errored and continued.';

  echo -e "\n\t\033[32mLogging an error message to stdout that should provide a debug shell\n\tExit the shell with 'exit 1' or a non-zero code of your choice.\n\tThe test is successful if this script exits with the same code\033[0m";
  log 'error' 'An error message';

  result fail 'Interactive Shell. This script should have exited with a non-zero code';

fi;

exit 0;
