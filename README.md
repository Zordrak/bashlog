# bashlog

A simple but powerful logging library for bash

## Simple Usage

Place log.sh in the directory with your bash script(s)

Add `. log.sh` to the top of your script(s)

Add logging lines with level info, warn, error or debug, for example:

  * `log info 'My info message';`

  * `log warn 'My warning message';`

  * `log error 'My error message';`

  * `log debug 'My debugging message';`


## Bash Shell Options

This library sets the following shell options:

`set -uo pipefail`

This is a recommended default for any scripts you write:
  * You should not use unbound variables (-u)
  * You should ensure pipelines fail if any of the commands in the pipeline fail (-o pipefail)

This library does _not_ `set -e` because automatically exiting a script
when any error is encountered is lazy and a poor user experience.
Errors should be caught and handled by your scripts.
This can be supported by the use of this library's 'error' log-level.

If you do not like these settings - change them or remove them.

## Debugging

To enable debugging, set `DEBUG=1` in your script's environment.

  * When `DEBUG=0`, log lines with level 'debug' are not printed.
  * When `DEBUG=1`, log lines with level 'debug' are printed.

### Interactive debugging of errors

When debugging is enabled, error messages are followed by an interactive
bash shell from which debugging can take place.

When debugging activity is complete: exiting the shell with code 0
will allow the rest of your script to continue, exiting the shell
with a non-zero code will cause your script to terminate with the
same non-zero code.

### Bash Debug Trap

This library enables a bash DEBUG trap, that provides you with
a variable called `prev_cmd` to help you write simple and useful
debug logging messages.

For example:

```
my_command --with very -c -o -m -p -l -e -x -- parameters \
  && log debug "${prev_cmd}" \
  || log error "${prev_cmd};
```

This will log the exact command that was executed as a debug log
(only when `DEBUG=1`).

If the command fails, the error message will show the precise command
that failed, and when `DEBUG=1` will then present you with a debug
shell from which you can choose to continue or to exit your script.

#### Advanced Debugging

This library contains an alternate debug trap that can be uncommented
which will log a debug log entry (when `DEBUG=1`) for every single
command that is executed throughout your script.

Enabling this alternate trap will severely impact performance of
your script, and the bashlog testing suite will not be applicable.

## File, JSON & Syslog

When instructed, the logging library can also log output:
  * To a file in plain text format: `BASHLOG_FILE=1`
  * To a file in JSON format: `BASHLOG_JSON=1`
  * To Syslog: `BASHLOG_SYSLOG=1`

## Additional environment variables

### BASHLOG_DATE_FORMAT

Default: `+%F %T`

The date format to use for stdout and file logging (passed to the `date` binary).

Syslog date format is determined by syslog configuration.

JSON date format is epoch.

### BASHLOG_FILE_PATH

Default: `/tmp/$(basename {0}).log`

When `BASHLOG_FILE=1`, logs are written to the file at `$BASHLOG_FILE_PATH`

This defaults to the name of your script (the one from which you sourced this library),
with a `.log` suffix, in the /tmp directory.

e.g. yourscript.sh will produce `/tmp/yourscript.sh.log`

### BASHLOG_JSON_PATH

Default: `/tmp/$(basename {0}).log.json`

When `BASHLOG_JSON=1`, logs are written in JSON format to the file at `$BASHLOG_JSON_PATH`

This defaults to the name of your script (the one from which you sourced this library),
with a `.log.json` suffix, in the /tmp directory.

e.g. yourscript.sh will produce `/tmp/yourscript.sh.log.json`

### BASHLOG_SYSLOG_FACILITY

Default: `local0`

When `BASHLOG_SYSLOG=1`, logs are written to Syslog.

This determines the syslog facility to use (local0 <-> local7)

### BASHLOG_SYSLOG_TAG

Default: `$(basename {0})`

When BASHLOG_SYSLOG=1, logs are written to Syslog.

This determines the syslog tag to use, defaulting to the name of your script,
e.g. `yourscript.sh`

## Recommended Usage

```
. log.sh;

cat << 'EOF' > /etc/yum.repos.d/smoo.repo &&
[smoo]
name=smoo
baseurl=file:///tmp/smoo/
enabled=1
gpgcheck=0
EOF
  log debug "Smoo repo yum repository configuration written successfully" \
  || log error "Failed to write smoo repo yum repository configuration";


# Install the smoo agent
yum -y install smoo-agent \
  && log info "smoo-agent RPM installed successfully" \
  || log error "Failed to install smoo-agent RPM";

# Change into the newly installed repository
cd /srv/smoo \
  && log debug "${prev_cmd}" \
  || log error "${prev_cmd}";

/opt/smoo-agent/bin/tests /srv/smoo \
  && log info "Smoo Tests Succeeded" \
  || log error "Smoo Tests Failed";

# Execute the smoo-agent
/opt/smoo-agent/bin/smoo \
  -r \
  --config config.json \
  --log_level "info" \
  && log info "Smoo Agent execution completed successfully" \
  || log error "Smoo Agent execution failed!";

if [ "${DEBUG:-0}" -eq "1" ]; then
  log debug "Entering end-of-script debug shell. Exit shell to continue.";
  /bin/bash;
fi;

log info 'Smoo Agent control finished';

exit 0;
```

## Testing

A full test suite is provided alongside the bashlog library in `test.sh`.

The test suite itself has been tested on Slackware Linux. If your syslog
configuration behaves differently to the default in Slackware, the test
suite may fail. Feel free to provide feedback / pull requests to improve it.

The test suite requires sudo privileges in order to create files that
cannot then be accessed. I could replace this with non-root privilege
modification - and maybe I will - but not today.

### Interactive Testing

If you pass `TEST_INTERACTIVE=1` to test.sh, the automated tests will be
followed by interactive tests which test the debug shell mechanisms.

User input is required, following instructional prompts in order to
properly validate the functionality.
