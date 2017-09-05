#!/usr/bin/env bash
# This file:
#
#  - Provides smoke test for standard Rancher requirements
#
# Usage:
#
#  LOG_LEVEL=7 ./smoketest.sh -o k8s -s -a
#
# Based on a template by BASH3 Boilerplate v2.3.0
# http://bash3boilerplate.sh/#authors
#
# The MIT License (MIT)
# Copyright (c) 2013 Kevin van Zonneveld and contributors
# You are not obligated to bundle the LICENSE file with your b3bp projects as long
# as you leave these references intact in the header comments of your source files.

# Exit on error. Append "|| true" if you expect an error.
set -o errexit
# Exit on error inside any functions or subshells.
set -o errtrace
# Do not allow use of undefined vars. Use ${VAR:-} to use an undefined VAR
set -o nounset
# Catch the error in case mysqldump fails (but gzip succeeds) in `mysqldump |gzip`
set -o pipefail
# Turn on traces, useful while debugging but commented out by default
# set -o xtrace

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  __i_am_main_script="0" # false

  if [[ "${__usage+x}" ]]; then
    if [[ "${BASH_SOURCE[1]}" = "${0}" ]]; then
      __i_am_main_script="1" # true
    fi

    __b3bp_external_usage="true"
    __b3bp_tmp_source_idx=1
  fi
else
  __i_am_main_script="1" # true
  [[ "${__usage+x}" ]] && unset -v __usage
  [[ "${__helptext+x}" ]] && unset -v __helptext
fi

# Set magic variables for current file, directory, os, etc.
__dir="$(cd "$(dirname "${BASH_SOURCE[${__b3bp_tmp_source_idx:-0}]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[${__b3bp_tmp_source_idx:-0}]}")"
__base="$(basename "${__file}" .sh)"


# Define the environment variables (and their defaults) that this script depends on
LOG_LEVEL="${LOG_LEVEL:-5}" # 7 = debug -> 0 = emergency
NO_COLOR="${NO_COLOR:-}"    # true = disable color. otherwise autodetected


### Functions
##############################################################################

function __b3bp_log () {
  local log_level="${1}"
  shift

  # shellcheck disable=SC2034
  local color_debug="\x1b[35m"
  # shellcheck disable=SC2034
  local color_info="\x1b[32m"
  # shellcheck disable=SC2034
  local color_notice="\x1b[34m"
  # shellcheck disable=SC2034
  local color_warning="\x1b[33m"
  # shellcheck disable=SC2034
  local color_error="\x1b[31m"
  # shellcheck disable=SC2034
  local color_critical="\x1b[1;31m"
  # shellcheck disable=SC2034
  local color_alert="\x1b[1;33;41m"
  # shellcheck disable=SC2034
  local color_emergency="\x1b[1;4;5;33;41m"

  local colorvar="color_${log_level}"

  local color="${!colorvar:-${color_error}}"
  local color_reset="\x1b[0m"

  if [[ "${NO_COLOR:-}" = "true" ]] || ( [[ "${TERM:-}" != "xterm"* ]] && [[ "${TERM:-}" != "screen"* ]] ) || [[ ! -t 2 ]]; then
    if [[ "${NO_COLOR:-}" != "false" ]]; then
      # Don't use colors on pipes or non-recognized terminals
      color=""; color_reset=""
    fi
  fi

  # all remaining arguments are to be printed
  local log_line=""

  while IFS=$'\n' read -r log_line; do
    echo -e "$(date -u +"%Y-%m-%d %H:%M:%S UTC") ${color}$(printf "[%9s]" "${log_level}")${color_reset} ${log_line}" 1>&2
  done <<< "${@:-}"
}

function emergency () {                                __b3bp_log emergency "${@}"; exit 1; }
function alert ()     { [[ "${LOG_LEVEL:-0}" -ge 1 ]] && __b3bp_log alert "${@}"; true; }
function critical ()  { [[ "${LOG_LEVEL:-0}" -ge 2 ]] && __b3bp_log critical "${@}"; true; }
function error ()     { [[ "${LOG_LEVEL:-0}" -ge 3 ]] && __b3bp_log error "${@}"; true; }
function warning ()   { [[ "${LOG_LEVEL:-0}" -ge 4 ]] && __b3bp_log warning "${@}"; true; }
function notice ()    { [[ "${LOG_LEVEL:-0}" -ge 5 ]] && __b3bp_log notice "${@}"; true; }
function info ()      { [[ "${LOG_LEVEL:-0}" -ge 6 ]] && __b3bp_log info "${@}"; true; }
function debug ()     { [[ "${LOG_LEVEL:-0}" -ge 7 ]] && __b3bp_log debug "${@}"; true; }

function help () {
  echo "" 1>&2
  echo " ${*}" 1>&2
  echo "" 1>&2
  echo "  ${__usage:-No usage available}" 1>&2
  echo "" 1>&2

  if [[ "${__helptext:-}" ]]; then
    echo " ${__helptext}" 1>&2
    echo "" 1>&2
  fi

  exit 1
}



### Parse commandline options
##############################################################################

# Commandline options. This defines the usage page, and is used to parse cli
# opts & defaults from. The parsing is unforgiving so be precise in your syntax
# - A short option must be preset for every long option; but every short option
#   need not have a long option
# - `--` is respected as the separator between options and arguments
# - We do not bash-expand defaults, so setting '~/app' as a default will not resolve to ${HOME}.
#   you can use bash variables to work around this (so use ${HOME} instead)

# shellcheck disable=SC2015
[[ "${__usage+x}" ]] || read -r -d '' __usage <<-'EOF' || true # exits non-zero when EOF encountered
  -o --orchestrator  [arg] Orchestration engine [cattle|k8s|kubernetes] Required.
  -s --server      Run tests for Rancher Server
  -a --agent       Run tests for Rancher Agent
  -v               Enable verbose mode, print script as it is executed
  -d --debug       Enables debug mode
  -h --help        This page
  -n --no-color    Disable color output
EOF

# shellcheck disable=SC2015
[[ "${__helptext+x}" ]] || read -r -d '' __helptext <<-'EOF' || true # exits non-zero when EOF encountered
 This script tests various things related to running Rancher, including HTTP access to various sites, ports, Docker version, and more. It is useful to determine if there are issues in the environment that might prevent Rancher from working correctly.
EOF

# Translate usage string -> getopts arguments, and set $arg_<flag> defaults
while read -r __b3bp_tmp_line; do
  if [[ "${__b3bp_tmp_line}" =~ ^- ]]; then
    # fetch single character version of option string
    __b3bp_tmp_opt="${__b3bp_tmp_line%% *}"
    __b3bp_tmp_opt="${__b3bp_tmp_opt:1}"

    # fetch long version if present
    __b3bp_tmp_long_opt=""

    if [[ "${__b3bp_tmp_line}" = *"--"* ]]; then
      __b3bp_tmp_long_opt="${__b3bp_tmp_line#*--}"
      __b3bp_tmp_long_opt="${__b3bp_tmp_long_opt%% *}"
    fi

    # map opt long name to+from opt short name
    printf -v "__b3bp_tmp_opt_long2short_${__b3bp_tmp_long_opt//-/_}" '%s' "${__b3bp_tmp_opt}"
    printf -v "__b3bp_tmp_opt_short2long_${__b3bp_tmp_opt}" '%s' "${__b3bp_tmp_long_opt//-/_}"

    # check if option takes an argument
    if [[ "${__b3bp_tmp_line}" =~ \[.*\] ]]; then
      __b3bp_tmp_opt="${__b3bp_tmp_opt}:" # add : if opt has arg
      __b3bp_tmp_init=""  # it has an arg. init with ""
      printf -v "__b3bp_tmp_has_arg_${__b3bp_tmp_opt:0:1}" '%s' "1"
    elif [[ "${__b3bp_tmp_line}" =~ \{.*\} ]]; then
      __b3bp_tmp_opt="${__b3bp_tmp_opt}:" # add : if opt has arg
      __b3bp_tmp_init=""  # it has an arg. init with ""
      # remember that this option requires an argument
      printf -v "__b3bp_tmp_has_arg_${__b3bp_tmp_opt:0:1}" '%s' "2"
    else
      __b3bp_tmp_init="0" # it's a flag. init with 0
      printf -v "__b3bp_tmp_has_arg_${__b3bp_tmp_opt:0:1}" '%s' "0"
    fi
    __b3bp_tmp_opts="${__b3bp_tmp_opts:-}${__b3bp_tmp_opt}"
  fi

  [[ "${__b3bp_tmp_opt:-}" ]] || continue

  if [[ "${__b3bp_tmp_line}" =~ (^|\.\ *)Default= ]]; then
    # ignore default value if option does not have an argument
    __b3bp_tmp_varname="__b3bp_tmp_has_arg_${__b3bp_tmp_opt:0:1}"

    if [[ "${!__b3bp_tmp_varname}" != "0" ]]; then
      __b3bp_tmp_init="${__b3bp_tmp_line##*Default=}"
      __b3bp_tmp_re='^"(.*)"$'
      if [[ "${__b3bp_tmp_init}" =~ ${__b3bp_tmp_re} ]]; then
        __b3bp_tmp_init="${BASH_REMATCH[1]}"
      else
        __b3bp_tmp_re="^'(.*)'$"
        if [[ "${__b3bp_tmp_init}" =~ ${__b3bp_tmp_re} ]]; then
          __b3bp_tmp_init="${BASH_REMATCH[1]}"
        fi
      fi
    fi
  fi

  if [[ "${__b3bp_tmp_line}" =~ (^|\.\ *)Required\. ]]; then
    # remember that this option requires an argument
    printf -v "__b3bp_tmp_has_arg_${__b3bp_tmp_opt:0:1}" '%s' "2"
  fi

  printf -v "arg_${__b3bp_tmp_opt:0:1}" '%s' "${__b3bp_tmp_init}"
done <<< "${__usage:-}"

# run getopts only if options were specified in __usage
if [[ "${__b3bp_tmp_opts:-}" ]]; then
  # Allow long options like --this
  __b3bp_tmp_opts="${__b3bp_tmp_opts}-:"

  # Reset in case getopts has been used previously in the shell.
  OPTIND=1

  # start parsing command line
  set +o nounset # unexpected arguments will cause unbound variables
                 # to be dereferenced
  # Overwrite $arg_<flag> defaults with the actual CLI options
  while getopts "${__b3bp_tmp_opts}" __b3bp_tmp_opt; do
    [[ "${__b3bp_tmp_opt}" = "?" ]] && help "Invalid use of script: ${*} "

    if [[ "${__b3bp_tmp_opt}" = "-" ]]; then
      # OPTARG is long-option-name or long-option=value
      if [[ "${OPTARG}" =~ .*=.* ]]; then
        # --key=value format
        __b3bp_tmp_long_opt=${OPTARG/=*/}
        # Set opt to the short option corresponding to the long option
        __b3bp_tmp_varname="__b3bp_tmp_opt_long2short_${__b3bp_tmp_long_opt//-/_}"
        printf -v "__b3bp_tmp_opt" '%s' "${!__b3bp_tmp_varname}"
        OPTARG=${OPTARG#*=}
      else
        # --key value format
        # Map long name to short version of option
        __b3bp_tmp_varname="__b3bp_tmp_opt_long2short_${OPTARG//-/_}"
        printf -v "__b3bp_tmp_opt" '%s' "${!__b3bp_tmp_varname}"
        # Only assign OPTARG if option takes an argument
        __b3bp_tmp_varname="__b3bp_tmp_has_arg_${__b3bp_tmp_opt}"
        printf -v "OPTARG" '%s' "${@:OPTIND:${!__b3bp_tmp_varname}}"
        # shift over the argument if argument is expected
        ((OPTIND+=__b3bp_tmp_has_arg_${__b3bp_tmp_opt}))
      fi
      # we have set opt/OPTARG to the short value and the argument as OPTARG if it exists
    fi
    __b3bp_tmp_varname="arg_${__b3bp_tmp_opt:0:1}"
    __b3bp_tmp_default="${!__b3bp_tmp_varname}"

    __b3bp_tmp_value="${OPTARG}"
    if [[ -z "${OPTARG}" ]] && [[ "${__b3bp_tmp_default}" = "0" ]]; then
      __b3bp_tmp_value="1"
    fi

    printf -v "${__b3bp_tmp_varname}" '%s' "${__b3bp_tmp_value}"
    debug "cli arg ${__b3bp_tmp_varname} = (${__b3bp_tmp_default}) -> ${!__b3bp_tmp_varname}"
  done
  set -o nounset # no more unbound variable references expected

  shift $((OPTIND-1))

  if [[ "${1:-}" = "--" ]] ; then
    shift
  fi
fi


### Automatic validation of required option arguments
##############################################################################

for __b3bp_tmp_varname in ${!__b3bp_tmp_has_arg_*}; do
  # validate only options which required an argument
  [[ "${!__b3bp_tmp_varname}" = "2" ]] || continue

  __b3bp_tmp_opt_short="${__b3bp_tmp_varname##*_}"
  __b3bp_tmp_varname="arg_${__b3bp_tmp_opt_short}"
  [[ "${!__b3bp_tmp_varname}" ]] && continue

  __b3bp_tmp_varname="__b3bp_tmp_opt_short2long_${__b3bp_tmp_opt_short}"
  printf -v "__b3bp_tmp_opt_long" '%s' "${!__b3bp_tmp_varname}"
  [[ "${__b3bp_tmp_opt_long:-}" ]] && __b3bp_tmp_opt_long=" (--${__b3bp_tmp_opt_long//_/-})"

  help "Option -${__b3bp_tmp_opt_short}${__b3bp_tmp_opt_long:-} requires an argument"
done


### Cleanup Environment variables
##############################################################################

for __tmp_varname in ${!__b3bp_tmp_*}; do
  unset -v "${__tmp_varname}"
done

unset -v __tmp_varname


### Externally supplied __usage. Nothing else to do here
##############################################################################

if [[ "${__b3bp_external_usage:-}" = "true" ]]; then
  unset -v __b3bp_external_usage
  return
fi


### Signal trapping and backtracing
##############################################################################

function __b3bp_cleanup_before_exit () {
  info "Cleaning up."
  info "Done."
}
trap __b3bp_cleanup_before_exit EXIT

# requires `set -o errtrace`
__b3bp_err_report() {
    local error_code
    error_code=${?}
    error "Error in ${__file} in function ${1} on line ${2}"
    exit ${error_code}
}
# Uncomment the following line for always providing an error backtrace
# trap '__b3bp_err_report "${FUNCNAME:-.}" ${LINENO}' ERR


### Command-line argument switches (like -d for debugmode, -h for showing helppage)
##############################################################################

# debug mode
if [[ "${arg_d:?}" = "1" ]]; then
  set -o xtrace
  LOG_LEVEL="7"
  # Enable error backtracing
  trap '__b3bp_err_report "${FUNCNAME:-.}" ${LINENO}' ERR
fi

# verbose mode
if [[ "${arg_v:?}" = "1" ]]; then
  set -o verbose
fi

# no color mode
if [[ "${arg_n:?}" = "1" ]]; then
  NO_COLOR="true"
fi

# help mode
if [[ "${arg_h:?}" = "1" ]]; then
  # Help exists with code 1
  help "Help using ${0}"
fi


### Validation. Error out if the things required for your script are not present
##############################################################################

[[ "${arg_o:-}" ]]     || help      "Setting an orchestrator with -o or --orchestrator is required"
[[ "${arg_s:-}" -eq 1 || "${arg_a:-}" -eq 1 ]]     || help      "Please specify which tests to run (server and/or agent)"
[[ "${LOG_LEVEL:-}" ]] || emergency "Cannot continue without LOG_LEVEL. "


### Runtime
##############################################################################

function log_error() {
  # stores errors for later display
  #
  # use like:
  #   `log_error {module} {message}`
  local module=$1 message=$2

  __errors+=("${module}: ${message}")

  true
}

function check_binaries() {
  debug "##################################"
  debug "## Binary Checks (for later tests)"
  debug "##################################"
  local p

  for binary in ${__required_binaries[@]}; do
    p=$(which ${binary} || true)
    if [[ -n $p ]]; then
      debug "  + $binary: $p"
      eval "__have_${binary}=0"
    else
      debug "  + $binary: NOT FOUND"
      eval "__have_${binary}=1"
    fi
  done

  true
}

function check_http() {
  notice "##############"
  notice "## HTTP Checks"
  notice "##############"
  # we expect there to be errors, and we want to capture them
  set +o errexit

  local response status proxied tempfile=$(mktemp)

  for site in ${__http_sites[@]}; do
    notice "Checking ${site}"

    # initial check for problems
    curl -sI -o /dev/null --connect-timeout 3 ${site}

    if [[ $? -eq 0 ]]; then
      # check again to get the headers
      curl -sI -o ${tempfile} ${site}

      # pull the status code
      status=$(head -n 1 ${tempfile} | awk '{ print $2 }')

      if [[ (${status} -ge 200 && ${status} -lt 500) ]]; then
        info "+ Status: ${status}"
      fi

      if [[ $(fgrep -c 'Via' ${tempfile}) -ne 0 ]]; then
        info "+ Proxied: true"
      fi
    else
      # check it again to collect the actual error output
      response=$(curl -# --connect-timeout 1 ${site} 2>&1 | tail -n 1 | sed -e 's/curl: (.*) //')

      if [[ ! ${response} = "OK" ]]; then
        error "  + ${response}"
        log_error "HTTP" "${site}: ${response}"
      fi
    fi

  done

  # no more errors expected
  set -o errexit

  # clean up the tempfile
  rm ${tempfile}

  true
}

function load_config() {
  # loads additional configuration info from an external file
  [[ -f smoketest.cfg ]] && . smoketest.cfg

  true
}

function containsElement() {
  # tests if `$1` is present in the array provided as `$2`
  local array="$2" match="$1"

  for e in ${array[@]}; do 
    if [[ "$e" == "$match" ]]; then
      return 0
    fi
  done

  return 1
}

function check_ports() {
  # checks UDP ports via nmap

  notice "################################"
  notice "## Port Checks (Overlay Network)"
  notice "################################"

  local sudo="" port proto p scan response nmap=$(which nmap)

  if [[ $(whoami) != 'root' ]]; then
    sudo="sudo"
  fi

  for host in ${RANCHER_AGENT_NODES[@]}; do
    notice "Checking ${host}"
    for p in ${__nmap_ports[@]}; do
      port=$(echo ${p} | awk -F/ '{ print $1 }')
      proto=$(echo ${p} | awk -F/ '{ print $2 }')

      if [[ ${proto} = "udp" || ${proto} = "UDP" ]]; then
        scan="-sU"
      elif [[ ${proto} = "tcp" || ${proto} = "TCP" ]]; then
        scan="-sS"
      else
        emergency "Unknown protocol ${proto} from ${p}"
      fi

      response=$(${sudo} ${nmap} ${scan} -P0 -p ${port} -oG - ${host} | grep Ports | grep ${port} | awk '{ print $5 }' | awk -F/ '{ print $2 }')

      if [[ ${response} =~ closed ]]; then
        warning "  + ${p}: CLOSED"
      elif [[ ${response} =~ filtered ]]; then
        warning "  + ${p}: FILTERED"
      elif [[ ${response} =~ open ]]; then
        notice "  + ${p}: OPEN"
      else
        info "  + ${p}: ${response}"
      fi

    done
  done

  true

}

function check_docker_version() {
  # Checks Docker version agains supported versions matrix
  local client server

  notice "#################"
  notice "## Docker Version"
  notice "#################"

  client=$(docker version | grep -A1 Client | tail -n 1 | awk '{ print $2 }')
  server=$(docker version | grep -A1 Server | tail -n 1 | awk '{ print $2 }')

  if [[ ${arg_o} = "k8s" || ${arg_o} = "kubernetes" ]]; then  
    if [[ ! ${client} =~ ${__docker_version_k8s} ]]; then
      warning "  + ${client}: UNSUPPORTED"
    else
      notice "  + ${client}: OK"
    fi
  elif [[ ${arg_o} = "cattle" ]]; then  
    if [[ ! ${client} =~ ${__docker_version_cattle} ]]; then
      warning "  + ${client}: UNSUPPORTED"
    else
      notice "  + ${client}: OK"
    fi 
  else
    help "Unknown orchestrator ${arg_o}"
  fi

  true
}


# These are overridden in `smoketest.cfg`
RANCHER_AGENT_NODES=()
EXTRA_SERVER_URLS=() 
EXTRA_AGENT_URLS=()

__errors=()
__http_sites=()

__required_binaries=(
    mktemp
    curl
    nmap
    sudo
    docker
  )

__http_sites_server=(
    https://git.rancher.io
    https://hub.docker.com
  )

__http_sites_agent=(
    http://gcr.io
    https://git.rancher.io
    https://hub.docker.com
    https://s3.amazonaws.com
  )

__nmap_ports=(
    500/udp
    4500/udp
    4789/udp
  )

__docker_version_k8s="^1\.12\.[0-9]+"
__docker_version_cattle="^(1\.1[23]\.[0-9]+|17\.0[36]\.[0-9]+-[ce]e)"

load_config

# pause automatic error exits
set +o errexit

if [[ ${RANCHER_SERVER:-} ]]; then
  __http_sites_agent+=(${RANCHER_SERVER})
fi

if [[ ${arg_s:-} -eq 1 ]]; then
  # If we're running server tests, copy the sites for server
  __http_sites=${__http_sites_server[@]}
fi

if [[ ${arg_a:-} -eq 1 ]]; then
  if [[ ${#__http_sites[@]:-} -gt 0 ]]; then
    # if we already have sites, we're running server and agent,
    # so we need to de-dupe
    for site in ${__http_sites_agent[@]}; do
      containsElement "${site}" "${__http_sites[@]}"
      if [[ $? -eq 1 ]]; then
        # not present in the array, so add it  
        __http_sites+=(${site})
      fi      
    done
  else
    # otherwise just copy the sites list over
    __http_sites=${__http_sites_agent}
  fi
fi

if [[ ${#EXTRA_AGENT_URLS[@]:-} -gt 0 ]]; then
    for site in ${EXTRA_AGENT_URLS[@]}; do
      containsElement "${site}" "${__http_sites[@]}"
      if [[ $? -eq 1 ]]; then
        # not present in the array, so add it  
        __http_sites+=(${site})
      fi      
    done
fi

# resume automatic error exits
set -o errexit

check_binaries

# make sure we have docker
if ! [[ ${__have_docker} -eq 0 ]]; then
  emergency "Docker binary not found. Unable to continue."
fi

check_docker_version

if ! [[ ${__have_mktemp:-} -eq 0 ]]; then
  error "Unable to continue without mktemp."
  exit 1
fi

if [[ ${__have_curl:-} -eq 0 ]]; then
  check_http
else
  warning "Skipping HTTP checks because curl is missing."
fi

if [[ ${arg_a} -eq 1 ]]; then
  if [[ ${__have_nmap:-} -eq 0 ]]; then
    if [[ ${#RANCHER_AGENT_NODES[@]} -gt 0 ]]; then
      check_ports
    else
      warning "Skipping port checks because RANCHER_AGENT_NODES is empty."
    fi
  else
    warning "Skipping port checks because nmap is missing."
  fi
fi

