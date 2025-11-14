#!/bin/bash

# epik-ddns.sh
# Author: CoeJoder [github.com]
#
# A simple DDNS bash script to update Epik DNS records.
#
# Suggested to be run periodically as a cron job, this script calls Epik's
# `set-ddns` API method whenever a change to the host's external IP address is
# detected.  As Epik has no `read-ddns` method available sans IP-whitelisting,
# the call is always made on the first run, and at least once every 24-hours.
#
# When run on OpenWRT router firmware, an internal library function is called
# which returns the device's WAN IP.  Otherwise, an external service is used to
# fetch the host's external IP: https://ipinfo.io/ip
#
# Requires: bash, curl, jq, grep
#
# The following variables are required to be set in: ~/.epik-ddns/properties.sh
#   EPIK_SIGNATURE - domain-specific API key
#   EPIK_HOSTNAME  - subdomain or root, e.g. @
#
# A cache file is created by the script here: ~/.epik-ddns/last_update_cache.txt
#
# Exit Statuses:
#   0: call successful
#   1: fatal error
#   2: call skipped (e.g., due to caching)
#
# Epik API docs and portal:
# https://docs-userapi.epik.com/v2/#/Ddns/setDdns
#
# Epik API account settings:
# https://registrar.epik.com/account/api-settings/
#
# Thanks to Nazar78 [TeaNazaR.com] for his `godaddy-ddns` script, on which this
# script is roughly based.

# contains script vars; required to exist
EPIK_DDNS_PROPERTIES_SH="$HOME/.epik-ddns/properties.sh"

# timestamped WAN IP cache
EPIK_DDNS_CACHE_TXT="$HOME/.epik-ddns/last_update_cache.txt"

# OpenWRT network functions; optional to exist
# if not present, external service is used to determine WAN IP
OPENWRT_NETWORK_SH='/lib/functions/network.sh'
EXTERNAL_IP_SERVICE='https://ipinfo.io/ip'

# used to validate IPv4 addresses
# source: https://unix.stackexchange.com/a/111852
IP_OCTET='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
IP_REGEX="^$IP_OCTET\.$IP_OCTET\.$IP_OCTET\.$IP_OCTET\$"

# used to validate timestamps
UINT_REGEX='^[[:digit:]]+$'
ONE_DAY_IN_SECONDS="$((24 * 60 * 60))"

# ensure availability of dependencies
for _command in curl jq grep; do
	if ! type -P "$_command" &>/dev/null; then
		echo "\`$_command\` not found" >&2
		exit 1
	fi
done

# ensure `curl` supports --fail-with-body
if curl --fail-with-body --head example.com 2>&1 >/dev/null | \
	grep -q -- '--fail-with-body'; then
	echo "curl does not support '--fail-with-body' option; please upgrade"
	exit 1
fi

# read & validate properties file
if [[ ! -f $EPIK_DDNS_PROPERTIES_SH ]]; then
	echo "file not found: ${EPIK_DDNS_PROPERTIES_SH}" >&2
	exit 1
fi
source "$EPIK_DDNS_PROPERTIES_SH"
if [[ -z $EPIK_SIGNATURE ]]; then
	echo 'EPIK_SIGNATURE not set' >&2
	exit 1
fi
if [[ -z $EPIK_HOSTNAMES ]]; then
	echo 'EPIK_HOSTNAMES not set' >&2
	exit 1
fi

# discover WAN IP address
if [[ -f $OPENWRT_NETWORK_SH ]]; then
	source "$OPENWRT_NETWORK_SH"
	network_get_ipaddr _wan_ip wan
fi
if [[ -z $_wan_ip ]]; then
	_wan_ip="$(curl -kLs "$EXTERNAL_IP_SERVICE")"
fi
if [[ -z $_wan_ip ]]; then
	echo 'WAN IP discovery failed' >&2
	exit 1
fi
if [[ ! $_wan_ip =~ $IP_REGEX ]]; then
	echo "WAN IP invalid: $_wan_ip" >&2
	exit 1
fi

_current_time="$(date +%s)"

function postUpdateAndExit() {
	local _response _response_error _hostname

	echo $EPIK_HOSTNAMES
	for _hostname in "${EPIK_HOSTNAMES[@]}"; do
		# API call
		_response="$(curl -LSsX 'POST' --fail-with-body \
			"https://usersapiv2.epik.com/v2/ddns/set-ddns?SIGNATURE=$EPIK_SIGNATURE" \
			-H 'Accept: application/json' \
			-H 'Content-Type: application/json' \
			-d "{
					\"hostname\": \"$_hostname\",
					\"value\": \"$_wan_ip\"
		}")"
		# check for server errors
		echo $_response
		_response_error="$(jq -r '.errors[0] | .description' <<<"$_response")"
		if [[ $_response_error != null ]]; then
			echo "Error updating $_hostname: $_response_error" >&2
			exit 1
		else
			echo "Updated $_hostname → $_wan_ip"
		fi
	done

	# update WAN IP cache (shared for all hostnames)
	if ! printf '%s %s' "$_current_time" "$_wan_ip" >"$EPIK_DDNS_CACHE_TXT"; then
		echo 'failed to write WAN IP cache' >&2
		exit 1
	fi

	exit 0
}

# POST the update iff:
#  - cached WAN IP is missing/unreadable, or
#  - cached WAN IP timestamp is missing/malformed, or
#  - current WAN IP doesn't match the cached one, or
#  - more than 24-hours has elapsed since last update
if [[ ! -r $EPIK_DDNS_CACHE_TXT ]]; then
	postUpdateAndExit
else
	read _last_update_timestamp _wan_ip_cached <"$EPIK_DDNS_CACHE_TXT"
	if [[ ! $_last_update_timestamp =~ $UINT_REGEX ]]; then
		postUpdateAndExit
	elif [[ $_wan_ip != $_wan_ip_cached ]]; then
		postUpdateAndExit
	else
		_time_since_last_update="$((_current_time - _last_update_timestamp))"
		if [[ $_time_since_last_update -gt $ONE_DAY_IN_SECONDS ]]; then
			postUpdateAndExit
		fi
	fi
fi
exit 2
