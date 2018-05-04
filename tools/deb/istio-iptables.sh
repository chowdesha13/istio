#!/bin/bash
#
# Copyright 2017, 2018 Istio Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#
# Initialization script responsible for setting up port forwarding for Istio sidecar.

function usage() {
  echo "${0} -p PORT -u UID [-m mode] [-b ports] [-d ports] [-i CIDR] [-x CIDR] [-h]"
  echo ''
  echo '  -p: Specify the envoy port to which redirect all TCP traffic (default $ENVOY_PORT = 15001)'
  echo '  -u: Specify the UID of the user for which the redirection is not'
  echo '      applied. Typically, this is the UID of the proxy container'
  echo '      (default to uid of $ENVOY_USER, uid of istio_proxy, or 1337)'
  echo '  -m: The mode used to redirect inbound connections to Envoy, either "REDIRECT" or "TPROXY"'
  echo '      (default to $ISTIO_INBOUND_INTERCEPTION_MODE)'
  echo '  -b: Comma separated list of inbound ports for which traffic is to be redirected to Envoy (optional). The'
  echo '      wildcard character "*" can be used to configure redirection for all ports. An empty list will disable'
  echo '      all inbound redirection (default to $ISTIO_INBOUND_PORTS)'
  echo '  -d: Comma separated list of inbound ports to be excluded from redirection to Envoy (optional). Only applies'
  echo '      when all inbound traffic (i.e. "*") is being redirected (default to $ISTIO_LOCAL_EXCLUDE_PORTS)'
  echo '  -i: Comma separated list of IP ranges in CIDR form to redirect to envoy (optional). The wildcard'
  echo '      character "*" can be used to redirect all outbound traffic. An empty list will disable all outbound'
  echo '      redirection (default to $ISTIO_SERVICE_CIDR)'
  echo '  -x: Comma separated list of IP ranges in CIDR form to be excluded from redirection. Only applies when all '
  echo '      outbound traffic (i.e. "*") is being redirected (default to $ISTIO_SERVICE_EXCLUDE_CIDR).'
  echo ''
  echo 'Using environment variables in $ISTIO_SIDECAR_CONFIG (default: /var/lib/istio/envoy/sidecar.env)'
}

# Use a comma as the separator for multi-value arguments.
IFS=,

# The cluster env can be used for common cluster settings, pushed to all VMs in the cluster.
# This allows separating per-machine settings (the list of inbound ports, local path overrides) from cluster wide
# settings (CIDR range)
ISTIO_CLUSTER_CONFIG=${ISTIO_CLUSTER_CONFIG:-/var/lib/istio/envoy/cluster.env}
if [ -r ${ISTIO_CLUSTER_CONFIG} ]; then
  . ${ISTIO_CLUSTER_CONFIG}
fi

ISTIO_SIDECAR_CONFIG=${ISTIO_SIDECAR_CONFIG:-/var/lib/istio/envoy/sidecar.env}
if [ -r ${ISTIO_SIDECAR_CONFIG} ]; then
  . ${ISTIO_SIDECAR_CONFIG}
fi

# TODO: load all files from a directory, similar with ufw, to make it easier for automated install scripts
# Ideally we should generate ufw (and similar) configs as well, in case user already has an iptables solution.

PROXY_PORT=${ENVOY_PORT:-15001}
PROXY_UID=
INBOUND_INTERCEPTION_MODE=${ISTIO_INBOUND_INTERCEPTION_MODE}
INBOUND_TPROXY_MARK=${ISTIO_INBOUND_TPROXY_MARK:-1337}
INBOUND_TPROXY_ROUTE_TABLE=${ISTIO_INBOUND_TPROXY_ROUTE_TABLE:-133}
INBOUND_PORTS_INCLUDE=${ISTIO_INBOUND_PORTS-}
INBOUND_PORTS_EXCLUDE=${ISTIO_LOCAL_EXCLUDE_PORTS-}
OUTBOUND_IP_RANGES_INCLUDE=${ISTIO_SERVICE_CIDR-}
OUTBOUND_IP_RANGES_EXCLUDE=${ISTIO_SERVICE_EXCLUDE_CIDR-}

while getopts ":p:u:m:b:d:i:x:h" opt; do
  case ${opt} in
    p)
      PROXY_PORT=${OPTARG}
      ;;
    u)
      PROXY_UID=${OPTARG}
      ;;
    m)
      INBOUND_INTERCEPTION_MODE=${OPTARG}
      ;;
    b)
      INBOUND_PORTS_INCLUDE=${OPTARG}
      ;;
    d)
      INBOUND_PORTS_EXCLUDE=${OPTARG}
      ;;
    i)
      OUTBOUND_IP_RANGES_INCLUDE=${OPTARG}
      ;;
    x)
      OUTBOUND_IP_RANGES_EXCLUDE=${OPTARG}
      ;;
    h)
      usage
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
  esac
done

# TODO: more flexibility - maybe a whitelist of users to be captured for output instead of a blacklist.
if [ -z "${PROXY_UID}" ]; then
  # Default to the UID of ENVOY_USER and root
  PROXY_UID=$(id -u ${ENVOY_USER:-istio-proxy})
  if [ $? -ne 0 ]; then
     PROXY_UID="1337"
  fi
  # If ENVOY_UID is not explicitly defined (as it would be in k8s env), we add root to the list,
  # for ca agent.
  PROXY_UID=${PROXY_UID},0
fi

# Remove the old chains, to generate new configs.
iptables -t nat -D PREROUTING -p tcp -j ISTIO_INBOUND 2>/dev/null
iptables -t nat -D OUTPUT -p tcp -j ISTIO_OUTPUT 2>/dev/null

# Flush and delete the istio chains.
iptables -t nat -F ISTIO_OUTPUT 2>/dev/null
iptables -t nat -X ISTIO_OUTPUT 2>/dev/null
iptables -t nat -F ISTIO_REDIRECT 2>/dev/null
iptables -t nat -X ISTIO_REDIRECT 2>/dev/null
iptables -t nat -F ISTIO_INBOUND 2>/dev/null
iptables -t nat -X ISTIO_INBOUND 2>/dev/null
iptables -t mangle -F ISTIO_INBOUND 2>/dev/null
iptables -t mangle -X ISTIO_INBOUND 2>/dev/null
iptables -t mangle -F ISTIO_DIVERT 2>/dev/null
iptables -t mangle -X ISTIO_DIVERT 2>/dev/null
iptables -t mangle -F ISTIO_TPROXY 2>/dev/null
iptables -t mangle -X ISTIO_TPROXY 2>/dev/null

if [ "${1:-}" = "clean" ]; then
  echo "Only cleaning, no new rules added"
  exit 0
fi

# Dump out our environment for debugging purposes.
echo "Environment:"
echo "------------"
echo "ENVOY_PORT=${ENVOY_PORT-}"
echo "ISTIO_INBOUND_INTERCEPTION_MODE=${ISTIO_INBOUND_INTERCEPTION_MODE-}"
echo "ISTIO_INBOUND_TPROXY_MARK=${ISTIO_INBOUND_TPROXY_MARK-}"
echo "ISTIO_INBOUND_TPROXY_ROUTE_TABLE=${ISTIO_INBOUND_TPROXY_ROUTE_TABLE-}"
echo "ISTIO_INBOUND_PORTS=${ISTIO_INBOUND_PORTS-}"
echo "ISTIO_LOCAL_EXCLUDE_PORTS=${ISTIO_LOCAL_EXCLUDE_PORTS-}"
echo "ISTIO_SERVICE_CIDR=${ISTIO_SERVICE_CIDR-}"
echo "ISTIO_SERVICE_EXCLUDE_CIDR=${ISTIO_SERVICE_EXCLUDE_CIDR-}"
echo
echo "Variables:"
echo "----------"
echo "PROXY_PORT=${PROXY_PORT}"
echo "PROXY_UID=${PROXY_UID}"
echo "INBOUND_INTERCEPTION_MODE=${INBOUND_INTERCEPTION_MODE}"
echo "INBOUND_TPROXY_MARK=${INBOUND_TPROXY_MARK}"
echo "INBOUND_TPROXY_ROUTE_TABLE=${INBOUND_TPROXY_ROUTE_TABLE}"
echo "INBOUND_PORTS_INCLUDE=${INBOUND_PORTS_INCLUDE}"
echo "INBOUND_PORTS_EXCLUDE=${INBOUND_PORTS_EXCLUDE}"
echo "OUTBOUND_IP_RANGES_INCLUDE=${OUTBOUND_IP_RANGES_INCLUDE}"
echo "OUTBOUND_IP_RANGES_EXCLUDE=${OUTBOUND_IP_RANGES_EXCLUDE}"
echo

set -o errexit
set -o nounset
set -o pipefail
set -x # echo on

# Create a new chain for redirecting outbound traffic to the common Envoy port.
# Use this chain also for redirecting inbound traffic to the common Envoy port
# when not using TPROXY.
# In both chains, '-j RETURN' bypasses Envoy and '-j ISTIO_REDIRECT'
# redirects to Envoy.
iptables -t nat -N ISTIO_REDIRECT
iptables -t nat -A ISTIO_REDIRECT -p tcp -j REDIRECT --to-port ${PROXY_PORT}

# Handling of inbound ports. Traffic will be redirected to Envoy, which will process and forward
# to the local service. If not set, no inbound port will be intercepted by istio iptables.
if [ -n "${INBOUND_PORTS_INCLUDE}" ]; then
  if [ "${INBOUND_INTERCEPTION_MODE}" = "TPROXY" ] ; then
    # When using TPROXY, create a new chain for routing all inbound traffic to
    # Envoy. Any packet entering this chain gets marked with the ${INBOUND_TPROXY_MARK} mark,
    # so that they get routed to the loopback interface in order to get redirected to Envoy.
    # In the ISTIO_INBOUND chain, '-j ISTIO_DIVERT' reroutes to the loopback
    # interface.
    # Mark all inbound packets.
    iptables -t mangle -N ISTIO_DIVERT
    iptables -t mangle -A ISTIO_DIVERT -j MARK --set-mark ${INBOUND_TPROXY_MARK}
    iptables -t mangle -A ISTIO_DIVERT -j ACCEPT

    # Route all packets marked in chain ISTIO_DIVERT using routing table ${INBOUND_TPROXY_ROUTE_TABLE}.
    ip -f inet rule add fwmark ${INBOUND_TPROXY_MARK} lookup ${INBOUND_TPROXY_ROUTE_TABLE}
    # In routing table ${INBOUND_TPROXY_ROUTE_TABLE}, create a single default rule to route all traffic to
    # the loopback interface.
    ip -f inet route add local default dev lo table ${INBOUND_TPROXY_ROUTE_TABLE}

    # Create a new chain for redirecting inbound traffic to the common Envoy
    # port.
    # In the ISTIO_INBOUND chain, '-j RETURN' bypasses Envoy and
    # '-j ISTIO_TPROXY' redirects to Envoy.
    iptables -t mangle -N ISTIO_TPROXY
    iptables -t mangle -A ISTIO_TPROXY ! -d 127.0.0.1/32 -p tcp -j TPROXY --tproxy-mark ${INBOUND_TPROXY_MARK}/0xffffffff --on-port ${PROXY_PORT}

    table=mangle
  else
    table=nat
  fi
  iptables -t ${table} -N ISTIO_INBOUND
  iptables -t ${table} -A PREROUTING -p tcp -j ISTIO_INBOUND

  if [ "${INBOUND_PORTS_INCLUDE}" == "*" ]; then
    # Makes sure SSH is not redirected
    iptables -t ${table} -A ISTIO_INBOUND -p tcp --dport 22 -j RETURN
    # Apply any user-specified port exclusions.
    if [ -n "${INBOUND_PORTS_EXCLUDE}" ]; then
      for port in ${INBOUND_PORTS_EXCLUDE}; do
        iptables -t ${table} -A ISTIO_INBOUND -p tcp --dport ${port} -j RETURN
      done
    fi
    # Redirect remaining inbound traffic to Envoy.
    if [ "${INBOUND_INTERCEPTION_MODE}" = "TPROXY" ]; then
      # If an inbound packet belongs to an established socket, route it to the
      # loopback interface.
      iptables -t mangle -A ISTIO_INBOUND -p tcp -m socket -j ISTIO_DIVERT
      # Otherwise, it's a new connection. Redirect it using TPROXY.
      iptables -t mangle -A ISTIO_INBOUND -p tcp -j ISTIO_TPROXY
    else
      iptables -t nat -A ISTIO_INBOUND -p tcp -j ISTIO_REDIRECT
    fi
  else
    # User has specified a non-empty list of ports to be redirected to Envoy.
    for port in ${INBOUND_PORTS_INCLUDE}; do
      if [ "${INBOUND_INTERCEPTION_MODE}" = "TPROXY" ]; then
        iptables -t mangle -A ISTIO_INBOUND -p tcp --dport ${port} -m socket -j ISTIO_DIVERT
        iptables -t mangle -A ISTIO_INBOUND -p tcp --dport ${port} -j ISTIO_TPROXY
      else
        iptables -t nat -A ISTIO_INBOUND -p tcp --dport ${port} -j ISTIO_REDIRECT
      fi
    done
  fi
fi

# TODO: change the default behavior to not intercept any output - user may use http_proxy or another
# iptables wrapper (like ufw). Current default is similar with 0.1

# Create a new chain for selectively redirecting outbound packets to Envoy.
iptables -t nat -N ISTIO_OUTPUT

# Jump to the ISTIO_OUTPUT chain from OUTPUT chain for all tcp traffic.
iptables -t nat -A OUTPUT -p tcp -j ISTIO_OUTPUT

# Redirect app calls to back itself via Envoy when using the service VIP or endpoint
# address, e.g. appN => Envoy (client) => Envoy (server) => appN.
iptables -t nat -A ISTIO_OUTPUT -o lo ! -d 127.0.0.1/32 -j ISTIO_REDIRECT

for uid in ${PROXY_UID}; do
  # Avoid infinite loops. Don't redirect Envoy traffic directly back to
  # Envoy for non-loopback traffic.
  iptables -t nat -A ISTIO_OUTPUT -m owner --uid-owner ${uid} -j RETURN
  iptables -t nat -A ISTIO_OUTPUT -m owner --gid-owner ${uid} -j RETURN
done

# Skip redirection for Envoy-aware applications and
# container-to-container traffic both of which explicitly use
# localhost.
iptables -t nat -A ISTIO_OUTPUT -d 127.0.0.1/32 -j RETURN

if [ -n "${OUTBOUND_IP_RANGES_INCLUDE}" ]; then
  if [ "${OUTBOUND_IP_RANGES_INCLUDE}" == "*" ]; then
    # Redirect exclusions must be applied before inclusions.
    if [ -n "${OUTBOUND_IP_RANGES_EXCLUDE}" ]; then
      for cidr in ${OUTBOUND_IP_RANGES_EXCLUDE}; do
        iptables -t nat -A ISTIO_OUTPUT -d ${cidr} -j RETURN
      done
    fi
    # Redirect remaining outbound traffic to Envoy
    iptables -t nat -A ISTIO_OUTPUT -j ISTIO_REDIRECT
  else
    # User has specified a non-empty list of cidrs to be redirected to Envoy.
    for cidr in ${OUTBOUND_IP_RANGES_INCLUDE}; do
      iptables -t nat -A ISTIO_OUTPUT -d ${cidr} -j ISTIO_REDIRECT
    done
    # All other traffic is not redirected.
    iptables -t nat -A ISTIO_OUTPUT -j RETURN
  fi
fi

# If ENABLE_IPV6 is unset (default unset), restrict IPv6 traffic.
if [ -z "${ENABLE_IPV6}" ]; then
  # Drop all incoming traffic except the established connections.
  # Drop all forward traffic.
  # TODO: support receiving IPv6 traffic in the same way as IPv4.
  ip6tables -F
  ip6tables -A INPUT -m state --state ESTABLISHED -j ACCEPT
  ip6tables -A INPUT -j REJECT
  ip6tables -P FORWARD DROP
fi
