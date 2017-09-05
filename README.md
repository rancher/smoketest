# Rancher Smoke Test

This is a script to perform basic tests for a Rancher Server or a Rancher
Node.

- Docker version compatibility (server/agent)
- Accessibility of critical websites (server/agent)
- Accessibility of ports for overlay network (agent)

The script provides options for tests of the Rancher Server and the Rancher Agent. Server tests are intended to be run from a Rancher Server node, and agent tests are intended to be run from a Rancher Agent node.  

## Usage

```
$ ./smoketest.sh --help

 Help using ./smoketest.sh

  -o --orchestrator  [arg] Orchestration engine [cattle|k8s|kubernetes] Required.
  -s --server      Run tests for Rancher Server
  -a --agent       Run tests for Rancher Agent
  -v               Enable verbose mode, print script as it is executed
  -d --debug       Enables debug mode
  -h --help        This page
  -n --no-color    Disable color output
```

You can run tests for Rancher Server with `--server` and/or tests for Rancher Agent with `--agent`. 

This script uses a logging level structure similar to syslog, where 1 is _emergency_ and 7 is _debug_. It defaults to logging output at a log level of `notice` (5) and higher. You can change this by setting `LOG_LEVEL` before running the script:
```
$ LOG_LEVEL=7 ./smoketest.sh --help
```

## Configuration

Core components are baked into the script. User-configurable components are set in `smoketest.cfg` as Bash variables. This file is optional, and if provided, will use the following variables:

- `RANCHER_SERVER` - the full URL of the Rancher Server or the load balancer in front of it
- `RANCHER_AGENT_NODES` - one or more agent nodes to test for UDP access
- `EXTRA_SERVER_URLS` - extra URLs to test as part of the Server suite
- `EXTRA_AGENT_URLS` - extra URLs to test as part of the Agent suite

## Understanding Test Output

### HTTP Checks

We're checking for reachability, so we accept anything from 200-499 as a response. Some sites return 401 or 405, which is still a valid response for this test.

### Port Checks

Port checks are run between Rancher Agent nodes and require that you set `RANCHER_AGENT_NODES` in `smoketest.cfg`:
```
RANCHER_AGENT_NODES=(
  18.22.12.199
  18.22.79.141
)
```

The ipsec overlay network uses `500/udp` and `4500/udp`. The vxlan overlay network uses `4789/udp`. When scanning with `nmap`, we might not be able to tell if a port is actually open. Some things which are _open_ show up as _filtered_ because the process on the other side never sent a response. It's also possible that the packets were filtered by a firewall. We can, however, tell if it's _closed_. 

The output from the port scan looks like this:

```
2017-09-05 18:48:11 UTC [   notice] ################################
2017-09-05 18:48:11 UTC [   notice] ## Port Checks (Overlay Network)
2017-09-05 18:48:11 UTC [   notice] ################################
2017-09-05 18:48:11 UTC [   notice] Checking 18.22.12.199
2017-09-05 18:48:12 UTC [  warning]   + 500/udp: CLOSED
2017-09-05 18:48:14 UTC [  warning]   + 4500/udp: FILTERED
2017-09-05 18:48:16 UTC [  warning]   + 4789/udp: FILTERED
2017-09-05 18:48:16 UTC [   notice] Checking 18.22.79.141
2017-09-05 18:48:17 UTC [   notice]   + 500/udp: OPEN
2017-09-05 18:48:19 UTC [  warning]   + 4500/udp: FILTERED
2017-09-05 18:48:19 UTC [  warning]   + 4789/udp: CLOSED
```

In this case the first node is probably correctly configured for vxlan, because `500/udp` is closed. `4789/udp` is filtered.

The second node is probably correctly configured for ipsec because `4789/udp` is _closed_, and `500/udp` is _open_.

