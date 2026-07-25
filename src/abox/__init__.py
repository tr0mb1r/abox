"""abox — sandboxed, network-restricted Claude Code environments.

The host-side CLI provisions a disposable container per project whose only MCP
endpoint is a Docker MCP Gateway instance. The agent inside is treated as
untrusted: no docker socket, no published ports, no root, default-deny egress.

abox drives the Docker CLI directly and installs Claude Code from its
checksum-verified native binary, so nothing it needs touches npm on the host.
"""

__version__ = "0.1.4"

__all__ = ["__version__"]
