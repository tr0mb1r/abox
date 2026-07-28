"""abox — sandboxed, network-restricted Claude Code environments.

The host-side CLI provisions a disposable container per project whose only MCP
endpoint is a Docker MCP Gateway instance. The agent inside is treated as
untrusted: no docker socket, no published ports, no root, default-deny egress.

abox drives the Docker CLI directly and installs Claude Code from its
checksum-verified native binary, so nothing it needs touches npm on the host.
"""

#: Keep in sync with ``version`` in pyproject.toml — the release chore bumps
#: both. A ``.devN`` suffix means "after that release, before the next one", so
#: a build from this branch is distinguishable from the tag it was cut from.
__version__ = "0.1.5.dev0"

__all__ = ["__version__"]
