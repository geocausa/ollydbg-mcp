# Security policy

## Supported version

Only the latest commit on the default branch is supported.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories when
available. Avoid opening a public issue for vulnerabilities involving arbitrary
memory writes, named-pipe access control, malformed bridge messages or debugger
process control.

Include the affected commit, reproduction steps, expected impact and whether the
issue requires local access.

## Security model

This project controls a debugger and can alter the memory and execution state of
a debuggee. It is intended for a trusted, local Windows user.

The Python server guards destructive MCP tools with explicit confirmation
arguments, but the current native named pipe is not an authentication boundary.
Do not expose the MCP transport to untrusted clients or use the bridge across a
multi-user trust boundary.
