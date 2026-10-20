# Security policy

This library runs in SCADA systems, where a bug can mean a command reaching
equipment that should not get it. Please report security problems
privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and click **Report a vulnerability**. Only the maintainers
can see the report. Please don't open a public issue or pull request for a
security problem.

A useful report says which crate and version it affects and how to reproduce
it, for example the bytes that trigger it, and what an attacker could do with
it.

We will acknowledge a report within a week. We will agree with you when to
publish it, normally once a fixed release is out, and credit you in the
advisory unless you would rather not be named.

## Supported versions

Only the latest release gets security fixes. While the version is below 1.0,
a fix ships in a new release, not as a backport to an older one.

| Version | Supported |
| --- | --- |
| 0.32.x | yes |
| older | no |

## Scope

In scope: the three crates in this repository. That includes parsing
anything a peer sends (a panic, unbounded memory or CPU use, or a hang),
anything that lets a peer or a malformed frame cause a command that should
have been refused, and weaknesses in how `iec104-tls` checks certificates.

Out of scope: plain IEC 104 has no authentication or encryption of its own,
by design of the standard. Use `iec104-tls`, or put the link on a network
you trust. Problems in dependencies such as rustls or Tokio belong with
those projects, unless this repository uses them wrongly.
