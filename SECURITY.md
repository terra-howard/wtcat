# Security policy

wtcat validates access tokens, so a flaw in it can let a request through that should have been refused. Reports
are welcome and taken seriously.

## Reporting a vulnerability

Please report privately, through GitHub's private vulnerability reporting:

https://github.com/terra-howard/wtcat/security/advisories/new

Please do not open a public issue, pull request or discussion for a suspected vulnerability until it has been
fixed and disclosed.

A useful report includes:

- the version or commit you tested;
- the smallest token, key and request that show the problem, ideally as a Go test;
- what wtcat did, and what you expected it to do, with the section of CTA-5007-B or the RFC you are relying on.

Use keys and tokens made for the report. Never send real credentials or tokens from a live system.

## What counts

Anything that makes wtcat accept what it should refuse, or fail in a way an attacker can trigger, for example:

- a token accepted with a bad signature or MAC, under the wrong key or algorithm, or outside its validity window;
- a restriction claim (such as `catu`, `catm`, `cath`, `catnip`, `cnf` or `catdpop`) that can be bypassed;
- a panic, hang or excessive memory use caused by token, header or URI input;
- timing differences that leak key or MAC material;
- a token left in a request that wtcat says it removed before forwarding.

Not in scope here:

- **Errata in CTA-5007-B itself.** Those belong with the Consumer Technology Association. If wtcat follows an
  erratum faithfully, though, a report here is still welcome.
- **Bugs in dependencies**, such as `github.com/fxamacker/cbor`. Please report them upstream. Tell us as well if
  wtcat is affected.
- Misconfiguration in the application that uses wtcat, such as weak keys or a missing `Location` source for
  geographic claims.

## Supported versions

wtcat is before 1.0. Fixes go to the latest release and to `main`. Older releases are not patched.

## What to expect

wtcat has a single maintainer, so responses are best effort and can be slower during absences. The aim is to
acknowledge a report within a week, agree on a fix and a disclosure date with you, and credit you in the advisory
unless you would rather not be named.
