# Security policy

moonpgp implements OpenPGP (RFC 4880/9580) in pure MoonBit: message
encryption, signatures, key management, and PGP/MIME email. A bug here can
break the confidentiality or the authentication of real mail, so security
reports are welcome and taken seriously.

## Supported versions

Only the newest release line gets security fixes.

| Version | Status |
| ------- | ------ |
| 0.3.x | Supported; security fixes land here |
| 0.2.x and earlier | End of life. 0.1.0 in particular ships a known subkey-injection flaw — upgrade to at least 0.2.0 |

## Reporting a vulnerability

Use GitHub private vulnerability reporting: the **Report a vulnerability**
button under Security → Advisories in this repository. Reports made there
stay private until a fix is ready. Please do not open a public issue with
exploit details.

If the form does not work for you, open an issue saying only that you have
a security report and how to reach you — no details.

A reproduction helps more than prose: a probe script, or an armored key
and message pair that shows the problem, is ideal. Please do not attack
systems you do not own while investigating.

## What to expect

An initial reply within a few days, an assessment of the report, and a
coordinated fix. You get credit in the changelog and in the advisory if
one is published, unless you would rather stay anonymous.
