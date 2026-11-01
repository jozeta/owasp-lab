# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub instead: go to the **Security** tab of this repository and click
**Report a vulnerability** ([direct link](https://github.com/jozeta/owasp-lab/security/advisories/new)).
Include what you found, how to reproduce it, and the impact you expect.

This is a personal project maintained in spare time. You can expect an acknowledgement within a
week. Fixes are released as soon as practical, and you'll be credited in the advisory unless you
prefer otherwise.

## Scope

**This application is intentionally vulnerable.** The OWASP Top 10 exercises (SQL injection, SSRF, XXE, broken access control and so on) are the product, so please don't report them. Do report anything that lets the lab escape its sandbox: the app reachable from other hosts despite the `127.0.0.1` binding, a container breakout, an exercise that attacks systems outside the lab, or real secrets in the repository.

## Supported versions

Only the latest version on the `main` branch receives security fixes.
