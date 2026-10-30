# Security policy

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub: open the **Security** tab of the repository and choose
**Report a vulnerability** (private vulnerability reporting).

If you cannot use GitHub, write to **contact@joselma.online** instead. Do not put exploit details in a
public place, and do not include real secrets in your report.

Include, if you can:

- the version or commit you tested,
- the steps to reproduce,
- what you expected and what happened,
- the impact you see (for example: a value leaked, an approval bypassed).

You will get an acknowledgement as soon as possible. Once the issue is confirmed, a fix is prepared
in a private branch, released, and then disclosed with credit to the reporter, if they wish.

## Scope

In scope: the cryptography, the storage format, the broker and its approval logic, the local IPC,
the masking of output, and the desktop interface.

Out of scope: a program already running as the same Windows user (see
[THREAT_MODEL.md](THREAT_MODEL.md)), weak master passwords, and vulnerabilities in dependencies
that are not triggered by Vault.
