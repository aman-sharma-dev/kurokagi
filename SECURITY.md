# Security policy

## Reporting a vulnerability in Kurokagi

Please do not publicly file an exploitable security issue before maintainers have had a chance to investigate and prepare a fix.

Use the repository's **Security** tab to report a vulnerability privately through a GitHub Security Advisory if private vulnerability reporting is enabled. If that option is unavailable, contact the repository maintainers through a private channel listed on the repository owner's profile and ask for a secure reporting route. Do not send secrets or exploit details through a public issue.

Examples of in-scope issues include:

- origin or path scope bypass, including SSRF;
- credential, cookie, token, or other secret leakage;
- arbitrary mutation or bypass of proof-bound mutation capabilities;
- unsafe cleanup, restoration, or destructive-write behavior;
- unsafe parsing that can cause a security boundary bypass, panic, or resource exhaustion;
- sensitive data exposure in findings, evidence, logs, or output.

When reporting, include the affected version or commit, impact, reproduction steps, and any relevant sanitized input. Do not include live credentials, customer data, or secrets. A minimal local reproduction is preferred.

The maintainers should enable GitHub private vulnerability reporting in repository settings before inviting public contributions. GitHub documents the private reporting feature [here](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-about-vulnerabilities/about-coordinated-disclosure-of-security-vulnerabilities).

## Vulnerabilities found in an application

If Kurokagi identifies a vulnerability in an application you tested, that is not a vulnerability in Kurokagi. Follow the application owner's security disclosure process and any applicable authorization or bug bounty program rules. Do not publish affected-party data or exploit details without permission.

Kurokagi is an authorization testing tool, not a guarantee of application security. Use it only on systems you own or have explicit permission to test. Enabled mutation checks can alter state; use local or staging systems and review the safety model before enabling them.
