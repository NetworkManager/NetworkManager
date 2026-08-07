# Reporting security vulnerabilities

If you believe you have found a security vulnerability in NetworkManager,
please do not report it in a public issue or merge request.

Instead, open a confidential issue in our GitLab issue tracker using the
"Security_Vulnerability" template:

  https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/issues/new?issuable_template=Security_Vulnerability

The template marks the issue confidential so that it is only visible to the
reporter and the NetworkManager project team members. If you cannot use the
issue tracker, you can instead contact the maintainers privately via Matrix
(supports end-to-end encryption):

- `@till:fedora.im`
- `@bgalvani:matrix.org`
- `@josie:fedora.im`

Please include:

- the affected NetworkManager version (`nmcli --version`) and distribution,
- a description of the vulnerability and its impact,
- steps to reproduce, and
- any relevant logs or a proof of concept, if available.

If an AI tool helped you find or describe the issue, please say so in the
report, and verify the findings yourself before submitting: confirm the
affected code actually exists and that the issue is reproducible. Unverified
AI-generated reports shift that work onto the maintainers and slow down triage
of real vulnerabilities (see https://stopsloppypasta.ai/).

We will triage the report and follow up in the confidential issue. Please
give the maintainers a reasonable amount of time to fix the problem before
disclosing it publicly.

NetworkManager does not offer a bug bounty.

For non-security bugs, use the regular issue tracker as described in
[CONTRIBUTING.md](CONTRIBUTING.md).
