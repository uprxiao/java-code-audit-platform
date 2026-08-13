# Trivy Repository policy

The Quick adapter enables Trivy's version-pinned built-in `misconfig`,
`secret`, and `license` scanners in `--offline-scan` mode, so Quick scans never
depend on a remote Maven repository. Misconfigurations and redacted secret hits
become Findings. License inventory remains coverage/raw evidence unless a
future explicit policy turns it into a violation; inventory counts are not
audit issue counts.

The checks bundle is dynamic runtime data and stays under the configured
Trivy cache. It is not committed with this policy directory.
