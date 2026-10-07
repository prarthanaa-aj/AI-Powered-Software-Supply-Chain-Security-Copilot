# Analyst review checklist for software dependency risk

This project-authored checklist is process guidance, not a vulnerability database.

For each dependency finding, verify the package ecosystem, exact installed version, affected version range, advisory identifier, source publication or modification date, and the source record itself. Treat a missing lookup result as unknown coverage rather than proof that a package is safe.

Review direct dependencies and the complete path for transitive dependencies. Consider exploit evidence, reachable use, deployment environment, and available patched versions. Separate observed facts from assumptions and record conflicting advisory data.

Do not apply an upgrade solely because an automated score is high. Check compatibility, release notes, test coverage, and organizational change controls. A human analyst owns the remediation decision.

Never send API credentials, source code, or unrelated project files to the language model. Use the minimum package and advisory context needed to explain a finding.
