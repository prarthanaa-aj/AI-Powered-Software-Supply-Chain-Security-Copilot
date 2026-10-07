# Remediation review checklist

This project-authored checklist is process guidance; the repository does not prescribe a package upgrade.

Before proposing a version change, identify a candidate fixed version from the advisory or package maintainer's release information. Confirm that the candidate is outside the affected range and is available for the project's ecosystem and supported Python versions. Record the source and date used to select it.

Review release notes and compatibility requirements. Check direct and transitive constraints, the dependency path, and whether another package prevents the proposed version. Prefer a narrowly scoped change that addresses the finding while preserving required behavior.

Plan validation before changing the project: run relevant automated tests, check installation or lockfile resolution, and review runtime behavior for affected features. Consider deployment reachability and compensating controls, but do not use them to erase a confirmed affected-version fact.

Present the advisory evidence, proposed change, compatibility findings, test plan, and remaining uncertainty to the responsible human reviewer. The analyst or project owner makes the remediation decision. The copilot does not edit files, install packages, or apply upgrades.
