# Dependency finding triage workflow

This project-authored workflow is analyst process guidance. It is not a vulnerability database and does not replace source records.

Start by recording the package ecosystem, normalized package name, exact installed version, manifest location, and whether the dependency is direct or transitive. For a transitive dependency, preserve the full dependency path from the project to the package. Resolve aliases and duplicate package names before comparing advisories.

For each candidate advisory, open the original source record and confirm its identifier, affected version range, publication or modification date, and package identity. Compare the installed version against the affected range using version-aware comparison. Do not infer that a package is affected from a name match alone.

Record the lookup source and time. A successful query with no records means that source returned no matching records at that time; it does not prove the package is safe. A timeout, invalid package identity, or unavailable source is an incomplete lookup and must remain distinct from an empty successful result.

Before prioritizing, separate verified facts from assumptions. Record missing evidence explicitly, including exploit status, reachability, dependency path, and deployment context. Escalate conflicting advisory records for analyst review rather than silently choosing one.
