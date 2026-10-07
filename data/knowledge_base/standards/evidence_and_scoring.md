# Evidence and score interpretation

This project-authored guidance describes how to interpret the prototype's evidence. It is not an authoritative scoring standard.

An OSV result is evidence returned by OSV for the queried package ecosystem and exact version at the retrieval time. Preserve the advisory identifier and source record. A missing OSV result is unknown source coverage, not evidence of safety. Lookup errors and local input rejection are not successful negative results.

When an advisory supplies a numeric CVSS score, retain its source and advisory association. The prototype can calculate a base score only from supported CVSS v3.1 vectors. A base score describes technical severity under the vector assumptions; it does not establish exploit activity, whether vulnerable code is reachable, or the risk in a particular deployment. Unsupported or malformed vectors should not be converted into a guessed score.

The prototype's risk category is a transparent heuristic over available evidence. It is not a calibrated probability, a validated prediction, or a remediation decision. If evidence is insufficient, report that no category was assigned. Do not fill gaps with model-generated features or treat a missing value as a reassuring zero.

Keep source facts, computed values, and analyst assumptions visibly separate. If sources disagree, preserve both records and ask an analyst to resolve the discrepancy before recommending action.
