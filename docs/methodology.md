# Methodology

## Scope and provider

The prototype is decision support for pinned Python requirements files. It uses the configured Vocareum-compatible chat-completions endpoint (`VOC_API_KEY`, `VOC_BASE_URL`, `VOC_MODEL`) and OSV.dev for advisory lookups. The provider and credentials are unchanged by this hardening work. The app does not edit projects, execute shell commands, install dependencies, push code, or deploy.

## Evidence flow

The parser accepts pinned requirements and reports unsupported lines. OSV queries use exact package/version pairs. The LangChain agent can select only the registered analysis tools, and tool outputs are returned for another model turn. Risk scores are transparent heuristics. The risk tool accepts a package name, then binds the computation to that exact package/version in the manifest and a successful OSV lookup from the current run. It no longer accepts model-generated feature values or promotes a saved experimental model. CVSS is used only when OSV provides a numeric score or a valid CVSS v3.1 vector; the vector parser follows the [FIRST CVSS v3.1 base-score equations](https://www.first.org/cvss/v3.1/specification-document) and excludes unsupported/malformed vectors. Exploit evidence and transitive dependency depth remain unknown.

## Modeling and labeling

`data/risk_labels_template.csv` defines the analyst-label schema, including a `group_id` for related cases. A meaningful label must be assigned independently of the current heuristic and documented with the analyst's decision rubric, source, timestamp, and review process. Do not fill the file with generated labels. `python -m evaluation.validate_risk_model path\to\risk_labels.csv` performs a deterministic group-disjoint holdout comparison against the heuristic and emits accuracy, precision, recall, F1, ROC-AUC, and confusion matrices. It returns `insufficient_data` until both classes have enough examples and `insufficient_group_diversity` if a group-disjoint holdout cannot represent both classes. A holdout from one dataset is not external validation.

## Retrieval and behavior evaluation

The corpus remains a small set of project-authored analyst guidance documents. Retrieval uses local sparse vectors with a manually curated security concept map, cosine ranking, chunking, and a TF-IDF fallback. It does not use pretrained neural embeddings; paraphrase generalization is limited to the concept map. The UI's RAG switch controls both prompt retrieval and whether the retrieval tool is available. `python -m evaluation.rag_evaluation` checks nine answerable queries and three unanswerable queries with a small manual term-overlap rubric. This tests retrieval and abstention only, not generated-answer factuality. The 100-case deterministic suite remains component regression coverage; its score is not a security accuracy metric.
