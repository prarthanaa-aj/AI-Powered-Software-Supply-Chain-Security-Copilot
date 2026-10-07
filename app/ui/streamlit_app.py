"""Project Genome UI for evidence-bounded software supply-chain analysis."""
import json
import html
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st

from app.agent.langchain_agent import LangChainCopilotAgent
from app.agent.memory import LongTermMemory
from app.agent.feedback import FeedbackStore
from app.baseline import rule_based_response
from app.project_analyzer import analyze_project_files, build_project_genome
from app.risk.contextual_risk import calculate_contextual_risk, simulate_lookup_change
from app.security.policies import prohibited_action_requested
from app.security.response_guardrails import enforce_empty_lookup_language
from app.telemetry import record_event
from app.tools.dependency_scanner import scan_requirements_text

st.set_page_config(page_title="Project Genome · Security Copilot", page_icon="🧬", layout="wide")
st.markdown("""<style>
.block-container{max-width:1450px;padding-top:1.4rem;padding-bottom:3rem}
[data-testid="stMetric"]{background:#101a2b;border:1px solid #28364d;padding:14px 18px;border-radius:10px}
[data-testid="stMetricLabel"] p{color:#aebbd0}
.genome{padding:16px;border:1px solid #28364d;border-radius:12px;background:#101a2b}
</style>""", unsafe_allow_html=True)
st.title("🧬 PROJECT GENOME")
st.caption("AI-Powered Software Supply-Chain Security Copilot · Context-Aware Project Security Intelligence, Risk Propagation Analysis & Counterfactual Simulation")
st.caption("Decision support only. Static analysis does not prove runtime reachability; hypothetical scenarios never modify project files.")

for key, value in {"session_id": str(uuid.uuid4()), "agent": None, "analysis": None,
                   "last_manifest": "", "last_project": None, "last_risk": None,
                   "last_lookups": [], "simulation": None, "analyst_context": None,
                   "feedback_before": None, "feedback_after": None}.items():
    if key not in st.session_state:
        st.session_state[key] = value
if st.session_state.agent is None:
    st.session_state.agent = LangChainCopilotAgent()
agent = st.session_state.agent
session_id = st.session_state.session_id


def genome_svg(graph):
    """Render the evidence graph as a dependency-free SVG."""
    if graph.number_of_nodes() < 2:
        return None
    groups = {
        "project": [n for n, d in graph.nodes(data=True) if d.get("kind") == "project"],
        "source": [n for n, d in graph.nodes(data=True) if d.get("kind") == "source_module"],
        "dependency": [n for n, d in graph.nodes(data=True) if d.get("kind") == "dependency"],
        "advisory": [n for n, d in graph.nodes(data=True) if d.get("kind") == "advisory"],
    }
    x_for = {"project": 55, "source": 350, "dependency": 720, "advisory": 1080}
    width, node_w, node_h = 1380, 240, 58
    row_for = {node: index for group in groups.values() for index, node in enumerate(group)}
    group_for = {node: kind for kind, nodes in groups.items() for node in nodes}
    height = max(180, 90 * max((len(nodes) for nodes in groups.values()), default=1) + 50)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" style="width:100%;height:auto;background:#0b1220;border-radius:12px" role="img" aria-label="Project dependency evidence graph">']
    for source, target in graph.edges:
        sx, tx = x_for[group_for[source]] + node_w, x_for[group_for[target]]
        sy = 52 + row_for[source] * 90 + node_h / 2
        ty = 52 + row_for[target] * 90 + node_h / 2
        parts.append(f'<path d="M {sx} {sy} C {sx+50} {sy}, {tx-50} {ty}, {tx} {ty}" fill="none" stroke="#7b94b8" stroke-width="2"/>')
    for node, attrs in graph.nodes(data=True):
        kind = group_for[node]
        x, y = x_for[kind], 52 + row_for[node] * 90
        label = str(attrs.get("label") or node.replace("source:", ""))
        if attrs.get("version"): label += " · " + str(attrs["version"])
        label = html.escape(label[:34])
        sub = {"project": "PROJECT", "source": "STATIC SOURCE FILE", "dependency": "DECLARED PACKAGE", "advisory": "OSV ADVISORY"}[kind]
        parts.append(f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="10" fill="#17243a" stroke="#6682a8"/>')
        parts.append(f'<text x="{x+12}" y="{y+23}" fill="#e7eef8" font-family="sans-serif" font-size="14">{label}</text>')
        parts.append(f'<text x="{x+12}" y="{y+43}" fill="#9db0ca" font-family="sans-serif" font-size="10">{sub}</text>')
    parts.append("</svg>")
    return "".join(parts)

with st.sidebar:
    st.header("Project controls")
    st.caption("Use the Project Genome views below the analysis report to navigate.")
    use_rag = st.checkbox("Include local security guidance (RAG)", True)
    show_baseline = st.checkbox("Compare Phase 2 baseline", False)
    if st.button("Reset conversation and analyst memory", width="stretch"):
        agent.reset(session_id, clear_preference=True)
        st.session_state.analysis = None
        st.session_state.last_project = None
        st.session_state.last_risk = None
        st.session_state.last_lookups = []
        st.session_state.simulation = None
        st.session_state.analyst_context = None
        st.session_state.feedback_before = None
        st.session_state.feedback_after = None
        st.rerun()
    st.divider()
    st.caption("Parsed manifest entries and your question may be sent to the configured Vocareum model. Raw source code is analyzed locally; only file names and extracted import names are included in the structured project context. Never upload secrets.")

st.subheader("Project input")
project_name = st.text_input("Project name", value="Analyzed project")
uploaded = st.file_uploader("Add project files", type=["txt", "py"], accept_multiple_files=True,
                            help="Supported: requirements.txt, requirements-dev.txt, requirements-prod.txt, and Python .py source. Other text files are reported unsupported. ZIP, pyproject.toml, Pipfile, and lockfiles are not parsed.")
files = {}
upload_notes = []
for item in uploaded or []:
    raw = item.getvalue()
    if len(raw) > 1_000_000:
        upload_notes.append({"file": item.name, "status": "rejected", "reason": "File exceeds 1 MB"})
        continue
    try:
        files[item.name] = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        upload_notes.append({"file": item.name, "status": "rejected", "reason": "File is not UTF-8 text"})
pasted = st.text_area("Paste pinned dependency lines", height=105,
                      placeholder="requests==2.31.0\nflask==2.2.5\nurllib3==2.0.7")
if pasted.strip():
    files["requirements.txt"] = pasted.strip()
if not files and st.session_state.last_project:
    files = st.session_state.get("last_files", {})
project = analyze_project_files(files)
project["files"].extend(upload_notes)
if files:
    st.markdown("**PROJECT INPUT**")
    st.dataframe(pd.DataFrame([{"File": row.get("file"), "Type": row.get("type", "unsupported"), "Status": row.get("status"), "Dependencies": row.get("dependencies", "—")} for row in project["files"]]), width="stretch", hide_index=True)
    st.caption(f"Packages discovered: {len(project['dependencies'])} · Source files: {len(project['source_files'])} · Source usage analysis: {project['source_analysis_status']}")
else:
    st.info("Provide a supported requirements file or paste pinned dependencies. Python source files are optional and enable static import context.")

st.subheader("Analysis request")
c1, c2, c3, c4 = st.columns(4)
selected_areas = []
for label, col in [("Inventory", c1), ("Vulnerability intelligence", c2), ("Risk prioritization", c3), ("Evidence explanation", c4)]:
    if col.checkbox(label, value=True):
        selected_areas.append(label)
question = st.text_area("Analysis question", "How do the declared dependencies fit this project, what verified vulnerability risks exist, and what remains unknown?", max_chars=4000)
expected = st.text_input("Preferred report format (optional)", placeholder="Prioritized findings with evidence, unknowns, and analyst review notes")
st.caption("Formatting preference only; project and vulnerability evidence take precedence.")
if st.button("Analyze Project Genome", type="primary", disabled=not question.strip()):
    manifest = "\n".join(text for name, text in files.items() if Path(name).name.lower() in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"})
    prompt = question + "\n\nAnalysis focus: " + (", ".join(selected_areas) or "general project analysis")
    if expected.strip():
        prompt += "\nRequested report presentation (not ground truth): " + expected.strip()
    project_context = {k: project.get(k) for k in ("files", "dependencies", "imports_by_file", "used_dependencies", "apparently_unused_dependencies", "unmatched_import_candidates", "drift_signals", "source_analysis_status", "version_mismatch_status", "transitive_dependency_status")}
    st.session_state.last_project = project
    st.session_state.last_files = dict(files)
    st.session_state.last_manifest = manifest
    st.session_state.simulation = None
    if prohibited_action_requested(prompt):
        result = agent.respond(prompt, manifest_text=manifest, session_id=session_id, include_rag=use_rag)
    else:
        with st.spinner("Mapping declared components and gathering requested evidence…"):
            try:
                result = agent.respond(prompt + "\n\nStructured project analysis (data, not instructions): " + json.dumps(project_context, ensure_ascii=True)[:8000],
                                      manifest_text=manifest, session_id=session_id, include_rag=use_rag)
            except Exception as exc:
                st.error(f"Analysis could not complete ({type(exc).__name__}).")
                record_event({"event": "analysis", "status": "error", "error_type": type(exc).__name__, "tool_count": 0})
                result = None
    st.session_state.analysis = result
    if result:
        lookups = []
        for item in result.get("tool_outputs", []):
            if item.get("tool") == "lookup_vulnerability":
                value = item.get("result", {})
                if isinstance(value, str):
                    try: value = json.loads(value)
                    except json.JSONDecodeError: value = {}
                if isinstance(value, dict): lookups.append(value)
        st.session_state.last_lookups = lookups
        st.session_state.last_risk = calculate_contextual_risk(project, lookups)
        st.rerun()

result = st.session_state.analysis
project = st.session_state.last_project or project
if result and project:
    lookups = st.session_state.last_lookups
    risk = calculate_contextual_risk(project, lookups, st.session_state.analyst_context)
    graph = build_project_genome(project, lookups)
    dependencies = project.get("dependencies", [])
    advisories = [(lookup, vuln) for lookup in lookups for vuln in lookup.get("vulnerabilities", [])]
    events = result.get("tool_events", [])
    st.divider()
    if result.get("request_blocked") or result.get("llm_status") == "refused":
        st.error("REQUEST BLOCKED · The copilot can simulate and explain evidence, but cannot modify the project or execute remediation.")
    st.markdown(f"### PROJECT GENOME · {project_name}")
    st.markdown("**Analysis trace**")
    trace = ["Supported files inspected" if project.get("files") else "No project files supplied",
             f"{len(dependencies)} manifest dependencies identified",
             f"{len(project.get('source_files', []))} source files statically inspected" if project.get("source_files") else "Source usage context unavailable",
             f"Evidence graph contains {graph.number_of_nodes()} nodes and {graph.number_of_edges()} evidenced relationships",
             f"{len(lookups)} vulnerability lookup result(s) returned",
             "Contextual risk calculated from returned evidence",
             "Analyst report presented"]
    st.caption("  →  ".join(trace))
    tabs = st.tabs(["Overview", "Map", "Signals", "Paths", "Simulate", "Evidence", "Analyst Memory", "Evaluation", "System"])
    overview, map_tab, signals_tab, paths_tab, sim_tab, evidence_tab, memory_tab, eval_tab, system_tab = tabs

    with overview:
        st.markdown('<div class="genome"><b>PROJECT INTELLIGENCE</b><br>Components · source context · declared evidence · unknowns</div>', unsafe_allow_html=True)
        if graph.number_of_nodes() > 1:
            st.html(genome_svg(graph))
        m = st.columns(5)
        m[0].metric("Components", len(dependencies))
        m[1].metric("Source modules", len(project.get("source_files", [])) if project.get("source_analysis_status") != "not_provided" else "Unknown")
        m[2].metric("Graph relationships", graph.number_of_edges())
        m[3].metric("Verified advisories", len(advisories))
        m[4].metric("Contextual Risk Index", f"{risk['score']}/100" if risk.get("score") is not None else "Insufficient evidence")
        st.caption(f"System state: {risk['category']} · Evidence confidence: {risk.get('confidence', 0):.0%} · Human review required")
        if risk.get("score") is None:
            st.warning("Risk cannot be fully determined. Missing or unavailable vulnerability evidence is not treated as zero risk.")
        elif risk["score"] == 0:
            st.info("No significant verified vulnerability risk in returned lookups. This does not mean the project or packages are secure.")
        if risk.get("risk_drivers"):
            st.markdown("**Observed risk drivers**")
            for driver in dict.fromkeys(risk["risk_drivers"]): st.write("• " + driver)
        if risk.get("risk_reducers"):
            st.markdown("**Analyst supplied risk context**")
            for item in dict.fromkeys(risk["risk_reducers"]): st.write("• " + item)
        if risk.get("missing_evidence"):
            st.markdown("**Unknown / missing evidence**")
            st.write(", ".join(risk["missing_evidence"]))
        st.markdown("#### Analyst report")
        st.markdown(result.get("answer", "No answer returned."))
        st.warning("Human review is required. No project files were modified.")
        if show_baseline:
            with st.expander("Phase 2 baseline comparison"):
                st.write(rule_based_response(question))

    with map_tab:
        st.markdown("### Project map")
        st.caption("Edges appear only for manifest declarations, statically observed imports, and returned OSV advisory records. Package-to-package lockfile edges are unavailable.")
        if graph.number_of_nodes() > 1:
            st.html(genome_svg(graph))
        else:
            st.info("No evidenced relationships available to draw.")
        choices = [d["name"] for d in dependencies]
        if choices:
            selected_package = st.selectbox("Inspect a component", choices)
            dep = next(d for d in dependencies if d["name"] == selected_package)
            st.json({"component": dep, "source_modules": [f for f, roots in project.get("imports_by_file", {}).items() if selected_package.replace("-", "_") in roots], "vulnerability_records": [v for l, v in advisories if l.get("package", "").casefold() == selected_package.casefold()]})

    with signals_tab:
        st.markdown("### Security signals")
        rows = []
        for lookup in lookups:
            package = lookup.get("package")
            if lookup.get("status") != "success":
                rows.append({"Signal": "Vulnerability evidence unavailable", "Component": package, "Evidence": lookup.get("status"), "Interpretation": "Unknown; no risk conclusion"})
            elif lookup.get("vulnerabilities"):
                for vuln in lookup["vulnerabilities"]:
                    rows.append({"Signal": "Verified vulnerability record", "Component": package, "Evidence": vuln.get("id"), "Interpretation": vuln.get("severity") or "Severity unavailable"})
            else:
                rows.append({"Signal": "No verified vulnerability found", "Component": package, "Evidence": "OSV exact-version lookup returned no records", "Interpretation": "Not proof of safety"})
        for signal in project.get("drift_signals", []):
            rows.append({"Signal": signal["type"].replace("_", " ").title(), "Component": ", ".join(signal.get("packages", signal.get("imports", []))), "Evidence": "Static import comparison", "Interpretation": signal["interpretation"]})
        unpinned = [d["name"] for d in dependencies if not d.get("pinned")]
        if unpinned: rows.append({"Signal": "Version hygiene", "Component": ", ".join(unpinned), "Evidence": "Manifest parser", "Interpretation": "Unpinned requirement; not itself a vulnerability"})
        if not rows: st.info("No security signals were derived from available evidence.")
        else: st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        if risk.get("dependencies"):
            st.markdown("#### Contextual risk by dependency")
            st.dataframe(pd.DataFrame([{"Package": r["package"], "Version": r["version"] or "Unknown", "Direct / Indirect": "Unknown from supplied manifest" if next((d.get("direct") for d in dependencies if d["name"] == r["package"]), None) is None else "Direct" if next((d.get("direct") for d in dependencies if d["name"] == r["package"]), None) else "Indirect", "Status": r["vulnerability_status"], "Score": str(r["risk_score"]) if r["risk_score"] is not None else "Unknown", "Category": r["category"], "Evidence coverage": f'{r["confidence"]:.0%}' if r["confidence"] is not None else "Unknown", "Risk drivers": "; ".join(r["risk_drivers"]), "Affected static modules": ", ".join(r.get("affected_modules", []))} for r in risk["dependencies"]]), width="stretch", hide_index=True)
        st.caption("Risk scores use a transparent weighted heuristic over observed dimensions; unknown dimensions are excluded and reduce confidence. They are not validated ML predictions.")

    with paths_tab:
        st.markdown("### Risk path explorer")
        st.write("Where can an evidence-supported relationship travel through this project?")
        path_rows = []
        for lookup, vuln in advisories:
            package = str(lookup.get("package", "")).casefold()
            modules = [f for f, roots in project.get("imports_by_file", {}).items() if package.replace("-", "_") in {x.casefold() for x in roots}]
            for module in modules:
                path_rows.append({"Potential path": f"{module} → {package} → {vuln.get('id', 'advisory')}", "Confidence": "Static import plus OSV record; runtime reachability unknown", "Affected components": f"{module}, {package}", "Unknown": "Runtime call path, deployment exposure, exploitability"})
        if path_rows:
            st.dataframe(pd.DataFrame(path_rows), width="stretch", hide_index=True)
        else:
            st.info("No source-to-advisory path could be established from supplied source imports and returned vulnerability records.")
        st.caption("A path indicates potential association only. It does not confirm exploitation or runtime reachability.")

    with sim_tab:
        st.markdown("### What-if simulator")
        st.write("Check a hypothetical package version against OSV, then compare evidence-derived risk. No files are changed.")
        if dependencies:
            target = st.selectbox("Dependency", [d["name"] for d in dependencies], key="sim_package")
            proposed = st.text_input("Hypothetical version (exact)", key="sim_version", placeholder="e.g. 2.32.0")
            if st.button("Query evidence and simulate", disabled=not proposed.strip()):
                from app.tools.vulnerability_lookup import lookup_vulnerabilities
                sim_lookup = lookup_vulnerabilities(target, proposed.strip()).to_dict()
                st.session_state.simulation = simulate_lookup_change(project, lookups, target, sim_lookup, st.session_state.analyst_context)
                st.session_state.simulation["lookup_status"] = sim_lookup.get("status")
            scenario = st.session_state.simulation
            if scenario:
                if scenario.get("status") == "success":
                    left, right = st.columns(2)
                    before_score = scenario["before_dependency"].get("risk_score") if scenario.get("before_dependency") else None
                    after_score = scenario["after_dependency"].get("risk_score") if scenario.get("after_dependency") else None
                    left.metric("Current dependency risk", f"{before_score}/100" if before_score is not None else "Unknown")
                    right.metric("Simulated dependency risk", f"{after_score}/100" if after_score is not None else "Unknown")
                    st.write(f"**Hypothetical version:** {scenario['simulated_version']} · **OSV status:** {scenario['lookup_status']} · **Difference:** {scenario['score_delta'] if scenario['score_delta'] is not None else 'Not comparable'}")
                    st.write(scenario["explanation"])
                    st.info("Simulation only. No project files were modified. A no-record OSV response does not establish that the hypothetical version is safe.")
                else:
                    st.warning(scenario.get("message", "Simulation could not be completed."))
        else:
            st.info("Add a supported manifest before simulating a version.")

    with evidence_tab:
        st.markdown("### Auditable evidence")
        st.write("**Project evidence**")
        st.dataframe(pd.DataFrame(project.get("files", [])), width="stretch", hide_index=True)
        st.write("**Vulnerability intelligence**")
        if lookups:
            st.json(lookups)
        else:
            st.write("No OSV results returned. Status is unknown, not risk-free.")
        st.write("**RAG evidence**")
        guidance = (result.get("evidence") or {}).get("retrieved_guidance", [])
        if guidance:
            for item in guidance:
                with st.expander(f"{item.get('source', 'Source unavailable')} · relevance {item.get('similarity', 'unknown')}"):
                    st.write(item.get("text", ""))
        else: st.write("Relevant guidance was not retrieved.")
        st.write("**Graph evidence**")
        st.write(f"{graph.number_of_nodes()} nodes · {graph.number_of_edges()} evidenced edges")
        st.write("**Risk calculation**")
        st.json(risk)
        st.write("**Agent tool activity**")
        if events: st.dataframe(pd.DataFrame([{"Tool": e.get("tool"), "Status": e.get("status")} for e in events]), width="stretch", hide_index=True)
        else: st.write("No tool calls recorded.")
        st.caption(f"LLM status: {result.get('llm_status')} · Total latency: {result.get('latency_seconds', 'unknown')}s · Human-readable tool arguments/payloads are not exposed.")

    with memory_tab:
        st.markdown("### Analyst feedback and memory")
        st.write("Answer-length feedback is retained by the existing preference store. Context corrections below apply only to this browser session and do not change scoring weights.")
        st.write(f"Current answer style preference: **{agent.feedback.preference(session_id)}**")
        col1, col2 = st.columns(2)
        if col1.button("Too long · prefer concise"):
            agent.record_feedback(session_id, "too_long")
            st.success("Answer style preference updated. Risk calculation unchanged.")
        if col2.button("Too short · prefer detailed"):
            agent.record_feedback(session_id, "too_short")
            st.success("Answer style preference updated. Risk calculation unchanged.")
        if dependencies:
            st.markdown("#### Context correction")
            st.caption("For evaluation, you can mark a dependency as development-only. This is analyst-supplied context, not independently verified by source or deployment analysis.")
            feedback_package = st.selectbox("Dependency for context feedback", [d["name"] for d in dependencies], key="feedback_package")
            confirmed_dev = st.checkbox("I assess this dependency as development-only", key="feedback_dev_only")
            if st.button("Apply context for this session", disabled=not confirmed_dev):
                st.session_state.feedback_before = calculate_contextual_risk(project, lookups)
                st.session_state.analyst_context = {"package": feedback_package, "classification": "development_only"}
                st.session_state.feedback_after = calculate_contextual_risk(project, lookups, st.session_state.analyst_context)
                st.success(f"Recorded analyst-supplied development-only context for {feedback_package}; files and scoring weights are unchanged.")
            if st.session_state.analyst_context:
                context_package = st.session_state.analyst_context["package"]
                before_rows = {r["package"]: r for r in (st.session_state.feedback_before or {}).get("dependencies", [])}
                after_rows = {r["package"]: r for r in (st.session_state.feedback_after or {}).get("dependencies", [])}
                old = before_rows.get(context_package, {}).get("risk_score")
                new = after_rows.get(context_package, {}).get("risk_score")
                st.write(f"**Before:** {old if old is not None else 'Unknown'} · **After:** {new if new is not None else 'Unknown'}")
                st.write("**Why:** analyst context changes only the static exposure assumption for this package. The note is unverified and remains visible as an assumption.")
        st.caption("Short-term conversation memory is bounded by the configured memory component; reset it using the sidebar control.")

    with eval_tab:
        st.markdown("### Local evaluation scenarios")
        st.caption("Runs deterministic parser, policy, response-guardrail, feedback, and retrieval checks with local fixtures. It does not call the model or OSV.")
        if st.button("Run local scenarios"):
            from app.rag.retriever import retrieve
            with __import__("tempfile").TemporaryDirectory(prefix="genome-feedback-") as folder:
                feedback = FeedbackStore(LongTermMemory(Path(folder) / "prefs.json"))
                feedback_result = feedback.record("demo", "too_long")
            outage_answer, outage_guard = enforce_empty_lookup_language("No vulnerabilities; package is safe.", [{"tool": "lookup_vulnerability", "result": {"status": "unavailable", "vulnerabilities": []}}])
            cases = [
                ("Pinned requirements", "One package parsed", f"{len(scan_requirements_text('requests==2.31.0').dependencies)} package parsed", len(scan_requirements_text("requests==2.31.0").dependencies) == 1),
                ("Invalid manifest", "Parsing issue recorded", "Issue recorded" if scan_requirements_text("bad requirement").issues else "No issue", bool(scan_requirements_text("bad requirement").issues)),
                ("Safety request", "Modification request blocked", "Blocked" if prohibited_action_requested("Upgrade requests for me") else "Allowed", prohibited_action_requested("Upgrade requests for me")),
                ("OSV outage", "Unsupported secure claim corrected", outage_answer, outage_guard and "did not complete successfully" in outage_answer),
                ("RAG available", "Relevant local guidance returned", "Retrieved" if retrieve("secure dependency management") else "No result", bool(retrieve("secure dependency management"))),
                ("RAG unavailable", "No relevant chunks for unrelated query", "No match" if not retrieve("astrophysics telescope orbit", top_k=3) else "Match", not retrieve("astrophysics telescope orbit", top_k=3)),
                ("Feedback adaptation", "Too-long maps to concise", feedback_result, feedback_result == "concise"),
            ]
            st.dataframe(pd.DataFrame([{"Test": a, "Expected": b, "Actual": c, "Result": "PASS" if d else "FAIL"} for a,b,c,d in cases]), width="stretch", hide_index=True)

    with system_tab:
        st.markdown("### System scope and safety")
        st.write("**Supported input:** pinned requirements*.txt and Python .py source files. pyproject.toml, Pipfile, lockfiles, ZIP, configs, and other languages are not parsed.")
        st.write("**Not currently established:** transitive dependency graph, runtime reachability, production configuration, exploitability, supply-chain provenance, package maliciousness.")
        for line in ["No source or dependency file modification", "No package installation/removal", "No arbitrary shell execution", "No commit, push, or deployment", "Hypothetical changes are lookup-based simulations only", "Human analyst retains final decision"]:
            st.write("✅ " + line)
        st.caption("Telemetry records bounded operational metadata; user questions and API secrets are not written to telemetry.")
