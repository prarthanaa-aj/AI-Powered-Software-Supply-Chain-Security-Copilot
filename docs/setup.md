# Local setup

## Requirements

- Windows PowerShell or a compatible Python environment.
- Python compatible with requirements.txt. The locally verified environment used Python 3.14.8.
- Vocareum-compatible credentials for live model analysis. Offline tests and local UI startup do not require a live model call.

## Install

From the repository root:

    py -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt

For another Python environment, install from requirements.txt and validate the resolved dependencies.

## Configure Vocareum

Copy .env.example to src/.env and set VOC_API_KEY. Keep the configured Vocareum URL and model unless intentionally changing provider settings. Never include the populated src/.env in a submission archive or repository.

## Run

    .\.venv\Scripts\python.exe -m streamlit run app/ui/streamlit_app.py

The app accepts pinned requirements*.txt and Python .py files. Python source is parsed locally for imports and is never executed. OSV lookups require network access; model answers require a configured Vocareum key and endpoint access.

## Verify

    .\.venv\Scripts\python.exe -B -m pytest -q --basetemp=.pytest-tmp
    .\.venv\Scripts\python.exe -B -m evaluation.evaluation_runner
    .\.venv\Scripts\python.exe -B -m evaluation.rag_evaluation

See README.md and docs/project_genome.md for supported formats, scoring, safety, and known limits.
