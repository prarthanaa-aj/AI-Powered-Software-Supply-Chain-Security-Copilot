# Phase 7: Adaptive answer length

The feedback controls let the analyst mark an answer as too long or too short. `app/agent/feedback.py` stores only the resulting `concise` or `detailed` preference locally. The next request adds a corresponding instruction to the system context. No model weights are updated, and no security ranking or evidence is changed by feedback.

The behavior change is inspectable in `data/processed/preferences.json` (ignored by Git) and can be reset in the UI. Feedback is a presentation preference, not a signal that a security finding is correct.

## Before/after adaptation check

The short-term memory and feedback path is covered with a fake LLM client: a second turn receives the prior question/answer, “too long” changes the next system instruction to prefer concise wording, “too short” changes it to prefer detail, and reset clears the saved preference. This verifies that adaptation instructions change; it does not claim a guaranteed response length or that model weights learn.
