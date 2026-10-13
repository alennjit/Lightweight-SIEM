"""Guards the public demo's honesty claim: its sample alerts must match what
the detection engine actually outputs today. If this fails after an engine
change, re-run `python -m scripts.generate_demo_data` and commit the result.
"""

import json

from scripts.generate_demo_data import OUTPUT_PATH, _score_samples


def test_committed_demo_alerts_match_current_engine_output() -> None:
    committed = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))["alerts"]
    assert committed == _score_samples()
