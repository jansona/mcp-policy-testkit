from __future__ import annotations

import json

from ..models import ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2)
