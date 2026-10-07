import pytest
from app.tools.cvss import cvss_v31_base_score


@pytest.mark.parametrize(("vector", "expected"), [
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
])
def test_cvss_v31_calculates_first_published_example_vectors(vector, expected):
    assert cvss_v31_base_score(vector) == expected


@pytest.mark.parametrize("vector", [
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:P",
    "CVSS:3.1/AV:N/AC:INVALID/PR:N/UI:N/S:U/C:H/I:H/A:H",
])
def test_cvss_parser_rejects_unsupported_or_malformed_vectors(vector):
    assert cvss_v31_base_score(vector) is None
