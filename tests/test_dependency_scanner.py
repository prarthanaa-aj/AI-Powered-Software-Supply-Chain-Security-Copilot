from app.tools.dependency_scanner import scan_requirements_text


def test_scans_pinned_requirements_and_normalizes_name():
    result = scan_requirements_text("Flask==2.3.1\nfoo_bar==1.0 # comment\n")
    assert [d.name for d in result.dependencies] == ["flask", "foo-bar"]
    assert len(result.issues) == 0


def test_ignores_utf8_bom_on_first_manifest_line():
    result = scan_requirements_text("\ufeffrequests==2.31.0\nflask==2.2.5\n")
    assert [dependency.name for dependency in result.dependencies] == ["requests", "flask"]
    assert not result.issues


def test_file_loader_keeps_first_requirement_when_file_has_utf8_bom(tmp_path):
    from app.tools.dependency_scanner import scan_requirements_file
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("\ufeffrequests==2.31.0\nflask==2.2.5\n", encoding="utf-8")
    result = scan_requirements_file(str(manifest))
    assert [dependency.name for dependency in result.dependencies] == ["requests", "flask"]
    assert not result.issues


def test_unpinned_and_options_are_not_silently_accepted():
    result = scan_requirements_text("requests>=2\n-r base.txt\n")
    assert not result.dependencies
    assert len(result.issues) == 2


def test_deduplicates_and_applies_input_limit():
    result = scan_requirements_text("x==1\nx==1\n")
    assert len(result.dependencies) == 1
    huge = scan_requirements_text("x" * 1_000_001)
    assert huge.issues[0].line == 0
