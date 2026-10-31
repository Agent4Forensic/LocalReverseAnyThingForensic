"""Static guards for the PowerShell scripts (they run on Windows PowerShell 5.1 and are not executed in CI)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = [*sorted((ROOT / "scripts").glob("*.ps1")), *sorted((ROOT / "infra").glob("*.ps1"))]


def test_scripts_are_ascii():
    for s in SCRIPTS:
        s.read_bytes().decode("ascii")  # PowerShell 5.1 misreads UTF-8 without BOM


def test_cleanup_is_wired_into_start_and_stop():
    assert "cleanup.ps1" in (ROOT / "scripts" / "start.ps1").read_text(encoding="ascii")
    assert "cleanup.ps1" in (ROOT / "scripts" / "stop.ps1").read_text(encoding="ascii")


def test_cleanup_docker_only_touches_labeled_objects():
    txt = (ROOT / "scripts" / "cleanup.ps1").read_text(encoding="ascii")
    assert "$Label     = 'sw-analyst'" in txt
    for forbidden in ("system prune", "container prune", "docker rm $(docker ps"):
        assert forbidden not in txt
    # every prune call carries the label filter, except the explicit -DockerDeep build-cache prune
    for line in txt.splitlines():
        if "'prune'" in line and "'builder'" not in line:
            assert "$filter" in line, line
