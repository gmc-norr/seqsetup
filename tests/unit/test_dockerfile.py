"""The image build can download Tailwind (group 3a): the pixi base image has no
curl, so the Dockerfile installs it before it builds the CSS. Measured
2026-10-11: without it, `docker build` stops at `RUN pixi run css` with
"curl: command not found", on main too."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class TestDockerfile:
    """Dockerfile as shipped (Docker is not needed to read it)."""

    def test_curl_is_installed_before_the_css_is_built(self):
        lines = (ROOT / "Dockerfile").read_text().splitlines()
        css = lines.index("RUN pixi run css")
        installs = [n for n, line in enumerate(lines)
                    if "apt-get install" in line and " curl " in f"{line} "]
        assert installs and installs[0] < css
