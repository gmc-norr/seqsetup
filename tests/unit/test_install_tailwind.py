"""tools/install-tailwind.sh checks the Tailwind binary against a pinned SHA-256
before it is made executable or run (group 3a, N-25).

Each test runs the script with bash in a scratch folder that holds its own
tools/tailwind-version.txt and tools/tailwind-sha256.txt, with stand-ins for
uname, curl and (where a test needs it) the hash tool first on PATH. Nothing
goes to the network. The fake programs leave a marker file when they run.
"""

import hashlib
import os
import shutil
import subprocess
import time
import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "install-tailwind.sh"
URL = "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.0/tailwindcss-linux-x64"

GOOD = '#!/bin/sh\necho "tailwindcss v4.3.0 (good)"\ntouch "$MARKERS/ran-good"\n'
BAD = '#!/bin/sh\necho "tailwindcss v4.3.0 (bad)"\ntouch "$MARKERS/ran-bad"\n'
OLD = '#!/bin/sh\necho "tailwindcss v4.3.0 (old)"\ntouch "$MARKERS/ran-old"\n'

FAKE_UNAME = '#!/bin/sh\necho "${FAKE_UNAME:-Linux x86_64}"\n'
FAKE_CURL = """#!/bin/sh
echo "curl $*" >> "$MARKERS/curl.log"
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; fi
  shift
done
if [ -n "$FAKE_CURL_PARTIAL" ]; then
  head -c 10 "$FAKE_CURL_SOURCE" > "$out"
  exit 22
fi
cat "$FAKE_CURL_SOURCE" > "$out"
if [ -n "$FAKE_CURL_WROTE" ]; then touch "$FAKE_CURL_WROTE"; fi
"""
# Wraps the real sha256sum: records the mode of the file it is given, can fail,
# and can hold the run after hashing until another run has written its file.
FAKE_SHA256SUM = """#!/bin/sh
stat -c %a "$1" >> "$MARKERS/modes"
if [ -n "$FAKE_SHA_FAIL" ]; then exit 1; fi
out=$({real} "$1") || exit 1
if [ -n "$FAKE_SHA_HASHED" ]; then touch "$FAKE_SHA_HASHED"; fi
if [ -n "$FAKE_SHA_WAIT_FOR" ]; then
  n=0
  while [ ! -e "$FAKE_SHA_WAIT_FOR" ] && [ $n -lt 300 ]; do sleep 0.1; n=$((n + 1)); done
fi
echo "$out"
"""

UNSUPPORTED = "tools/tailwind-sha256.txt has no single SHA-256 for tailwindcss-linux-x64."
NO_HASH_TOOL = ("Neither sha256sum nor shasum is installed, so the Tailwind binary cannot "
                "be checked.")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _refusal(source: str, actual: str) -> str:
    return (
        f"tailwindcss-linux-x64 from {source} has SHA-256\n"
        f"{actual}, not the {_sha256(GOOD)} that tools/tailwind-sha256.txt pins. It was not "
        "installed.\n"
        "If you changed tools/tailwind-version.txt, copy the new release's values from its\n"
        "sha256sums.txt into tools/tailwind-sha256.txt.\n"
    )


class Checkout:
    """A scratch folder the script runs in, as if it were the repo root."""

    def __init__(self, root: Path, sums_lines=None):
        self.root = root
        self.markers = root / "markers"
        self.markers.mkdir()
        (root / "tools").mkdir()
        (root / "tools" / "tailwind-version.txt").write_text("v4.3.0\n")
        if sums_lines is None:
            sums_lines = [f"{_sha256(GOOD)}  tailwindcss-linux-x64"]
        (root / "tools" / "tailwind-sha256.txt").write_text(
            "# tailwindcss v4.3.0\n# A test's own pins.\n" + "".join(l + "\n" for l in sums_lines))
        self.fakebin = root / "fakebin"
        self.fakebin.mkdir()
        self._program("uname", FAKE_UNAME)
        self._program("curl", FAKE_CURL)
        self.downloads = root / "downloads"
        self.downloads.mkdir()
        self.serve(GOOD)

    def _program(self, name: str, text: str) -> None:
        path = self.fakebin / name
        path.write_text(text)
        path.chmod(0o755)

    def wrap_sha256sum(self) -> None:
        self._program("sha256sum", FAKE_SHA256SUM.format(real=shutil.which("sha256sum")))

    def serve(self, text: str) -> None:
        """What the stand-in curl downloads."""
        (self.downloads / "tailwindcss").write_text(text)

    def vendor(self, text: str, mode: int = 0o755) -> None:
        path = self.root / "tools" / "vendor" / "tailwindcss-linux-x64"
        path.parent.mkdir(exist_ok=True)
        path.write_text(text)
        path.chmod(mode)

    def install(self, text: str) -> None:
        path = self.root / ".pixi" / "bin" / "tailwindcss"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o755)

    def env(self, path=None, **extra) -> dict:
        env = {**os.environ, "MARKERS": str(self.markers),
               "FAKE_CURL_SOURCE": str(self.downloads / "tailwindcss"),
               "PATH": path or f"{self.fakebin}:{os.environ['PATH']}"}
        env.update(extra)
        return env

    def run(self, path=None, **extra) -> subprocess.CompletedProcess:
        return subprocess.run([shutil.which("bash"), str(SCRIPT)], cwd=self.root,
                              env=self.env(path, **extra), capture_output=True, text=True,
                              timeout=60)

    def start(self, **extra) -> subprocess.Popen:
        return subprocess.Popen([shutil.which("bash"), str(SCRIPT)], cwd=self.root,
                                env=self.env(None, **extra), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)

    @property
    def installed(self) -> Path:
        return self.root / ".pixi" / "bin" / "tailwindcss"

    def bin_files(self) -> list:
        folder = self.root / ".pixi" / "bin"
        return sorted(p.name for p in folder.iterdir()) if folder.exists() else []

    def ran(self, which: str) -> bool:
        return (self.markers / f"ran-{which}").exists()

    def curl_calls(self) -> list:
        log = self.markers / "curl.log"
        return log.read_text().splitlines() if log.exists() else []

    def modes(self) -> list:
        return (self.markers / "modes").read_text().split()


@pytest.fixture
def checkout(tmp_path):
    return Checkout(tmp_path)


class TestADownload:
    """Nothing installed yet: the script downloads, checks, then installs."""

    def test_a_good_download_is_installed(self, checkout):
        result = checkout.run()
        assert result.returncode == 0, result.stderr
        assert checkout.installed.read_text() == GOOD
        assert os.access(checkout.installed, os.X_OK)
        assert checkout.bin_files() == ["tailwindcss"]
        assert checkout.curl_calls() == [f"curl -fsSL -o {checkout.curl_calls()[0].split()[3]} {URL}"]
        assert "Installed Tailwind v4.3.0 at .pixi/bin/tailwindcss" in result.stdout
        # Never run by the install: `--version` in Tailwind v4 also prints a whole stylesheet.
        assert not checkout.ran("good")

    def test_a_bad_download_is_refused(self, checkout):
        checkout.serve(BAD)
        result = checkout.run()
        assert result.returncode == 1
        assert _refusal(URL, _sha256(BAD)) in result.stderr
        assert checkout.bin_files() == []
        assert not checkout.ran("bad")

    def test_a_failed_download_leaves_nothing(self, checkout):
        result = checkout.run(FAKE_CURL_PARTIAL="1")
        assert result.returncode != 0
        assert checkout.bin_files() == []

    def test_the_downloaded_file_is_not_executable_when_checked(self, checkout):
        checkout.wrap_sha256sum()
        assert checkout.run().returncode == 0
        assert checkout.modes() == ["600"]


class TestTheHashTool:
    """No check, no install."""

    def test_a_failing_hash_tool_leaves_nothing(self, checkout):
        checkout.wrap_sha256sum()
        result = checkout.run(FAKE_SHA_FAIL="1")
        assert result.returncode != 0
        assert checkout.bin_files() == []
        assert not checkout.ran("good")

    def test_no_hash_tool_stops_before_downloading(self, checkout):
        # A PATH with only the tools the script needs, without sha256sum and shasum.
        tools = checkout.root / "tools-only"
        tools.mkdir()
        for name in ("cat", "mkdir", "mktemp", "rm", "mv", "chmod", "awk", "head", "touch"):
            (tools / name).symlink_to(shutil.which(name))
        result = checkout.run(path=f"{checkout.fakebin}:{tools}")
        assert result.returncode == 1
        assert NO_HASH_TOOL in result.stderr
        assert checkout.curl_calls() == []
        assert checkout.bin_files() == []


class TestAnInstalledBinary:
    """A file already at .pixi/bin/tailwindcss is hashed, never run, before it is trusted."""

    def test_a_matching_install_is_kept(self, checkout):
        checkout.install(GOOD)
        result = checkout.run()
        assert result.returncode == 0
        assert "Tailwind v4.3.0 already installed at .pixi/bin/tailwindcss" in result.stdout
        assert checkout.curl_calls() == []
        assert not checkout.ran("good")

    def test_a_mismatching_install_is_replaced_without_running(self, checkout):
        checkout.install(OLD)
        result = checkout.run()
        assert result.returncode == 0, result.stderr
        assert (".pixi/bin/tailwindcss does not match the pinned SHA-256; removed, installing "
                "again.") in result.stdout
        assert checkout.installed.read_text() == GOOD
        assert not checkout.ran("old") and not checkout.ran("good")

    def test_a_mismatching_install_and_a_bad_download_leave_nothing(self, checkout):
        checkout.install(OLD)
        checkout.serve(BAD)
        result = checkout.run()
        assert result.returncode == 1
        assert checkout.bin_files() == []
        assert not checkout.ran("old") and not checkout.ran("bad")


class TestAVendoredCopy:
    """tools/vendor/tailwindcss-<platform> is used instead of a download, and checked."""

    def test_a_good_vendored_copy_is_installed_without_curl(self, checkout):
        checkout.vendor(GOOD)
        checkout.serve(BAD)
        result = checkout.run()
        assert result.returncode == 0, result.stderr
        assert checkout.installed.read_text() == GOOD
        assert checkout.curl_calls() == []
        assert "Using the vendored binary at tools/vendor/tailwindcss-linux-x64" in result.stdout

    def test_a_bad_vendored_copy_is_refused_without_curl(self, checkout):
        checkout.vendor(BAD)
        result = checkout.run()
        assert result.returncode == 1
        assert _refusal("tools/vendor/tailwindcss-linux-x64", _sha256(BAD)) in result.stderr
        assert checkout.curl_calls() == []
        assert checkout.bin_files() == []
        assert not checkout.ran("bad")

    def test_an_executable_vendored_copy_is_not_executable_when_checked(self, checkout):
        checkout.vendor(GOOD, mode=0o755)
        checkout.wrap_sha256sum()
        assert checkout.run().returncode == 0
        assert checkout.modes() == ["600"]


class TestThePinnedHashes:
    """The sums file must name the platform exactly once."""

    @pytest.mark.parametrize("sums_lines", [
        [],
        ["0" * 64 + "  tailwindcss-linux-arm64"],
        [f"{_sha256(GOOD)}  tailwindcss-linux-x64", f"{_sha256(GOOD)}  tailwindcss-linux-x64"],
        [f"# {_sha256(GOOD)}  tailwindcss-linux-x64"],
    ], ids=["empty", "other-platform-only", "twice", "commented-out"])
    def test_no_single_pin_stops_before_downloading(self, tmp_path, sums_lines):
        checkout = Checkout(tmp_path, sums_lines=sums_lines)
        result = checkout.run()
        assert result.returncode == 1
        assert UNSUPPORTED in result.stderr
        assert checkout.curl_calls() == []
        assert checkout.bin_files() == []


class TestTwoInstallsAtOnce:
    """Each run has its own staging file: one run's download can never replace
    the bytes another run has just checked."""

    def test_a_bad_download_cannot_replace_a_checked_one(self, checkout):
        checkout.wrap_sha256sum()
        sync = checkout.root / "sync"
        sync.mkdir()
        bad_source = checkout.root / "bad-download"
        bad_source.write_text(BAD)
        # Run A downloads the good file, hashes it, then waits for run B.
        run_a = checkout.start(FAKE_SHA_HASHED=str(sync / "a-hashed"),
                               FAKE_SHA_WAIT_FOR=str(sync / "b-wrote"))
        deadline = time.monotonic() + 30
        while not (sync / "a-hashed").exists():
            assert time.monotonic() < deadline, "run A never hashed its file"
            assert run_a.poll() is None, run_a.communicate()
            time.sleep(0.05)
        # Run B downloads a bad file while A waits between its check and its install.
        run_b = checkout.run(FAKE_CURL_SOURCE=str(bad_source), FAKE_CURL_WROTE=str(sync / "b-wrote"))
        out_a, err_a = run_a.communicate(timeout=60)
        assert run_a.returncode == 0, err_a
        assert run_b.returncode == 1
        assert checkout.installed.read_text() == GOOD
        assert not checkout.ran("bad")
        assert checkout.bin_files() == ["tailwindcss"]


class TestTheRepoPins:
    """The repo's own pins and the pixi task that runs the script."""

    def test_the_pins_are_tailwinds_own(self):
        lines = (ROOT / "tools" / "tailwind-sha256.txt").read_text().splitlines()
        assert [l for l in lines if not l.startswith("#")] == [
            "73f0e5459054e5cfaa8ab6f3b940f3fbe0f13cc7fd83bc24e7c655033c203400  tailwindcss-linux-x64",
            "8f48dcb72be3b351c10563c5329b4638ba8516820dc3b3a1609625a166e87cbd  tailwindcss-linux-arm64",
            "2ba252f770817091e6d0d12a84e0dd531bcc29aad1bfd9d976a3aff1a071b67a  tailwindcss-macos-x64",
            "56b4bbc62dbdc4614a78930d9c6986423a2ec63e4e640144a59a5d95c914322e  tailwindcss-macos-arm64",
        ]

    def test_the_pins_name_the_pinned_version(self):
        version = (ROOT / "tools" / "tailwind-version.txt").read_text().strip()
        first = (ROOT / "tools" / "tailwind-sha256.txt").read_text().splitlines()[0]
        assert first == f"# tailwindcss {version}"

    def test_the_pixi_task_runs_the_script(self):
        tasks = tomllib.loads((ROOT / "pixi.toml").read_text())["tasks"]
        assert tasks["tailwind-install"] == "bash tools/install-tailwind.sh"
