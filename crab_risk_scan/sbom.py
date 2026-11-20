"""Generate a CycloneDX inventory using a separately installed Syft binary."""
import json
import os
import subprocess
import tempfile
from pathlib import Path


def generate(directory, executable=None):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("expected a repository directory")
    target = directory.resolve()
    # Only search absolute PATH entries. Never pick a binary in the scanned tree.
    search = [p for p in os.get_exec_path() if Path(p).is_absolute()]
    if executable is None:
        name = "syft.exe" if os.name == "nt" else "syft"
        executable = next((Path(p) / name for p in search if
                           (Path(p) / name).is_file() and os.access(Path(p) / name, os.X_OK)
                           and not (Path(p) / name).resolve().is_relative_to(target)), None)
    if executable is None:
        raise ValueError("install Syft or pass --syft with its absolute path")
    binary = Path(executable)
    if not binary.is_absolute() or not binary.is_file() or binary.resolve().is_relative_to(target):
        raise ValueError("use a trusted Syft executable outside the scanned directory")
    binary = binary.resolve()
    # A private working directory prevents loading the target's local .syft.yaml.
    with tempfile.TemporaryDirectory() as scratch:
        output = Path(scratch) / "inventory.json"
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR", "LANG"}}
        env.update({"HOME": scratch, "USERPROFILE": scratch, "XDG_CONFIG_HOME": scratch,
                    "SYFT_CHECK_FOR_APP_UPDATE": "false"})
        subprocess.run([str(binary), "scan", "dir:" + str(target), "-o",
                        "cyclonedx-json=" + str(output)], check=True, timeout=180,
                       cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with output.open("rb") as stream:
            data = stream.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise ValueError("SBOM exceeds the 32 MiB output limit")
        bom = json.loads(data)
        if (not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX"
                or not isinstance(bom.get("specVersion"), str)
                or not isinstance(bom.get("components", []), list)):
            raise ValueError("Syft returned an invalid CycloneDX document")
        return bom
