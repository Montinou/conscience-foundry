"""Runtime identity inventory refuses changed files."""

import pytest

from conscience_foundry.contracts.common import ContractError


def test_file_drift_changes_manifest_and_verification_refuses(tmp_path, monkeypatch) -> None:
    from conscience_foundry.execution import local_runtime

    file = tmp_path / "code.py"
    file.write_text("before")
    monkeypatch.setattr(local_runtime, "_inventory", lambda: [("test/code.py", file)])
    expected = local_runtime.runtime_digest(local_runtime.runtime_manifest())
    file.write_text("after")
    with pytest.raises(ContractError):
        local_runtime.verify_runtime(expected)
    assert str(tmp_path) not in repr(local_runtime.runtime_manifest())


def test_hash_refuses_atomic_path_replacement_during_read(tmp_path, monkeypatch) -> None:
    from conscience_foundry.execution import local_runtime

    path = tmp_path / "code.py"
    replacement = tmp_path / "replacement.py"
    path.write_text("old")
    replacement.write_text("new")
    real_digest = local_runtime.hashlib.file_digest

    def replace_during_digest(stream, algorithm):
        result = real_digest(stream, algorithm)
        replacement.replace(path)
        return result

    monkeypatch.setattr(local_runtime.hashlib, "file_digest", replace_during_digest)
    with pytest.raises(ContractError, match="hash_mismatch"):
        local_runtime._hash_file(path)


def test_inventory_selects_stable_runtime_files_and_rejects_missing(tmp_path, monkeypatch) -> None:
    from pathlib import Path

    from conscience_foundry.execution import local_runtime

    stdlib = tmp_path / "stdlib"
    package = tmp_path / "package"
    distroot = tmp_path / "distribution"
    for path in [
        stdlib / "os.py",
        stdlib / "lib-dynload" / "native.so",
        stdlib / "__pycache__" / "os.pyc",
        stdlib / "site-packages" / "skip.py",
        package / "execution" / "local_runtime.py",
        package / "module.py",
        distroot / "demo" / "code.py",
        distroot / "demo" / "data.bin",
        distroot / "demo-1.dist-info" / "RECORD",
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture")
    interpreter = tmp_path / "python"
    interpreter.write_text("binary")

    class Distribution:
        metadata = {"Name": "demo"}
        files = [Path("demo/data.bin"), Path("demo/code.py"), Path("demo-1.dist-info/RECORD")]

        def locate_file(self, item):
            return distroot / item

    monkeypatch.setattr(local_runtime.sys, "executable", str(interpreter))
    monkeypatch.setattr(local_runtime.sysconfig, "get_path", lambda name: str(stdlib))
    monkeypatch.setattr(local_runtime, "__file__", str(package / "execution" / "local_runtime.py"))
    monkeypatch.setattr(local_runtime.importlib.metadata, "distributions", lambda: [Distribution()])
    entries = local_runtime._inventory()
    labels = [label for label, _ in entries]
    assert labels == sorted(labels)
    assert labels == [
        "distribution/demo/demo/code.py",
        "distribution/demo/demo/data.bin",
        "interpreter",
        "package/execution/local_runtime.py",
        "package/module.py",
        "stdlib/lib-dynload/native.so",
        "stdlib/os.py",
    ]
    assert str(tmp_path) not in repr(labels)
    (distroot / "demo" / "data.bin").unlink()
    with pytest.raises(ContractError, match="unavailable"):
        local_runtime._inventory()
