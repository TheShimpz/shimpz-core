from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UV_IMAGE = "ghcr.io/astral-sh/uv:0.11.25@sha256:1e3808aa9023d0980e7c15b1fa7c1ac16ff35925780cf5c459858b2d693f01a9"


def _runtime_import_closure(*entrypoints: str) -> tuple[set[str], set[str], set[str]]:
    pending = list(entrypoints)
    visited = set()
    root_modules = set()
    root_packages = set()
    imported_paths = set()
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        visited.add(module)
        path = ROOT / f"{module.replace('.', '/')}.py"
        if not path.is_file():
            path = ROOT / module.replace(".", "/") / "__init__.py"
        if not path.is_file():
            continue
        imported_paths.add(path.relative_to(ROOT).as_posix())
        if "." not in module and path.parent == ROOT:
            root_modules.add(module)
        package = module.partition(".")[0]
        if (ROOT / package / "__init__.py").is_file():
            root_packages.add(package)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            imported = []
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported_module = node.module
                if node.level:
                    package_parts = module.split(".") if path.name == "__init__.py" else module.split(".")[:-1]
                    parent_levels = node.level - 1
                    if parent_levels >= len(package_parts):
                        raise AssertionError(f"invalid relative import in {path}")
                    base = package_parts[: len(package_parts) - parent_levels]
                    imported_module = ".".join((*base, node.module) if node.module else base)
                if imported_module:
                    imported = [
                        imported_module,
                        *(f"{imported_module}.{alias.name}" for alias in node.names),
                    ]
            pending.extend(imported)
    return {f"{module}.py" for module in root_modules}, root_packages, imported_paths


class StaticTeamDriverImageContractTests(unittest.TestCase):
    def test_static_build_context_excludes_dependencies_caches_and_secrets(self) -> None:
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

        self.assertLessEqual(
            {
                ".env",
                ".env.*",
                "**/.env",
                "**/.env.*",
                ".venv",
                "**/__pycache__",
                "**/*.pyc",
            },
            set(dockerignore),
        )

    def test_static_image_packages_the_exact_runtime_import_closure(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        runtime = dockerfile.rsplit("\nFROM ", 1)[-1]
        logical_lines = re.sub(r"\\\n\s*", " ", runtime).splitlines()
        runtime_copy = next((line for line in logical_lines if line.startswith("COPY ") and "app.py" in line), "")
        packaged = set(re.findall(r"\b[a-z][a-z0-9_]*[.]py\b", runtime_copy))

        modules, packages, imported_paths = _runtime_import_closure("app", "healthcheck")
        self.assertEqual(packaged, modules)
        copied_packages = {
            match.group(1)
            for line in logical_lines
            if (match := re.fullmatch(r"COPY ([a-z][a-z0-9_]*) [.]\/\1", line))
            and (ROOT / match.group(1) / "__init__.py").is_file()
        }
        self.assertEqual(copied_packages, packages)
        for package in packages:
            self.assertIn(f"COPY {package} ./{package}", runtime)
        hosted_files = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "hosted_install").glob("*.py")
        }
        self.assertEqual(
            hosted_files,
            {path for path in imported_paths if path.startswith("hosted_install/")},
        )
        for package in ("container_policy", "hosted_install"):
            package_tree = ast.parse((ROOT / package / "__init__.py").read_text(encoding="utf-8"))
            self.assertFalse(
                [node for node in ast.walk(package_tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
            )

    def test_static_image_keeps_brain_access_and_private_state_narrow(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn("ARG SHIMPZ_BRAIN_RUNTIME_TOKEN_GID=10016", dockerfile)
        self.assertIn(
            'groupadd -g "${SHIMPZ_BRAIN_RUNTIME_TOKEN_GID}" shimpzbrain-runtime-token',
            dockerfile,
        )
        self.assertNotIn("r2", dockerfile.lower())
        self.assertIn(
            "chown teamdriver:shimpzbrain-runtime-token /run/shimpz-brain-runtime",
            dockerfile,
        )
        self.assertIn("chmod 0750 /run/shimpz-brain-runtime", dockerfile)
        self.assertIn("/var/lib/team-driver/inference", dockerfile)
        self.assertIn("/var/lib/team-driver/power-journal", dockerfile)
        self.assertNotIn("/var/lib/team-driver/assistant-secrets", dockerfile)
        self.assertIn("/var/lib/team-driver/assistant-accounts/state", dockerfile)
        self.assertIn("/var/lib/team-driver/assistant-accounts/key", dockerfile)
        self.assertIn(
            "/var/lib/team-driver/cleanup \\\n"
            "        /var/lib/team-driver/inference \\\n"
            "        /var/lib/team-driver/power-journal \\",
            dockerfile,
        )

    def test_static_local_image_copies_the_exact_runtime_import_closure(self) -> None:
        dockerfile = (ROOT / "Dockerfile.local").read_text(encoding="utf-8")
        runtime = dockerfile.split(" AS runtime\n", 1)[1]
        logical_lines = re.sub(r"\\\n\s*", " ", runtime).splitlines()
        runtime_copy = next((line for line in logical_lines if line.startswith("COPY local_app.py ")), "")
        packaged = {
            filename
            for line in logical_lines
            if line.startswith("COPY ") and not line.startswith("COPY --from")
            for filename in re.findall(r"\b[a-z][a-z0-9_]*[.]py\b", line)
        }

        self.assertIn(f"FROM {UV_IMAGE} AS uv", dockerfile)
        self.assertIn("COPY --from=uv /uv /usr/local/bin/uv", dockerfile)
        self.assertIn("COPY --from=dependencies /opt/venv /opt/venv", runtime)
        self.assertIn("COPY container_policy ./container_policy", runtime)
        modules, packages, _imported_paths = _runtime_import_closure("local_app", "local_healthcheck")
        self.assertEqual(packaged, modules)
        for package in packages:
            self.assertIn(f"COPY {package} ./{package}", runtime)
        self.assertIn("model_catalog.json", runtime_copy)
        self.assertIn("/var/lib/shimpz-local/chat-continuations/state", runtime)
        self.assertIn("/var/lib/shimpz-local/chat-continuations/key", runtime)
        self.assertNotIn("uv-install.sh", dockerfile)
        self.assertNotIn("apt-get", runtime)
        self.assertNotIn("curl", runtime)
        self.assertNotIn("/usr/local/bin/uv", runtime)

    def test_reference_image_exposes_the_sdk_baked_manifest_contract(self) -> None:
        dockerfile = (ROOT / "tests" / "fixtures" / "reference-assistant" / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn("tests/fixtures/reference-assistant/shimpz.toml /opt/shimpz/shimpz.toml", dockerfile)
        self.assertIn(
            "tests/fixtures/reference-assistant/shimpz.contract.json /opt/shimpz/shimpz.contract.json",
            dockerfile,
        )
        self.assertNotIn("assistant_catalog", dockerfile)
        self.assertIn("/opt/shimpz/shimpz.toml /opt/shimpz/shimpz.contract.json", dockerfile)


if __name__ == "__main__":
    unittest.main()
