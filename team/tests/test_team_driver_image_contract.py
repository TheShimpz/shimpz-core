from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UV_IMAGE = "ghcr.io/astral-sh/uv:0.11.25@sha256:1e3808aa9023d0980e7c15b1fa7c1ac16ff35925780cf5c459858b2d693f01a9"
HOSTED_ENTRYPOINTS = ("app", "healthcheck")  # Compose invokes the auxiliary healthcheck entrypoint.
LOCAL_ENTRYPOINTS = ("local_app", "local_healthcheck")
ROOT_RUNTIME_DATA = {"model_catalog.json"}
PRODUCTION_PACKAGES = {
    "assistant_human",
    "container_policy",
    "hosted_install",
    "http_boundary",
    "local_support",
}
# Package data has no import graph; these per-image maps are its reviewed necessity authority.
HOSTED_PACKAGE_DATA = {"assistant_human": {"assistant_human/assistant_catalog.json"}}
LOCAL_PACKAGE_DATA = HOSTED_PACKAGE_DATA
DYNAMIC_IMPORT_MODULES = {"importlib", "pkgutil", "runpy"}


def _source_imports(module: str, path: Path) -> set[str]:
    imports = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
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
                imports.add(imported_module)
                imports.update(f"{imported_module}.{alias.name}" for alias in node.names)
    return imports


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


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
        if path.parent != ROOT:
            if package not in PRODUCTION_PACKAGES:
                raise AssertionError(f"{path} belongs to an unregistered production package")
            root_packages.add(package)
        for imported_module in _source_imports(module, path):
            parts = imported_module.split(".")
            pending.extend(".".join(parts[:depth]) for depth in range(1, len(parts) + 1))
    return {f"{module}.py" for module in root_modules}, root_packages, imported_paths


def _copy_parts(line: str) -> tuple[list[str], str] | None:
    stripped = line.lstrip()
    if not stripped:
        return None
    instruction = stripped.split(maxsplit=1)[0].upper()
    if instruction == "ADD":
        raise AssertionError(f"ADD is outside the exact-closure contract: {line}")
    if instruction != "COPY":
        return None
    if not stripped.startswith("COPY "):
        raise AssertionError(f"COPY must use the modeled canonical spelling: {line}")
    parts = stripped.split()
    sources = parts[1:-1]
    unsupported_flags = {"--parents", "--exclude"}
    if any(flag.split("=", 1)[0] in unsupported_flags for flag in sources if flag.startswith("--")):
        raise AssertionError(f"unsupported COPY semantics: {line}")
    while sources and sources[0].startswith("--"):
        sources.pop(0)
    if any("*" in source or "?" in source or "[" in source for source in sources):
        raise AssertionError(f"wildcard COPY source is outside the exact-closure contract: {line}")
    return sources, parts[-1]


def _copied_package_sources(logical_lines: list[str]) -> dict[str, set[str]]:
    copied = {}
    for line in logical_lines:
        copy_parts = _copy_parts(line)
        if not copy_parts:
            continue
        sources, destination = copy_parts
        match = re.fullmatch(r"[.]\/([a-z][a-z0-9_]*)/", destination)
        if match and match.group(1) in PRODUCTION_PACKAGES:
            copied.setdefault(match.group(1), set()).update(sources)
    return copied


class StaticTeamDriverImageContractTests(unittest.TestCase):
    def _assert_package_copy_closure(
        self,
        packages: set[str],
        copied_packages: dict[str, set[str]],
        imported_paths: set[str],
        package_data: dict[str, set[str]],
    ) -> None:
        self.assertEqual(set(copied_packages), packages)
        for package in packages:
            package_files = copied_packages[package]
            copied_python = {path for path in package_files if path.endswith(".py")}
            self.assertEqual(
                copied_python,
                {path for path in imported_paths if path.startswith(f"{package}/")},
            )
            nested_sources = {
                source for source in package_files if not re.fullmatch(rf"{re.escape(package)}/[A-Za-z0-9_.-]+", source)
            }
            self.assertEqual(
                set(),
                nested_sources,
                f"{package} has nested sources that multi-source COPY would flatten",
            )
            self.assertEqual(package_data.get(package, set()), package_files - copied_python)

    def _assert_image_closure(
        self,
        logical_lines: list[str],
        entrypoints: tuple[str, ...],
        package_data: dict[str, set[str]],
    ) -> None:
        root_copy_sources = self._root_copy_sources(logical_lines)
        packaged = {source for source in root_copy_sources if re.fullmatch(r"[a-z][a-z0-9_]*[.]py", source)}
        modules, packages, imported_paths = _runtime_import_closure(*entrypoints)
        self.assertEqual(packaged, modules)
        self.assertEqual(root_copy_sources, modules | ROOT_RUNTIME_DATA)
        modeled_destinations = {"./", "./contracts", "/opt/venv"}
        for line in logical_lines:
            copy_parts = _copy_parts(line)
            if copy_parts:
                _sources, destination = copy_parts
                package_destination = re.fullmatch(r"[.]\/([a-z][a-z0-9_]*)/", destination)
                self.assertTrue(
                    destination in modeled_destinations
                    or (package_destination and package_destination.group(1) in PRODUCTION_PACKAGES),
                    f"unmodeled COPY destination: {line}",
                )
        self._assert_package_copy_closure(
            packages,
            _copied_package_sources(logical_lines),
            imported_paths,
            package_data,
        )

    def _root_copy_sources(self, logical_lines: list[str]) -> set[str]:
        return {
            source
            for line in logical_lines
            if (copy_parts := _copy_parts(line)) and copy_parts[1] == "./"
            for source in copy_parts[0]
        }

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
        for line in re.sub(r"\\\n\s*", " ", dockerfile).splitlines():
            _copy_parts(line)
        runtime = dockerfile.rsplit("\nFROM ", 1)[-1]
        logical_lines = re.sub(r"\\\n\s*", " ", runtime).splitlines()

        self.assertIn(
            f'ENTRYPOINT ["/opt/venv/bin/python", "/app/{HOSTED_ENTRYPOINTS[0]}.py"]',
            logical_lines,
        )
        self.assertNotIn("HEALTHCHECK", runtime)
        self._assert_image_closure(logical_lines, HOSTED_ENTRYPOINTS, HOSTED_PACKAGE_DATA)
        self.assertIn("source=pyproject.toml,target=/app/pyproject.toml,ro", runtime)
        self.assertIn("source=uv.lock,target=/app/uv.lock,ro", runtime)
        self.assertIn("COPY contracts ./contracts", runtime)
        contracts = ROOT / "contracts"
        self.assertEqual({"developers-controller"}, {path.name for path in contracts.iterdir()})
        self.assertEqual(
            {"upstream.json", "v1"},
            {path.name for path in (contracts / "developers-controller").iterdir()},
        )
        for package in PRODUCTION_PACKAGES:
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
        for line in re.sub(r"\\\n\s*", " ", dockerfile).splitlines():
            _copy_parts(line)
        runtime = dockerfile.split(" AS runtime\n", 1)[1]
        logical_lines = re.sub(r"\\\n\s*", " ", runtime).splitlines()

        self.assertIn(f"FROM {UV_IMAGE} AS uv", dockerfile)
        self.assertIn("COPY --from=uv /uv /usr/local/bin/uv", dockerfile)
        self.assertIn("COPY --from=dependencies /opt/venv /opt/venv", runtime)
        self.assertTrue(
            any(
                line.startswith("HEALTHCHECK ") and f'/app/{LOCAL_ENTRYPOINTS[1]}.py"]' in line
                for line in logical_lines
            ),
        )
        self.assertIn(
            f'ENTRYPOINT ["/opt/venv/bin/python", "/app/{LOCAL_ENTRYPOINTS[0]}.py"]',
            logical_lines,
        )
        self._assert_image_closure(logical_lines, LOCAL_ENTRYPOINTS, LOCAL_PACKAGE_DATA)
        self.assertIn("/var/lib/shimpz-local/chat-continuations/state", runtime)
        self.assertIn("/var/lib/shimpz-local/chat-continuations/key", runtime)
        self.assertNotIn("uv-install.sh", dockerfile)
        self.assertNotIn("apt-get", runtime)
        self.assertNotIn("curl", runtime)
        self.assertNotIn("/usr/local/bin/uv", runtime)

    def test_every_package_module_is_reachable_from_an_image_entrypoint(self) -> None:
        hosted_modules, hosted_packages, hosted_paths = _runtime_import_closure(*HOSTED_ENTRYPOINTS)
        local_modules, local_packages, local_paths = _runtime_import_closure(*LOCAL_ENTRYPOINTS)
        imported_paths = hosted_paths | local_paths

        self.assertEqual({path.name for path in ROOT.glob("*.py")}, hosted_modules | local_modules)
        self.assertEqual({path.name for path in ROOT.glob("*.json")}, ROOT_RUNTIME_DATA)
        filesystem_packages = {
            path.name for path in ROOT.iterdir() if path.is_dir() and (path / "__init__.py").is_file()
        }
        self.assertEqual(PRODUCTION_PACKAGES, filesystem_packages)
        self.assertEqual(PRODUCTION_PACKAGES, hosted_packages | local_packages)
        for package in PRODUCTION_PACKAGES:
            package_files = {path.relative_to(ROOT).as_posix() for path in (ROOT / package).rglob("*.py")}
            self.assertEqual(
                package_files,
                {path for path in imported_paths if path.startswith(f"{package}/")},
            )
        source_package_data = {
            path.relative_to(ROOT).as_posix()
            for package in PRODUCTION_PACKAGES
            for path in (ROOT / package).rglob("*")
            if path.is_file()
            and path.suffix not in {".py", ".pyc"}
            and not any(part.startswith(".") or part == "__pycache__" for part in path.relative_to(ROOT).parts)
        }
        declared_package_data = {
            path
            for image_data in (HOSTED_PACKAGE_DATA, LOCAL_PACKAGE_DATA)
            for paths in image_data.values()
            for path in paths
        }
        self.assertEqual(source_package_data, declared_package_data)
        production_sources = [*ROOT.glob("*.py")]
        production_sources.extend(path for package in PRODUCTION_PACKAGES for path in (ROOT / package).rglob("*.py"))
        for path in production_sources:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported_roots = {module.partition(".")[0] for module in _source_imports(_module_name(path), path)}
            self.assertEqual(
                set(),
                imported_roots & DYNAMIC_IMPORT_MODULES,
                f"{path.relative_to(ROOT)} imports a dynamic-loading module",
            )
            dynamic_imports = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and (
                    (
                        isinstance(node.func, ast.Name)
                        and node.func.id in {"__import__", "compile", "eval", "exec", "import_module"}
                    )
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == "__import__")
                )
            ]
            self.assertEqual([], dynamic_imports, f"{path.relative_to(ROOT)} hides imports from the image closure")

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
