"""Private bearer token shared only by the Team Controller and Brain runtime."""

from __future__ import annotations

import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

TOKEN_PATH = Path(os.environ.get("SHIMPZ_BRAIN_RUNTIME_TOKEN_FILE", "/run/shimpz-brain-runtime/token"))
TOKEN_GROUP_GID = 10016
TOKEN_BYTES = 32
DIRECTORY_MODE = 0o750
TOKEN_MODE = 0o440


class RuntimeTokenError(RuntimeError):
    """The shared runtime token could not be created or trusted safely."""


def _check_directory(metadata: os.stat_result, group_id: int) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != group_id
        or stat.S_IMODE(metadata.st_mode) != DIRECTORY_MODE
    ):
        raise RuntimeTokenError("the Brain runtime token directory has unsafe metadata")


def _prepare_directory(path: Path, group_id: int) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(parents=True, mode=DIRECTORY_MODE)
            os.chown(path, -1, group_id)
            path.chmod(DIRECTORY_MODE)
            metadata = path.lstat()
        except OSError as exc:
            raise RuntimeTokenError("the Brain runtime token directory could not be created") from exc
    _check_directory(metadata, group_id)


def _check_token(metadata: os.stat_result, group_id: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != group_id
        or stat.S_IMODE(metadata.st_mode) != TOKEN_MODE
        or metadata.st_size != TOKEN_BYTES * 2
    ):
        raise RuntimeTokenError("the Brain runtime token has unsafe metadata")


def _read_checked(directory: int, name: str, group_id: int) -> str:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except OSError as exc:
        raise RuntimeTokenError("the Brain runtime token is unavailable or unsafe") from exc
    try:
        _check_token(os.fstat(descriptor), group_id)
        raw = os.read(descriptor, TOKEN_BYTES * 2 + 1)
    finally:
        os.close(descriptor)
    if len(raw) != TOKEN_BYTES * 2:
        raise RuntimeTokenError("the Brain runtime token is invalid")
    try:
        token = raw.decode("ascii")
        decoded = bytes.fromhex(token)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeTokenError("the Brain runtime token is invalid") from exc
    if len(decoded) != TOKEN_BYTES:
        raise RuntimeTokenError("the Brain runtime token is invalid")
    return token


def _create(directory: int, name: str, group_id: int) -> None:
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        token = secrets.token_hex(TOKEN_BYTES).encode("ascii")
        written = 0
        while written < len(token):
            written += os.write(descriptor, token[written:])
        os.fchown(descriptor, -1, group_id)
        os.fchmod(descriptor, TOKEN_MODE)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError as exc:
        raise RuntimeTokenError("the Brain runtime token could not be created") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory)


def ensure(path: Path = TOKEN_PATH, *, group_id: int = TOKEN_GROUP_GID) -> str:
    """Create the shared token once, then reuse it only while its metadata remains safe."""
    target = Path(path)
    _prepare_directory(target.parent, group_id)
    try:
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise RuntimeTokenError("the Brain runtime token directory is unavailable or unsafe") from exc
    try:
        _check_directory(os.fstat(directory), group_id)
        try:
            metadata = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            _create(directory, target.name, group_id)
        else:
            _check_token(metadata, group_id)
        return _read_checked(directory, target.name, group_id)
    finally:
        os.close(directory)
