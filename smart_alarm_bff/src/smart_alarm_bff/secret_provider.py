"""Resolve database secret references from an immutable mounted secret root."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_REFERENCE = re.compile(r"^mounted:([A-Za-z0-9][A-Za-z0-9._/-]{0,503})$")


class SecretReferenceError(ValueError):
    pass


class MountedSecretProvider:
    def __init__(self, root: Path, *, maximum_bytes: int = 65536) -> None:
        self._root = root.resolve(strict=True)
        if not self._root.is_dir():
            raise SecretReferenceError("secret root is not a directory")
        if not 1 <= maximum_bytes <= 1048576:
            raise SecretReferenceError("secret size limit is invalid")
        self._maximum_bytes = maximum_bytes

    def read(self, reference: str) -> bytes:
        match = _REFERENCE.fullmatch(reference)
        if match is None:
            raise SecretReferenceError("secret reference must use the mounted: scheme")
        relative = PurePosixPath(match.group(1))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise SecretReferenceError("secret reference escapes its namespace")
        candidate = self._root.joinpath(*relative.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self._root)
        except (OSError, ValueError) as exc:
            raise SecretReferenceError("secret reference is unavailable") from exc
        if not resolved.is_file():
            raise SecretReferenceError("secret reference is not a regular file")
        try:
            descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                value = os.read(descriptor, self._maximum_bytes + 1)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise SecretReferenceError("secret reference is unreadable") from exc
        value = value.rstrip(b"\r\n")
        if not value or len(value) > self._maximum_bytes:
            raise SecretReferenceError("secret value is empty or too large")
        return value


_ENCRYPTED_REFERENCE = re.compile(r"^encrypted:v([1-9][0-9]{0,9}):([A-Za-z0-9][A-Za-z0-9._/-]{0,470})$")


class EncryptedFileSecretStore:
    """Shared encrypted-at-rest device credential store with atomic creation."""

    def __init__(self, root: Path, key: bytes, key_version: int) -> None:
        self._root = root.resolve(strict=True)
        if not self._root.is_dir():
            raise SecretReferenceError("device secret root is not a directory")
        if len(key) != 32:
            raise SecretReferenceError("device secret key must contain exactly 32 bytes")
        if not 1 <= key_version <= 2147483647:
            raise SecretReferenceError("device secret key version is invalid")
        self._cipher = AESGCM(key)
        self._key_version = key_version

    def reference(self, relative_name: str) -> str:
        relative = self._relative(relative_name)
        return f"encrypted:v{self._key_version}:{relative.as_posix()}"

    def get_or_create(self, relative_name: str, factory: Callable[[], bytes]) -> tuple[str, bytes]:
        reference = self.reference(relative_name)
        try:
            return reference, self.read(reference)
        except SecretReferenceError as exc:
            if "unavailable" not in str(exc):
                raise
        value = factory()
        if not isinstance(value, bytes) or not value or len(value) > 65536:
            raise SecretReferenceError("generated secret is invalid")
        relative = self._relative(relative_name)
        nonce = secrets.token_bytes(12)
        envelope = b"SAE1" + nonce + self._cipher.encrypt(nonce, value, reference.encode("utf-8"))
        try:
            parent, filename = self._open_parent(relative, create=True)
        except OSError as exc:
            raise SecretReferenceError("encrypted secret path is unavailable") from exc
        temporary = f".{filename}.{secrets.token_hex(8)}.tmp"
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent,
            )
            try:
                view = memoryview(envelope)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short encrypted secret write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.link(temporary, filename, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)
        return reference, self.read(reference)

    def read(self, reference: str) -> bytes:
        match = _ENCRYPTED_REFERENCE.fullmatch(reference)
        if match is None or int(match.group(1)) != self._key_version:
            raise SecretReferenceError("encrypted secret key version is unavailable")
        relative = self._relative(match.group(2))
        try:
            parent, filename = self._open_parent(relative, create=False)
            try:
                descriptor = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
                try:
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise OSError("not a regular file")
                    envelope = os.read(descriptor, 65570)
                finally:
                    os.close(descriptor)
            finally:
                os.close(parent)
        except OSError as exc:
            raise SecretReferenceError("encrypted secret is unavailable") from exc
        if len(envelope) < 33 or not envelope.startswith(b"SAE1"):
            raise SecretReferenceError("encrypted secret envelope is invalid")
        nonce = envelope[4:16]
        try:
            value = self._cipher.decrypt(nonce, envelope[16:], reference.encode("utf-8"))
        except Exception as exc:
            raise SecretReferenceError("encrypted secret authentication failed") from exc
        if not value or len(value) > 65536:
            raise SecretReferenceError("encrypted secret value is invalid")
        return value

    def delete(self, reference: str) -> None:
        match = _ENCRYPTED_REFERENCE.fullmatch(reference)
        if match is None or int(match.group(1)) != self._key_version:
            raise SecretReferenceError("encrypted secret key version is unavailable")
        relative = self._relative(match.group(2))
        try:
            parent, filename = self._open_parent(relative, create=False)
            try:
                os.unlink(filename, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise SecretReferenceError("encrypted secret deletion failed") from exc

    def _relative(self, value: str) -> PurePosixPath:
        relative = PurePosixPath(value)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise SecretReferenceError("encrypted secret path escapes its namespace")
        return relative

    def _open_parent(self, relative: PurePosixPath, *, create: bool) -> tuple[int, str]:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._root, flags)
        try:
            for part in relative.parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor, relative.parts[-1]
        except Exception:
            os.close(descriptor)
            raise
