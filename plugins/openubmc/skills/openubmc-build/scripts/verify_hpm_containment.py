#!/usr/bin/env python3
"""Verify the supported PICMG/AES/GPP/tar chain without extracting image files.

This proves byte containment, not CMS certificate trust or firmware suitability.
Input files are held open and checked for drift. Decrypted GPP bytes use an
anonymous temporary spool; rootfs bytes are hashed while streaming from gzip.
Unknown layouts fail closed instead of searching for plausible nested images.
"""
from __future__ import annotations

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
from typing import BinaryIO
import zlib

SCHEMA = "openubmc-build/hpm-containment-v1"
METHOD = "openubmc-picmg-ext4-aes128cbc-gzip-tar"
_CHUNK = 64 * 1024
_CIPHER_RECORD = 10272
_PLAIN_RECORD = 10240
_IV = b"a" + b"\0" * 15
_TAR_TAIL_LIMIT = 11264


class _Unverified(ValueError):
    """Only fixed, nonsensitive reason codes may cross the public boundary."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise _Unverified(reason)


class _Region:
    def __init__(self, file: BinaryIO, offset: int, size: int):
        self.file, self.offset, self.size = file, offset, size

    def read(self, offset: int, size: int) -> bytes:
        _require(0 <= offset <= self.size and 0 <= size <= self.size - offset,
                 "container_range_out_of_bounds")
        self.file.seek(self.offset + offset)
        data = self.file.read(size)
        _require(len(data) == size, "truncated_input")
        return data

    def sub(self, offset: int, size: int) -> _Region:
        _require(0 <= offset <= self.size and 0 <= size <= self.size - offset,
                 "container_range_out_of_bounds")
        return _Region(self.file, self.offset + offset, size)

    def digest(self) -> str:
        digest = hashlib.sha256()
        for offset in range(0, self.size, _CHUNK):
            digest.update(self.read(offset, min(_CHUNK, self.size - offset)))
        return digest.hexdigest()

    def evidence(self, parent: str, *, origin: int = 0) -> dict[str, object]:
        return {"parent": parent, "offset": self.offset - origin,
                "size": self.size, "sha256": self.digest()}


def _snapshot(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class _StableFile:
    def __init__(self, path: Path, cap: int, role: str):
        self.path, self.cap, self.role = path, cap, role
        self.file: BinaryIO | None = None

    def __enter__(self) -> _StableFile:
        try:
            before = os.lstat(self.path)
            _require(stat.S_ISREG(before.st_mode), self.role + "_not_regular")
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
            self.file = os.fdopen(fd, "rb")
            opened = os.fstat(self.file.fileno())
            _require(stat.S_ISREG(opened.st_mode) and _snapshot(opened) == _snapshot(before),
                     self.role + "_changed_before_read")
            _require(0 < opened.st_size <= self.cap, self.role + "_size_limit")
            self.original = _snapshot(opened)
            self.region = _Region(self.file, 0, opened.st_size)
            return self
        except OSError as exc:
            if self.file is not None:
                self.file.close()
            raise _Unverified(self.role + "_unavailable") from exc
        except BaseException:
            if self.file is not None:
                self.file.close()
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        assert self.file is not None
        try:
            if exc_type is None:
                try:
                    current = os.lstat(self.path)
                    opened = os.fstat(self.file.fileno())
                except OSError as error:
                    raise _Unverified(self.role + "_changed_while_reading") from error
                _require(_snapshot(current) == self.original == _snapshot(opened),
                         self.role + "_changed_while_reading")
        finally:
            self.file.close()


def _wrapper(artifact: _Region) -> tuple[_Region, dict[str, object]]:
    _require(artifact.size >= 8, "unsupported_hpm_format")
    if artifact.read(0, 8) == b"PICMGFWU":
        return artifact, {}
    _require(artifact.size >= 56, "unsupported_hpm_format")
    header = artifact.read(0, 56)
    _require(re.fullmatch(rb"[0-9a-fA-F]{56}", header) is not None,
             "unsupported_hpm_format")
    values = [int(header[i:i + 8], 16) for i in range(0, 56, 8)]
    _require(values[0:2] == [3, 1] and values[3] == 2 and values[5] == 3,
             "invalid_signed_wrapper_tags")
    manifest_size, cms_size, crl_size = values[2], values[4], values[6]
    _require(0 < manifest_size <= 65536 and 0 < cms_size <= 16 * 1024**2
             and 0 < crl_size <= 16 * 1024**2, "signed_wrapper_size_limit")
    offset = 56 + manifest_size + cms_size + crl_size
    _require(offset < artifact.size, "truncated_signed_wrapper")
    manifest = artifact.sub(56, manifest_size)
    try:
        lines = manifest.read(0, manifest.size).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise _Unverified("invalid_manifest_encoding") from exc
    _require(len(lines) == 4 and lines[0] == "Manifest Version: 1.0"
             and re.fullmatch(r"Create By: [\x20-\x7e]+", lines[1]) is not None
             and re.fullmatch(r"Name: [A-Za-z0-9_.-]+\.hpm", lines[2]) is not None,
             "unsupported_manifest_layout")
    match = re.fullmatch(r"SHA256-Digest: ([0-9a-fA-F]{64})", lines[3])
    _require(match is not None, "missing_or_ambiguous_manifest_digest")
    raw = artifact.sub(offset, artifact.size - offset)
    assert match is not None
    _require(raw.digest() == match.group(1).lower(), "manifest_digest_mismatch")
    return raw, {"manifest": manifest.evidence("artifact"),
                 "manifest_digest_verified": True, "signature_trust_verified": False}


def _picmg(raw: _Region) -> tuple[_Region, _Region, dict[str, object]]:
    _require(raw.size >= 38, "truncated_picmg_header")
    header = raw.read(0, 38)
    _require(header[:8] == b"PICMGFWU" and header[8] == 1
             and header[35:37] == b"\0\0", "unsupported_picmg_header")
    _require(sum(header) % 256 == 0, "picmg_header_checksum_mismatch")
    # This variant has one prepare action followed by CONFIG and APP uploads.
    pos = 38
    prepare = raw.read(pos, 6)
    _require(prepare[0] == 1, "unsupported_picmg_action_order")
    _require(sum(prepare) % 256 == 0, "action_checksum_mismatch")
    _require(prepare[1:5] == b"\x01\0\0\x02", "unsupported_action_components")
    pos += 6
    payloads: dict[str, object] = {}
    app = None
    config = None
    for description, bank_path in ((b"CONFIG", b"/data/conf.tar.gz"),
                                   (b"APP", b"/data/ipmc.jffs2")):
        action = raw.read(pos, 6)
        _require(action[0] == 2, "unsupported_picmg_action_order")
        _require(sum(action) % 256 == 0, "action_checksum_mismatch")
        expected_mask = b"\x01\0\0\0" if description == b"CONFIG" else b"\0\0\0\x02"
        _require(action[1:5] == expected_mask, "unsupported_action_components")
        firmware = raw.read(pos + 6, 31)
        _require(firmware[6:27] == description.ljust(21, b"\0"),
                 "unexpected_or_duplicate_firmware_payload")
        length = struct.unpack_from("<I", firmware, 27)[0]
        _require(length >= 512, "invalid_firmware_payload_length")
        data = raw.sub(pos + 37, length)
        banks = data.read(0, 512)
        _require(banks[:256] == b"\0" * 256 and banks[288:] == b"\0" * 224,
                 "unsupported_or_multiple_active_banks")
        bank_offset, bank_size = struct.unpack_from("<II", banks, 256)
        _require(bank_offset == 512 and bank_size == length - 512,
                 "bank_range_mismatch")
        _require(banks[264:288] == bank_path.ljust(24, b"\0"), "unexpected_bank_path")
        encrypted = data.sub(512, bank_size)
        _cipher_shape(encrypted)
        payloads[description.decode("ascii").lower()] = encrypted.evidence("artifact")
        if description == b"APP":
            app = encrypted
        else:
            config = encrypted
        pos += 37 + length
    _require(pos == raw.size, "unexpected_picmg_trailer_or_action")
    assert app is not None and config is not None
    return app, config, payloads


def _cipher_shape(encrypted: _Region) -> None:
    _require(encrypted.size >= 288, "truncated_cipher_envelope")
    size = encrypted.size - 256
    remainder = size % _CIPHER_RECORD
    _require(size % 16 == 0 and (remainder == 0 or remainder >= 32),
             "invalid_cipher_record_length")
    for offset in range(256, encrypted.size, _CIPHER_RECORD):
        _require(encrypted.read(offset, 16) == _IV, "unsupported_cipher_iv")


def _decrypt(encrypted: _Region, key: bytes, spool: BinaryIO) -> _Region:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise _Unverified("crypto_backend_unavailable") from exc
    written = 0
    for offset in range(256, encrypted.size, _CIPHER_RECORD):
        size = min(_CIPHER_RECORD, encrypted.size - offset)
        record = encrypted.read(offset, size)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(record[:16])).decryptor()
        padded = decryptor.update(record[16:]) + decryptor.finalize()
        pad = padded[-1] if padded else 0
        _require(1 <= pad <= 16 and padded[-pad:] == bytes([pad]) * pad,
                 "invalid_cipher_padding_or_key")
        plain = padded[:-pad]
        _require(0 < len(plain) <= _PLAIN_RECORD
                 and (offset + size == encrypted.size or len(plain) == _PLAIN_RECORD),
                 "invalid_cipher_plaintext_length")
        spool.write(plain)
        written += len(plain)
    spool.flush()
    return _Region(spool, 0, written)


def _gpp(gpp: _Region) -> tuple[_Region, _Region]:
    header = gpp.read(0, 512)
    _require(struct.unpack_from("<I", header)[0] == 3 and not any(header[4:16])
             and not any(header[64:]), "unsupported_gpp_header")
    pos = 512
    rootfs = None
    for index, expected_type in enumerate((0, 4, 1)):
        kind, offset, size, reserved = struct.unpack_from("<IIII", header, 16 + 16 * index)
        _require(kind == expected_type and reserved == 0 and size > 0,
                 "unsupported_gpp_descriptor")
        _require(offset == pos, "gpp_overlap_or_gap")
        region = gpp.sub(offset, size)
        pos += size
        if kind == 1:
            rootfs = region
    _require(pos == gpp.size, "unexpected_gpp_trailer")
    assert rootfs is not None
    subheader = rootfs.read(0, 164)
    magic, size, version, count = struct.unpack_from("<IIHH", subheader)
    _require(magic == 0x55AA55AA and size == rootfs.size and version == 3 and count == 7
             and not any(subheader[12:76])
             and struct.unpack_from("<I", subheader, 160)[0] == 0x33CC33CC,
             "unsupported_rootfs_container_header")
    pos = 164
    archive = None
    for index, expected_type in enumerate((16, 17, 18, 0, 0, 0, 4)):
        kind, offset, size = struct.unpack_from("<III", subheader, 76 + 12 * index)
        if expected_type == 0:
            _require((kind, offset, size) == (0, 0, 0), "ambiguous_rootfs_descriptor")
            continue
        _require(kind == expected_type and size > 0, "unsupported_rootfs_descriptor")
        _require(offset == pos, "rootfs_overlap_or_gap")
        region = rootfs.sub(offset, size)
        pos += size
        if kind == 4:
            archive = region
    _require(pos == rootfs.size, "unexpected_rootfs_container_trailer")
    assert archive is not None
    return rootfs, archive


class _GzipReader:
    """A single gzip stream with bounded output and no concatenation/trailers."""
    def __init__(self, region: _Region, limit: int):
        self.region, self.limit = region, limit
        self.z = zlib.decompressobj(31)
        self.pos = self.produced = 0
        self.pending = b""

    def read(self, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            if self.z.eof:
                _require(not self.z.unused_data and not self.pending
                         and self.pos == self.region.size,
                         "gzip_trailer_or_concatenated_stream")
                break
            if self.pending:
                data, self.pending = self.pending, b""
            else:
                _require(self.pos < self.region.size, "truncated_gzip")
                data = self.region.read(self.pos, min(_CHUNK, self.region.size - self.pos))
                self.pos += len(data)
            try:
                chunk = self.z.decompress(data, min(_CHUNK, size - len(output)))
            except zlib.error as exc:
                raise _Unverified("malformed_gzip") from exc
            self.pending = self.z.unconsumed_tail
            self.produced += len(chunk)
            _require(self.produced <= self.limit, "decompressed_size_limit")
            output.extend(chunk)
        return bytes(output)


def _octal(value: bytes) -> int:
    value = value.strip(b" \0")
    _require(re.fullmatch(rb"[0-7]+", value) is not None, "invalid_tar_numeric_field")
    return int(value, 8)


def _tar_rootfs(archive: _Region, size: int, digest: str) -> dict[str, object]:
    reader = _GzipReader(archive, size + 512 + 511 + _TAR_TAIL_LIMIT)
    header = reader.read(512)
    _require(len(header) == 512, "truncated_tar_header")
    checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
    _require(_octal(header[148:156]) == checksum, "tar_checksum_mismatch")
    _require(header[:100] == b"rootfs_iBMC.img".ljust(100, b"\0")
             and header[156:157] in (b"0", b"\0") and not any(header[157:257])
             and header[257:265] in (b"ustar\00000", b"ustar  \0")
             and not any(header[345:]), "unexpected_or_nonregular_tar_member")
    _require(_octal(header[124:136]) == size, "contained_rootfs_size_mismatch")
    found = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = reader.read(min(_CHUNK, remaining))
        _require(bool(chunk), "truncated_tar_member")
        found.update(chunk)
        remaining -= len(chunk)
    padding = (-size) % 512
    _require(reader.read(padding) == b"\0" * padding, "invalid_tar_member_padding")
    tail = bytearray()
    while True:
        chunk = reader.read(min(_CHUNK, _TAR_TAIL_LIMIT + 1 - len(tail)))
        if not chunk:
            break
        tail.extend(chunk)
        _require(len(tail) <= _TAR_TAIL_LIMIT, "tar_trailer_size_limit")
    _require(len(tail) >= 1024 and len(tail) % 512 == 0 and not any(tail),
             "unexpected_tar_trailer_or_multiple_members")
    _require(found.hexdigest() == digest, "contained_rootfs_hash_mismatch")
    return {"parent": "uncompressed-tar", "offset": 512, "size": size,
            "sha256": found.hexdigest()}


def _matches(actual: str, expected: str | None, role: str) -> None:
    if expected is not None:
        _require(isinstance(expected, str) and re.fullmatch(r"[0-9a-fA-F]{64}", expected)
                 is not None, "invalid_expected_" + role + "_sha256")
        _require(actual == expected.lower(), role + "_hash_mismatch")


def verify_hpm_containment(
    artifact_path: Path,
    rootfs_path: Path,
    *,
    key_path: Path | None = None,
    expected_artifact_sha256: str | None = None,
    expected_rootfs_sha256: str | None = None,
    max_artifact_bytes: int = 1024**3,
    max_rootfs_bytes: int = 4 * 1024**3,
) -> dict[str, object]:
    """Return verified only for an exact, stable byte binding to the rootfs.

    Explicit local AES keys are the only supported decryption input. No key
    search, subprocess, network, extraction, or public key identity is used.
    Missing/unsupported/malformed input always returns an unverified reason.
    """
    report: dict[str, object] = {"schema": SCHEMA, "method": METHOD, "version": 1,
                               "status": "unverified"}
    try:
        _require(type(max_artifact_bytes) is int and max_artifact_bytes > 0
                 and type(max_rootfs_bytes) is int and max_rootfs_bytes > 0,
                 "invalid_size_limit")
        with ExitStack() as stack:
            artifact = stack.enter_context(_StableFile(Path(artifact_path), max_artifact_bytes,
                                                       "artifact")).region
            rootfs = stack.enter_context(_StableFile(Path(rootfs_path), max_rootfs_bytes,
                                                     "rootfs")).region
            report["artifact"] = {"sha256": artifact.digest(), "size": artifact.size}
            report["rootfs"] = {"sha256": rootfs.digest(), "size": rootfs.size}
            _matches(str(report["artifact"]["sha256"]), expected_artifact_sha256, "artifact")
            _matches(str(report["rootfs"]["sha256"]), expected_rootfs_sha256, "rootfs")
            raw, wrapper = _wrapper(artifact)
            encrypted, config, payloads = _picmg(raw)
            _require(key_path is not None, "missing_key")
            key_file = stack.enter_context(_StableFile(Path(key_path), 16, "key"))
            _require(key_file.region.size == 16, "invalid_key_length")
            key = key_file.region.read(0, 16)
            spool = stack.enter_context(tempfile.TemporaryFile(mode="w+b"))
            _decrypt(config, key, spool)
            spool.seek(0)
            spool.truncate()
            gpp = _decrypt(encrypted, key, spool)
            subcontainer, archive = _gpp(gpp)
            contained = _tar_rootfs(archive, rootfs.size, str(report["rootfs"]["sha256"]))
            payloads.update({"hpm": raw.evidence("artifact"), "signed_wrapper": wrapper,
                             "gpp": gpp.evidence("decrypted-app"),
                             "rootfs_container": subcontainer.evidence("decrypted-app"),
                             "archive": archive.evidence("decrypted-app"),
                             "rootfs_member": contained})
        # Closing each input context checks fd and pathname stability first.
        report.update(status="verified", reason="contained_rootfs_digest_matches", payloads=payloads)
    except _Unverified as exc:
        report["reason"] = str(exc)
    except (OSError, ValueError, TypeError, struct.error, zlib.error):
        report["reason"] = "malformed_or_unreadable_input"
    return report


__all__ = ["verify_hpm_containment"]
