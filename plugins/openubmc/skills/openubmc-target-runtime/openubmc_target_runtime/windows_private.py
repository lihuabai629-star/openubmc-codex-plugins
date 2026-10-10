"""Windows current-user file boundary for local Runtime state and credentials.

Only built-in Win32 APIs and icacls are used; credential bytes never cross a
subprocess boundary.  Linux callers do not import or execute these primitives.
"""
from __future__ import annotations

from contextlib import contextmanager
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


class WindowsPrivateError(ValueError):
    pass


def _apis():
    if sys.platform != "win32":
        raise WindowsPrivateError("Windows private storage requires native Windows")
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi.EqualSid.restype = wintypes.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                             ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    return advapi, kernel, wintypes


def _current_user_sid(advapi, kernel, wintypes) -> tuple[str, ctypes.Array]:
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise WindowsPrivateError("Cannot inspect the current Windows user token")
    try:
        required = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi.GetTokenInformation(token, 1, buffer, required, ctypes.byref(required)):
            raise WindowsPrivateError("Cannot inspect the current Windows user token")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = ctypes.c_void_p()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise WindowsPrivateError("Cannot inspect the current Windows user SID")
        try:
            return ctypes.wstring_at(text), buffer
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def _sid_text(advapi, kernel, sid: int) -> str:
    text = ctypes.c_void_p()
    if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise WindowsPrivateError("Cannot inspect a Windows access entry")
    try:
        return ctypes.wstring_at(text)
    finally:
        kernel.LocalFree(text)


def verify_private_path(path: Path, *, safe_parent: bool = False) -> None:
    """Reject a foreign owner, a null DACL, or effective access by other users.

    A parent used only to create a private child may grant read/traverse to
    others, but cannot grant write, delete, ownership or ACL changes.
    """
    path = Path(path)
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise WindowsPrivateError("Private Windows paths cannot be reparse links")
    advapi, kernel, wintypes = _apis()
    user_sid, user_buffer = _current_user_sid(advapi, kernel, wintypes)
    del user_buffer  # The string identity has been copied from the token.
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi.GetNamedSecurityInfoW(str(path), 1, 1 | 4,
                                          ctypes.byref(owner), None, ctypes.byref(dacl),
                                          None, ctypes.byref(descriptor))
    if result:
        raise WindowsPrivateError("Cannot inspect Windows file ownership and access")
    try:
        if not owner.value or _sid_text(advapi, kernel, owner) != user_sid or not dacl.value:
            raise WindowsPrivateError("Windows private path has an unsafe owner or access list")

        class AclSize(ctypes.Structure):
            _fields_ = [("ace_count", wintypes.DWORD), ("bytes_in_use", wintypes.DWORD),
                        ("bytes_free", wintypes.DWORD)]

        size = AclSize()
        if not advapi.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2):
            raise WindowsPrivateError("Cannot inspect Windows access entries")
        trusted = {user_sid, "S-1-3-4", "S-1-5-18", "S-1-5-32-544"}  # Owner Rights, SYSTEM, Administrators.
        # Generic all/write, delete, ACL/owner changes, and directory writes.
        unsafe_parent_rights = (1 << 28) | (1 << 30) | (13 << 16) | 342
        for index in range(size.ace_count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise WindowsPrivateError("Cannot inspect Windows access entries")
            kind = ctypes.c_ubyte.from_address(ace.value).value
            if kind == 1:  # Explicit or inherited deny entry.
                continue
            if kind != 0:  # Unknown or conditional allow entry: fail closed.
                raise WindowsPrivateError("Windows private path has unsupported access entries")
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            sid = _sid_text(advapi, kernel, ace.value + 8)
            if sid not in trusted and mask and (not safe_parent or mask & unsafe_parent_rights):
                raise WindowsPrivateError("Windows private path grants access to another user")
    finally:
        kernel.LocalFree(descriptor)


@contextmanager
def _directory_acl_handle(path: Path, *, write: bool = False):
    """Pin a directory so a path replacement cannot redirect its ACL edit."""
    path = Path(path)
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise WindowsPrivateError("private_root_reparse_link")
    if not path.is_dir():
        raise WindowsPrivateError("private_root_not_directory")
    advapi, kernel, wintypes = _apis()
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    access = (1 << 17) | ((1 << 18) if write else 0)  # READ_CONTROL, WRITE_DAC.
    handle = kernel.CreateFileW(str(path), access, 1 | 2, None, 3,
                                (1 << 25) | (1 << 21), None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise WindowsPrivateError("private_root_inspection_failed")
    try:
        class FileInfo(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD),
                        ("created", wintypes.FILETIME), ("accessed", wintypes.FILETIME),
                        ("modified", wintypes.FILETIME), ("volume", wintypes.DWORD),
                        ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD),
                        ("links", wintypes.DWORD), ("index_high", wintypes.DWORD),
                        ("index_low", wintypes.DWORD)]
        kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInfo)]
        kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        info = FileInfo()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise WindowsPrivateError("private_root_inspection_failed")
        if info.attributes & (1 << 10):  # FILE_ATTRIBUTE_REPARSE_POINT.
            raise WindowsPrivateError("private_root_reparse_link")
        identity = (info.volume, info.index_high, info.index_low)
        yield handle, identity, advapi, kernel, wintypes
    finally:
        kernel.CloseHandle(handle)


def _directory_acl_state(path: Path, handle, identity, advapi, kernel, wintypes) -> dict:
    """Read one handle-bound ACL snapshot before a repair or rollback."""
    user_sid, user_buffer = _current_user_sid(advapi, kernel, wintypes)
    del user_buffer
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    result = advapi.GetSecurityInfo(handle, 1, 1 | 4, ctypes.byref(owner), None,
                                    ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if result:
        raise WindowsPrivateError("private_root_inspection_failed")
    try:
        if not owner.value or _sid_text(advapi, kernel, owner) != user_sid or not dacl.value:
            raise WindowsPrivateError("private_root_unsafe_owner")

        class AclSize(ctypes.Structure):
            _fields_ = [("ace_count", wintypes.DWORD), ("bytes_in_use", wintypes.DWORD),
                        ("bytes_free", wintypes.DWORD)]

        size = AclSize()
        if not advapi.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2):
            raise WindowsPrivateError("private_root_inspection_failed")
        aces = []
        for index in range(size.ace_count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise WindowsPrivateError("private_root_inspection_failed")
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            ace_size = ctypes.c_ushort.from_address(ace.value + 2).value
            if ace_size < 8 or kind not in {0, 1}:
                raise WindowsPrivateError("private_root_unsupported_access")
            aces.append({"kind": kind, "flags": flags,
                         "mask": ctypes.c_uint32.from_address(ace.value + 4).value,
                         "sid": _sid_text(advapi, kernel, ace.value + 8),
                         "bytes": ctypes.string_at(ace, ace_size)})
        advapi.GetSecurityDescriptorLength.argtypes = [ctypes.c_void_p]
        advapi.GetSecurityDescriptorLength.restype = wintypes.DWORD
        length = advapi.GetSecurityDescriptorLength(descriptor)
        if not length:
            raise WindowsPrivateError("private_root_inspection_failed")
        digest = hashlib.sha256()
        digest.update(str(path.absolute()).casefold().encode("utf-8"))
        digest.update(str(identity).encode("ascii"))
        digest.update(ctypes.string_at(descriptor, length))
        advapi.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p,
                                                         ctypes.POINTER(wintypes.WORD),
                                                         ctypes.POINTER(wintypes.DWORD)]
        advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise WindowsPrivateError("private_root_inspection_failed")
        return {"token": digest.hexdigest(), "acl": ctypes.string_at(dacl, size.bytes_in_use),
                "aces": aces, "protected": bool(control.value & (1 << 12)),
                "identity": identity}
    finally:
        kernel.LocalFree(descriptor)


def _inherited_read_plan(path: Path, handle, identity, advapi, kernel, wintypes) -> dict:
    """Omit only the inherited read-only outside allows from one ACL snapshot."""
    state = _directory_acl_state(path, handle, identity, advapi, kernel, wintypes)
    user_sid, user_buffer = _current_user_sid(advapi, kernel, wintypes)
    del user_buffer
    trusted = {user_sid, "S-1-3-4", "S-1-5-18", "S-1-5-32-544"}
    read_only = (1 << 31) | (1 << 29) | 0x1200A9
    retained = []
    removed = False
    for ace in state["aces"]:
        if ace["sid"] in trusted or not ace["mask"]:
            retained.append(ace["bytes"])
        elif ace["kind"] != 0 or not ace["flags"] & 0x10:
            raise WindowsPrivateError("private_root_explicit_outside_access")
        elif ace["mask"] & ~read_only:
            raise WindowsPrivateError("private_root_outside_write_access")
        else:
            removed = True
    if not removed:
        raise WindowsPrivateError("private_root_not_repairable")
    return {**state, "retained": retained}


def _inherited_read_snapshot(path: Path) -> str:
    with _directory_acl_handle(path) as (handle, identity, advapi, kernel, wintypes):
        return _inherited_read_plan(path, handle, identity, advapi, kernel, wintypes)["token"]


def _set_directory_acl(handle, advapi, acl: bytes, *, protected: bool) -> None:
    advapi.SetSecurityInfo.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_ulong,
                                      ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    advapi.SetSecurityInfo.restype = ctypes.c_ulong
    buffer = ctypes.create_string_buffer(acl)
    protection = (1 << 31) if protected else (1 << 29)
    if advapi.SetSecurityInfo(handle, 1, 4 | protection, None, None, buffer, None):
        raise WindowsPrivateError("private_root_acl_update_failed")


def _retained_acl(advapi, retained: list[bytes]) -> bytes:
    size = 8 + sum(len(ace) for ace in retained)
    buffer = ctypes.create_string_buffer(size)
    advapi.InitializeAcl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    advapi.InitializeAcl.restype = ctypes.c_int
    advapi.AddAce.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                              ctypes.c_void_p, ctypes.c_ulong]
    advapi.AddAce.restype = ctypes.c_int
    if not advapi.InitializeAcl(buffer, size, 4):
        raise WindowsPrivateError("private_root_acl_update_failed")
    for ace in retained:
        copy = ctypes.create_string_buffer(ace)
        if not advapi.AddAce(buffer, 4, ctypes.c_ulong(-1).value, copy, len(ace)):
            raise WindowsPrivateError("private_root_acl_update_failed")
    return buffer.raw


def private_directory_recovery_status(path: Path) -> dict[str, str]:
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return {"status": "ready"}
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        return {"status": "blocked", "reason_code": "private_root_reparse_link"}
    if not path.is_dir():
        return {"status": "blocked", "reason_code": "private_root_not_directory"}
    try:
        verify_private_path(path)
        return {"status": "ready"}
    except (WindowsPrivateError, OSError):
        pass
    try:
        return {"status": "repairable", "snapshot_token": _inherited_read_snapshot(path)}
    except (WindowsPrivateError, OSError) as error:
        code = str(error) if str(error).startswith("private_root_") else "private_root_inspection_failed"
        return {"status": "blocked", "reason_code": code}


def _recovery_record_path(path: Path, transaction: str) -> Path:
    if len(transaction) != 32 or any(character not in "0123456789abcdef" for character in transaction):
        raise WindowsPrivateError("private_root_unknown_transaction")
    return path.parent / "openubmc-acl-recovery" / (transaction + ".json")


def _write_recovery_record(path: Path, record: dict, *, create: bool) -> None:
    content = (json.dumps(record, sort_keys=True) + "\n").encode()
    if create:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(descriptor)
        try:
            harden_new_file(path)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    else:
        verify_private_path(path)
    temporary = path.with_name("." + path.stem + "-" + secrets.token_hex(8) + ".tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(descriptor)
    try:
        harden_new_file(temporary)
        with temporary.open("wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        verify_private_path(path)
    finally:
        temporary.unlink(missing_ok=True)


def repair_inherited_read_directory(path: Path, *, expected_token: str) -> str:
    path = Path(path)
    if not isinstance(expected_token, str) or len(expected_token) != 64:
        raise WindowsPrivateError("private_root_changed")
    with _directory_acl_handle(path, write=True) as (handle, identity, advapi, kernel, wintypes):
        plan = _inherited_read_plan(path, handle, identity, advapi, kernel, wintypes)
        if plan["token"] != expected_token:
            raise WindowsPrivateError("private_root_changed")
        backup = path.parent / "openubmc-acl-recovery"
        ensure_private_directory(backup)
        transaction = secrets.token_hex(16)
        record_path = _recovery_record_path(path, transaction)
        new_acl = _retained_acl(advapi, plan["retained"])
        record = {"schema": "openubmc.windows-acl-recovery.v1", "path": str(path),
                  "identity": list(identity), "original_token": plan["token"],
                  "original_acl": base64.b64encode(plan["acl"]).decode("ascii"),
                  "original_protected": plan["protected"],
                  "expected_acl": base64.b64encode(new_acl).decode("ascii"),
                  "status": "pending"}
        _write_recovery_record(record_path, record, create=True)
        changed = False
        try:
            if _directory_acl_state(path, handle, identity, advapi, kernel, wintypes)["token"] != plan["token"]:
                raise WindowsPrivateError("private_root_changed")
            _set_directory_acl(handle, advapi, new_acl, protected=True)
            changed = True
            verify_private_path(path)
            after = _directory_acl_state(path, handle, identity, advapi, kernel, wintypes)
            record.update(status="repaired", after_token=after["token"])
            _write_recovery_record(record_path, record, create=False)
        except BaseException:
            if changed:
                try:
                    _set_directory_acl(handle, advapi, plan["acl"], protected=plan["protected"])
                except WindowsPrivateError as exc:
                    raise WindowsPrivateError("private_root_rollback_failed") from exc
            record_path.unlink(missing_ok=True)
            raise
        return transaction


def restore_inherited_read_directory(path: Path, *, transaction: str) -> None:
    path = Path(path)
    record_path = _recovery_record_path(path, transaction)
    verify_private_path(record_path.parent)
    verify_private_path(record_path)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if (record.get("schema") != "openubmc.windows-acl-recovery.v1"
            or record.get("path") != str(path)):
        raise WindowsPrivateError("private_root_unknown_transaction")
    with _directory_acl_handle(path, write=True) as (handle, identity, advapi, kernel, wintypes):
        if record.get("identity") != list(identity):
            raise WindowsPrivateError("private_root_changed")
        current = _directory_acl_state(path, handle, identity, advapi, kernel, wintypes)
        expected_acl = base64.b64decode(record["expected_acl"], validate=True)
        if (record.get("status") == "repaired" and current["token"] != record.get("after_token")
                or record.get("status") == "pending" and
                (current["acl"] != expected_acl or not current["protected"])):
            raise WindowsPrivateError("private_root_changed")
        if record.get("status") not in {"repaired", "pending"}:
            raise WindowsPrivateError("private_root_unknown_transaction")
        original = base64.b64decode(record["original_acl"], validate=True)
        _set_directory_acl(handle, advapi, original, protected=record["original_protected"])
        try:
            restored = _inherited_read_plan(path, handle, identity, advapi, kernel, wintypes)
            if restored["acl"] != original:
                raise WindowsPrivateError("private_root_restore_failed")
        except BaseException:
            _set_directory_acl(handle, advapi, current["acl"], protected=current["protected"])
            raise
    record_path.unlink()


def _harden(path: Path, *, directory: bool) -> None:
    advapi, kernel, wintypes = _apis()
    sid, _buffer = _current_user_sid(advapi, kernel, wintypes)
    suffix = ":(OI)(CI)F" if directory else ":F"
    result = subprocess.run(
        ["icacls.exe", str(path), "/inheritance:r", "/grant:r",
         f"*{sid}{suffix}", f"*S-1-5-18{suffix}", f"*S-1-5-32-544{suffix}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=1 << 27, timeout=10,  # CREATE_NO_WINDOW
    )
    if result.returncode:
        raise WindowsPrivateError("Cannot establish current-user Windows access")
    verify_private_path(path)


def ensure_private_directory(path: Path) -> None:
    path = Path(path)
    if path.exists():
        if not path.is_dir():
            raise WindowsPrivateError("Private configuration path is not a directory")
        verify_private_path(path)
        return
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise WindowsPrivateError("Private configuration path cannot be a reparse link")
    parent = path.parent
    if parent == path:
        raise WindowsPrivateError("Cannot establish a private configuration directory")
    if not parent.exists():
        ensure_private_directory(parent)
    else:
        verify_private_path(parent, safe_parent=True)
    try:
        path.mkdir()
    except FileExistsError:
        verify_private_path(path)
        return
    try:
        _harden(path, directory=True)
    except BaseException:
        path.rmdir()
        raise


def harden_new_file(path: Path) -> None:
    _harden(Path(path), directory=False)


@contextmanager
def locked_file(descriptor: int, *, blocking: bool = True):
    """Hold one mandatory Windows byte-range lock across the caller's update."""
    if sys.platform != "win32":
        raise WindowsPrivateError("Windows file locking requires native Windows")
    import msvcrt

    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.fstat(descriptor).st_size == 0:
        os.write(descriptor, b"\0")
        os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        msvcrt.locking(descriptor, msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        raise WindowsPrivateError("Windows configuration lock is held by another process") from exc
    try:
        yield
    finally:
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
