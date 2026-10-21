"""Bounded, offline iOS package inspection. No target content is executed.

This is a metadata/string inspector, not a decompiler or a signature verifier.
All offsets are zero-based offsets in the named file, including fat Mach-O files.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import tempfile
import zipfile

MAX_ENTRIES = 10_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_PLIST_BYTES = 8 * 1024 * 1024
MAX_CANDIDATES = 10_000
MAX_SOURCES = 32
MAX_COMMAND_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 10_000
CHUNK_BYTES = 1024 * 1024
MAX_LITERAL = 4096
_THIN = {b"\xce\xfa\xed\xfe": ("<", 32), b"\xcf\xfa\xed\xfe": ("<", 64),
         b"\xfe\xed\xfa\xce": (">", 32), b"\xfe\xed\xfa\xcf": (">", 64)}
_FAT = {b"\xca\xfe\xba\xbe": (">", 32), b"\xbe\xba\xfe\xca": ("<", 32),
        b"\xca\xfe\xba\xbf": (">", 64), b"\xbf\xba\xfe\xca": ("<", 64)}
_DYLIB_CMDS = {0xC, 0x18, 0x1F, 0x20, 0x23}
_PATTERNS = {
    "url": re.compile(rb"(?i)\b(?:https?|wss?)://[^\s\x00-\x20\x7f<>\"'\\]{1,4096}"),
    "domain": re.compile(rb"(?i)(?<![a-z0-9_@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?![a-z0-9_.-])"),
    "path": re.compile(rb"(?<![A-Za-z0-9:/])/(?:[A-Za-z0-9_~.@%+{}:-]+/)*[A-Za-z0-9_~.@%+{}:-]+(?:\?[^\s\x00<>\"']{1,1024})?"),
}
_OBJC = re.compile(rb"(?:_?OBJC_CLASS_\$_[A-Za-z_][A-Za-z0-9_]{1,200}|(?:[A-Za-z_][A-Za-z0-9_]{0,100}:){1,12})")
_ESCAPED_URL = re.compile(rb"(?i)\b(?:https?|wss?):\\/\\/[^\s\x00-\x20\x7f<>\"']{1,4096}")


class AnalysisError(ValueError):
    """Unsafe input or an explicit resource limit was encountered."""


def _json_value(value, depth=0):
    if depth > 24:
        return "[nested value omitted: depth limit]"
    if isinstance(value, dict):
        result = {str(k)[:1024]: _json_value(v, depth + 1) for k, v in list(value.items())[:1000]}
        if len(value) > 1000:
            result["__truncated__"] = True
        return result
    if isinstance(value, (list, tuple)):
        result = [_json_value(v, depth + 1) for v in value[:1000]]
        if len(value) > 1000:
            result.append("[items omitted: limit]")
        return result
    if isinstance(value, bytes):
        return {"base64_prefix": base64.b64encode(value[:2048]).decode(), "length": len(value), "truncated": len(value) > 2048}
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, str):
        return value if len(value) <= MAX_LITERAL else value[:MAX_LITERAL] + "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_LITERAL]


def _read_at(handle, offset, length, limit):
    if offset < 0 or length < 0 or offset + length > limit:
        raise AnalysisError("binary range is outside file/slice")
    handle.seek(offset)
    data = handle.read(length)
    if len(data) != length:
        raise AnalysisError("truncated binary")
    return data


def _parse_plist(data):
    if len(data) > MAX_PLIST_BYTES:
        raise AnalysisError("plist exceeds 8 MiB parser limit")
    # plistlib does not resolve external entities; reject any entity declaration too.
    if b"<!ENTITY" in data.upper():
        raise AnalysisError("XML entity declarations are not accepted")
    try:
        value = plistlib.loads(data)
    except Exception as exc:
        # plistlib can raise XML/binary parser specific exceptions.
        raise AnalysisError("invalid plist: " + type(exc).__name__) from exc
    if not isinstance(value, dict):
        raise AnalysisError("expected a plist dictionary")
    return value


def _signature(handle, absolute, length, file_limit):
    result = {"classification": "confirmed_configuration", "offset": absolute,
              "size": length, "signature_verification": "unverified", "entitlements": []}
    if length > MAX_COMMAND_BYTES:
        result["warning"] = "code signature exceeds parser limit; presence only"
        return result
    blob = _read_at(handle, absolute, length, file_limit)
    if len(blob) < 12:
        result["warning"] = "truncated code signature blob"
        return result
    magic, blob_len, count = struct.unpack_from(">III", blob)
    if magic != 0xFADE0CC0 or blob_len > len(blob) or count > 1024 or 12 + 8 * count > blob_len:
        result["warning"] = "unsupported or malformed signature superblob"
        return result
    for index in range(count):
        slot, offset = struct.unpack_from(">II", blob, 12 + 8 * index)
        if offset < 12 + 8 * count or offset + 8 > blob_len:
            result["warning"] = "invalid code signature child range"
            continue
        child_magic, child_len = struct.unpack_from(">II", blob, offset)
        if child_len < 8 or offset + child_len > blob_len:
            result["warning"] = "invalid code signature child length"
            continue
        if child_magic == 0xFADE7171:
            try:
                ent = _parse_plist(blob[offset + 8:offset + child_len])
                result["entitlements"].append({"classification": "confirmed_configuration", "slot": slot,
                    "offset": absolute + offset + 8, "value": _json_value(ent),
                    "note": "Embedded entitlement values; signature and runtime grant not verified."})
            except AnalysisError as exc:
                result["warning"] = str(exc)
        elif child_magic == 0xFADE7172:
            result["entitlements"].append({"classification": "unverified", "slot": slot,
                "offset": absolute + offset + 8, "encoding": "DER", "note": "DER entitlements not decoded."})
    return result


def _thin(handle, start, size, file_size):
    magic = _read_at(handle, start, 4, file_size)
    if magic not in _THIN:
        raise AnalysisError("fat slice is not a supported Mach-O")
    endian, bits = _THIN[magic]
    header_size = 32 if bits == 64 else 28
    if size < header_size:
        raise AnalysisError("truncated Mach-O header")
    header = _read_at(handle, start, header_size, start + size)
    _, cpu, subtype, filetype, ncmds, cmdbytes, flags = struct.unpack_from(endian + "IiiIIII", header)
    result = {"classification": "confirmed_configuration", "offset": start, "size": size,
              "bits": bits, "byte_order": "little" if endian == "<" else "big", "cpu_type": cpu,
              "cpu_subtype": subtype, "file_type": filetype, "flags": flags, "valid": True,
              "encryption": [], "dependencies": [], "rpaths": [], "code_signatures": [], "warnings": []}
    if cmdbytes > MAX_COMMAND_BYTES or ncmds > 100_000 or ncmds * 8 > cmdbytes or header_size + cmdbytes > size:
        raise AnalysisError("invalid or oversized Mach-O load command region")
    cursor = start + header_size
    end = cursor + cmdbytes
    signature_bytes = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack(endian + "II", _read_at(handle, cursor, 8, end))
        if cmdsize < 8 or cmdsize % 4 or cursor + cmdsize > end:
            raise AnalysisError("invalid Mach-O load command size")
        raw = _read_at(handle, cursor, cmdsize, end)
        basecmd = cmd & 0x7FFFFFFF
        if basecmd in (0x21, 0x2C):
            minimum = 24 if basecmd == 0x2C else 20
            if cmdsize < minimum:
                raise AnalysisError("truncated encryption command")
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", raw, 8)
            range_valid = cryptoff + cryptsize <= size
            result["encryption"].append({"classification": "confirmed_configuration", "command_offset": cursor,
                "cryptoff": cryptoff, "absolute_offset": start + cryptoff, "cryptsize": cryptsize,
                "cryptid": cryptid, "encrypted": cryptid != 0, "range_valid": range_valid})
            if not range_valid:
                result["valid"] = False
                result["warnings"].append("encryption range outside Mach-O slice")
        elif basecmd == 0x1D:
            if cmdsize < 16:
                raise AnalysisError("truncated code signature command")
            offset, length = struct.unpack_from(endian + "II", raw, 8)
            if offset + length > size:
                result["valid"] = False
                result["warnings"].append("code signature range outside Mach-O slice")
            else:
                signature_bytes += length
                if signature_bytes > MAX_COMMAND_BYTES or len(result["code_signatures"]) >= 16:
                    if "signature parsing resource limit reached" not in result["warnings"]:
                        result["warnings"].append("signature parsing resource limit reached")
                    cursor += cmdsize
                    continue
                signature = _signature(handle, start + offset, length, file_size)
                signature["command_offset"] = cursor
                result["code_signatures"].append(signature)
        elif basecmd in _DYLIB_CMDS or basecmd == 0x1C:
            minimum = 12 if basecmd == 0x1C else 24
            if cmdsize < minimum:
                raise AnalysisError("truncated dependency/rpath command")
            stroff = struct.unpack_from(endian + "I", raw, 8)[0]
            if stroff < minimum or stroff >= cmdsize:
                raise AnalysisError("invalid dependency/rpath name offset")
            name = raw[stroff:].split(b"\0", 1)[0].decode("utf-8", "replace")[:MAX_LITERAL]
            target = "rpaths" if basecmd == 0x1C else "dependencies"
            result[target].append({"classification": "confirmed_configuration", "value": name,
                                   "offset": cursor + stroff, "command": hex(cmd)})
        cursor += cmdsize
    if cursor != end:
        result["valid"] = False
        result["warnings"].append("load command count/size mismatch")
    result["encrypted"] = any(e["encrypted"] for e in result["encryption"])
    result["encryption_status"] = ("encrypted" if result["encrypted"] else
        "cryptid_zero" if result["encryption"] else "no_encryption_command")
    return result


def inspect_macho(path: Path) -> dict:
    """Inspect thin/fat Mach-O headers without tools or executing target code.

    encrypted=False means no nonzero cryptid was observed, never proof that a dump
    is complete or executable. Check valid, warnings, and every architecture too.
    """
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AnalysisError("Mach-O input must be a regular non-symlink file")
    file_size = path.stat().st_size
    result = {"is_macho": False, "format": None, "valid": False, "encrypted": None,
              "architectures": [], "warnings": [], "decryption_verified": False}
    with path.open("rb") as handle:
        magic = handle.read(4)
        if magic not in _THIN and magic not in _FAT:
            return result
        result["is_macho"] = True
        result["format"] = "thin" if magic in _THIN else "fat"
        try:
            if magic in _THIN:
                result["architectures"].append(_thin(handle, 0, file_size, file_size))
            else:
                endian, bits = _FAT[magic]
                count = struct.unpack(endian + "I", _read_at(handle, 4, 4, file_size))[0]
                width = 32 if bits == 64 else 20
                if not 1 <= count <= 128 or 8 + count * width > file_size:
                    raise AnalysisError("invalid fat Mach-O architecture table")
                ranges = []
                for index in range(count):
                    raw = _read_at(handle, 8 + index * width, width, file_size)
                    if bits == 64:
                        cpu, subtype, offset, size, align, _reserved = struct.unpack(endian + "iiQQII", raw)
                    else:
                        cpu, subtype, offset, size, align = struct.unpack(endian + "iiIII", raw)
                    if not size or offset < 8 + count * width or offset + size > file_size or align > 63:
                        raise AnalysisError("invalid fat Mach-O slice range")
                    if any(offset < old_end and offset + size > old_start for old_start, old_end in ranges):
                        raise AnalysisError("overlapping fat Mach-O slices")
                    ranges.append((offset, offset + size))
                    arch = _thin(handle, offset, size, file_size)
                    if arch["cpu_type"] != cpu or arch["cpu_subtype"] != subtype:
                        arch["valid"] = False
                        arch["warnings"].append("fat table and Mach-O CPU fields disagree")
                    result["architectures"].append(arch)
            result["valid"] = all(a["valid"] for a in result["architectures"])
        except (AnalysisError, struct.error, OverflowError) as exc:
            result["warnings"].append(str(exc))
        result["encrypted"] = (True if any(a["encrypted"] for a in result["architectures"])
                               else False if result["valid"] else None)
        result["encryption_status"] = ("encrypted" if result["encrypted"] is True else
            "unverified" if result["encrypted"] is None else "no_nonzero_cryptid_observed")
        result["analysis_complete"] = False
    return result


def _zip_extract(path, destination):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise AnalysisError("archive exceeds 10000 entry limit")
        seen, total, plans = set(), 0, []
        for entry in entries:
            name = entry.filename
            parts = PurePosixPath(name).parts
            mode = entry.external_attr >> 16
            filetype = stat.S_IFMT(mode)
            if (not name or "\\" in name or "\0" in name or name.startswith("/") or
                    any(p in ("..", ".") for p in name.rstrip("/").split("/")) or
                    any(":" in p for p in parts) or not parts or len(name) > 1024):
                raise AnalysisError("unsafe archive path")
            normalized = str(PurePosixPath(name))
            if normalized in seen:
                raise AnalysisError("duplicate archive path")
            seen.add(normalized)
            if filetype not in (0, stat.S_IFREG, stat.S_IFDIR) or stat.S_ISLNK(mode):
                raise AnalysisError("archive symlinks/special files are not accepted")
            if entry.flag_bits & 1:
                raise AnalysisError("password-encrypted archives are not supported")
            if entry.file_size > MAX_FILE_BYTES:
                raise AnalysisError("archive member exceeds 128 MiB limit")
            if entry.file_size > 1024 * 1024 and entry.file_size > max(1, entry.compress_size) * 1000:
                raise AnalysisError("archive compression ratio exceeds zip-bomb limit")
            total += entry.file_size
            if total > MAX_TOTAL_BYTES:
                raise AnalysisError("archive exceeds 512 MiB expanded limit")
            plans.append((entry, destination.joinpath(*parts)))
        # Parent-file collisions are rejected before writing any archive payload.
        file_names = {str(PurePosixPath(e.filename)) for e, _ in plans if not e.is_dir()}
        for entry, _ in plans:
            if any(str(parent) in file_names for parent in PurePosixPath(entry.filename).parents if str(parent) != "."):
                raise AnalysisError("archive file/directory collision")
        actual_total = 0
        for entry, target in plans:
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            actual = 0
            with archive.open(entry) as source, target.open("xb") as output:
                while block := source.read(CHUNK_BYTES):
                    actual += len(block)
                    actual_total += len(block)
                    if actual > MAX_FILE_BYTES or actual_total > MAX_TOTAL_BYTES or actual > entry.file_size:
                        raise AnalysisError("archive expanded data exceeds declared/resource limit")
                    output.write(block)
            if actual != entry.file_size:
                raise AnalysisError("archive member length mismatch")


def _collect_files(root):
    files, count, total = [], 0, 0
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        names.sort()
        for name in dirs + names:
            path = Path(current) / name
            info = path.lstat()
            count += 1
            if count > MAX_ENTRIES:
                raise AnalysisError("app exceeds 10000 entries")
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise AnalysisError("app symlinks/special files are not accepted")
            if len(path.relative_to(root).as_posix()) > 1024:
                raise AnalysisError("app path exceeds limit")
            if stat.S_ISREG(info.st_mode):
                if info.st_size > MAX_FILE_BYTES:
                    raise AnalysisError("app file exceeds 128 MiB limit")
                total += info.st_size
                if total > MAX_TOTAL_BYTES:
                    raise AnalysisError("app exceeds 512 MiB limit")
                files.append(path)
    return files


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(CHUNK_BYTES):
            digest.update(block)
    return digest.hexdigest()


class _Candidates:
    def __init__(self):
        self.items = {}
        self.omitted = 0
        self.omitted_sources = 0

    def add(self, kind, value, source):
        value = value.rstrip(".,;)")[:MAX_LITERAL]
        if kind == "domain":
            value = value.lower()
        if not value:
            return
        key = (kind, value)
        if key not in self.items:
            if len(self.items) >= MAX_CANDIDATES:
                self.omitted += 1
                return
            self.items[key] = {"classification": "candidate", "kind": kind, "value": value,
                               "sources": [], "source_count": 0, "sources_truncated": False}
        record = self.items[key]
        if source in record["sources"]:
            return
        record["source_count"] += 1
        if len(record["sources"]) < MAX_SOURCES:
            record["sources"].append(source)
        else:
            record["sources_truncated"] = True
            self.omitted_sources += 1


def _scan(path, relative, candidates, objc=False):
    """Scan bytes with overlap; cap each regex match and retain true file offsets."""
    patterns = dict(_PATTERNS)
    patterns["escaped_url"] = _ESCAPED_URL
    if objc:
        patterns["objc_string"] = _OBJC
    overlap = MAX_LITERAL + 512
    with path.open("rb") as handle:
        carry, prefix, position = b"", b"", 0
        while True:
            block = handle.read(CHUNK_BYTES)
            data = prefix + carry + block
            base = position - len(carry) - len(prefix)
            safe_end = len(data) if not block else max(0, len(data) - overlap)
            for kind, pattern in patterns.items():
                for match in pattern.finditer(data):
                    # Defer matches starting in the retained tail to the next iteration.
                    if match.start() < len(prefix) or match.start() >= safe_end:
                        continue
                    if (kind == "domain" and len(match.group()) > 253) or (kind == "path" and len(match.group()) > MAX_LITERAL):
                        continue
                    value = match.group().decode("utf-8", "replace")
                    output_kind = kind
                    if kind == "escaped_url":
                        output_kind, value = "url", value.replace("\\/", "/")
                    candidates.add(output_kind, value, {"file": relative, "offset": base + match.start(), "encoding": "escaped_string" if kind == "escaped_url" else "byte_string"})
            if not block:
                break
            # Preserve from safe_end; starts before it were already processed.
            prefix = data[safe_end - 1:safe_end] if safe_end else b""
            carry = data[safe_end:]
            position += len(block)


def _structured_strings(value, raw, relative, candidates):
    """Recover exact values from binary/XML plists and JSON, including escaped text.

    A container offset is explicit when a decoded string cannot be mapped directly
    to original bytes; the key path then identifies the structured source value.
    """
    pending, visited = [(value, "$", 0)], 0
    search_budget = min(MAX_PLIST_BYTES, 4 * len(raw))
    while pending and visited < 50_000:
        item, key, depth = pending.pop()
        visited += 1
        if depth > 24:
            continue
        if isinstance(item, dict):
            pending.extend((v, (key + "." + str(k))[:2048], depth + 1) for k, v in list(item.items())[:5000])
        elif isinstance(item, list):
            pending.extend((v, (key + f"[{i}]")[:2048], depth + 1) for i, v in enumerate(item[:5000]))
        elif isinstance(item, str) and len(item) <= MAX_LITERAL:
            encoded = item.encode("utf-8")
            search_length = min(search_budget, len(raw))
            location = raw.find(encoded, 0, search_length) if encoded else -1
            search_budget -= search_length
            encoding, scale = "utf-8", 1
            if location < 0 and item:
                search_length = min(search_budget, len(raw))
                location = raw.find(item.encode("utf-16be"), 0, search_length)
                search_budget -= search_length
                encoding, scale = "utf-16be", 2
            for kind, pattern in _PATTERNS.items():
                for match in pattern.finditer(encoded):
                    offset = location + match.start() if scale == 1 else location + len(encoded[:match.start()].decode("utf-8", "ignore").encode("utf-16be"))
                    candidates.add(kind, match.group().decode("utf-8", "replace"), {
                        "file": relative, "offset": max(0, offset) if location >= 0 else 0,
                        "offset_scope": "string" if location >= 0 else "structured_container",
                        "encoding": encoding if location >= 0 else "decoded_value", "key_path": key})


def _finding(findings, kind, value, relative, key, note="", offset=0):
    if len(findings) >= MAX_FINDINGS:
        return
    findings.append({"classification": "confirmed_configuration", "kind": kind, "value": _json_value(value),
                     "source": {"file": relative, "offset": offset, "plist_key": key}, "note": note})


def _info_findings(info, relative, findings):
    for key in ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleShortVersionString", "CFBundleVersion"):
        if key in info:
            _finding(findings, "bundle_metadata", info[key], relative, key)
    ats = info.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        for key, value in ats.items():
            if key != "NSExceptionDomains":
                _finding(findings, "ats_configuration", value, relative, "NSAppTransportSecurity." + key,
                         "Declared ATS value; runtime network behavior has not been tested.")
        exceptions = ats.get("NSExceptionDomains", {})
        if isinstance(exceptions, dict):
            for domain, values in exceptions.items():
                _finding(findings, "ats_domain_exception", {"domain": domain, "settings": values}, relative,
                         "NSAppTransportSecurity.NSExceptionDomains." + str(domain),
                         "HTTP/relaxed TLS allowances are configuration only, not a verified vulnerability.")
    types = info.get("CFBundleURLTypes", [])
    if isinstance(types, list):
        for index, item in enumerate(types):
            if isinstance(item, dict) and "CFBundleURLSchemes" in item:
                _finding(findings, "url_scheme", item["CFBundleURLSchemes"], relative,
                         f"CFBundleURLTypes[{index}].CFBundleURLSchemes", "Declared handler; reachability/authentication not tested.")
    if "LSApplicationQueriesSchemes" in info:
        _finding(findings, "queried_url_schemes", info["LSApplicationQueriesSchemes"], relative, "LSApplicationQueriesSchemes")
    for key, value in info.items():
        if key.startswith("NS") and key.endswith("UsageDescription"):
            _finding(findings, "permission_description", value, relative, key, "Description exists; permission grant/use not verified.")
        if key in ("UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace", "UISupportsDocumentBrowser",
                   "NSFileProtectionComplete", "NSURLIsExcludedFromBackupKey", "NSFileProtectionKey"):
            _finding(findings, "storage_configuration", value, relative, key,
                     "Plist value only; does not establish runtime file protection or backup exclusion.")


def _profile(path, relative, findings):
    if path.stat().st_size > MAX_PLIST_BYTES:
        raise AnalysisError("mobileprovision exceeds parser limit")
    data = path.read_bytes()
    start = data.find(b"<?xml")
    if start < 0:
        start = data.find(b"<plist")
    end = data.find(b"</plist>", max(start, 0))
    if start < 0 or end < 0:
        raise AnalysisError("no embedded XML plist found in provisioning profile")
    profile = _parse_plist(data[start:end + len(b"</plist>")])
    for key in ("Name", "UUID", "TeamIdentifier", "CreationDate", "ExpirationDate", "ProvisionsAllDevices", "Entitlements"):
        if key in profile:
            _finding(findings, "profile_entitlements" if key == "Entitlements" else "provisioning_metadata",
                     profile[key], relative, key,
                     "Extracted embedded plist; CMS signature and effective runtime entitlements are unverified.", start)


def _write_artifact(path, chunks):
    # Never overwrite a destination symlink; replace only after the size guard passes.
    fd, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    written = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            for chunk in chunks:
                block = chunk.encode("utf-8")
                written += len(block)
                if written >= MAX_ARTIFACT_BYTES:
                    raise AnalysisError("report would exceed 50 MiB artifact limit")
                handle.write(block)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _md_code(value):
    value = str(value).replace("\n", " ").replace("\r", " ")
    width = max((len(part) for part in re.findall(r"`+", value)), default=0) + 1
    delimiter = "`" * width
    return delimiter + " " + value + " " + delimiter


def _markdown(report):
    yield "# iOS 静态端点候选清单\n\n"
    yield "所有端点/域名/路径/ObjC 字符串均为 candidate：未联网验证，不代表可调用 API 或漏洞。\n\n"
    yield "配置字段为 confirmed_configuration；签名有效性、实际权限、备份范围与运行行为均为 unverified。\n\n"
    yield "加密 Mach-O 只能分析可见头部/资源；复制安装目录不等于脱壳。本工具不反编译、不还原源代码。\n\n"
    for item in report["candidates"]:
        yield f"- **candidate / {item['kind']}** {_md_code(item['value'])}\n"
        for source in item["sources"]:
            scope = "容器起始偏移" if source.get("offset_scope") == "structured_container" else "字节偏移"
            key = " · " + _md_code(source["key_path"]) if "key_path" in source else ""
            yield f"  - {_md_code(source['file'])} · {scope} {source['offset']}{key}\n"
        if item["sources_truncated"]:
            yield f"  - 来源超过 {MAX_SOURCES} 个，已截断；总命中 {item['source_count']}。\n"
    yield "\n## 限制与未验证项\n\n"
    for entry in report["limitations"]:
        yield f"- unverified: {entry}\n"


def analyze_package(path: Path, output_dir: Path) -> dict:
    """Analyze a local IPA/ZIP or .app directory and write bounded JSON/Markdown.

    Raises AnalysisError/ValueError on unsafe paths or resource limits. Returns
    summary plus files (basenames only). No network, device, external executables.
    """
    path, output_dir = Path(path), Path(output_dir)
    if path.is_symlink() or not path.exists():
        raise AnalysisError("input must exist and cannot be a symlink")
    resolved = path.resolve()
    destination = output_dir.resolve()
    if path.is_dir() and (destination == resolved or resolved in destination.parents):
        raise AnalysisError("output directory must be outside the app input")
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ios-static-", dir=output_dir) as scratch:
        if path.is_dir():
            root, input_kind = path, "app_directory"
        elif path.is_file() and zipfile.is_zipfile(path):
            root, input_kind = Path(scratch), "ipa_zip"
            try:
                _zip_extract(path, root)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                raise AnalysisError("invalid or unsupported ZIP: " + str(exc)) from exc
        else:
            raise AnalysisError("input must be an IPA/ZIP or app directory")
        files = _collect_files(root)
        candidates, findings, binaries, inventory, warnings = _Candidates(), [], [], [], []
        for file in files:
            relative = file.relative_to(root).as_posix()
            inventory.append({"file": relative, "size": file.stat().st_size, "sha256": _sha256(file)})
            macho = inspect_macho(file)
            if macho["is_macho"]:
                macho["file"] = relative
                binaries.append(macho)
                for arch in macho["architectures"]:
                    for signature in arch["code_signatures"]:
                        for entitlement in signature["entitlements"]:
                            if "value" in entitlement:
                                _finding(findings, "embedded_entitlements", entitlement["value"], relative,
                                         "LC_CODE_SIGNATURE.Entitlements", entitlement["note"], entitlement["offset"])
            _scan(file, relative, candidates, objc=macho["is_macho"])
            try:
                if file.suffix.lower() in (".plist", ".entitlements", ".xcent"):
                    if file.stat().st_size > MAX_PLIST_BYTES:
                        raise AnalysisError("plist exceeds parser limit")
                    raw = file.read_bytes()
                    parsed = _parse_plist(raw)
                    _structured_strings(parsed, raw, relative, candidates)
                    if file.name == "Info.plist":
                        _info_findings(parsed, relative, findings)
                    elif file.suffix in (".entitlements", ".xcent"):
                        _finding(findings, "resource_entitlements", parsed, relative, "Entitlements",
                                 "Resource plist only; signature binding and runtime grant unverified.")
                elif file.name == "embedded.mobileprovision":
                    _profile(file, relative, findings)
                elif file.suffix.lower() == ".json":
                    if file.stat().st_size > MAX_PLIST_BYTES:
                        raise AnalysisError("JSON exceeds structured parser limit; byte strings still scanned")
                    raw = file.read_bytes()
                    try:
                        _structured_strings(json.loads(raw), raw, relative, candidates)
                    except (ValueError, UnicodeError, RecursionError) as exc:
                        raise AnalysisError("invalid JSON: " + type(exc).__name__) from exc
            except AnalysisError as exc:
                warnings.append({"classification": "unverified", "file": relative, "message": str(exc)})
        encrypted = sum(item["encrypted"] is True for item in binaries)
        invalid = sum(not item["valid"] for item in binaries)
        summary = {"input_kind": input_kind, "file_count": len(files), "total_bytes": sum(i["size"] for i in inventory),
                   "macho_count": len(binaries), "encrypted_macho_count": encrypted, "invalid_macho_count": invalid,
                   "configuration_count": len(findings), "candidate_count": len(candidates.items),
                   "candidate_hits_omitted": candidates.omitted, "candidate_sources_omitted": candidates.omitted_sources,
                   "configuration_limit_reached": len(findings) >= MAX_FINDINGS,
                   "code_analysis": "limited_encrypted" if encrypted else "static_metadata_and_strings_only",
                   "decryption_verified": False, "network_verified": False}
        limitations = ["未执行应用、未联网/连接设备；字符串可能来自测试、第三方资源或不可达代码。",
            "未恢复 Objective-C/Swift 源码；依赖声明不证明代码已执行。",
            "cryptid=0 或未发现加密命令只说明头部状态；无法证明转储完整、已正确脱壳或可运行。",
            "代码签名/CMS 未做密码学校验；entitlements 不证明系统实际授予相应权限。",
            "Info.plist 无法证明实际备份排除、数据保护类别、权限授予或网络安全性。",
            f"候选最多 {MAX_CANDIDATES} 条/每条 {MAX_SOURCES} 个来源；超限计数在 summary 中。",
            "扫描可见 ASCII/UTF-8 字节字符串；混淆、动态拼接、压缩嵌套资源、UTF-16 字符串可能未提取。"]
        limitations.append("结构化资源解析最多 8 MiB/50000 节点/24 层；不能精确映射原始字符串时保留容器偏移和键路径。")
        if encrypted:
            limitations.append("存在 cryptid 非零的 Mach-O，加密代码内容无法完整分析；目录复制不等于脱壳。")
        if invalid:
            limitations.append("存在不完整/非法 Mach-O 头部，相关架构/加密状态可能无法判定。")
        report = {"schema_version": 1, "summary": summary,
                  "classifications": {"confirmed_configuration": "Observed declared metadata; effectiveness unverified.",
                                      "candidate": "Static string lead, not a verified endpoint/API/vulnerability.",
                                      "unverified": "Not established by this offline inspection."},
                  "input": {"name": path.name, "kind": input_kind,
                            "sha256": _sha256(path) if path.is_file() else None},
                  "configurations": findings, "mach_o": binaries, "files": inventory,
                  "candidates": sorted(candidates.items.values(), key=lambda x: (x["kind"], x["value"])),
                  "warnings": warnings, "limitations": limitations}
        json_name, md_name = "static-analysis.json", "endpoint-candidates.md"
        _write_artifact(output_dir / json_name, json.JSONEncoder(ensure_ascii=False, indent=2).iterencode(report))
        _write_artifact(output_dir / md_name, _markdown(report))
    return {"summary": summary, "files": [json_name, md_name]}
