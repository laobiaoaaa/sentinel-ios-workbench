import hashlib
import json
from pathlib import Path
import plistlib
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import static_analysis as sa


def macho(bits=64, endian="<", cryptid=0, with_signature=True):
    """Build actual load commands/signature bytes, not mocked parser results."""
    cpu = 0x0100000C if bits == 64 else 12
    header_size = 32 if bits == 64 else 28
    encryption = struct.pack(endian + "IIIII", 0x2C if bits == 64 else 0x21,
                             24 if bits == 64 else 20, 512, 32, cryptid)
    if bits == 64:
        encryption += struct.pack(endian + "I", 0)
    name = b"/System/Library/Frameworks/Foundation.framework/Foundation\0"
    cmdsize = (24 + len(name) + 7) // 8 * 8
    dep = struct.pack(endian + "IIIIII", 0xC, cmdsize, 24, 0, 0, 0) + name
    dep += b"\0" * (cmdsize - len(dep))
    commands = [encryption, dep]
    entitlements = plistlib.dumps({"get-task-allow": True, "application-identifier": "TEAM.example.fixture"})
    child = struct.pack(">II", 0xFADE7171, 8 + len(entitlements)) + entitlements
    signature = struct.pack(">III", 0xFADE0CC0, 20 + len(child), 1) + struct.pack(">II", 5, 20) + child
    if with_signature:
        commands.append(struct.pack(endian + "IIII", 0x1D, 16, 640, len(signature)))
    header = struct.pack(endian + "IiiIIII", 0xFEEDFACF if bits == 64 else 0xFEEDFACE,
                         cpu, 0, 2, len(commands), sum(map(len, commands)), 0)
    if bits == 64:
        header += struct.pack(endian + "I", 0)
    result = header + b"".join(commands)
    result += b"\0" * (512 - len(result))
    result += b"X" * 32
    result += b"\0https://api.fixture.test/v1\0_OBJC_CLASS_$_FixtureClient\0sendRequest:completion:\0"
    result += b"\0" * (640 - len(result))
    return result + signature if with_signature else result


def fat(slices, endian=">", bits=32):
    width = 32 if bits == 64 else 20
    offset = 8 + len(slices) * width
    table, payload = [], []
    for item in slices:
        e, b = sa._THIN[item[:4]]
        cpu, subtype = struct.unpack_from(e + "ii", item, 4)
        args = (cpu, subtype, offset, len(item), 0)
        table.append(struct.pack(endian + ("iiQQII" if bits == 64 else "iiIII"),
                                 *(args + (0,) if bits == 64 else args)))
        offset += len(item)
        payload.append(item)
    return struct.pack(endian + "II", 0xCAFEBABF if bits == 64 else 0xCAFEBABE, len(slices)) + b"".join(table + payload)


class StaticTests(unittest.TestCase):
    def setUp(self):
        # Keep generated fixtures in the project workspace, not /tmp.
        self.workspace = Path(__file__).resolve().parents[1]
        self.temp = tempfile.TemporaryDirectory(prefix=".static-tests-", dir=self.workspace)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def ipa(self, members, name="fixture.ipa"):
        path = self.root / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for member, data in members:
                archive.writestr(member, data)
        return path

    def test_thin_all_bitwidths_and_endianness(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                with self.subTest(bits=bits, endian=endian):
                    result = sa.inspect_macho(self.write("binary", macho(bits, endian, 1)))
                    self.assertTrue(result["is_macho"])
                    self.assertTrue(result["valid"])
                    self.assertTrue(result["encrypted"])
                    self.assertFalse(result["decryption_verified"])
                    arch = result["architectures"][0]
                    self.assertEqual(arch["bits"], bits)
                    self.assertEqual(arch["byte_order"], "little" if endian == "<" else "big")
                    self.assertEqual(arch["encryption"][0]["cryptid"], 1)
                    self.assertIn("Foundation", arch["dependencies"][0]["value"])
                    signature = arch["code_signatures"][0]
                    self.assertEqual(signature["signature_verification"], "unverified")
                    self.assertTrue(signature["entitlements"][0]["value"]["get-task-allow"])

    def test_fat_all_endianness_and_header_widths(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                with self.subTest(bits=bits, endian=endian):
                    result = sa.inspect_macho(self.write("binary", fat([macho(32, ">", 0), macho(64, "<", 1)], endian, bits)))
                    self.assertTrue(result["valid"])
                    self.assertEqual(result["format"], "fat")
                    self.assertEqual(len(result["architectures"]), 2)
                    self.assertTrue(result["encrypted"])
                    second = result["architectures"][1]
                    self.assertEqual(second["encryption"][0]["absolute_offset"], second["offset"] + 512)

    def test_zero_cryptid_not_claimed_as_decrypted(self):
        result = sa.inspect_macho(self.write("binary", macho(cryptid=0)))
        self.assertFalse(result["encrypted"])
        self.assertFalse(result["decryption_verified"])
        self.assertEqual(result["architectures"][0]["encryption_status"], "cryptid_zero")

    def test_absent_encryption_command_is_distinct(self):
        data = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
        result = sa.inspect_macho(self.write("binary", data))
        self.assertTrue(result["valid"])
        self.assertEqual(result["architectures"][0]["encryption_status"], "no_encryption_command")
        self.assertFalse(result["decryption_verified"])

    def test_malformed_headers_fail_closed(self):
        bad_command = bytearray(macho())
        struct.pack_into("<I", bad_command, 36, 0xFFFFFFFC)
        bad_crypt_range = bytearray(macho())
        struct.pack_into("<I", bad_crypt_range, 40, 0xFFFFFFFF)
        cases = [b"\xcf\xfa\xed\xfe", bytes(bad_command), bytes(bad_crypt_range),
                 struct.pack(">II", 0xCAFEBABE, 1000000)]
        for data in cases:
            with self.subTest(size=len(data)):
                result = sa.inspect_macho(self.write("binary", data))
                self.assertTrue(result["is_macho"])
                self.assertFalse(result["valid"])
                self.assertIsNone(result["encrypted"])

    def test_fat_overlap_rejected(self):
        data = bytearray(fat([macho(), macho()]))
        first_offset = struct.unpack_from(">I", data, 16)[0]
        struct.pack_into(">I", data, 36, first_offset)
        result = sa.inspect_macho(self.write("binary", data))
        self.assertFalse(result["valid"])
        self.assertTrue(any("overlapping" in warning for warning in result["warnings"]))

    def test_real_ipa_configuration_resources_and_provenance(self):
        info = {"CFBundleIdentifier": "test.fixture", "CFBundleExecutable": "Fixture",
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True,
                    "NSExceptionDomains": {"fixture.test": {"NSExceptionAllowsInsecureHTTPLoads": True}}},
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["fixture"]}],
                "NSCameraUsageDescription": "Fixture camera description", "UIFileSharingEnabled": True}
        profile = b"CMS PREFIX\x00" + plistlib.dumps({"UUID": "fixture-id", "Entitlements": {"get-task-allow": True}}) + b"CMS SUFFIX"
        js = b'const api="https://api.fixture.test/v1"; const route="/v2/accounts";\n'
        members = [("Payload/Fixture.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY)),
                   ("Payload/Fixture.app/Fixture", macho(cryptid=1)),
                   ("Payload/Fixture.app/embedded.mobileprovision", profile),
                   ("Payload/Fixture.app/assets/client.js", js),
                   ("Payload/Fixture.app/config.json", b'{"base":"https://api.fixture.test/v1"}'),
                   ("Payload/Fixture.app/Settings.plist", plistlib.dumps({"api": "https://settings.fixture.test/api"}))]
        path = self.ipa(members)
        output = self.root / "reports"
        result = sa.analyze_package(path, output)
        self.assertEqual(result["summary"]["encrypted_macho_count"], 1)
        self.assertEqual(result["summary"]["code_analysis"], "limited_encrypted")
        self.assertEqual(result["files"], ["static-analysis.json", "endpoint-candidates.md"])
        self.assertTrue(all(Path(f).name == f for f in result["files"]))
        report = json.loads((output / result["files"][0]).read_text())
        self.assertEqual(report["input"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        kinds = {item["kind"] for item in report["configurations"]}
        self.assertTrue({"ats_configuration", "ats_domain_exception", "url_scheme", "permission_description",
                         "storage_configuration", "profile_entitlements", "embedded_entitlements"} <= kinds)
        self.assertTrue(all(item["classification"] == "confirmed_configuration" for item in report["configurations"]))
        candidates = report["candidates"]
        url = next(item for item in candidates if item["kind"] == "url" and item["value"] == "https://api.fixture.test/v1")
        self.assertGreaterEqual(len(url["sources"]), 3)
        self.assertTrue(all(item["classification"] == "candidate" for item in candidates))
        source = next(s for s in url["sources"] if s["file"].endswith("client.js"))
        self.assertEqual(source["offset"], js.index(b"https://"))
        self.assertTrue(any(item["kind"] == "objc_string" for item in candidates))
        self.assertTrue(any(item["value"] == "/v2/accounts" for item in candidates))
        md = (output / result["files"][1]).read_text()
        self.assertIn("不等于脱壳", md)
        self.assertIn("candidate", md)
        for filename in result["files"]:
            self.assertLess((output / filename).stat().st_size, 50 * 1024 * 1024)
        self.assertFalse(list(output.glob(".ios-static-*")))

    def test_app_input_and_invalid_profile_are_reported(self):
        self.write("Fixture.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "fixture"}))
        self.write("Fixture.app/embedded.mobileprovision", b"malformed")
        self.write("Fixture.app/client.js", b'"https://one.fixture.test/path"')
        result = sa.analyze_package(self.root / "Fixture.app", self.root / "out")
        report = json.loads((self.root / "out" / result["files"][0]).read_text())
        self.assertEqual(report["summary"]["input_kind"], "app_directory")
        self.assertEqual(report["warnings"][0]["classification"], "unverified")

    def test_unsafe_zip_paths_rejected(self):
        for index, name in enumerate(("../escape", "/absolute", "C:/escape", "folder\\escape", "a/../b", "./file")):
            with self.subTest(name=name):
                path = self.ipa([(name, b"bad")], f"bad{index}.ipa")
                with self.assertRaises(sa.AnalysisError):
                    sa.analyze_package(path, self.root / f"out{index}")
        self.assertFalse((self.root / "escape").exists())

    def test_zip_symlink_and_collision_rejected(self):
        link = zipfile.ZipInfo("Payload/Fixture.app/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for index, members in enumerate(([(link, b"/etc/passwd")], [("a", b"x"), ("a/file", b"x")], [("same", b"a"), ("same", b"b")])):
            with self.subTest(index=index):
                path = self.ipa(members, f"bad{index}.ipa")
                with self.assertRaises(sa.AnalysisError):
                    sa.analyze_package(path, self.root / f"out{index}")

    def test_app_symlink_and_nested_output_rejected(self):
        app = self.root / "Fixture.app"
        app.mkdir()
        (app / "bad").symlink_to("/etc/passwd")
        with self.assertRaises(sa.AnalysisError):
            sa.analyze_package(app, self.root / "out")
        (app / "bad").unlink()
        with self.assertRaises(sa.AnalysisError):
            sa.analyze_package(app, app / "out")

    def test_archive_resource_limits_enforced(self):
        path = self.ipa([("a", b"0123456789"), ("b", b"0123456789")])
        for constant, limit in (("MAX_ENTRIES", 1), ("MAX_FILE_BYTES", 9), ("MAX_TOTAL_BYTES", 19)):
            with self.subTest(constant=constant), patch.object(sa, constant, limit):
                with self.assertRaises(sa.AnalysisError):
                    sa.analyze_package(path, self.root / "out")
        bomb = self.ipa([("compresses-too-well", b"0" * (2 * 1024 * 1024))], "bomb.ipa")
        with self.assertRaises(sa.AnalysisError):
            sa.analyze_package(bomb, self.root / "bomb-out")

    def test_candidate_bounds_and_chunk_boundary_offsets(self):
        data = b"\0" * 61 + b"https://boundary.fixture.test/v1\0" + b"https://two.fixture.test/v2\0"
        file = self.write("resource.js", data)
        candidates = sa._Candidates()
        with patch.object(sa, "CHUNK_BYTES", 64):
            sa._scan(file, "resource.js", candidates)
        item = candidates.items[("url", "https://boundary.fixture.test/v1")]
        self.assertEqual(item["sources"][0]["offset"], 61)
        candidates = sa._Candidates()
        with patch.object(sa, "MAX_CANDIDATES", 1), patch.object(sa, "MAX_SOURCES", 2):
            for index in range(4):
                candidates.add("url", "https://same.test", {"file": "a", "offset": index})
            candidates.add("url", "https://other.test", {"file": "a", "offset": 10})
        self.assertEqual(candidates.omitted, 1)
        self.assertEqual(candidates.omitted_sources, 2)

    def test_scanner_overlap_does_not_invent_suffix_domains(self):
        boundary = sa.CHUNK_BYTES - (sa.MAX_LITERAL + 512)
        prefix = b"\0" * (boundary - 20)
        url = b"https://boundary.fixture.test/v1"
        file = self.write("boundary.js", prefix + url + b"\0" * (sa.CHUNK_BYTES + 50))
        candidates = sa._Candidates()
        sa._scan(file, "boundary.js", candidates)
        item = candidates.items[("url", url.decode())]
        self.assertEqual(item["source_count"], 1)
        domains = [value for kind, value in candidates.items if kind == "domain"]
        self.assertEqual(domains, ["boundary.fixture.test"])

    def test_escaped_json_and_binary_plist_strings(self):
        escaped = b'{"url":"https:\\/\\/escaped.fixture.test\\/path?x=1&y=2"}'
        app = self.root / "Fixture.app"
        self.write("Fixture.app/config.json", escaped)
        self.write("Fixture.app/settings.plist", plistlib.dumps({"endpoint": "https://binary.fixture.test/路径"}, fmt=plistlib.FMT_BINARY))
        self.write("Fixture.app/client.js", b'var u="https:\\/\\/script.fixture.test\\/api";')
        result = sa.analyze_package(app, self.root / "out")
        report = json.loads((self.root / "out" / result["files"][0]).read_text())
        urls = {item["value"] for item in report["candidates"] if item["kind"] == "url"}
        self.assertIn("https://escaped.fixture.test/path?x=1&y=2", urls)
        self.assertIn("https://script.fixture.test/api", urls)
        self.assertIn("https://binary.fixture.test/路径", urls)

    def test_report_limit_does_not_publish_oversized_artifact(self):
        with patch.object(sa, "MAX_ARTIFACT_BYTES", 10):
            with self.assertRaises(sa.AnalysisError):
                sa._write_artifact(self.root / "report.json", ["too long for a ten byte limit"])
        self.assertFalse((self.root / "report.json").exists())
        self.assertFalse(list(self.root.glob(".report-*")))

    def test_plist_xml_entity_is_rejected(self):
        data = b'<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY x "bad">]><plist><dict/></plist>'
        with self.assertRaises(sa.AnalysisError):
            sa._parse_plist(data)


if __name__ == "__main__":
    unittest.main()
