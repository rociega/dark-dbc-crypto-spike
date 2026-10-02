import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from check_dbc_devnet import (
    DEVNET_SNAPSHOT_EXECUTABLE_BYTES,
    DEVNET_SNAPSHOT_SHA256,
    DEVNET_SNAPSHOT_SLOT,
    DEVNET_SNAPSHOT_UPGRADE_AUTHORITY,
    PROGRAM_DATA_ADDRESS,
    base58_encode,
    matches_devnet_snapshot,
    parse_program_data,
    program_data_address,
    write_verified_executable,
)


class LoaderAccountParsingTests(unittest.TestCase):
    def test_base58_encoding_preserves_leading_zeroes(self):
        self.assertEqual(base58_encode(b"\0\0\x01"), "112")

    def test_program_account_yields_programdata_address(self):
        public_key_bytes = bytes(range(32))
        account_data = struct.pack("<I", 2) + public_key_bytes
        self.assertEqual(
            program_data_address(account_data),
            base58_encode(public_key_bytes),
        )

    def test_program_account_rejects_wrong_loader_state(self):
        with self.assertRaisesRegex(ValueError, "not UpgradeableLoaderState"):
            program_data_address(struct.pack("<I", 3) + bytes(32))

    def test_programdata_without_authority_uses_13_byte_header(self):
        slot = 503_167_099
        account_data = struct.pack("<IQB", 3, slot, 0) + b"\x7fELF"
        self.assertEqual(parse_program_data(account_data), (slot, None, b"\x7fELF"))

    def test_programdata_with_authority_uses_45_byte_header(self):
        slot = 42
        authority = bytes(range(32))
        account_data = struct.pack("<IQB", 3, slot, 1) + authority + b"\x7fELF"
        self.assertEqual(
            parse_program_data(account_data),
            (slot, base58_encode(authority), b"\x7fELF"),
        )

    def test_programdata_rejects_invalid_authority_option(self):
        account_data = struct.pack("<IQB", 3, 42, 2) + b"\x7fELF"
        with self.assertRaisesRegex(ValueError, "option tag"):
            parse_program_data(account_data)

    def test_snapshot_match_includes_upgrade_authority(self):
        snapshot = (
            PROGRAM_DATA_ADDRESS,
            DEVNET_SNAPSHOT_SLOT,
            DEVNET_SNAPSHOT_UPGRADE_AUTHORITY,
            DEVNET_SNAPSHOT_EXECUTABLE_BYTES,
            DEVNET_SNAPSHOT_SHA256,
        )
        self.assertTrue(matches_devnet_snapshot(*snapshot))
        self.assertFalse(
            matches_devnet_snapshot(
                *snapshot[:2], "11111111111111111111111111111111", *snapshot[3:]
            )
        )


class VerifiedExecutableExportTests(unittest.TestCase):
    def test_export_writes_only_the_expected_digest_and_refuses_overwrite(self):
        executable = b"\x7fELF\x01test-image"
        digest = hashlib.sha256(executable).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "dynamic_bonding_curve.so"
            write_verified_executable(output, executable, digest)
            self.assertEqual(output.read_bytes(), executable)

            with self.assertRaisesRegex(ValueError, "unexpected SHA-256"):
                write_verified_executable(output, b"different", digest)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                write_verified_executable(output, b"different", hashlib.sha256(b"different").hexdigest())

    def test_export_is_idempotent_for_the_same_verified_elf(self):
        executable = b"\x7fELF\x02same-image"
        digest = hashlib.sha256(executable).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dynamic_bonding_curve.so"
            write_verified_executable(output, executable, digest)
            write_verified_executable(output, executable, digest)
            self.assertEqual(output.read_bytes(), executable)


if __name__ == "__main__":
    unittest.main()