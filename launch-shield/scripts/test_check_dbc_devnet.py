import struct
import unittest

from check_dbc_devnet import (
    base58_encode,
    parse_program_data,
    program_data_address,
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
        self.assertEqual(parse_program_data(account_data), (slot, b"\x7fELF"))

    def test_programdata_with_authority_uses_45_byte_header(self):
        slot = 42
        authority = bytes(range(32))
        account_data = struct.pack("<IQB", 3, slot, 1) + authority + b"\x7fELF"
        self.assertEqual(parse_program_data(account_data), (slot, b"\x7fELF"))

    def test_programdata_rejects_invalid_authority_option(self):
        account_data = struct.pack("<IQB", 3, 42, 2) + b"\x7fELF"
        with self.assertRaisesRegex(ValueError, "option tag"):
            parse_program_data(account_data)


if __name__ == "__main__":
    unittest.main()