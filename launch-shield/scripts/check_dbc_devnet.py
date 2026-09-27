#!/usr/bin/env python3
"""Read-only check of the Meteora DBC Devnet executable fingerprint.

This confirms a match to the recorded Devnet snapshot; it does not prove which
source revision produced the executable or establish settlement compatibility.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
from urllib.request import Request, urlopen


PROGRAM_ID = "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN"
PROGRAM_DATA_ADDRESS = "HUfnSSiJxgspQm6C1rkqv6L3XgVtn7AESApgCQpCXCYh"
UPGRADEABLE_LOADER_ID = "BPFLoaderUpgradeab1e11111111111111111111111"
DEVNET_SNAPSHOT_SLOT = 503_167_099
DEVNET_SNAPSHOT_EXECUTABLE_BYTES = 1_983_568
DEVNET_SNAPSHOT_SHA256 = "f5ccbb01e37165d16108bda0259fb3acbfca29305e23098c3b248e50c22979f0"
DEFAULT_RPC_URL = "https://api.devnet.solana.com"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(value: bytes) -> str:
    """Encode raw public-key bytes without an external package."""
    leading_zeroes = len(value) - len(value.lstrip(b"\0"))
    number = int.from_bytes(value, "big")
    digits: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        digits.append(BASE58_ALPHABET[remainder])
    return "1" * leading_zeroes + "".join(reversed(digits))


def program_data_address(program_account_data: bytes) -> str:
    """Decode the Program variant of UpgradeableLoaderState."""
    if len(program_account_data) < 36:
        raise ValueError("program account data is truncated")
    if struct.unpack_from("<I", program_account_data)[0] != 2:
        raise ValueError("program account is not UpgradeableLoaderState::Program")
    return base58_encode(program_account_data[4:36])


def parse_program_data(program_data: bytes) -> tuple[int, bytes]:
    """Return (last-upgrade slot, executable bytes) from ProgramData account data."""
    if len(program_data) < 13:
        raise ValueError("ProgramData account data is truncated")
    if struct.unpack_from("<I", program_data)[0] != 3:
        raise ValueError("account is not UpgradeableLoaderState::ProgramData")

    slot = struct.unpack_from("<Q", program_data, 4)[0]
    authority_tag = program_data[12]
    if authority_tag == 0:
        metadata_len = 13
    elif authority_tag == 1:
        metadata_len = 45
        if len(program_data) < metadata_len:
            raise ValueError("ProgramData upgrade-authority metadata is truncated")
    else:
        raise ValueError("invalid ProgramData upgrade-authority option tag")

    executable = program_data[metadata_len:]
    if not executable:
        raise ValueError("ProgramData account contains no executable bytes")
    return slot, executable


def rpc_call(endpoint: str, method: str, params: list[object]) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read())
    except Exception as error:
        raise RuntimeError(f"{method} RPC request failed ({type(error).__name__})") from None
    if payload.get("error") is not None:
        raise RuntimeError(f"{method} RPC error: {payload['error']}")
    result = payload.get("result")
    if not isinstance(result, dict) or "value" not in result:
        raise RuntimeError(f"{method} returned an unexpected response")
    return result


def get_account(endpoint: str, address: str) -> tuple[dict, bytes]:
    result = rpc_call(
        endpoint,
        "getAccountInfo",
        [address, {"encoding": "base64", "commitment": "finalized"}],
    )
    info = result["value"]
    if not isinstance(info, dict):
        raise RuntimeError(f"account not found: {address}")
    encoded = info.get("data")
    if (
        not isinstance(encoded, list)
        or len(encoded) != 2
        or encoded[1] != "base64"
        or not isinstance(encoded[0], str)
    ):
        raise RuntimeError(f"RPC returned invalid base64 account data: {address}")
    try:
        raw_data = base64.b64decode(encoded[0], validate=True)
    except ValueError:
        raise RuntimeError(f"RPC returned malformed base64 account data: {address}") from None
    return info, raw_data


def main() -> int:
    endpoint = os.environ.get("SOLANA_DEVNET_RPC_URL", DEFAULT_RPC_URL)
    try:
        program_info, program_data = get_account(endpoint, PROGRAM_ID)
        if program_info.get("owner") != UPGRADEABLE_LOADER_ID:
            raise RuntimeError("DBC program is not owned by the upgradeable loader")
        if program_info.get("executable") is not True:
            raise RuntimeError("DBC program account is not executable")

        discovered_program_data = program_data_address(program_data)
        data_info, raw_program_data = get_account(endpoint, discovered_program_data)
        if data_info.get("owner") != UPGRADEABLE_LOADER_ID:
            raise RuntimeError("DBC ProgramData account has an unexpected owner")
        if data_info.get("executable") is not False:
            raise RuntimeError("DBC ProgramData account has an unexpected executable flag")

        slot, executable = parse_program_data(raw_program_data)
    except (RuntimeError, ValueError, struct.error) as error:
        print(f"Devnet preflight failed: {error}", file=sys.stderr)
        return 2

    digest = hashlib.sha256(executable).hexdigest()
    matches_snapshot = (
        discovered_program_data == PROGRAM_DATA_ADDRESS
        and slot == DEVNET_SNAPSHOT_SLOT
        and len(executable) == DEVNET_SNAPSHOT_EXECUTABLE_BYTES
        and digest == DEVNET_SNAPSHOT_SHA256
    )
    print(f"Program: {PROGRAM_ID}")
    print(f"ProgramData: {discovered_program_data}")
    print(f"Upgrade slot: {slot}")
    print(f"Executable bytes: {len(executable)}")
    print(f"SHA-256: {digest}")
    print(f"Matches 2026-09-27 Devnet snapshot: {str(matches_snapshot).lower()}")
    if not matches_snapshot:
        print(
            "Snapshot mismatch; investigate the deployment and its source before "
            "treating it as compatible.",
            file=sys.stderr,
        )
        return 1
    print(
        "Snapshot match only: this does not prove source identity or settlement "
        "compatibility."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())