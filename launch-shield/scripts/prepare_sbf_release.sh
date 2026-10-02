#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
program_dir="$(cd -- "$script_dir/../program" && pwd)"
source_file="${1:-$program_dir/target/sbpf-solana-solana/release/deps/launch_shield_program.so}"
output_file="${2:-$program_dir/target/deploy/launch_shield_program.so}"
expected_size=321064
expected_sha256="ab0e74f0e074f5c8c47b9898e0786a8fe091ad10497343f385dad3ce8bb01115"
strip_tool="${LLVM_STRIP:-$(command -v llvm-strip || true)}"

if [[ ! -f "$source_file" ]]; then
  echo "SBF input not found: $source_file" >&2
  exit 1
fi
if [[ -z "$strip_tool" || ! -x "$strip_tool" ]]; then
  echo "Set LLVM_STRIP to an llvm-strip executable that supports SBPF ELF files." >&2
  exit 1
fi

mkdir -p "$(dirname -- "$output_file")"
temporary_file="${output_file}.tmp"
trap 'rm -f -- "$temporary_file"' EXIT
cp -- "$source_file" "$temporary_file"
"$strip_tool" --strip-all "$temporary_file"

actual_size="$(wc -c < "$temporary_file" | tr -d '[:space:]')"
actual_sha256="$(sha256sum "$temporary_file" | awk '{print $1}')"
if [[ "$actual_size" != "$expected_size" || "$actual_sha256" != "$expected_sha256" ]]; then
  echo "Refusing to publish an unexpected SBF artifact." >&2
  echo "Expected: $expected_size bytes, SHA-256 $expected_sha256" >&2
  echo "Actual:   $actual_size bytes, SHA-256 $actual_sha256" >&2
  exit 1
fi

mv -- "$temporary_file" "$output_file"
trap - EXIT
echo "Verified SBF release: $output_file ($actual_size bytes, SHA-256 $actual_sha256)"