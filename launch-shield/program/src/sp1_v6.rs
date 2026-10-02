use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use sha2::{Digest, Sha256};

use crate::instruction::{BID_PUBLIC_VALUES_LEN, SP1_PROOF_LEN};

const GROTH16_VK_LEN: usize = 492;
const SP1_V6_HEADER_LEN: usize = 100;
const GROTH16_PROOF_LEN: usize = 256;
const SP1_V6_VK_ROOT: [u8; 32] =
    decode_hex::<32>("002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352");

// SP1 6.8.1 / circuit 6.1.0. SHA-256:
// 4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696
const GROTH16_VK: [u8; GROTH16_VK_LEN] = decode_hex::<GROTH16_VK_LEN>(concat!(
    "e1c7d728a5fd961fc179ec5eab938f564deba5b271e1c90c2c29a79648418fc182e78e216b27cb2b30abd22d17fb65b7",
    "47ad8050d18e543498522d01a2c3fe79dc3c9339849225980c7d3f824f80d19e2a9c2554b6ab2160fa9635528f693fc0",
    "0d964538da2653f2e62499571e6c78afb8909d3ea8107f306bd6928253680a3a998e9393920d483a7260bfb731fb5d25",
    "f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
    "d7e00b2ca4f62668135017ed8a68894e104ac26dfd9bf376634b42af9e5ae50e91b7e9276171bb0efd647fc63e38bbfb",
    "a3076f20daca8cd52bcc7284d9b1c6eb1723616533dd6ae53502c9c506a81f23f543d68750b5133ebfbe1f4746b3b011",
    "00000006acd6bf7f164af0b6b0bbbe0fdcb06ee0c1ba07f8e6eb2f9f3943a90cb1d402908f5460f3b7221705435e745d",
    "a21e276536379c0113c13c4255e7ae101f1e90bf8b0ae6e491bc04c544da9e8cd4857d201b4cfa0222dbe96aac97f044",
    "fdf1c922c97c875a6ebd0999b06e7267ff3d8a6bf859bb9635abae07cb6b3534ba409a839807204ddcd27506ba72e17b",
    "55227b0bf310136ecb40c74acd52f3ccfbcba9f7808c7b7c98d78c07a2c4be5f6be7082ba41021611f9a2dfc016f8bbb",
    "37d36bee0000000000000000",
));

const fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    let encoded = hex.as_bytes();
    assert!(encoded.len() == N * 2);
    let mut decoded = [0u8; N];
    let mut i = 0;
    while i < N {
        decoded[i] = (hex_nibble(encoded[i * 2]) << 4) | hex_nibble(encoded[i * 2 + 1]);
        i += 1;
    }
    decoded
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal constant"),
    }
}

fn parse_vkey_hash(value: &str) -> Result<[u8; 32], ()> {
    let encoded = value.strip_prefix("0x").ok_or(())?;
    if encoded.len() != 64 {
        return Err(());
    }

    let mut hash = [0u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        hash[index] = (runtime_hex_nibble(pair[0]).ok_or(())? << 4)
            | runtime_hex_nibble(pair[1]).ok_or(())?;
    }
    // SP1 key hashes occupy 248 bits, and are zero-padded to 32 bytes.
    if hash[0] != 0 {
        return Err(());
    }
    Ok(hash)
}

fn runtime_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn verify_proof(
    proof: &[u8; SP1_PROOF_LEN],
    public_values: &[u8; BID_PUBLIC_VALUES_LEN],
    vkey_hash: &str,
) -> Result<(), ()> {
    verify_sp1_v6_proof(proof, public_values, vkey_hash)
}

pub(crate) fn verify_sp1_v6_proof(
    proof: &[u8],
    public_values: &[u8],
    vkey_hash: &str,
) -> Result<(), ()> {
    if proof.len() != SP1_PROOF_LEN {
        return Err(());
    }

    let selector = Sha256::digest(GROTH16_VK);
    if proof.get(..4).ok_or(())? != &selector[..4] {
        return Err(());
    }
    if proof.get(4..36).ok_or(())?.iter().any(|byte| *byte != 0)
        || proof.get(36..68).ok_or(())? != SP1_V6_VK_ROOT
    {
        return Err(());
    }

    let vkey_hash = parse_vkey_hash(vkey_hash)?;
    let mut public_inputs = [[0u8; 32]; 5];
    public_inputs[0] = vkey_hash;
    public_inputs[1] = hash_public_values(public_values);
    public_inputs[2].copy_from_slice(proof.get(4..36).ok_or(())?);
    public_inputs[3] = SP1_V6_VK_ROOT;
    public_inputs[4].copy_from_slice(proof.get(68..100).ok_or(())?);

    let groth16_proof = load_groth16_proof(proof.get(SP1_V6_HEADER_LEN..).ok_or(())?)?;
    let groth16_vk = load_groth16_verifying_key(&GROTH16_VK)?;
    let verifying_key = Groth16Verifyingkey {
        nr_pubinputs: 5,
        vk_alpha_g1: groth16_vk.alpha_g1,
        vk_beta_g2: groth16_vk.beta_g2,
        vk_gamme_g2: groth16_vk.gamma_g2,
        vk_delta_g2: groth16_vk.delta_g2,
        vk_ic: &groth16_vk.ic,
    };

    let mut verifier = Groth16Verifier::new(
        &groth16_proof.pi_a,
        &groth16_proof.pi_b,
        &groth16_proof.pi_c,
        &public_inputs,
        &verifying_key,
    )
    .map_err(|_| ())?;
    verifier.verify().map_err(|_| ())
}

fn hash_public_values(public_values: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::digest(public_values);
    digest[0] &= 0x1f;
    digest.into()
}

struct Groth16Proof {
    pi_a: [u8; 64],
    pi_b: [u8; 128],
    pi_c: [u8; 64],
}

fn load_groth16_proof(bytes: &[u8]) -> Result<Groth16Proof, ()> {
    if bytes.len() != GROTH16_PROOF_LEN {
        return Err(());
    }
    let pi_a: [u8; 64] = bytes.get(..64).ok_or(())?.try_into().map_err(|_| ())?;
    let pi_b: [u8; 128] = bytes.get(64..192).ok_or(())?.try_into().map_err(|_| ())?;
    let pi_c: [u8; 64] = bytes.get(192..256).ok_or(())?.try_into().map_err(|_| ())?;
    Ok(Groth16Proof {
        pi_a: negate_g1(&pi_a)?,
        pi_b,
        pi_c,
    })
}

fn negate_g1(bytes: &[u8; 64]) -> Result<[u8; 64], ()> {
    let x = Fq::from_be_bytes_mod_order(&bytes[..32]);
    let y = Fq::from_be_bytes_mod_order(&bytes[32..]);
    let point = -G1Affine::new_unchecked(x, y);

    let mut serialized = [0u8; 64];
    point.serialize_uncompressed(&mut serialized[..]).map_err(|_| ())?;
    Ok(convert_endianness::<32, 64>(&serialized))
}

struct Groth16VerifyingKey {
    alpha_g1: [u8; 64],
    beta_g2: [u8; 128],
    gamma_g2: [u8; 128],
    delta_g2: [u8; 128],
    ic: Vec<[u8; 64]>,
}

fn load_groth16_verifying_key(bytes: &[u8]) -> Result<Groth16VerifyingKey, ()> {
    if bytes.len() != GROTH16_VK_LEN || bytes.len() < 292 {
        return Err(());
    }

    let alpha_g1 = decompress_g1(bytes.get(..32).ok_or(())?.try_into().map_err(|_| ())?)?;
    let beta_g2 = decompress_g2(bytes.get(64..128).ok_or(())?.try_into().map_err(|_| ())?)?;
    let gamma_g2 = decompress_g2(bytes.get(128..192).ok_or(())?.try_into().map_err(|_| ())?)?;
    let delta_g2 = decompress_g2(bytes.get(224..288).ok_or(())?.try_into().map_err(|_| ())?)?;

    let count_bytes: [u8; 4] = bytes.get(288..292).ok_or(())?.try_into().map_err(|_| ())?;
    let ic_count = u32::from_be_bytes(count_bytes);
    if ic_count != 6 {
        return Err(());
    }

    let mut ic = Vec::with_capacity(ic_count as usize);
    let mut offset = 292usize;
    for _ in 0..ic_count {
        let end = offset.checked_add(32).ok_or(())?;
        let compressed: &[u8; 32] = bytes.get(offset..end).ok_or(())?.try_into().map_err(|_| ())?;
        ic.push(decompress_g1(compressed)?);
        offset = end;
    }

    Ok(Groth16VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

fn decompress_g1(bytes: &[u8; 32]) -> Result<[u8; 64], ()> {
    let compressed = gnark_compressed_x_to_ark(bytes)?;
    groth16_solana::decompression::decompress_g1(&compressed).map_err(|_| ())
}

fn decompress_g2(bytes: &[u8; 64]) -> Result<[u8; 128], ()> {
    let compressed = gnark_compressed_x_to_ark(bytes)?;
    groth16_solana::decompression::decompress_g2(&compressed).map_err(|_| ())
}

fn gnark_compressed_x_to_ark<const N: usize>(bytes: &[u8; N]) -> Result<[u8; N], ()> {
    if N != 32 && N != 64 {
        return Err(());
    }

    let ark_flag = match bytes[0] & 0xc0 {
        0x80 => 0x00,
        0xc0 => 0x80,
        0x40 => 0x40,
        _ => return Err(()),
    };
    let mut converted = *bytes;
    converted[0] = (converted[0] & !0xc0) | ark_flag;
    converted.reverse();
    Ok(convert_endianness::<N, N>(&converted))
}

fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    bytes: &[u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    let mut converted = [0u8; ARRAY_SIZE];
    for (index, chunk) in bytes.chunks_exact(CHUNK_SIZE).enumerate() {
        for (offset, byte) in chunk.iter().rev().enumerate() {
            converted[index * CHUNK_SIZE + offset] = *byte;
        }
    }
    converted
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PROOF: [u8; 356] = decode_hex::<356>(concat!(
        "4388a21c0000000000000000000000000000000000000000000000000000000000000000002f850ee998974d6cc00e50",
        "cd0814b098c05bfade466d28573240d057f2535200000000000000000000000000000000000000000000000000000000",
        "000000002ae95d5adb14ba0a1529ff72324ede806b0c30a43790c770c2f38df18600ebf011a6ca7b24e538f7d0fd83d5",
        "6e338e5f098afc692567b2b0f5d8b4c7bb82a071225e061371d201c1310b0f3228b7caf35ebbad934f3d1c8c493fc9a3",
        "10ca9f6d1ad2635ea7f6886939a166ccf8b22cb921df3e54d0b52113eeea6ba0e6c6eb101e381cddb1b918ffe1d2a6a6",
        "241ea9476dc77b522a9034f078942e2d9b4ade632cb1ffaf4205708f31c0c3fcf132cc97b825b6a8740caa427ea129a7",
        "889210cc2cae5ea9417ce2649efaa1509a22f35c68f33c4dcbda5a17a6c5bc0151e34bbc14b8ab708aedbe9b24e7200b",
        "e1541dd534fc2d7fcf53a33b69638480410b503c",
    ));
    const TEST_PUBLIC_VALUES: [u8; 96] = decode_hex::<96>(concat!(
        "00000000000000000000000000000000000000000000000000000000000000460913644c8b396ebcee2b280e10247556",
        "a2f65c4a8e02242e5d041895cbddb0430000000000000000000000000000000000000000000000000000000000000001",
    ));
    const TEST_VKEY_HASH: &str =
        "0x00a79ec59ae56e59d55164056cb52b261ac1bafd368d93deb43f153e5d93b414";

    #[test]
    fn verifies_sp1_v6_proof_and_public_input_framing() {
        verify_sp1_v6_proof(&TEST_PROOF, &TEST_PUBLIC_VALUES, TEST_VKEY_HASH).unwrap();
    }

    #[test]
    fn rejects_bad_selector_exit_code_vk_root_and_public_values() {
        let mut bad = TEST_PROOF;
        bad[0] ^= 1;
        assert!(verify_sp1_v6_proof(&bad, &TEST_PUBLIC_VALUES, TEST_VKEY_HASH).is_err());

        let mut bad = TEST_PROOF;
        bad[4] = 1;
        assert!(verify_sp1_v6_proof(&bad, &TEST_PUBLIC_VALUES, TEST_VKEY_HASH).is_err());

        let mut bad = TEST_PROOF;
        bad[36] ^= 1;
        assert!(verify_sp1_v6_proof(&bad, &TEST_PUBLIC_VALUES, TEST_VKEY_HASH).is_err());

        let mut bad_values = TEST_PUBLIC_VALUES;
        bad_values[0] ^= 1;
        assert!(verify_sp1_v6_proof(&TEST_PROOF, &bad_values, TEST_VKEY_HASH).is_err());
    }

    #[test]
    fn rejects_malformed_vkey_hash_and_proof_size() {
        assert!(verify_sp1_v6_proof(&TEST_PROOF[..355], &TEST_PUBLIC_VALUES, TEST_VKEY_HASH).is_err());
        assert!(verify_sp1_v6_proof(&TEST_PROOF, &TEST_PUBLIC_VALUES, "0x01").is_err());
        assert!(verify_sp1_v6_proof(
            &TEST_PROOF,
            &TEST_PUBLIC_VALUES,
            "0x10a79ec59ae56e59d55164056cb52b261ac1bafd368d93deb43f153e5d93b414"
        )
        .is_err());
    }
}