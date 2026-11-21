use aes::Aes128;
use cbc::cipher::{
    block_padding::{NoPadding, ZeroPadding},
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
};
use packed_struct::prelude::{PackedStruct, PackedStructSlice};
use rand::Rng;

use crate::{
    constants,
    network::util::{checksum, reverse_mac},
    traits::CommandTrait,
};

/// AES-128-CBC encryption, as Broadlink devices expect it.
type AesCbcEncryptor = cbc::Encryptor<Aes128>;

/// AES-128-CBC decryption, as Broadlink devices expect it.
type AesCbcDecryptor = cbc::Decryptor<Aes128>;

/// The AES block size, in bytes.
const AES_BLOCK: usize = 16;

/// Encrypts a payload with AES-128-CBC and the Broadlink IV, zero-padded to whole
/// blocks (no padding block when the payload is already aligned).
pub fn encrypt(payload: &[u8], key: &[u8; 16]) -> Vec<u8> {
    AesCbcEncryptor::new(key.into(), &constants::INITIAL_VECTOR.into())
        .encrypt_padded_vec::<ZeroPadding>(payload)
}

/// Decrypts an AES-128-CBC ciphertext with the Broadlink IV.
///
/// Trailing zero bytes are stripped, the first byte always kept: an all-zero plaintext
/// comes back as a single zero. The ciphertext must be whole blocks.
pub fn decrypt(ciphertext: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
    if ciphertext.len() % AES_BLOCK != 0 {
        return Err(format!(
            "Ciphertext is not whole {}-byte blocks: {} bytes",
            AES_BLOCK,
            ciphertext.len()
        ));
    }

    let mut plaintext = AesCbcDecryptor::new(key.into(), &constants::INITIAL_VECTOR.into())
        .decrypt_padded_vec::<NoPadding>(ciphertext)
        .map_err(|e| format!("Could not decrypt! {}", e))?;

    // Zero padding, removed as Broadlink payloads have always been read: back to the last
    // nonzero byte, across blocks, keeping at least one byte.
    let kept = plaintext
        .iter()
        .rposition(|&b| b != 0)
        .map_or(plaintext.len().min(1), |last| last + 1);
    plaintext.truncate(kept);

    Ok(plaintext)
}

/// A message used to send commands to a broadlink device on the network.
#[derive(PackedStruct, Clone, Debug)]
#[packed_struct(bit_numbering = "msb0", endian = "lsb", size_bytes = "0x38")]
pub struct CommandMessage {
    /// Magic header
    #[packed_field(bytes = "0x00:0x07")]
    magic_header: [u8; 0x08],

    /// The type of device receiving this message
    #[packed_field(bytes = "0x24:0x25")]
    device_type: u16,

    /// The type of packet being sent. This should be populated from the wrapped
    /// message type using the [CommandTrait].
    #[packed_field(bytes = "0x26:0x27")]
    packet_type: u16,

    /// The message count.
    #[packed_field(bytes = "0x28:0x29")]
    count: u16,

    /// The mac address, reversed.
    #[packed_field(bytes = "0x2A:0x2F")]
    mac_reversed: [u8; 6],

    /// The device ID. Set to 0 when authenticating for the first time.
    #[packed_field(bytes = "0x30:0x33")]
    id: u32,

    /// The checksum of the entire command + payload
    #[packed_field(bytes = "0x20:0x21")]
    checksum: u16,

    /// The checksum of just the payload, before encryption
    #[packed_field(bytes = "0x34:0x35")]
    payload_checksum: u16,
}

impl CommandMessage {
    /// Create a new CommandMessage using the specified count.
    ///
    /// Typically, the count of a message is randomly generated using [CommandMessage::new],
    /// but there may be a case where you need to use a specific value for the count, such as when
    /// testing.
    pub fn with_count<T>(
        count: u16,
        device_model_code: u16,
        mac: [u8; 6],
        id: u32,
    ) -> CommandMessage
    where
        T: CommandTrait,
    {
        return CommandMessage {
            magic_header: [0x5A, 0xA5, 0xAA, 0x55, 0x5A, 0xA5, 0xaa, 0x55],
            device_type: device_model_code,
            packet_type: T::packet_type(),
            count: count | 0x8000,
            mac_reversed: reverse_mac(mac),
            id: id,
            checksum: 0,         // This will be populated later.
            payload_checksum: 0, // This will be populated later.
        };
    }

    /// Create a new CommandMessage.
    pub fn new<T>(device_model_code: u16, mac: [u8; 6], id: u32) -> CommandMessage
    where
        T: CommandTrait,
    {
        let mut r = rand::thread_rng();
        let random_count = r.gen_range(0x8000..0xFFFF);

        return CommandMessage::with_count::<T>(random_count, device_model_code, mac, id);
    }

    /// Pack the command message while appending the payload.
    pub fn pack_with_payload(mut self, payload: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
        // Save the checksum of the payload before encrypting
        self.payload_checksum = checksum(payload);

        // Encrypt the payload
        let encrypted = encrypt(payload, key);

        // Pack the command with the payload appended
        let packed = self
            .pack()
            .map_err(|e| format!("Could not pack command header! {}", e))?;

        let mut appended = packed.to_vec();
        appended.extend(&encrypted);

        // Save the complete checksum
        self.checksum = checksum(&appended);

        // Construct the final message
        let completely_packed = self
            .pack()
            .map_err(|e| format!("Could not pack completed command! {}", e))?;

        let mut complete_command: Vec<u8> = completely_packed.to_vec();
        complete_command.extend(&encrypted);

        return Ok(complete_command);
    }

    /// Unpack the command message with the associated payload.
    pub fn unpack_with_payload(mut bytes: Vec<u8>, key: &[u8; 16]) -> Result<Vec<u8>, String> {
        // Ensure that the data is correct
        if bytes.len() < 0x38 {
            return Err(format!(
                "Command is too short! Expected 0x38 bytes, got {}",
                bytes.len()
            ));
        }

        // Unpack the header
        let command_header = CommandMessage::unpack_from_slice(&bytes[0..0x38])
            .map_err(|e| format!("Could not unpack command from bytes! {}", e))?;

        // Zero out the checksum from the header for verification
        // TODO: Is there a nicer way to do this?
        bytes[0x20] = 0;
        bytes[0x21] = 0;

        // Ensure that the checksums match
        let real_checksum = checksum(&bytes);
        if command_header.checksum != real_checksum {
            return Err(format!(
                "Command checksum does not match actual checksum! Expected {:#06X} got {:#06X}",
                real_checksum, command_header.checksum,
            ));
        }

        // Decrypt the message
        let decrypted = decrypt(&bytes[0x38..], key)
            .map_err(|e| format!("Could not decrypt command payload! {}", e))?;

        // Ensure that the payload checksums match
        let real_checksum = checksum(&decrypted);
        if command_header.payload_checksum != real_checksum {
            return Err(format!(
                "Payload checksum does not match actual checksum! Expected {:#06X} got {:#06X}",
                real_checksum, command_header.payload_checksum,
            ));
        }

        return Ok(decrypted);
    }
}
