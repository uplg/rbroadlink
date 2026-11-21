#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hex_literal::hex;
    use jiff::{
        civil::datetime,
        tz::{Offset, TimeZone},
        ZonedDateTime,
    };
    use packed_struct::prelude::PackedStruct;

    use crate::{
        constants,
        network::{
            AuthenticationMessage, CommandMessage, DiscoveryMessage, RemoteDataCommand,
            RemoteDataMessage, WirelessConnection,
        },
    };

    /// A local time at a fixed offset (in seconds east of UTC), as discovery reads it.
    fn local_time(
        (year, month, day): (i16, i8, i8),
        (hour, minute, second): (i8, i8, i8),
        offset_seconds: i32,
    ) -> ZonedDateTime {
        let offset = Offset::from_seconds(offset_seconds).expect("Offset out of range!");
        datetime(year, month, day, hour, minute, second, 0)
            .to_zoned_datetime(TimeZone::fixed(offset))
            .expect("Time out of range!")
    }

    /// The command header every known-answer packet below shares.
    fn known_command() -> CommandMessage {
        CommandMessage::with_count::<AuthenticationMessage>(
            0x0102,
            0x2712,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            0x01020304,
        )
    }

    /// A session key, as a device hands one out after authentication.
    const SESSION_KEY: [u8; 16] = *b"0123456789abcdef";

    /// The header of [known_command], its two checksums left out.
    const KNOWN_HEADER: [u8; 0x38] = hex!(
        "5aa5aa555aa5aa55 0000000000000000 0000000000000000 0000000000000000"
        "00000000 12276500 0281ffeeddccbbaa 04030201 00000000"
    );

    /// [KNOWN_HEADER] with its checksum (0x20) and payload checksum (0x34) written in.
    fn known_header(checksum: [u8; 2], payload_checksum: [u8; 2]) -> Vec<u8> {
        let mut header = KNOWN_HEADER.to_vec();
        header[0x20..0x22].copy_from_slice(&checksum);
        header[0x34..0x36].copy_from_slice(&payload_checksum);
        header
    }

    #[test]
    fn discovery_packs_summer_time_on_a_sunday() {
        // 2026-07-05 14:07:09 at UTC+02:00, a Sunday: the weekday is 7, the offset in seconds.
        let discover = DiscoveryMessage::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
            54321,
            Some(local_time((2026, 7, 5), (14, 7, 9), 2 * 3600)),
        )
        .expect("Could not construct DiscoveryMessage!");

        let expected: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 32, 28, 0, 0, 234, 7, 7, 14, 26, 7, 5, 7, 0, 0, 0, 0, 103, 1,
            168, 192, 49, 212, 0, 0, 249, 194, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(expected, discover.pack().expect("Could not pack!"));
    }

    #[test]
    fn discovery_packs_a_negative_offset_at_the_end_of_a_century() {
        // 1999-12-31 23:59:59 at UTC-05:00, a Friday: the local fields, not UTC's.
        let discover = DiscoveryMessage::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            Some(local_time((1999, 12, 31), (23, 59, 59), -5 * 3600)),
        )
        .expect("Could not construct DiscoveryMessage!");

        let expected: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 176, 185, 255, 255, 207, 7, 59, 23, 99, 5, 31, 12, 0, 0, 0, 0,
            2, 0, 0, 10, 80, 0, 0, 0, 51, 196, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(expected, discover.pack().expect("Could not pack!"));
    }

    #[test]
    fn command_packs_an_empty_payload_as_its_header_alone() {
        let actual = known_command()
            .pack_with_payload(&[], &constants::INITIAL_KEY)
            .expect("Could not pack!");

        assert_eq!(known_header([0x3E, 0xCA], [0xAF, 0xBE]), actual);
    }

    #[test]
    fn command_encrypts_an_aligned_payload_without_padding() {
        let payload: Vec<u8> = (0u8..32).collect();
        let actual = known_command()
            .pack_with_payload(&payload, &SESSION_KEY)
            .expect("Could not pack!");

        // AES-128-CBC, the Broadlink IV, no padding block: `openssl enc -aes-128-cbc -nopad`.
        let mut expected = known_header([0x3D, 0xDA], [0x9F, 0xC0]);
        expected.extend(hex!(
            "3405e80726c10fd6abc2df2e68a75339 2cdc9b7e82bea9c9f48a79d81b81695d"
        ));
        assert_eq!(expected, actual);
    }

    #[test]
    fn command_zero_pads_a_short_payload_to_one_block() {
        let actual = known_command()
            .pack_with_payload(&[1, 2, 3, 0, 0], &SESSION_KEY)
            .expect("Could not pack!");

        // The payload checksum is the unpadded payload's.
        let mut expected = known_header([0x57, 0xD1], [0xB5, 0xBE]);
        expected.extend(hex!("a1c2e5fc154fbc720cda093bea1a050a"));
        assert_eq!(expected, actual);
    }

    #[test]
    fn command_unpacks_and_decrypts_a_known_packet() {
        let mut packet = known_header([0x3D, 0xDA], [0x9F, 0xC0]);
        packet.extend(hex!(
            "3405e80726c10fd6abc2df2e68a75339 2cdc9b7e82bea9c9f48a79d81b81695d"
        ));

        let payload =
            CommandMessage::unpack_with_payload(packet, &SESSION_KEY).expect("Could not unpack!");
        assert_eq!((0u8..32).collect::<Vec<u8>>(), payload);
    }

    #[test]
    fn command_unpacking_strips_trailing_zeros() {
        let mut packet = known_header([0x57, 0xD1], [0xB5, 0xBE]);
        packet.extend(hex!("a1c2e5fc154fbc720cda093bea1a050a"));
        let payload =
            CommandMessage::unpack_with_payload(packet, &SESSION_KEY).expect("Could not unpack!");
        assert_eq!(vec![1, 2, 3], payload);

        // An all-zero payload keeps its first byte.
        let mut packet = known_header([0xB3, 0xCF], [0xAF, 0xBE]);
        packet.extend(hex!("600d393e661f648e2c2ef9047f2779a4"));
        let payload =
            CommandMessage::unpack_with_payload(packet, &SESSION_KEY).expect("Could not unpack!");
        assert_eq!(vec![0], payload);
    }

    #[test]
    fn command_unpacks_a_header_alone_as_an_empty_payload() {
        // Decrypting nothing used to panic in block-modes' zero unpadding.
        let packet = known_header([0x3E, 0xCA], [0xAF, 0xBE]);
        let payload = CommandMessage::unpack_with_payload(packet, &constants::INITIAL_KEY)
            .expect("Could not unpack!");
        assert!(payload.is_empty());
    }

    #[test]
    fn command_unpacking_refuses_a_bad_packet() {
        let mut packet = known_header([0x57, 0xD1], [0xB5, 0xBE]);
        packet.extend(hex!("a1c2e5fc154fbc720cda093bea1a050a"));

        // Too short for a header.
        assert!(
            CommandMessage::unpack_with_payload(packet[..0x37].to_vec(), &SESSION_KEY).is_err()
        );

        // A checksum that does not match.
        let mut corrupted = packet.clone();
        corrupted[0x40] ^= 1;
        assert!(CommandMessage::unpack_with_payload(corrupted, &SESSION_KEY).is_err());

        // A payload checksum that does not match: the wrong key.
        assert!(
            CommandMessage::unpack_with_payload(packet.clone(), &constants::INITIAL_KEY).is_err()
        );

        // A ciphertext that is not whole blocks (its checksum fixed up).
        let mut ragged = packet;
        ragged.push(0x01);
        ragged[0x20..0x22].copy_from_slice(&[0, 0]);
        let real = crate::network::util::checksum(&ragged).to_le_bytes();
        ragged[0x20..0x22].copy_from_slice(&real);
        assert!(CommandMessage::unpack_with_payload(ragged, &SESSION_KEY).is_err());
    }

    #[test]
    fn authentication_packs_correctly() {
        let auth = AuthenticationMessage::new("Test 1");

        // Calculated using the python-broadlink library
        let expected: [u8; 0x50] = [
            0, 0, 0, 0, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 84, 101, 115,
            116, 32, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];
        let actual = auth.pack().expect("Could not pack test auth message!");

        assert_eq!(expected, actual);
    }

    #[test]
    fn command_packs_correctly() {
        let payload: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cmd = CommandMessage::with_count::<AuthenticationMessage>(
            0x1234,
            0x649B,
            [0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x5u8, 0x6u8],
            0xABCDEFAB,
        );

        // Calculated using the python-broadlink library
        let expected: &[u8] = &[
            90, 165, 170, 85, 90, 165, 170, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 205, 209, 0, 0, 155, 100, 101, 0, 52, 146, 6, 5, 4, 3, 2, 1, 171,
            239, 205, 171, 220, 190, 0, 0, 165, 197, 88, 183, 43, 70, 174, 88, 109, 241, 187, 8,
            228, 74, 30, 218,
        ];
        let actual = cmd
            .pack_with_payload(&payload, &constants::INITIAL_KEY)
            .expect("Could not pack test command message!");

        assert_eq!(expected, &actual);
    }

    #[test]
    fn discovery_packs_correctly() {
        // 2000-02-14 10:30:55 at five seconds west of UTC, a Monday.
        let discover = DiscoveryMessage::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            42424,
            Some(local_time((2000, 2, 14), (10, 30, 55), -5)),
        )
        .expect("Could not construct DiscoveryMessage!");

        // Calculated using the python-broadlink library
        let expected: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 251, 255, 255, 255, 208, 7, 30, 10, 0, 1, 14, 2, 0, 0, 0, 0, 4,
            3, 2, 1, 184, 165, 0, 0, 36, 197, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let actual = discover
            .pack()
            .expect("Could not pack test discover message!");

        assert_eq!(expected, actual);
    }

    #[test]
    fn remote_data_packs_correctly() {
        let remote = RemoteDataMessage::new(RemoteDataCommand::SendCode);
        let payload: [u8; 8] = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];

        // Calculated using the python-broadlink library
        let expected: &[u8] = &[12, 0, 2, 0, 0, 0, 171, 205, 239, 1, 35, 69, 103, 137];
        let actual = remote
            .pack_with_payload(&payload)
            .expect("Could not pack test remote data message!");

        assert_eq!(expected, &actual);
    }

    #[test]
    fn wireless_connection_packs_correctly() {
        let connection = WirelessConnection::WPA1("Test SSID", "Test Password");

        // Calculated using the python-broadlink library
        let expected: [u8; 136] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 225, 198, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 101, 115, 116, 32, 83, 83, 73, 68, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 101, 115, 116, 32, 80, 97,
            115, 115, 119, 111, 114, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            9, 13, 2, 0,
        ];
        let actual = connection
            .to_message()
            .expect("Could not create test connection message!")
            .pack()
            .expect("Could not pack test connection message!");

        assert_eq!(expected, actual);
    }
}

/// Every packed message's layout, pinned: a byte pattern is unpacked, its fields
/// checked, then packed again. Bytes no field covers come back as zeros.
#[cfg(test)]
mod layouts {
    use packed_struct::prelude::{PackedStruct, PackedStructSlice};

    use crate::network::{
        AirCondInfo, AirCondState, AuthenticationMessage, AuthenticationResponse, CommandMessage,
        DiscoveryMessage, DiscoveryResponse, HvacDataMessage, RemoteDataMessage,
        WirelessConnectionMessage,
    };

    /// A byte pattern, each byte different from its neighbours.
    fn pattern(size: usize) -> Vec<u8> {
        (0..size)
            .map(|i| (i as u8).wrapping_mul(0x9D).wrapping_add(0x5B))
            .collect()
    }

    /// [pattern], with the fields that take only some values (booleans, enums) set to one.
    fn valid(name: &str, size: usize) -> Vec<u8> {
        let mut bytes = pattern(size);
        match name {
            "DiscoveryResponse" => bytes[127] = 1,
            "RemoteDataMessage" => bytes[2] = 0x1B,
            "AirCondState" => {
                bytes[0] = (bytes[0] & !0x07) | 3; // swing_v: Pos3
                bytes[1] = (bytes[1] & !0xE0) | 0xC0; // swing_h: RightFix
                bytes[3] = (bytes[3] & !0xE0) | 0xA0; // fanspeed: Auto
                bytes[4] = (bytes[4] & !0x03) | 2; // preset: Mute
                bytes[5] = (bytes[5] & !0xE0) | 0x80; // mode: Fan
            }
            _ => {}
        }
        bytes
    }

    macro_rules! layout {
        ($type:ty, $size:expr, $fields:expr, $packed:expr) => {{
            let unpacked = <$type>::unpack_from_slice(&valid(stringify!($type), $size))
                .expect(concat!("Could not unpack ", stringify!($type)));
            assert_eq!($fields, format!("{:?}", unpacked));
            assert_eq!(
                $packed,
                hex::encode(unpacked.pack().expect("Could not pack!"))
            );
        }};
    }

    #[test]
    fn packed_layouts_are_unchanged() {
        layout!(CommandMessage, 56, "CommandMessage { magic_header: [91, 248, 149, 50, 207, 108, 9, 166], device_type: 3183, packet_type: 18089, count: 32995, mac_reversed: [29, 186, 87, 244, 145, 46], id: 2718263499, checksum: 39163, payload_checksum: 56383 }", "5bf89532cf6c09a6000000000000000000000000000000000000000000000000fb9800006f0ca946e3801dba57f4912ecb6805a23fdc0000");
        layout!(DiscoveryMessage, 48, "DiscoveryMessage { gmt_offset: 444457027, year: 21687, minute: 241, hour: 142, year_without_century: 43, day_of_the_week: 200, day_of_the_month: 101, month: 2, local_ip_reversed: [19, 176, 77, 234], local_port: 9351, checksum: 39163, magic_constant: 169 }", "000000000000000043e07d1ab754f18e2bc865020000000013b04dea87240000fb9800000000a9000000000000000000");
        layout!(DiscoveryResponse, 128, "DiscoveryResponse { model_code: 56383, mac: [237, 138, 39, 196, 97, 254], name: [155, 56, 213, 114, 15, 172, 73, 230, 131, 32, 189, 90, 247, 148, 49, 206, 107, 8, 165, 66, 223, 124, 25, 182, 83, 240, 141, 42, 199, 100, 1, 158, 59, 216, 117, 18, 175, 76, 233, 134, 35, 192, 93, 250, 151, 52, 209, 110, 11, 168, 69, 226, 127, 28, 185, 86, 243, 144, 45, 202, 103, 4], is_locked: true }", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fdc00000000ed8a27c461fe9b38d5720fac49e68320bd5af79431ce6b08a542df7c19b653f08d2ac764019e3bd87512af4ce98623c05dfa9734d16e0ba845e27f1cb956f3902dca67040001");
        layout!(AuthenticationMessage, 80, "AuthenticationMessage { id: [207, 108, 9, 166, 67, 224, 125, 26, 183, 84, 241, 142, 43, 200, 101, 2], magic0: 193, magic1: 244, name: [203, 104, 5, 162, 63, 220, 121, 22, 179, 80, 237, 138, 39, 196, 97, 254, 155, 56, 213, 114, 15, 172, 73, 230, 131, 32, 189, 90, 247, 148, 49, 206] }", "00000000cf6c09a643e07d1ab754f18e2bc8650200000000000000000000c10000000000000000000000000000f40000cb6805a23fdc7916b350ed8a27c461fe9b38d5720fac49e68320bd5af79431ce");
        layout!(AuthenticationResponse, 20, "AuthenticationResponse { id: 848689243, key: [207, 108, 9, 166, 67, 224, 125, 26, 183, 84, 241, 142, 43, 200, 101, 2] }", "5bf89532cf6c09a643e07d1ab754f18e2bc86502");
        layout!(
            RemoteDataMessage,
            6,
            "RemoteDataMessage { payload_length: 63579, command: StartLearningRF }",
            "5bf81b000000"
        );
        layout!(AirCondState, 13, "AirCondState { power: false, target_temp_int: 11, swing_v: Pos3, swing_h: RightFix, mode: Fan, magic1: 5, fanspeed: Auto, preset: Mute, sleep: true, ifeel: true, health: true, clean: false, display: true, mildew: true }", "5bc005a0028c00000200180000");
        layout!(
            AirCondInfo,
            22,
            "AirCondInfo { power: false, ambient_temp_int: 12, ambient_temp_fract: 28 }",
            "00000000000c0000000000000000000000000000001c"
        );
        layout!(HvacDataMessage, 12, "HvacDataMessage { payload_length: 63579, magic1: 12949, magic2: 27855, magic3: 42505, data_length: 57411, command: 6781 }", "5bf89532cf6c09a643e07d1a");
        layout!(WirelessConnectionMessage, 136, "WirelessConnectionMessage { checksum: 39163, magic_constant: -87, ssid: [15, 172, 73, 230, 131, 32, 189, 90, 247, 148, 49, 206, 107, 8, 165, 66, 223, 124, 25, 182, 83, 240, 141, 42, 199, 100, 1, 158, 59, 216, 117, 18], password: [175, 76, 233, 134, 35, 192, 93, 250, 151, 52, 209, 110, 11, 168, 69, 226, 127, 28, 185, 86, 243, 144, 45, 202, 103, 4, 161, 62, 219, 120, 21, 178], ssid_length: 79, password_length: 236, security_mode: 137 }", "0000000000000000000000000000000000000000000000000000000000000000fb9800000000a900000000000000000000000000000000000000000000000000000000000fac49e68320bd5af79431ce6b08a542df7c19b653f08d2ac764019e3bd87512af4ce98623c05dfa9734d16e0ba845e27f1cb956f3902dca6704a13edb7815b24fec8900");
    }
}
