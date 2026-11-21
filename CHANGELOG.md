# Changelog

## 0.5.0

Dependencies brought to their latest releases. Nothing changes on the wire: known-answer
tests pin the discovery packet, AES-CBC encryption and decryption, full command packets
(checksums included) and every packed message's layout, written against 0.4.2 and passing
unchanged.

### Breaking

- `chrono` is replaced by `jiff` 1.0: `DiscoveryMessage::new` takes an
  `Option<jiff::ZonedDateTime>`. `None` is now in the system's time zone, as before.
- `aes` 0.7 and the abandoned `block-modes` give way to `aes` 0.9 and `cbc` 0.2. The public
  `AesCbc` alias is gone: `network::encrypt` and `network::decrypt` do what it did.
- Edition 2024, MSRV 1.89.
- The `mqtt-broadlink` example uses `rumqttc` (`mqtt-async-client` is abandoned).
  `--operation-timeout` is now the connection timeout; `--auto-connect` reconnects
  when the connection drops.

### Changed

- `get_if_addrs` (unmaintained) is replaced by `if-addrs`.
- `hex-literal` 1.1, `packed_struct` 0.12, `phf` 0.14, `rand` 0.10; for the examples
  `clap` 4, `env_logger` 0.11, `rpassword` 7, `tokio` 1.54.
- `packed_struct` 0.12 refuses byte ranges wider than their arrays: three fields that
  named one byte more than they hold now name the bytes they always filled.

### Fixed

- Unpacking a command with an empty payload panicked; it now returns an empty
  payload.
