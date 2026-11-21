use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

use clap::Parser;
use log::{info, warn};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, SubscribeReasonCode};
use rbroadlink::{traits::DeviceTrait, Device};

#[derive(Parser, Clone, Debug)]
#[command(about, version, author)]
struct Args {
    /// Add a client to track. Can be repeated.
    #[arg(short, long)]
    client: Vec<Ipv4Addr>,

    /// Enable automatically discovering devices
    #[arg(short, long)]
    auto_discover: bool,

    /// Specify the local IP of this machine, if multiple interfaces are available.
    #[arg(long)]
    local_ip: Option<Ipv4Addr>,

    /// The MQTT username, if needed
    #[arg(short, long)]
    username: Option<String>,

    /// The MQTT password, if needed
    #[arg(short, long)]
    password: Option<String>,

    /// The MQTT ID to use for this client, if needed
    #[arg(long, default_value = "mqtt-broadlink")]
    mqtt_id: String,

    /// The keepalive interval, in seconds.
    #[arg(long, default_value = "30")]
    keep_alive: u16,

    /// The connection timeout, in seconds.
    #[arg(long, default_value = "20")]
    operation_timeout: u16,

    /// Reconnect to the broker when the connection drops, instead of giving up.
    #[arg(long)]
    auto_connect: bool,

    /// The MQTT broker used for publishing / subscribing to topics, as a URL
    /// (`mqtt://host[:port]`, `tcp://`, `mqtts://`, `ssl://`).
    mqtt_broker: String,
}

type DeviceMap = HashMap<Ipv4Addr, Device>;

#[tokio::main]
async fn main() {
    // Initialize needed vars
    let args = Args::parse();
    env_logger::init();

    info!("Starting broadlink-mqtt v{}...", env!("CARGO_PKG_VERSION"));

    // Get the devices
    let devices = get_devices(&args).expect("Could not find devices!");

    // Start an update thread on all the devices
    let mut threads: Vec<tokio::task::JoinHandle<_>> = vec![];
    for (_, device) in devices {
        let args_copy = args.clone();

        threads.push(tokio::spawn(async move {
            handle_device(&device, args_copy)
                .await
                .expect("Could not handle device!");
        }));
    }

    // Await on all of the threads
    for thread in threads {
        thread.await.expect("Could not run thread!");
    }
}

async fn handle_device(device: &Device, args: Args) -> Result<(), String> {
    let info = device.get_info();
    let sanitized_name = info
        .friendly_model
        .to_lowercase()
        .replace(" ", "-")
        .replace("/", ">");
    let mqtt_id = format!("{}-{}", args.mqtt_id.clone(), sanitized_name);

    // Construct the mqtt client
    let separator = if args.mqtt_broker.contains('?') { '&' } else { '?' };
    let mut options =
        MqttOptions::parse_url(format!("{}{}client_id={}", args.mqtt_broker, separator, mqtt_id))
            .expect("Could not parse the MQTT broker URL!");
    options.set_keep_alive(Duration::from_secs(args.keep_alive.into()));
    if let Some(username) = &args.username {
        options.set_credentials(username, args.password.clone().unwrap_or_default());
    }

    let (mqtt_client, mut event_loop) = AsyncClient::new(options, 10);
    let mut network = event_loop.network_options();
    network.set_connection_timeout(args.operation_timeout.into());
    event_loop.set_network_options(network);

    // Connect to the broker: the event loop connects at its first poll
    info!("Connecting to the MQTT broker at {}", &args.mqtt_broker);

    // Handle events indefinitely
    loop {
        let event = match event_loop.poll().await {
            Ok(event) => event,
            Err(e) if args.auto_connect => {
                warn!("Disconnected from the broker, reconnecting: {:?}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(e) => {
                return Err(format!("Device was disconnected from the broker! {:?}", e));
            }
        };

        let message = match event {
            // (Re)connected: publish the device information and listen for commands
            Event::Incoming(Packet::ConnAck(_)) => {
                mqtt_client
                    .publish(
                        get_path(&sanitized_name, &["info"]),
                        QoS::AtLeastOnce,
                        false,
                        info.friendly_type.clone(),
                    )
                    .await
                    .expect("Could not publish to the broker!");

                mqtt_client
                    .subscribe(get_path(&sanitized_name, &["cmd"]), QoS::AtLeastOnce)
                    .await
                    .expect("Could not subscribe to command topic!");
                continue;
            }
            Event::Incoming(Packet::SubAck(ack)) => {
                if ack
                    .return_codes
                    .iter()
                    .any(|code| matches!(code, SubscribeReasonCode::Failure))
                {
                    return Err("Failures encountered when subscribing to command topic!".into());
                }
                continue;
            }
            Event::Incoming(Packet::Publish(message)) => message,
            _ => continue,
        };

        // Consume the command
        let data = String::from_utf8(message.payload.to_vec())
            .expect("Couldn't read subscription message!");

        info!("Parsing message => {:?}", data);
        let parts: Vec<&str> = data.split(" ").collect();
        let (Some(cmd), Some(payload)) = (parts.first(), parts.get(1)) else {
            // Make sure that we skip non-cmds.
            warn!(
                "Skipping incomplete command for {}: {}",
                &sanitized_name, &data
            );
            continue;
        };

        info!("Got command '{}' with payload => {}", cmd, payload);
        match *cmd {
            "blast" => handle_blast(&mqtt_client, device, &sanitized_name, payload)
                .await
                .expect("Could not handle blast!"),
            "learn" => handle_learn(&mqtt_client, device, &sanitized_name, payload)
                .await
                .expect("Could not handle learn!"),
            _ => warn!(
                "Skipping unknown command for {}: {}",
                &sanitized_name, &cmd
            ),
        }
    }
}

/// Handles a blast command
async fn handle_blast(
    client: &AsyncClient,
    device: &Device,
    sanitized_name: &str,
    payload: &str,
) -> Result<(), String> {
    // Decode the payload into a hex array.
    let hex = hex::decode(payload);
    if let Err(e) = hex {
        warn!("Skipping invalid hex data: {:?}", e);
        return Ok(());
    }

    let hex = hex.unwrap();
    info!("Blasting payload {:?}", &hex);

    match device {
        Device::Remote { remote } => match remote.send_code(&hex) {
            Err(e) => {
                client
                    .publish(
                        get_path(sanitized_name, &["blast_error"]),
                        QoS::AtMostOnce,
                        false,
                        e.to_string(),
                    )
                    .await
                    .expect("Could not publish blast error!");

                return Ok(());
            }
            _ => info!("Blasted code successfully: {:?}", hex),
        },
        _ => {
            warn!("Device sent blast command, but is not a remote: {}", device);
            return Ok(());
        }
    };

    // Tell the MQTT broker that we successfully blasted
    client
        .publish(
            get_path(sanitized_name, &["blast_status"]),
            QoS::AtMostOnce,
            false,
            "ok",
        )
        .await
        .expect("Could not publish blast status!");

    return Ok(());
}

/// Handles a learn command
async fn handle_learn(
    client: &AsyncClient,
    device: &Device,
    sanitized_name: &str,
    payload: &str,
) -> Result<(), String> {
    // Only remotes can learn, so extract it here.
    let remote = match device {
        Device::Remote { remote } => remote,
        _ => {
            warn!("Device sent learn command, but is not a remote: {}", device);
            return Ok(());
        }
    };

    // Try to learn the code
    let code = match payload {
        "ir" => remote.learn_ir(),
        "rf" => remote.learn_rf(),
        _ => {
            warn!("Skipping invalid learn mode {}", payload);
            return Ok(());
        }
    };

    // Short out if no code was learned.
    if let Err(e) = code {
        warn!("Device did not find any code! {:?}", e);
        client
            .publish(
                get_path(sanitized_name, &["code_error"]),
                QoS::AtMostOnce,
                false,
                e.to_string(),
            )
            .await
            .expect("Could not publish code error message!");

        return Ok(());
    }

    // Convert the code into a hex string
    let hex_code = hex::encode(code.unwrap());

    // Publish the learned code
    client
        .publish(
            get_path(sanitized_name, &["code"]),
            QoS::AtMostOnce,
            false,
            hex_code,
        )
        .await
        .expect("Could not send learned code!");

    return Ok(());
}

/// Returns a topic path for a given device and path structure.
fn get_path(sanitized_name: &str, paths: &[&str]) -> String {
    return format!("broadlink/{}/{}", sanitized_name, paths.join("/"));
}

/// Get devices through autodiscovery or manual clients
fn get_devices(args: &Args) -> Result<DeviceMap, String> {
    let mut result: DeviceMap = DeviceMap::new();

    // Auto discover devices, if enabled
    if args.auto_discover {
        info!("Autodiscovering devices...");
        let discovered = Device::list(args.local_ip).expect("Could not enumerate devices!");
        for device in discovered {
            let addr = device.get_info().address;

            info!("Discovered device at {} => {}", addr, device);
            result.insert(addr, device);
        }
    }

    // Add all of the static clients, if present
    for addr in &args.client {
        info!("Adding client at {}", addr);

        // Skip clients that we know of already
        if result.contains_key(&addr) {
            warn!("Skipping duplicate client {}", addr);
            continue;
        }

        let client = Device::from_ip(*addr, args.local_ip)
            .expect(format!("Could not add client {}!", addr).as_str());

        info!("Client added => {}", client);
        result.insert(*addr, client);
    }

    return Ok(result);
}
