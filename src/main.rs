use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;
use color_eyre::Result;
use etherparse::PacketHeaders;
use pcap::{Capture, Packet};
use serde::Serialize;
use solana_sdk::{
    sanitize::Sanitize,
    transaction::Transaction,
};

#[derive(Parser, Debug)]
#[clap()]
struct Args {
    /// List of pcaps to load
    #[clap()]
    pcaps: Vec<PathBuf>,

    #[clap(long, short)]
    tpu_addr: Option<String>,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let tpu_addr: Option<SocketAddr> = args
        .tpu_addr
        .as_ref()
        .map(|s| s.parse().expect("invalid tpu address"));

    let stdout =  std::io::stdout();
    let stdout_lock = stdout.lock();
    let mut writer = csv::Writer::from_writer(stdout_lock);

    for pcap_file in args.pcaps.iter() {
        let mut pcap = Capture::from_file(pcap_file)?;
        if let Some(tpu_addr) = tpu_addr {
            pcap.filter(
                format!(
                    "ip dst host {} and udp dst port {}",
                    tpu_addr.ip(),
                    tpu_addr.port()
                )
                .as_str(),
                true,
            )?;
        } else {
            pcap.filter("udp", true)?;
        }
        while let Ok(packet) = pcap.next() {
            if let Some(record) = Record::from_packet(packet) {
                if writer.serialize(record).is_err() {
                    return Ok(()) // gracefully handle broken pipe
                }
            }
        }
    }

    Ok(())
}

#[derive(Default, Serialize)]
struct Record {
    src_ip: String,
    src_port: u16,
    payload_len: usize,
    sanitized: &'static str,
    signature: String,
    fee_payer: String,
    num_ins: usize,
}

impl Record {
    fn from_packet(packet: Packet) -> Option<Self> {
        let packet = PacketHeaders::from_ethernet_slice(&packet).ok()?;
        let ip_header = packet.ip?;
        let udp_header = packet.transport?.udp()?;
        let source_ip = match ip_header {
            etherparse::IpHeader::Version4(header, _) => IpAddr::V4(Ipv4Addr::from(header.source)),
            etherparse::IpHeader::Version6(header, _) => IpAddr::V6(Ipv6Addr::from(header.source)),
        };

        let mut record: Self = Default::default();
        record.payload_len = packet.payload.len();
        record.src_ip = source_ip.to_string();
        record.src_port = udp_header.source_port;

        record.sanitized = match record.parse_tx(packet.payload) {
            Ok(_) => "1",
            Err(_) => "0",
        };

        Some(record)
    }

    fn parse_tx(&mut self, payload: &[u8]) -> Result<()> {
        let tx = bincode::deserialize::<Transaction>(payload)?;
        tx.sanitize()?;

        self.signature = tx.signatures[0].to_string();
        self.fee_payer = tx.message.account_keys[0].to_string();
        self.num_ins = tx.message.instructions.len();

        Ok(())
    }
}
