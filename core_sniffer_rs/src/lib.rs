use pyo3::prelude::*;
use pyo3::types::PyDict;
use pcap::{Device, Capture};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[pyclass]
pub struct RustSniffer {
    is_running: Arc<Mutex<bool>>,
}

#[pymethods]
impl RustSniffer {
    #[new]
    fn new() -> Self {
        RustSniffer {
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    fn stop_capture(&self) {
        let mut running = self.is_running.lock().unwrap();
        *running = false;
    }

    fn start_capture(&self, py: Python, interface_name: String, bpf_filter: String, callback: PyObject) -> PyResult<()> {
        let mut running = self.is_running.lock().unwrap();
        if *running {
            return Ok(());
        }
        *running = true;
        let is_running_clone = Arc::clone(&self.is_running);

        thread::spawn(move || {
            let mut cap = match Capture::from_device(interface_name.as_str()) {
                Ok(c) => c.promisc(true).snaplen(65535).timeout(100).open().unwrap(),
                Err(e) => {
                    eprintln!("Failed to open device {}: {:?}", interface_name, e);
                    return;
                }
            };

            if !bpf_filter.is_empty() {
                if let Err(e) = cap.filter(&bpf_filter, true) {
                    eprintln!("Failed to apply BPF filter {}: {:?}", bpf_filter, e);
                }
            }

            while *is_running_clone.lock().unwrap() {
                if let Ok(packet) = cap.next_packet() {
                    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
                    
                    if let Some(ethernet) = EthernetPacket::new(packet.data) {
                        let mut packet_info = serde_json::Map::new();
                        packet_info.insert("timestamp".to_string(), serde_json::json!(ts));
                        packet_info.insert("length".to_string(), serde_json::json!(packet.header.len));

                        match ethernet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                    packet_info.insert("src_ip".to_string(), serde_json::json!(ipv4.get_source().to_string()));
                                    packet_info.insert("dst_ip".to_string(), serde_json::json!(ipv4.get_destination().to_string()));

                                    match ipv4.get_next_level_protocol() {
                                        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                                packet_info.insert("protocol".to_string(), serde_json::json!("TCP"));
                                                packet_info.insert("src_port".to_string(), serde_json::json!(tcp.get_source()));
                                                packet_info.insert("dst_port".to_string(), serde_json::json!(tcp.get_destination()));
                                                packet_info.insert("tcp_flags".to_string(), serde_json::json!(tcp.get_flags()));
                                            }
                                        },
                                        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                                packet_info.insert("protocol".to_string(), serde_json::json!("UDP"));
                                                packet_info.insert("src_port".to_string(), serde_json::json!(udp.get_source()));
                                                packet_info.insert("dst_port".to_string(), serde_json::json!(udp.get_destination()));
                                            }
                                        },
                                        pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                                            if let Some(_) = IcmpPacket::new(ipv4.payload()) {
                                                packet_info.insert("protocol".to_string(), serde_json::json!("ICMP"));
                                            }
                                        },
                                        _ => {}
                                    }
                                }
                            },
                            EtherTypes::Arp => {
                                packet_info.insert("protocol".to_string(), serde_json::json!("ARP"));
                            },
                            _ => {}
                        }

                        let json_str = serde_json::to_string(&packet_info).unwrap();
                        
                        Python::with_gil(|py| {
                            let _ = callback.call1(py, (json_str,));
                        });
                    }
                }
            }
        });

        Ok(())
    }
}

#[pymodule]
fn core_sniffer_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RustSniffer>()?;
    Ok(())
}
