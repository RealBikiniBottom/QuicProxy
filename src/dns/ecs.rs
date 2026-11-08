//! EDNS Client Subnet (RFC 7871).

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use simple_dns::Packet;
use simple_dns::rdata::{OPT, OPTCode};
use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const OPTION_CODE: u16 = 8;
pub const DEFAULT_IPV4_PREFIX: u8 = 24;
pub const DEFAULT_IPV6_PREFIX: u8 = 56;
const FAMILY_IPV4: u16 = 1;
const FAMILY_IPV6: u16 = 2;
const DEFAULT_UDP_PAYLOAD: u16 = 1232;

/// A client subnet as carried in the ECS option. The scope prefix only matters in
/// responses and is kept so it survives a rewrite of the source subnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientSubnet {
    net: IpNet,
    scope: u8,
}

impl ClientSubnet {
    pub fn new(net: IpNet) -> Self {
        Self {
            net: net.trunc(),
            scope: 0,
        }
    }

    pub fn from_ip(ip: IpAddr, ipv4_prefix: u8, ipv6_prefix: u8) -> Result<Self> {
        let net = match ip.to_canonical() {
            IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), ipv4_prefix),
            IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), ipv6_prefix),
        }
        .with_context(|| format!("invalid client subnet prefix for {ip}"))?;
        Ok(Self::new(net))
    }

    /// `"203.0.113.0/24"`, or a bare address which gets the default prefix of its family.
    pub fn parse(value: &str) -> Result<Self> {
        if let Ok(net) = value.parse::<IpNet>() {
            return Ok(Self::new(net));
        }
        let ip = value
            .parse::<IpAddr>()
            .with_context(|| format!("invalid client subnet {value:?}"))?;
        Self::from_ip(ip, DEFAULT_IPV4_PREFIX, DEFAULT_IPV6_PREFIX)
    }

    pub fn net(&self) -> IpNet {
        self.net
    }

    pub fn scope(&self) -> u8 {
        self.scope
    }

    /// Wire format of the option data: FAMILY, SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH,
    /// then only the address octets the source prefix covers.
    pub fn encode(&self) -> Vec<u8> {
        let (family, octets): (u16, Vec<u8>) = match self.net.addr() {
            IpAddr::V4(v4) => (FAMILY_IPV4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (FAMILY_IPV6, v6.octets().to_vec()),
        };
        let prefix = self.net.prefix_len();
        let mut data = Vec::with_capacity(4 + octets.len());
        data.extend_from_slice(&family.to_be_bytes());
        data.push(prefix);
        data.push(self.scope);
        data.extend_from_slice(&octets[..(prefix as usize).div_ceil(8)]);
        data
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            bail!("ECS option too short");
        }
        let family = u16::from_be_bytes([data[0], data[1]]);
        let prefix = data[2];
        let scope = data[3];
        let address = &data[4..];
        if address.len() != (prefix as usize).div_ceil(8) {
            bail!("ECS address length does not match prefix {prefix}");
        }
        let addr = match family {
            FAMILY_IPV4 if prefix <= 32 => {
                let mut octets = [0u8; 4];
                octets[..address.len()].copy_from_slice(address);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            FAMILY_IPV6 if prefix <= 128 => {
                let mut octets = [0u8; 16];
                octets[..address.len()].copy_from_slice(address);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => bail!("unsupported ECS family {family} / prefix {prefix}"),
        };
        Ok(Self {
            net: IpNet::new(addr, prefix)?.trunc(),
            scope,
        })
    }
}

impl fmt::Display for ClientSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.net)
    }
}

/// The ECS option in `packet`, if it has a valid one.
pub fn get(packet: &Packet<'_>) -> Option<ClientSubnet> {
    packet
        .opt()?
        .opt_codes
        .iter()
        .find(|o| o.code == OPTION_CODE)
        .and_then(|o| ClientSubnet::decode(&o.data).ok())
}

/// Replaces the ECS option in `packet`, or removes it with `None`. An OPT record is added
/// when the packet has none and a subnet is set.
pub fn set(packet: &mut Packet<'_>, subnet: Option<ClientSubnet>) {
    let opt = packet.opt_mut();
    if opt.is_none() && subnet.is_none() {
        return;
    }
    let opt = opt.get_or_insert_with(|| OPT {
        opt_codes: Vec::new(),
        udp_packet_size: DEFAULT_UDP_PAYLOAD,
        version: 0,
    });
    opt.opt_codes.retain(|o| o.code != OPTION_CODE);
    if let Some(subnet) = subnet {
        opt.opt_codes.push(OPTCode {
            code: OPTION_CODE,
            data: Cow::Owned(subnet.encode()),
        });
    }
}

/// Makes a response answer the query the client actually sent: no OPT record if it sent
/// none, no ECS if it sent none (RFC 7871 section 7.2.2), otherwise its own source subnet
/// with the upstream scope.
pub fn restore_response(response: &mut Packet<'_>, sent: Option<ClientSubnet>, sent_opt: bool) {
    if !sent_opt {
        *response.opt_mut() = None;
        return;
    }
    let restored = sent.map(|sent| ClientSubnet {
        scope: get(response).map_or(0, |r| r.scope.min(sent.net.prefix_len())),
        ..sent
    });
    if get(response) != restored {
        set(response, restored);
    }
}

/// A DNS server's `client_subnet`: added to queries that carry none, or to every
/// query with `override`.
#[derive(Clone, Copy, Debug)]
pub struct ClientSubnetPolicy {
    pub subnet: ClientSubnet,
    pub override_existing: bool,
}

impl ClientSubnetPolicy {
    pub fn from_config(value: Option<&str>, override_existing: bool) -> Result<Option<Self>> {
        value
            .map(|v| {
                Ok(Self {
                    subnet: ClientSubnet::parse(v)?,
                    override_existing,
                })
            })
            .transpose()
    }

    /// The query to send upstream, when this policy changes it.
    pub fn apply(&self, packet: &Packet<'_>) -> Option<Packet<'static>> {
        let current = get(packet);
        if current.is_some() && !self.override_existing {
            return None;
        }
        if current == Some(self.subnet) {
            return None;
        }
        let mut adjusted = super::into_owned_packet(packet.clone());
        set(&mut adjusted, Some(self.subnet));
        Some(adjusted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{QTYPE, TYPE};

    fn query() -> Packet<'static> {
        super::super::build_dns_query_packet("example.com", QTYPE::TYPE(TYPE::A)).unwrap()
    }

    #[test]
    fn encodes_rfc7871_example() {
        let subnet = ClientSubnet::parse("198.51.100.77/24").unwrap();
        assert_eq!(subnet.to_string(), "198.51.100.0/24");
        assert_eq!(subnet.encode(), vec![0, 1, 24, 0, 198, 51, 100]);
        assert_eq!(ClientSubnet::decode(&subnet.encode()).unwrap(), subnet);

        let v6 = ClientSubnet::parse("2001:db8:1234:5678::1/56").unwrap();
        assert_eq!(
            v6.encode(),
            vec![0, 2, 56, 0, 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56]
        );
        assert_eq!(ClientSubnet::decode(&v6.encode()).unwrap(), v6);
    }

    #[test]
    fn bare_address_gets_family_default_prefix() {
        assert_eq!(
            ClientSubnet::parse("203.0.113.9").unwrap().to_string(),
            "203.0.113.0/24"
        );
        assert_eq!(
            ClientSubnet::parse("2001:db8::1").unwrap().to_string(),
            "2001:db8::/56"
        );
        assert!(ClientSubnet::parse("nope").is_err());
    }

    #[test]
    fn from_ip_unmaps_ipv4_mapped_peers() {
        let ip: IpAddr = "::ffff:203.0.113.200".parse().unwrap();
        let subnet = ClientSubnet::from_ip(ip, 24, 56).unwrap();
        assert_eq!(subnet.to_string(), "203.0.113.0/24");
    }

    #[test]
    fn decode_rejects_inconsistent_lengths() {
        assert!(ClientSubnet::decode(&[0, 1, 24, 0, 1, 2]).is_err());
        assert!(ClientSubnet::decode(&[0, 1, 33, 0, 1, 2, 3, 4, 5]).is_err());
        assert!(ClientSubnet::decode(&[0, 3, 0, 0]).is_err());
    }

    #[test]
    fn opt_out_prefix_zero_round_trips() {
        let subnet = ClientSubnet::parse("0.0.0.0/0").unwrap();
        assert_eq!(subnet.encode(), vec![0, 1, 0, 0]);
        assert_eq!(ClientSubnet::decode(&[0, 1, 0, 0]).unwrap(), subnet);
    }

    #[test]
    fn set_get_and_remove_survive_the_wire() {
        let mut packet = query();
        let subnet = ClientSubnet::parse("192.0.2.0/24").unwrap();
        set(&mut packet, Some(subnet));
        let bytes = packet.build_bytes_vec().unwrap();
        let mut parsed = Packet::parse(&bytes).unwrap();
        assert_eq!(get(&parsed), Some(subnet));

        set(&mut parsed, None);
        let bytes = parsed.build_bytes_vec().unwrap();
        assert_eq!(get(&Packet::parse(&bytes).unwrap()), None);
    }

    #[test]
    fn policy_respects_existing_subnet_unless_override() {
        let configured = ClientSubnet::parse("192.0.2.0/24").unwrap();
        let client = ClientSubnet::parse("198.51.100.0/24").unwrap();
        let mut with_client = query();
        set(&mut with_client, Some(client));

        let keep = ClientSubnetPolicy {
            subnet: configured,
            override_existing: false,
        };
        assert_eq!(get(&keep.apply(&query()).unwrap()), Some(configured));
        assert!(keep.apply(&with_client).is_none());

        let force = ClientSubnetPolicy {
            override_existing: true,
            ..keep
        };
        assert_eq!(get(&force.apply(&with_client).unwrap()), Some(configured));
    }

    #[test]
    fn restore_response_hides_or_restores_the_client_subnet() {
        let mut response = query();
        let upstream = ClientSubnet {
            scope: 20,
            ..ClientSubnet::parse("192.0.2.0/24").unwrap()
        };
        set(&mut response, Some(upstream));

        let mut hidden = response.clone();
        restore_response(&mut hidden, None, true);
        assert!(hidden.opt().is_some());
        assert_eq!(get(&hidden), None);

        let client = ClientSubnet::parse("198.51.100.0/24").unwrap();
        restore_response(&mut response, Some(client), true);
        let restored = get(&response).unwrap();
        assert_eq!(restored.net(), client.net());
        assert_eq!(restored.scope(), 20);

        restore_response(&mut response, None, false);
        assert!(response.opt().is_none());
    }
}
