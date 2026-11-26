//! Chromium reaches the network only through this proxy. It resolves every
//! host itself and connects to the address it checked, so no navigation,
//! redirect, popup, subresource or changed DNS answer reaches loopback,
//! private, link-local or cloud-metadata services on the agent's behalf.
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// What the proxy does with one resolved address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    Allow,
    /// Not routed from this host, so never tried. A dual-stack name still
    /// connects over its IPv4 addresses.
    Skip,
    /// Refuses the whole name.
    Refuse,
}

/// Which resolved addresses shopping may connect to.
pub(crate) type Policy = std::sync::Arc<dyn Fn(SocketAddr) -> Reach + Send + Sync>;

/// How this host reaches IPv6 destinations.
#[derive(Clone, Debug, Default)]
pub struct Ipv6Routes {
    /// Native global IPv6 reaches the internet. Off by default: an unknown
    /// global prefix can be a NAT64 gateway that reaches private IPv4.
    pub native: bool,
    /// NAT64 prefixes on this network. Addresses inside them are judged by
    /// the IPv4 address they embed.
    pub nat64: Vec<Nat64Prefix>,
}

/// An RFC 6052 NAT64 prefix, such as `64:ff9b:1::/96`.
#[derive(Clone, Copy, Debug)]
pub struct Nat64Prefix {
    bytes: [u8; 16],
    len: usize,
}

impl std::str::FromStr for Nat64Prefix {
    type Err = anyhow::Error;
    fn from_str(text: &str) -> Result<Self> {
        let (address, len) = text
            .split_once('/')
            .context("NAT64 prefix needs a length, as in 64:ff9b:1::/96")?;
        let len: usize = len.parse()?;
        if ![32, 40, 48, 56, 64, 96].contains(&len) {
            bail!("NAT64 prefix length must be 32, 40, 48, 56, 64 or 96");
        }
        let bytes = address.parse::<Ipv6Addr>()?.octets();
        if bytes[len / 8..].iter().any(|byte| *byte != 0) {
            bail!("NAT64 prefix has bits set past its length");
        }
        Ok(Self { bytes, len })
    }
}

impl Nat64Prefix {
    /// The IPv4 address inside `ip`, if `ip` is in this prefix. RFC 6052
    /// skips bits 64..72, so the address can straddle them.
    fn embedded(&self, ip: Ipv6Addr) -> Option<Ipv4Addr> {
        let octets = ip.octets();
        let start = self.len / 8;
        if octets[..start] != self.bytes[..start] {
            return None;
        }
        let mut v4 = (start..16).filter(|&i| i != 8).map(|i| octets[i]);
        Some(Ipv4Addr::from(std::array::from_fn(|_| {
            v4.next().unwrap_or(0)
        })))
    }
}

/// Public addresses, plus loopback for test and developer fixture merchants.
pub(crate) fn policy(allow_loopback: bool, ipv6: Ipv6Routes) -> Policy {
    std::sync::Arc::new(move |address| reach(address.ip(), allow_loopback, &ipv6))
}

/// Starts the proxy on a loopback port and returns it.
pub(crate) async fn start(policy: Policy) -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                continue;
            };
            let policy = policy.clone();
            tokio::spawn(async move {
                let _ = serve(client, &policy).await;
            });
        }
    });
    Ok(port)
}

/// Chromium flags that send all of its traffic through the proxy.
pub(crate) fn chromium_flags(port: u16) -> Vec<String> {
    vec![
        format!("--proxy-server=http://127.0.0.1:{port}"),
        // Chromium otherwise sends localhost directly, bypassing any proxy.
        "--proxy-bypass-list=<-loopback>".into(),
        // WebRTC can otherwise send UDP to any address the page names.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
    ]
}

async fn serve(client: TcpStream, policy: &Policy) -> Result<()> {
    let mut client = BufReader::new(client);
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if client.read_until(b'\n', &mut head).await? == 0 || head.len() > 16384 {
            return Ok(());
        }
    }
    let text = std::str::from_utf8(&head).context("Invalid proxy request")?;
    let (line, headers) = text.split_once("\r\n").context("Invalid proxy request")?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        bail!("Invalid proxy request");
    };
    let (host, port, request) = if method == "CONNECT" {
        let (host, port) = target.rsplit_once(':').context("Invalid CONNECT target")?;
        (host.to_owned(), port.parse()?, None)
    } else {
        // Plain HTTP arrives in absolute form. Forward one request per
        // connection so a reused proxy connection cannot change its host.
        let url = url::Url::parse(target)?;
        if url.scheme() != "http" {
            bail!("Unsupported proxy scheme");
        }
        let host = url.host_str().context("Missing host")?.to_owned();
        let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let mut request = format!("{method} {path} {version}\r\n");
        for header in headers.split("\r\n").filter(|h| !h.is_empty()) {
            let name = header.split(':').next().unwrap_or("").trim();
            if ![
                "connection",
                "proxy-connection",
                "keep-alive",
                "proxy-authorization",
            ]
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
            {
                request.push_str(header);
                request.push_str("\r\n");
            }
        }
        request.push_str("Connection: close\r\n\r\n");
        (
            host,
            url.port_or_known_default().unwrap_or(80),
            Some(request),
        )
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let upstream = match connect(host, port, policy).await {
        Ok(upstream) => upstream,
        Err(_) => {
            client
                .get_mut()
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Ok(());
        }
    };
    let mut upstream = upstream;
    match request {
        None => {
            client
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?
        }
        Some(request) => upstream.write_all(request.as_bytes()).await?,
    }
    // Bytes already read past the head (a request body) belong upstream.
    upstream.write_all(client.buffer()).await?;
    let mut client = client.into_inner();
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Connects only to an address the policy allows. A name with any refused
/// address is refused, so a mixed DNS answer cannot pick the private one.
async fn connect(host: &str, port: u16, policy: &Policy) -> Result<TcpStream> {
    let addresses = usable(tokio::net::lookup_host((host, port)).await?, policy)?;
    let mut last = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.context("No address")?.into())
}

fn usable(addresses: impl Iterator<Item = SocketAddr>, policy: &Policy) -> Result<Vec<SocketAddr>> {
    let mut usable = Vec::new();
    for address in addresses {
        match policy(address) {
            Reach::Allow => usable.push(address),
            Reach::Skip => {}
            Reach::Refuse => bail!("Shopping cannot reach that address"),
        }
    }
    if usable.is_empty() {
        bail!("Shopping cannot reach that address");
    }
    Ok(usable)
}

fn reach(ip: IpAddr, allow_loopback: bool, ipv6: &Ipv6Routes) -> Reach {
    if allow_loopback && ip.to_canonical().is_loopback() {
        return Reach::Allow;
    }
    match ip {
        IpAddr::V4(ip) => v4_reach(ip),
        IpAddr::V6(ip) => match ipv6.nat64.iter().find_map(|prefix| prefix.embedded(ip)) {
            Some(v4) => v4_reach(v4),
            None => v6_reach(ip, ipv6.native),
        },
    }
}

fn v4_reach(ip: Ipv4Addr) -> Reach {
    if public_v4(ip) {
        Reach::Allow
    } else {
        Reach::Refuse
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (18..20).contains(&b)) // benchmarking
        || a >= 240)
}

fn v6_reach(ip: Ipv6Addr, native: bool) -> Reach {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_reach(v4);
    }
    let s = ip.segments();
    // NAT64 embeds an IPv4 address; judge that address. This covers the
    // well-known prefix 64:ff9b::/96 and the local-use 64:ff9b:1::/48
    // (RFC 8215) when it is used as a /96.
    if s[0] == 0x64 && s[1] == 0xff9b && (s[2..6] == [0; 4] || (s[2] == 1 && s[3..6] == [0; 3])) {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return v4_reach(Ipv4Addr::new(a, b, c, d));
    }
    // Other lengths inside 64:ff9b:1::/48 put the IPv4 address elsewhere, so
    // refuse them rather than guess.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1 {
        return Reach::Refuse;
    }
    let special = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || s[0..6] == [0; 6] // IPv4-compatible
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || (s[0] & 0xffc0) == 0xfec0 // site-local
        || s[0] == 0x2002 // 6to4 can carry a private IPv4 address
        || (s[0] == 0x2001 && s[1] == 0x0db8); // documentation
    match (special, native) {
        (true, _) => Reach::Refuse,
        (false, true) => Reach::Allow,
        // Unless native IPv6 is routed, a global address may be a
        // deployment's own NAT64 prefix in front of private IPv4.
        (false, false) => Reach::Skip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(ip: &str, allow_loopback: bool) -> bool {
        let native = Ipv6Routes {
            native: true,
            nat64: Vec::new(),
        };
        reach(ip.parse().unwrap(), allow_loopback, &native) == Reach::Allow
    }

    #[test]
    fn only_public_addresses_are_reachable() {
        for refused in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::169.254.169.254",
            "64:ff9b:1::10.0.0.1",
            "64:ff9b:1:a9fe:a9:fe00::",
            "2002:c0a8:0101::1",
        ] {
            assert!(!allowed(refused, false), "{refused}");
        }
        for public in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
            "64:ff9b:1::8.8.8.8",
        ] {
            assert!(allowed(public, false), "{public}");
        }
        // Test fixtures may use loopback, never other private networks.
        assert!(allowed("127.0.0.1", true));
        assert!(allowed("::1", true));
        assert!(!allowed("169.254.169.254", true));
        assert!(!allowed("10.0.0.1", true));
    }

    #[test]
    fn global_ipv6_needs_native_routes_or_a_known_nat64_prefix() {
        let default = Ipv6Routes::default();
        let reach = |ip: &str, routes: &Ipv6Routes| reach(ip.parse().unwrap(), false, routes);
        // A deployment's own NAT64 prefix looks like any global address.
        assert_eq!(reach("2001:db9:64::a9fe:a9fe", &default), Reach::Skip);
        assert_eq!(reach("2606:4700:4700::1111", &default), Reach::Skip);
        let nat64 = Ipv6Routes {
            native: true,
            nat64: vec![
                "2001:db9:64::/96".parse().unwrap(),
                "2001:db9:4000::/40".parse().unwrap(),
            ],
        };
        assert_eq!(reach("2001:db9:64::a9fe:a9fe", &nat64), Reach::Refuse);
        assert_eq!(reach("2001:db9:64::10.0.0.1", &nat64), Reach::Refuse);
        assert_eq!(reach("2001:db9:64::8.8.8.8", &nat64), Reach::Allow);
        // A /40 prefix puts 169.254.169.254 around the reserved octet.
        assert_eq!(reach("2001:db9:40a9:fea9:fe:fe00::", &nat64), Reach::Refuse);
        assert_eq!(reach("2001:db9:4008:808:8:800::", &nat64), Reach::Allow);
        assert_eq!(reach("2606:4700:4700::1111", &nat64), Reach::Allow);
        for bad in ["64:ff9b:1::", "64:ff9b:1::/100", "64:ff9b:1::1/96"] {
            assert!(bad.parse::<Nat64Prefix>().is_err(), "{bad}");
        }
    }

    #[test]
    fn dual_stack_names_use_ipv4_without_native_ipv6() {
        let policy = policy(false, Ipv6Routes::default());
        let v6: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        let v4: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(usable([v6, v4].into_iter(), &policy).unwrap(), [v4]);
        assert!(usable([v6].into_iter(), &policy).is_err());
        let private: SocketAddr = "[fd00::1]:443".parse().unwrap();
        assert!(usable([private, v4].into_iter(), &policy).is_err());
    }
}
