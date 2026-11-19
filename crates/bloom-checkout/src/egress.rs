//! Chromium reaches the network only through this proxy. It resolves every
//! host itself and connects to the address it checked, so no navigation,
//! redirect, popup, subresource or changed DNS answer reaches loopback,
//! private, link-local or cloud-metadata services on the agent's behalf.
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Which resolved addresses shopping may connect to.
pub(crate) type Policy = std::sync::Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

/// Public addresses, plus loopback for test and developer fixture merchants.
pub(crate) fn policy(allow_loopback: bool) -> Policy {
    std::sync::Arc::new(move |address| allowed(address.ip(), allow_loopback))
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
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addresses.is_empty() || addresses.iter().any(|address| !policy(*address)) {
        bail!("Shopping cannot reach that address");
    }
    let mut last = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.context("No address")?.into())
}

fn allowed(ip: IpAddr, allow_loopback: bool) -> bool {
    if allow_loopback && ip.to_canonical().is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
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

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = ip.segments();
    // NAT64 embeds an IPv4 address; judge that address.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return public_v4(Ipv4Addr::new(a, b, c, d));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || s[0..6] == [0; 6] // IPv4-compatible
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || (s[0] & 0xffc0) == 0xfec0 // site-local
        || s[0] == 0x2002 // 6to4 can carry a private IPv4 address
        || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "2002:c0a8:0101::1",
        ] {
            assert!(!allowed(refused.parse().unwrap(), false), "{refused}");
        }
        for public in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
        ] {
            assert!(allowed(public.parse().unwrap(), false), "{public}");
        }
        // Test fixtures may use loopback, never other private networks.
        assert!(allowed("127.0.0.1".parse().unwrap(), true));
        assert!(allowed("::1".parse().unwrap(), true));
        assert!(!allowed("169.254.169.254".parse().unwrap(), true));
        assert!(!allowed("10.0.0.1".parse().unwrap(), true));
    }
}
