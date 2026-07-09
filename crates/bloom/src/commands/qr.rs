//! Terminal QR helpers for wallet deposit addresses.

use qrcode::QrCode;
use qrcode::render::svg;
use qrcode::render::unicode;

/// Render `data` as a terminal QR code (Unicode half-blocks), or `None` if the
/// payload is too large to encode. Callers should always print the raw payload
/// too, so a `None` here is non-fatal.
pub fn render_qr(data: &str) -> Option<String> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    Some(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

/// Render `data` as a standalone SVG QR document (scannable image file), or
/// `None` if the payload is too large to encode.
pub fn render_qr_svg(data: &str) -> Option<String> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(256, 256)
            .quiet_zone(true)
            .build(),
    )
}

/// Print the deposit QR + plain address block for a single address.
pub fn print_deposit(address: &str) {
    println!("deposit address (same EOA on every EVM chain; send only on supported chains):");
    if let Some(qr) = render_qr(address) {
        println!("\n{qr}");
    }
    println!("  {address}\n");
}
