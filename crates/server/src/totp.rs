//! TOTP (RFC 6238) : SHA-1, 6 chiffres, 30 s, ±1 pas de tolérance, sans rejeu.

use totp_rs::{Algorithm, Builder, Totp};

const ISSUER: &str = "Portique";

/// Graine de 160 bits (recommandation RFC 4226).
pub fn new_secret() -> Vec<u8> {
    crate::crypto::random_bytes::<20>().to_vec()
}

pub(crate) fn build(secret: &[u8], account: &str) -> anyhow::Result<Totp> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(ISSUER))
        .with_account_name(account)
        .build()
        .map_err(|e| anyhow::anyhow!("TOTP : {e}"))
}

pub fn setup_info(secret: &[u8], account: &str) -> anyhow::Result<(String, String)> {
    let t = build(secret, account)?;
    let url = t.to_url().map_err(|e| anyhow::anyhow!("TOTP : {e}"))?;
    Ok((t.secret().to_base32(), url))
}

/// Vérifie `code` et renvoie le pas accepté, refusé s'il n'est pas postérieur à `last_step`.
pub fn verify(secret: &[u8], account: &str, code: &str, last_step: i64) -> anyhow::Result<Option<i64>> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let t = build(secret, account)?;
    Ok(t.check_current(&code).map(|s| s as i64).filter(|s| *s > last_step))
}

pub fn qr_svg(url: &str) -> anyhow::Result<String> {
    let code = qrcode::QrCode::new(url.as_bytes())?;
    Ok(code.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_current_code_once() {
        let s = new_secret();
        let t = build(&s, "alice").unwrap();
        let code = t.generate_current().to_string();
        let step = verify(&s, "alice", &code, 0).unwrap().expect("code courant accepté");
        assert_eq!(verify(&s, "alice", &code, step).unwrap(), None, "rejeu refusé");
        assert_eq!(verify(&s, "alice", "12345", 0).unwrap(), None);
    }
}
