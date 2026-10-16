//! « HTML Format » (CF_HTML) : en-tête ASCII d'offsets en octets UTF-8, puis le document
//! contexte avec le fragment entre `<!--StartFragment-->` et `<!--EndFragment-->`
//! (doc Microsoft « HTML Clipboard Format »).

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

const START: &str = "<!--StartFragment-->";
const END: &str = "<!--EndFragment-->";

/// Emballe un fragment HTML en CF_HTML (UTF-8, terminé par un octet nul).
pub fn html_to_cf_html(fragment: &str) -> Vec<u8> {
    const PRE: &str = "<html><body>\r\n";
    const POST: &str = "\r\n</body></html>";
    // Offsets sur 10 chiffres : longueur d'en-tête fixe.
    let header_len = format!(
        "Version:0.9\r\nStartHTML:{0:010}\r\nEndHTML:{0:010}\r\nStartFragment:{0:010}\r\nEndFragment:{0:010}\r\n",
        0
    )
    .len();
    let start_fragment = header_len + PRE.len() + START.len();
    let end_fragment = start_fragment + fragment.len();
    let end_html = end_fragment + END.len() + POST.len();
    let mut out = format!(
        "Version:0.9\r\nStartHTML:{header_len:010}\r\nEndHTML:{end_html:010}\r\n\
         StartFragment:{start_fragment:010}\r\nEndFragment:{end_fragment:010}\r\n\
         {PRE}{START}{fragment}{END}{POST}"
    )
    .into_bytes();
    out.push(0);
    out
}

/// Valeur entière d'une clé de l'en-tête (`Clé:valeur`), si présente et positive.
fn offset(header: &str, key: &str) -> Option<usize> {
    header.lines().find_map(|l| l.trim().strip_prefix(key)?.strip_prefix(':')?.trim().parse().ok())
}

/// Fragment d'un CF_HTML. Les offsets de l'en-tête priment s'ils sont cohérents (après
/// l'en-tête, ordonnés, dans les bornes, sur des limites de caractères) ; sinon les
/// commentaires StartFragment/EndFragment ; sinon le contexte entier. UTF-8 invalide remplacé.
pub fn cf_html_fragment(data: &[u8]) -> String {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let text = String::from_utf8_lossy(&data[..end]);
    // Si le remplacement a changé les longueurs, les offsets ne valent plus : on passe aux marqueurs.
    let exact = text.len() == end;
    let header_end = text.find('<').unwrap_or(text.len());
    let header = &text[..header_end];

    let slice = |s: Option<usize>, e: Option<usize>| {
        let (s, e) = (s?, e?);
        (exact && header_end <= s && s <= e && e <= text.len()).then(|| text.get(s..e)).flatten()
    };
    if let Some(f) = slice(offset(header, "StartFragment"), offset(header, "EndFragment")) {
        return f.to_string();
    }
    let body = &text[header_end..];
    if let Some(i) = body.find("<!--StartFragment") {
        let rest = &body[i..];
        if let Some(open) = rest.find("-->") {
            let rest = &rest[open + 3..];
            let close = rest.find("<!--EndFragment").unwrap_or(rest.len());
            return rest[..close].to_string();
        }
    }
    slice(offset(header, "StartHTML"), offset(header, "EndHTML")).unwrap_or(body).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_offsets_exact() {
        let frag = "<b>été</b> &amp; <i>ok</i>";
        let cf = html_to_cf_html(frag);
        assert_eq!(cf.last(), Some(&0));
        let s = core::str::from_utf8(&cf[..cf.len() - 1]).unwrap();
        let get = |k| offset(s, k).unwrap();
        assert_eq!(&s[get("StartFragment")..get("EndFragment")], frag);
        assert!(s[get("StartHTML")..].starts_with("<html>"));
        assert_eq!(get("EndHTML"), s.len());
        assert_eq!(cf_html_fragment(&cf), frag);
    }

    #[test]
    fn microsoft_doc_example() {
        // Exemple « Scenario 1 » de la doc Microsoft : ses offsets ne tombent pas dans le
        // document (StartFragment:0006 est dans l'en-tête), d'où le repli sur les marqueurs.
        let cf = "Version:1.0\r\nStartHTML:0121\r\nEndHTML:0272\r\nStartFragment:0006\r\n\
                  EndFragment:0106\r\nStartSelection:0180\r\nEndSelection:0225\r\n\
                  <html><!--StartFragment--><body>This is normal. <b>This is bold.</b> <i><b>This is \
                  bold italic.</b> This is italic.</i></body><!--EndFragment--></html>";
        assert_eq!(
            cf_html_fragment(cf.as_bytes()),
            "<body>This is normal. <b>This is bold.</b> <i><b>This is bold italic.</b> \
             This is italic.</i></body>"
        );
    }

    #[test]
    fn markers_with_space_and_garbage() {
        let cf = "Version:0.9\nStartFragment:-1\n<html><!--StartFragment -->x<!--EndFragment --></html>\0\0";
        assert_eq!(cf_html_fragment(cf.as_bytes()), "x");
        assert_eq!(cf_html_fragment(b""), "");
        assert_eq!(cf_html_fragment(b"Version:0.9\r\nStartFragment:99999\r\n"), "");
        assert_eq!(cf_html_fragment(b"<p>brut</p>"), "<p>brut</p>");
        // Offsets au milieu d'un caractère multioctet : rejetés, repli sur le contexte.
        let bad = "StartFragment:35\r\nEndFragment:36\r\n<é>";
        assert_eq!(cf_html_fragment(bad.as_bytes()), "<é>");
        let _ = cf_html_fragment(&[0xFF, b'<', 0xC3]);
    }
}
