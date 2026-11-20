use super::*;
use alloc::{string::ToString, vec};

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// MS-RDPECLIP 4.1.1 : CB_CLIP_CAPS du serveur (noms longs, fichiers).
const SERVER_CAPS: &str = "07 00 00 00 10 00 00 00 01 00 00 00 01 00 0c 00 02 00 00 00 0e 00 00 00";
/// 4.1.2 : Monitor Ready.
const MONITOR_READY: &str = "01 00 00 00 00 00 00 00";
/// Format List Response refusée (2.2.3.2, CB_RESPONSE_FAIL).
const LIST_FAIL: &str = "03 00 02 00 00 00 00 00";
/// PNG 1×1 RGBA valide (signature, IHDR, IDAT, IEND).
const PNG_1X1: &str = "89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 00 01 00 00 00 01 08 06 00 00 00 \
    1f 15 c4 89 00 00 00 0d 49 44 41 54 78 9c 63 60 64 62 66 01 00 00 19 00 0b e7 5a 46 a4 00 00 00 00 \
    49 45 4e 44 ae 42 60 82";

fn sends(ev: &[ClipEvent]) -> Vec<&[u8]> {
    ev.iter().filter_map(|e| if let ClipEvent::Send(b) = e { Some(b.as_slice()) } else { None }).collect()
}

fn ready() -> Clipboard {
    let mut c = Clipboard::new();
    assert!(c.receive(&unhex(SERVER_CAPS)).unwrap().is_empty());
    c.receive(&unhex(MONITOR_READY)).unwrap();
    c
}

#[test]
fn initialization_matches_spec() {
    let mut c = Clipboard::new();
    c.receive(&unhex(SERVER_CAPS)).unwrap();
    assert!(c.long_names);
    let ev = c.receive(&unhex(MONITOR_READY)).unwrap();
    let s = sends(&ev);
    // 4.1.3 sans CB_STREAM_FILECLIP_ENABLED ni CB_FILECLIP_NO_FILE_PATHS : drapeaux 0x02.
    assert_eq!(s[0], unhex("07 00 00 00 10 00 00 00 01 00 00 00 01 00 0c 00 02 00 00 00 02 00 00 00"));
    // Format List vide (rien de local encore).
    assert_eq!(s[1], unhex("02 00 00 00 00 00 00 00"));
    assert_eq!(s.len(), 2);
}

#[test]
fn spec_format_list_and_response() {
    // 4.1.5 : « Native », 3, 8, 17 → réponse 4.1.6 et formats reconnus (CF_DIB).
    let mut c = ready();
    let list = unhex(
        "02 00 00 00 24 00 00 00 04 c0 00 00 4e 00 61 00 74 00 69 00 76 00 65 00 00 00 \
         03 00 00 00 00 00 08 00 00 00 00 00 11 00 00 00 00 00",
    );
    let ev = c.receive(&list).unwrap();
    assert_eq!(c.remote[0], (0xC004, "Native".to_string()));
    assert_eq!(c.remote.len(), 4);
    assert_eq!(ev[0], ClipEvent::Send(unhex("03 00 01 00 00 00 00 00")));
    assert_eq!(ev[1], ClipEvent::RemoteChanged(vec![ClipFormat::Dib]));
}

#[test]
fn spec_rich_text_list_offers_text() {
    // 4.2.1 : RTF, CF_TEXT, CF_UNICODETEXT, « Native »… → seul le texte nous concerne.
    let mut c = ready();
    let list = unhex(
        "02 00 00 00 e0 00 00 00 8a c0 00 00 52 00 69 00 63 00 68 00 20 00 54 00 65 00 78 00 74 00 20 00 \
         46 00 6f 00 72 00 6d 00 61 00 74 00 00 00 45 c1 00 00 52 00 69 00 63 00 68 00 20 00 54 00 65 00 \
         78 00 74 00 20 00 46 00 6f 00 72 00 6d 00 61 00 74 00 20 00 57 00 69 00 74 00 68 00 6f 00 75 00 \
         74 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 00 00 43 c1 00 00 52 00 54 00 46 00 20 00 \
         41 00 73 00 20 00 54 00 65 00 78 00 74 00 00 00 01 00 00 00 00 00 0d 00 00 00 00 00 04 c0 00 00 \
         4e 00 61 00 74 00 69 00 76 00 65 00 00 00 0e c0 00 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 \
         44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 6f 00 72 00 00 00 03 00 00 00 00 00 10 00 00 00 \
         00 00 07 00 00 00 00 00",
    );
    let ev = c.receive(&list).unwrap();
    assert_eq!(c.remote.len(), 10);
    assert_eq!(c.remote[1].1, "Rich Text Format Without Objects");
    assert_eq!(ev[1], ClipEvent::RemoteChanged(vec![ClipFormat::Text]));

    // 4.4.1 puis 4.4.2 : demande de CF_UNICODETEXT, réponse « hello world ».
    let ev = c.request(&[ClipFormat::Html, ClipFormat::Text]);
    assert_eq!(sends(&ev), [unhex("04 00 00 00 04 00 00 00 0d 00 00 00").as_slice()]);
    assert!(c.request(&[ClipFormat::Text]).is_empty(), "une seule demande en vol");
    let resp = unhex(
        "05 00 01 00 18 00 00 00 68 00 65 00 6c 00 6c 00 6f 00 20 00 77 00 6f 00 72 00 6c 00 64 00 00 00",
    );
    let ev = c.receive(&resp).unwrap();
    assert_eq!(ev, [ClipEvent::RemoteData(Some(LocalData::Text("hello world".into())))]);
    // Réponse en trop : ignorée.
    assert!(c.receive(&resp).unwrap().is_empty());
}

#[test]
fn full_sequence_with_local_content() {
    let mut c = Clipboard::new();
    // Contenu local avant Monitor Ready : gardé, annoncé à l'initialisation.
    let ev = c.set_local(vec![
        LocalData::Html("<b>gras</b>".into()),
        LocalData::Text("a\nb".into()),
        LocalData::Rgba { width: 1, height: 1, rgba: vec![1, 2, 3, 4] },
    ]);
    assert!(ev.is_empty());
    c.receive(&unhex(SERVER_CAPS)).unwrap();
    let ev = c.receive(&unhex(MONITOR_READY)).unwrap();
    let list = sends(&ev)[1];
    let mut expected = unhex("02 00 00 00 00 00 00 00 f0 c0 00 00");
    expected.extend("HTML Format\0".encode_utf16().flat_map(u16::to_le_bytes));
    expected.extend_from_slice(&unhex("0d 00 00 00 00 00 08 00 00 00 00 00"));
    expected[4] = (expected.len() - 8) as u8;
    assert_eq!(list, expected);

    // Le serveur demande le texte, le HTML, l'image, puis un format absent.
    let req = |id: u32| {
        let mut m = unhex("04 00 00 00 04 00 00 00");
        m.extend_from_slice(&id.to_le_bytes());
        m
    };
    let ev = c.receive(&req(13)).unwrap();
    assert_eq!(sends(&ev)[0], unhex("05 00 01 00 0a 00 00 00 61 00 0d 00 0a 00 62 00 00 00"));
    let ev = c.receive(&req(LOCAL_HTML)).unwrap();
    let html = &sends(&ev)[0][8..];
    assert_eq!(cf_html_fragment(html), "<b>gras</b>");
    let ev = c.receive(&req(CF_DIB)).unwrap();
    let dib = &sends(&ev)[0][8..];
    assert_eq!(dib_to_rgba(dib).unwrap(), (1, 1, vec![1, 2, 3, 4]));
    let ev = c.receive(&req(LOCAL_PNG)).unwrap();
    assert_eq!(sends(&ev)[0], unhex("05 00 02 00 00 00 00 00"));

    // Le serveur copie du HTML et un PNG : réponse OK, RemoteChanged, contenu local oublié.
    let mut list = Vec::new();
    for (id, name) in [(0xC0AAu32, "HTML Format"), (0xC0BB, "PNG"), (13, "")] {
        list.extend_from_slice(&id.to_le_bytes());
        list.extend(name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    }
    let ev = c.receive(&pdu(msg::FORMAT_LIST, 0, &list)).unwrap();
    assert_eq!(ev[1], ClipEvent::RemoteChanged(vec![ClipFormat::Text, ClipFormat::Html, ClipFormat::Png]));
    assert_eq!(sends(&c.receive(&req(13)).unwrap())[0], unhex("05 00 02 00 00 00 00 00"));

    let ev = c.request(&[ClipFormat::Dib, ClipFormat::Png]);
    assert_eq!(sends(&ev)[0], unhex("04 00 00 00 04 00 00 00 bb c0 00 00"));
    let png = unhex(PNG_1X1);
    let ev = c.receive(&pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_OK, &png)).unwrap();
    assert_eq!(ev, [ClipEvent::RemoteData(Some(LocalData::Png(png)))]);
    // Sans signature PNG : illisible, l'appelant peut demander le DIB.
    c.request(&[ClipFormat::Png]);
    let ev = c.receive(&pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_OK, b"\x89PNG")).unwrap();
    assert_eq!(ev, [ClipEvent::RemoteData(None)]);

    // Refus du serveur : RemoteData(None), et une nouvelle demande redevient possible.
    c.request(&[ClipFormat::Html]);
    let ev = c.receive(&pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_FAIL, &[])).unwrap();
    assert_eq!(ev, [ClipEvent::RemoteData(None)]);
    let html = html_to_cf_html("<i>x</i>");
    c.request(&[ClipFormat::Html]);
    let ev = c.receive(&pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_OK, &html)).unwrap();
    assert_eq!(ev, [ClipEvent::RemoteData(Some(LocalData::Html("<i>x</i>".into())))]);

    // Nouveau contenu local après l'initialisation : Format List immédiate.
    let ev = c.set_local(vec![LocalData::Text("z".into()), LocalData::Text("ignoré".into())]);
    assert_eq!(sends(&ev)[0], unhex("02 00 00 00 06 00 00 00 0d 00 00 00 00 00"));
}

#[test]
fn short_names_without_server_caps() {
    let mut c = Clipboard::new();
    let ev = c.receive(&unhex(MONITOR_READY)).unwrap();
    assert_eq!(sends(&ev).len(), 1, "pas de capacités client sans celles du serveur");
    let ev = c.set_local(vec![LocalData::Png(vec![1])]);
    let list = sends(&ev)[0];
    assert_eq!(list.len(), 8 + 36);
    assert_eq!(&list[8..18], &unhex("f1 c0 00 00 50 00 4e 00 47 00")[..]);

    // Liste serveur en noms courts ASCII (CB_ASCII_NAMES) puis Unicode.
    let mut body = vec![0u8; 72];
    body[..4].copy_from_slice(&0xC123u32.to_le_bytes());
    body[4..15].copy_from_slice(b"HTML Format");
    body[36..40].copy_from_slice(&8u32.to_le_bytes());
    let ev = c.receive(&pdu(msg::FORMAT_LIST, ASCII_NAMES, &body)).unwrap();
    assert_eq!(ev[1], ClipEvent::RemoteChanged(vec![ClipFormat::Html, ClipFormat::Dib]));
    // Liste inexploitable : refusée (CB_RESPONSE_FAIL), la précédente reste.
    let ev = c.receive(&pdu(msg::FORMAT_LIST, 0, &[0; 35])).unwrap();
    assert_eq!(ev, [ClipEvent::Send(unhex(LIST_FAIL))]);
    assert_eq!(c.remote_formats(), [ClipFormat::Html, ClipFormat::Dib]);
}

#[test]
fn text_conversions() {
    assert_eq!(utf16_to_string(&string_to_utf16("é\r\nx\ny")), "é\nx\ny");
    assert_eq!(string_to_utf16("a\r\n"), unhex("61 00 0d 00 0a 00 00 00"));
    assert_eq!(utf16_to_string(&unhex("61 00 00 00 62 00")), "a");
    assert_eq!(utf16_to_string(&unhex("3d d8 61 00 3d d8 00 de 62")), "\u{FFFD}a😀");
}

#[test]
fn hostile_messages() {
    let mut c = ready();
    assert!(c.receive(&[]).is_err());
    assert!(c.receive(&unhex("02 00 00 00 10 00 00 00")).is_err());
    assert!(c.receive(&unhex("02 00 00 00 ff ff ff 7f")).is_err());
    assert!(c.receive(&unhex("04 00 00 00 00 00 00 00")).is_err());
    assert!(c.receive(&unhex("07 00 00 00 08 00 00 00 05 00 00 00 01 00 00 00")).is_err());
    assert!(c.receive(&unhex("07 00 00 00 04 00 00 00 02 00 00 00")).is_err());
    // Format List longue tronquée en plein identifiant : refusée ; nom sans terminateur toléré.
    let ev = c.receive(&unhex("02 00 00 00 02 00 00 00 0d 00")).unwrap();
    assert_eq!(ev, [ClipEvent::Send(unhex(LIST_FAIL))]);
    assert!(c.receive(&unhex("02 00 00 00 06 00 00 00 0d 00 00 00 41 00")).is_ok());
    // Type inconnu, remplissage après dataLen : sans effet.
    assert!(c.receive(&unhex("63 00 00 00 00 00 00 00")).unwrap().is_empty());
    assert!(c.receive(&unhex("03 00 01 00 00 00 00 00 00 00 00 00")).unwrap().is_empty());
    // DIB illisible : RemoteData(None).
    c.remote = vec![(8, String::new())];
    c.request(&[ClipFormat::Dib]);
    let ev = c.receive(&pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_OK, &[1, 2, 3])).unwrap();
    assert_eq!(ev, [ClipEvent::RemoteData(None)]);
    // File Contents Request : refus avec le streamId.
    let ev = c.receive(&pdu(msg::FILECONTENTS_REQUEST, 0, &[7, 0, 0, 0, 0, 0, 0, 0])).unwrap();
    assert_eq!(sends(&ev)[0], unhex("09 00 02 00 04 00 00 00 07 00 00 00"));
}

#[test]
fn truncated_response_ends_the_request() {
    let mut c = ready();
    c.remote = vec![(13, String::new())];
    // dataLen plus grand que le message, puis que le plafond : la demande se termine quand même.
    for resp in ["05 00 01 00 10 00 00 00 61 00", "05 00 01 00 ff ff ff ff"] {
        assert_eq!(c.request(&[ClipFormat::Text]).len(), 1);
        assert_eq!(c.receive(&unhex(resp)).unwrap(), [ClipEvent::RemoteData(None)]);
    }
    assert_eq!(c.request(&[ClipFormat::Text]).len(), 1, "nouvelle demande possible");
    // En-tête incomplet (moins de 8 octets) pendant la demande : elle se termine aussi.
    for short in ["05 00 01", ""] {
        assert_eq!(c.receive(&unhex(short)).unwrap(), [ClipEvent::RemoteData(None)]);
        assert!(c.receive(&unhex(short)).is_err(), "sans demande en vol : erreur");
        assert_eq!(c.request(&[ClipFormat::Text]).len(), 1, "nouvelle demande possible");
    }
}

#[test]
fn response_to_a_replaced_list_is_discarded() {
    let mut c = ready();
    let list = |id: u32| {
        let mut l = id.to_le_bytes().to_vec();
        l.extend_from_slice(&[0, 0]);
        pdu(msg::FORMAT_LIST, 0, &l)
    };
    c.receive(&list(13)).unwrap();
    assert_eq!(c.request(&[ClipFormat::Text]).len(), 1);
    // Le PC copie une image avant de répondre pour le texte.
    let ev = c.receive(&list(8)).unwrap();
    assert_eq!(ev[1], ClipEvent::RemoteChanged(vec![ClipFormat::Dib]));
    assert!(c.request(&[ClipFormat::Dib]).is_empty(), "une seule demande en vol");
    // La réponse pour le texte arrive : écartée, la demande du DIB peut partir.
    let text = pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_OK, &string_to_utf16("ancien"));
    assert_eq!(c.receive(&text).unwrap(), [ClipEvent::RemoteData(None)]);
    assert_eq!(c.request(&[ClipFormat::Dib]).len(), 1);
    let dib = rgba_to_dib(1, 1, &[1, 2, 3, 4]).unwrap();
    let ev = c.receive(&pdu(msg::FORMAT_DATA_RESPONSE, RESPONSE_OK, &dib)).unwrap();
    assert_eq!(
        ev,
        [ClipEvent::RemoteData(Some(LocalData::Rgba { width: 1, height: 1, rgba: vec![1, 2, 3, 4] }))]
    );
}

#[test]
fn caps_validated_before_use() {
    // Premier jeu général valide (noms longs), second tronqué : rien n'est retenu.
    let mut c = Clipboard::new();
    let caps = "07 00 00 00 14 00 00 00 02 00 00 00 01 00 0c 00 02 00 00 00 02 00 00 00 01 00 0c 00";
    assert!(c.receive(&unhex(caps)).is_err());
    assert!(!c.server_caps && !c.long_names);
    // Jeu général de 8 octets suivi d'octets : les indicateurs hors du jeu ne sont pas lus.
    let caps = "07 00 00 00 10 00 00 00 01 00 00 00 01 00 08 00 02 00 00 00 02 00 00 00";
    assert!(c.receive(&unhex(caps)).is_err());
    assert!(!c.long_names);
}

#[test]
fn format_list_entries_capped() {
    let mut c = ready();
    // 1025 entrées sans nom : refusée sans tout allouer.
    let body: Vec<u8> =
        (0..=MAX_FORMATS as u32).flat_map(|i| [i.to_le_bytes().as_slice(), &[0, 0]].concat()).collect();
    assert_eq!(c.receive(&pdu(msg::FORMAT_LIST, 0, &body)).unwrap(), [ClipEvent::Send(unhex(LIST_FAIL))]);
    let body = vec![0u8; 36 * (MAX_FORMATS + 1)];
    c.long_names = false;
    assert_eq!(c.receive(&pdu(msg::FORMAT_LIST, 0, &body)).unwrap(), [ClipEvent::Send(unhex(LIST_FAIL))]);
    // Au plafond : acceptée.
    let body = vec![0u8; 36 * MAX_FORMATS];
    assert_eq!(
        c.receive(&pdu(msg::FORMAT_LIST, 0, &body)).unwrap()[0],
        ClipEvent::Send(unhex("03 00 01 00 00 00 00 00"))
    );
}
