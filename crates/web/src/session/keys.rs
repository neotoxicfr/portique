//! `KeyboardEvent.code` (position physique de la touche) → code de balayage PC/AT (jeu 1).
//! Windows applique ensuite sa propre disposition (AZERTY…) : on transmet des positions, pas
//! des caractères, comme un vrai clavier.

use rdp_pdu::fastpath::{
    Input,
    kbd::{EXTENDED, EXTENDED1, RELEASE},
};

/// (code de balayage, touche étendue E0).
pub fn scancode(code: &str) -> Option<(u8, bool)> {
    Some(match code {
        "Escape" => (0x01, false),
        "Digit1" => (0x02, false),
        "Digit2" => (0x03, false),
        "Digit3" => (0x04, false),
        "Digit4" => (0x05, false),
        "Digit5" => (0x06, false),
        "Digit6" => (0x07, false),
        "Digit7" => (0x08, false),
        "Digit8" => (0x09, false),
        "Digit9" => (0x0A, false),
        "Digit0" => (0x0B, false),
        "Minus" => (0x0C, false),
        "Equal" => (0x0D, false),
        "Backspace" => (0x0E, false),
        "Tab" => (0x0F, false),
        "KeyQ" => (0x10, false),
        "KeyW" => (0x11, false),
        "KeyE" => (0x12, false),
        "KeyR" => (0x13, false),
        "KeyT" => (0x14, false),
        "KeyY" => (0x15, false),
        "KeyU" => (0x16, false),
        "KeyI" => (0x17, false),
        "KeyO" => (0x18, false),
        "KeyP" => (0x19, false),
        "BracketLeft" => (0x1A, false),
        "BracketRight" => (0x1B, false),
        "Enter" => (0x1C, false),
        "ControlLeft" => (0x1D, false),
        "KeyA" => (0x1E, false),
        "KeyS" => (0x1F, false),
        "KeyD" => (0x20, false),
        "KeyF" => (0x21, false),
        "KeyG" => (0x22, false),
        "KeyH" => (0x23, false),
        "KeyJ" => (0x24, false),
        "KeyK" => (0x25, false),
        "KeyL" => (0x26, false),
        "Semicolon" => (0x27, false),
        "Quote" => (0x28, false),
        "Backquote" => (0x29, false),
        "ShiftLeft" => (0x2A, false),
        "Backslash" => (0x2B, false),
        "KeyZ" => (0x2C, false),
        "KeyX" => (0x2D, false),
        "KeyC" => (0x2E, false),
        "KeyV" => (0x2F, false),
        "KeyB" => (0x30, false),
        "KeyN" => (0x31, false),
        "KeyM" => (0x32, false),
        "Comma" => (0x33, false),
        "Period" => (0x34, false),
        "Slash" => (0x35, false),
        "ShiftRight" => (0x36, false),
        "NumpadMultiply" => (0x37, false),
        "AltLeft" => (0x38, false),
        "Space" => (0x39, false),
        "CapsLock" => (0x3A, false),
        "F1" => (0x3B, false),
        "F2" => (0x3C, false),
        "F3" => (0x3D, false),
        "F4" => (0x3E, false),
        "F5" => (0x3F, false),
        "F6" => (0x40, false),
        "F7" => (0x41, false),
        "F8" => (0x42, false),
        "F9" => (0x43, false),
        "F10" => (0x44, false),
        "NumLock" => (0x45, false),
        "ScrollLock" => (0x46, false),
        "Numpad7" => (0x47, false),
        "Numpad8" => (0x48, false),
        "Numpad9" => (0x49, false),
        "NumpadSubtract" => (0x4A, false),
        "Numpad4" => (0x4B, false),
        "Numpad5" => (0x4C, false),
        "Numpad6" => (0x4D, false),
        "NumpadAdd" => (0x4E, false),
        "Numpad1" => (0x4F, false),
        "Numpad2" => (0x50, false),
        "Numpad3" => (0x51, false),
        "Numpad0" => (0x52, false),
        "NumpadDecimal" => (0x53, false),
        "IntlBackslash" => (0x56, false),
        "F11" => (0x57, false),
        "F12" => (0x58, false),
        "F13" => (0x64, false),
        "F14" => (0x65, false),
        "F15" => (0x66, false),
        "F16" => (0x67, false),
        "F17" => (0x68, false),
        "F18" => (0x69, false),
        "F19" => (0x6A, false),
        "F20" => (0x6B, false),
        "F21" => (0x6C, false),
        "F22" => (0x6D, false),
        "F23" => (0x6E, false),
        "F24" => (0x76, false),
        "IntlRo" => (0x73, false),
        "IntlYen" => (0x7D, false),
        "NumpadEnter" => (0x1C, true),
        "ControlRight" => (0x1D, true),
        "NumpadDivide" => (0x35, true),
        "PrintScreen" => (0x37, true),
        "AltRight" => (0x38, true),
        "Home" => (0x47, true),
        "ArrowUp" => (0x48, true),
        "PageUp" => (0x49, true),
        "ArrowLeft" => (0x4B, true),
        "ArrowRight" => (0x4D, true),
        "End" => (0x4F, true),
        "ArrowDown" => (0x50, true),
        "PageDown" => (0x51, true),
        "Insert" => (0x52, true),
        "Delete" => (0x53, true),
        "MetaLeft" | "OSLeft" => (0x5B, true),
        "MetaRight" | "OSRight" => (0x5C, true),
        "ContextMenu" => (0x5D, true),
        "AudioVolumeMute" => (0x20, true),
        "AudioVolumeDown" => (0x2E, true),
        "AudioVolumeUp" => (0x30, true),
        "MediaPlayPause" => (0x22, true),
        "MediaStop" => (0x24, true),
        "MediaTrackPrevious" => (0x10, true),
        "MediaTrackNext" => (0x19, true),
        _ => return None,
    })
}

/// Code de balayage d'un événement clavier : sa position (`code`) ; à défaut (clavier virtuel :
/// `code` vide, ou « Unidentified » que permet UI Events), le nom de la touche (`key`), que les
/// touches nommées (Retour arrière, Entrée, flèches…) partagent avec leur position.
pub fn scancode_of(code: &str, key: &str) -> Option<(u8, bool)> {
    // Sans position (clavier virtuel), Entrée, Retour arrière et Suppr passent déjà par `beforeinput`
    // (insertParagraph, deleteContent…) : les reprendre ici les enverrait deux fois.
    let by_input = matches!(key, "Enter" | "Backspace" | "Delete");
    scancode(code)
        .or_else(|| (matches!(code, "" | "Unidentified") && !by_input).then(|| scancode(key)).flatten())
}

/// Touches sans code de balayage simple, rendues par une séquence complète. Pause : Ctrl avec
/// EXTENDED1 puis Verr num (MS-RDPBCGR 2.2.8.1.2.2.1), appui et relâchement envoyés à l'appui
/// (la touche n'a pas de relâchement propre).
pub fn sequence(code: &str, down: bool) -> Option<Vec<Input>> {
    match code {
        "Pause" if down => Some(vec![
            Input::Scancode { code: 0x1D, flags: EXTENDED1 },
            Input::Scancode { code: 0x45, flags: 0 },
            Input::Scancode { code: 0x1D, flags: EXTENDED1 | RELEASE },
            Input::Scancode { code: 0x45, flags: RELEASE },
        ]),
        "Pause" => Some(Vec::new()),
        _ => None,
    }
}

/// Appui puis relâchement d'une touche.
pub fn tap(code: u8, extended: bool) -> [Input; 2] {
    let ext = if extended { EXTENDED } else { 0 };
    [Input::Scancode { code, flags: ext }, Input::Scancode { code, flags: ext | RELEASE }]
}

/// Texte tapé au clavier virtuel : caractères en Unicode (une paire de substitution est appuyée
/// puis relâchée d'un bloc), fins de ligne (CRLF, CR ou LF) en une touche Entrée.
pub fn text_events(text: &str) -> Vec<Input> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n' || c == '\r' {
            if c == '\r' {
                chars.next_if_eq(&'\n');
            }
            out.extend(tap(0x1C, false));
            continue;
        }
        let mut buf = [0u16; 2];
        let units = c.encode_utf16(&mut buf);
        out.extend(units.iter().map(|u| Input::Unicode { code: *u, release: false }));
        out.extend(units.iter().map(|u| Input::Unicode { code: *u, release: true }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_sends_extended1_sequence_on_press_only() {
        let frame = rdp_pdu::fastpath::input_frame(&sequence("Pause", true).unwrap());
        // En-tête (4 événements), longueur, puis (drapeaux, code) × 4.
        assert_eq!(frame, [4 << 2, 10, 0x04, 0x1D, 0x00, 0x45, 0x05, 0x1D, 0x01, 0x45]);
        assert_eq!(sequence("Pause", false), Some(Vec::new()));
        assert_eq!(sequence("KeyA", true), None);
        assert_eq!(scancode("Pause"), None, "jamais par la table : (code, E0) ne peut la représenter");
    }

    #[test]
    fn named_keys_without_a_position() {
        assert_eq!(scancode_of("", "ArrowDown"), scancode("ArrowDown"));
        assert_eq!(scancode_of("Unidentified", "ArrowDown"), scancode("ArrowDown"));
        assert_eq!(scancode_of("Unidentified", "Enter"), None, "Entrée : par beforeinput seulement");
        assert_eq!(scancode_of("", "Backspace"), None, "Retour arrière : par beforeinput seulement");
        assert_eq!(scancode_of("Enter", "Enter"), Some((0x1C, false)), "clavier physique inchangé");
        assert_eq!(scancode_of("Unidentified", "a"), None, "caractère : par Unicode");
        assert_eq!(scancode_of("KeyQ", "a"), scancode("KeyQ"), "la position prime (AZERTY)");
    }

    #[test]
    fn virtual_keyboard_text() {
        let u = |code, release| Input::Unicode { code, release };
        assert_eq!(text_events("é"), [u(0xE9, false), u(0xE9, true)]);
        assert_eq!(
            text_events("a\n"),
            [u(0x61, false), u(0x61, true), tap(0x1C, false)[0], tap(0x1C, false)[1]]
        );
        assert_eq!(text_events("😀"), [u(0xD83D, false), u(0xDE00, false), u(0xD83D, true), u(0xDE00, true)]);
        let enter = tap(0x1C, false);
        let ab = |eol: &str| text_events(&format!("a{eol}b"));
        let one = [u(0x61, false), u(0x61, true), enter[0], enter[1], u(0x62, false), u(0x62, true)];
        assert_eq!(ab("\r\n"), one, "CRLF = une seule Entrée");
        assert_eq!(ab("\r"), one);
        assert_eq!(ab("\n\r").len(), one.len() + 2, "LF puis CR : deux lignes");
    }
}
