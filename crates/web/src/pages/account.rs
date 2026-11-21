use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use portique_proto::{
    ChangePassword, Combo, Me, PasskeyInfo, ReAuth, TERMINAL_THEMES, TerminalPrefs, TotpConfirm, TotpSetup,
};

use crate::{Session, api, glyph, icon};

const KEY: &str = r#"<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M15 8l2 2"/>"#;
const LOCK: &str = r#"<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>"#;
const CROSS: &str = r#"<path d="M6 6l12 12M18 6L6 18"/>"#;

/// Nombre maximal de combinaisons de la barre de touches (limite du serveur).
const MAX_COMBOS: usize = 12;

type Status = RwSignal<Option<Result<String, String>>>;

#[component]
pub fn Account() -> impl IntoView {
    let session = Session::get();
    let external = move || session.me.with(|m| m.as_ref().is_some_and(|m| m.external));
    view! {
        <h1 class="sr-only">"Mon compte"</h1>
        <div class="cols">
            <div>
                <Show
                    when=move || !external()
                    fallback=|| view! { <p class="muted">"Compte géré par le proxy d'authentification : mot de passe et double authentification se règlent là-bas."</p> }
                >
                    <Password/>
                    <Security/>
                </Show>
            </div>
            <Terminal/>
        </div>
    }
}

fn status() -> Status {
    RwSignal::new(None)
}

fn show_status(s: Status) -> impl IntoView {
    move || {
        s.get().map(|r| match r {
            Ok(m) => view! { <p class="alert ok" role="status">{m}</p> }.into_any(),
            Err(m) => view! { <p class="alert" role="alert">{m}</p> }.into_any(),
        })
    }
}

fn totp_enabled() -> bool {
    Session::get().me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled))
}

fn confirm(msg: &str) -> bool {
    window().confirm_with_message(msg).unwrap_or(false)
}

/// Champs de réauthentification : mot de passe actuel, et code TOTP s'il est actif.
#[derive(Clone, Copy)]
struct Proof {
    password: RwSignal<String>,
    totp: RwSignal<String>,
}

impl Proof {
    fn new() -> Self {
        Self { password: RwSignal::new(String::new()), totp: RwSignal::new(String::new()) }
    }

    /// Lit puis efface les champs : un secret ne reste pas affiché après envoi. Appelée aussi après une
    /// réponse : si la page a été quittée entre-temps, les signaux n'existent plus (lecture tolérante).
    fn take(&self) -> ReAuth {
        let proof = ReAuth {
            password: self.password.try_get_untracked().unwrap_or_default(),
            totp: self.totp.try_get_untracked().filter(|c| !c.is_empty()),
        };
        self.password.set(String::new());
        self.totp.set(String::new());
        proof
    }

    fn password_line(self, label: &'static str) -> impl IntoView {
        view! {
            <label class="line">
                <span class="line-label">{label}</span>
                <input type="password" autocomplete="current-password" required
                    prop:value=move || self.password.get() on:input=move |ev| self.password.set(event_target_value(&ev))/>
            </label>
        }
    }

    fn totp_line(self) -> impl IntoView {
        view! {
            <Show when=totp_enabled>
                <label class="line">
                    <span class="line-label">"Code TOTP"</span>
                    <input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" required
                        prop:value=move || self.totp.get() on:input=move |ev| self.totp.set(event_target_value(&ev))/>
                </label>
            </Show>
        }
    }
}

#[component]
fn Password() -> impl IntoView {
    let session = Session::get();
    let proof = Proof::new();
    let new = RwSignal::new(String::new());
    let st = status();
    let busy = RwSignal::new(false);
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let body = ChangePassword { auth: proof.take(), new: new.get_untracked() };
        new.set(String::new());
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            // Le serveur ferme toutes les sessions du compte, celle-ci comprise : écran de connexion, même si
            // la page a été quittée pendant l'envoi, avec la confirmation.
            match api::send_empty("POST", "/api/account/password", Some(&body)).await {
                Ok(()) => session.ended_by_server(
                    epoch,
                    "Mot de passe changé : toutes les sessions sont fermées. Reconnecte-toi avec le nouveau.",
                ),
                Err(e) => {
                    session.handle(epoch, &e);
                    st.set(Some(Err(e.to_string())));
                }
            }
            busy.set(false);
        });
    };
    view! {
        <section>
            <h2 class="group-title">"Mot de passe"</h2>
            <form on:submit=submit>
                <div class="group">
                    {proof.password_line("Actuel")}
                    {proof.totp_line()}
                    <label class="line">
                        <span class="line-label">"Nouveau"</span>
                        <input type="password" autocomplete="new-password" minlength="12" required placeholder="12 caractères minimum"
                            prop:value=move || new.get() on:input=move |ev| new.set(event_target_value(&ev))/>
                    </label>
                </div>
                {show_status(st)}
                <div class="actions"><button type="submit" disabled=move || busy.get()>"Changer"</button></div>
            </form>
        </section>
    }
}

/// Double authentification : le TOTP (interrupteur) et les passkeys partagent un groupe et un message.
#[component]
fn Security() -> impl IntoView {
    let st = status();
    view! {
        <section>
            <h2 class="group-title">"Double authentification"</h2>
            <div class="group">
                <Totp st/>
                <Passkeys st/>
            </div>
            {show_status(st)}
        </section>
    }
}

fn totp_done(on: bool) -> String {
    if on { "TOTP activé." } else { "TOTP désactivé." }.into()
}

#[component]
fn Totp(st: Status) -> impl IntoView {
    let session = Session::get();
    let setup = RwSignal::new(None::<TotpSetup>);
    // Some(true) : l'utilisateur veut activer ; Some(false) : désactiver ; None : rien en cours.
    let intent = RwSignal::new(None::<bool>);
    // Verrou de la session, pas de la page : il survit à un départ de Compte pendant l'envoi.
    let busy = session.totp_busy;
    let proof = Proof::new();
    let code = RwSignal::new(String::new());

    let reset = move || {
        let _ = proof.take();
        code.set(String::new());
        setup.set(None);
        intent.set(None);
    };
    let toggle = move |ev| {
        let on = event_target_checked(&ev);
        let now = session.me.with_untracked(|m| m.as_ref().is_some_and(|m| m.totp_enabled));
        st.set(None);
        // Toute bascule repart de zéro : une preuve saisie pour l'intention abandonnée ne doit pas revenir.
        reset();
        intent.set((on != now).then_some(on));
    };

    // Étape 1 : mot de passe → graine et QR code. Un seul envoi à la fois : deux graines
    // en vol, et le QR affiché pourrait ne pas être celle que le serveur retient.
    let start = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let body = proof.take();
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            // Bornée : le verrou de session doit retomber même si le serveur ne répond jamais. Au délai, la
            // requête a pu aboutir quand même : un nouvel essai refait une graine, la confirmation dira si le QR
            // affiché n'est plus le bon.
            match api::bounded(api::send::<_, TotpSetup>("POST", "/api/account/totp/setup", &body)).await {
                Ok(s) => {
                    setup.set(Some(s));
                    st.set(None);
                }
                Err(e) => {
                    session.handle(epoch, &e);
                    st.set(Some(Err(e.to_string())));
                }
            }
            busy.set(false);
        });
    };
    // Activation ou désactivation sans réponse dans le délai : le serveur a pu l'appliquer, ou peut encore le
    // faire. L'état est relu : atteint, c'est un succès ; sinon il reste incertain (une relecture précoce ne
    // prouve pas l'échec), et la page le dit au lieu d'annoncer l'ancien état.
    let after_timeout = move |epoch: u32, on: bool| async move {
        match api::bounded(api::get::<Me>("/api/me")).await {
            Ok(me) if me.totp_enabled == on => {
                session.set_totp(epoch, on);
                reset();
                st.set(Some(Ok(totp_done(on))));
            }
            r => {
                if let Err(e) = &r {
                    session.handle(epoch, e);
                }
                st.set(Some(Err(
                    "le serveur n'a pas répondu à temps et la demande peut encore aboutir : recharge la page \
                     dans un instant pour voir l'état du TOTP"
                        .into(),
                )));
            }
        }
    };
    // Étape 2 : premier code de l'appli → activation.
    let confirm_code = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let body = TotpConfirm { code: code.get_untracked() };
        code.set(String::new());
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            match crate::within(15_000, api::send_empty("POST", "/api/account/totp/confirm", Some(&body)))
                .await
            {
                Some(Ok(())) => {
                    session.set_totp(epoch, true);
                    reset();
                    st.set(Some(Ok(totp_done(true))));
                }
                Some(Err(e)) => {
                    session.handle(epoch, &e);
                    st.set(Some(Err(e.to_string())));
                }
                None => after_timeout(epoch, true).await,
            }
            busy.set(false);
        });
    };
    let disable = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let body = proof.take();
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            match crate::within(15_000, api::send_empty("POST", "/api/account/totp/disable", Some(&body)))
                .await
            {
                Some(Ok(())) => {
                    session.set_totp(epoch, false);
                    reset();
                    st.set(Some(Ok(totp_done(false))));
                }
                Some(Err(e)) => {
                    session.handle(epoch, &e);
                    st.set(Some(Err(e.to_string())));
                }
                None => after_timeout(epoch, false).await,
            }
            busy.set(false);
        });
    };

    view! {
        <label class="line">
            <span class="pastille green">{icon(LOCK)}</span>
            <span class="line-label grow">"Code TOTP"</span>
            <span class="switch">
                <input type="checkbox" role="switch" disabled=move || busy.get()
                    prop:checked=move || intent.get().unwrap_or_else(totp_enabled) on:change=toggle/>
                <span class="track"></span>
            </span>
        </label>
        {move || match (intent.get(), totp_enabled(), setup.get()) {
            (Some(true), false, None) => view! {
                <form on:submit=start>
                    {proof.password_line("Mot de passe")}
                    <div class="line end">
                        <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| reset()>"Annuler"</button>
                        <button type="submit" disabled=move || busy.get()>"Configurer"</button>
                    </div>
                </form>
            }.into_any(),
            (Some(true), false, Some(s)) => view! {
                <form on:submit=confirm_code>
                    <div class="line col qr-line">
                        <div class="qr" inner_html=s.qr_svg></div>
                        <span class="val">{s.secret_base32}</span>
                    </div>
                    <label class="line">
                        <span class="line-label">"Code de l'appli"</span>
                        <input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" required
                            prop:value=move || code.get() on:input=move |ev| code.set(event_target_value(&ev))/>
                    </label>
                    <div class="line end">
                        <button type="button" class="secondary" disabled=move || busy.get()
                            on:click=move |_| { st.set(None); reset(); intent.set(Some(true)); }>"Recommencer"</button>
                        <button type="submit" disabled=move || busy.get()>"Activer"</button>
                    </div>
                </form>
            }.into_any(),
            (Some(false), true, _) => view! {
                <form on:submit=disable>
                    {proof.password_line("Mot de passe")}
                    {proof.totp_line()}
                    <div class="line end">
                        <button type="button" class="secondary" disabled=move || busy.get() on:click=move |_| reset()>"Annuler"</button>
                        <button type="submit" class="danger" disabled=move || busy.get()>"Désactiver"</button>
                    </div>
                </form>
            }.into_any(),
            _ => ().into_any(),
        }}
    }
}

#[component]
fn Passkeys(st: Status) -> impl IntoView {
    let session = Session::get();
    let list = RwSignal::new(Vec::<PasskeyInfo>::new());
    // Échec de la dernière lecture (hors 401, qui renvoie à la connexion) : sans lui, une liste vide ne dirait
    // pas si la lecture a abouti.
    let load_err = RwSignal::new(None::<String>);
    let name = RwSignal::new(String::new());
    let adding = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let proof = Proof::new();
    // Seule la dernière lecture lancée met la page à jour : une plus ancienne, revenue après, est dépassée.
    let generation = StoredValue::new(0u32);
    let reload = move || {
        let epoch = session.epoch.get_untracked();
        // Page quittée (rechargement après un ajout ou une suppression) : plus rien à mettre à jour.
        let Some(mine) = generation.try_update_value(|g| {
            *g = g.wrapping_add(1);
            *g
        }) else {
            return;
        };
        spawn_local(async move {
            let result = crate::within(15_000, api::get("/api/account/passkeys")).await;
            if generation.try_get_value() != Some(mine) {
                return;
            }
            match result {
                Some(Ok(l)) => {
                    list.set(l);
                    load_err.set(None);
                }
                Some(Err(e)) => {
                    session.handle(epoch, &e);
                    load_err.set(Some(e.to_string()));
                }
                None => load_err.set(Some("le serveur ne répond pas".into())),
            }
        })
    };
    reload();

    let add = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let n = name.get_untracked();
        let body = proof.take();
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            match api::passkey_register(n, body).await {
                Ok(()) => {
                    st.set(Some(Ok("Passkey ajoutée.".into())));
                    name.set(String::new());
                    adding.set(false);
                    reload();
                }
                Err(e) => {
                    session.handle(epoch, &e);
                    st.set(Some(Err(e.to_string())));
                }
            }
            busy.set(false);
        });
    };
    let remove = move |id: i64, label: String| {
        if !confirm(&format!("Supprimer la passkey « {label} » ?")) {
            return;
        }
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            match api::send_empty::<()>("DELETE", &format!("/api/account/passkeys/{id}"), None).await {
                Ok(()) => reload(),
                Err(e) => {
                    session.handle(epoch, &e);
                    st.set(Some(Err(e.to_string())));
                }
            }
        });
    };

    view! {
        {move || load_err.get().map(|m| view! {
            <div class="line" role="alert">
                <span class="grow error">{crate::sentence(&format!("passkeys non lues : {m}"))}</span>
                <button type="button" class="secondary" on:click=move |_| reload()>"Réessayer"</button>
            </div>
        })}
        <For each=move || list.get() key=|p| p.id let(p)>
            {
                let label = p.name.clone();
                let aria = format!("Supprimer la passkey {}", p.name);
                view! {
                    <div class="line">
                        <span class="pastille gray">{icon(KEY)}</span>
                        <span class="line-label grow">{p.name.clone()}
                            <span class="sub">{p.created_at.get(..10).unwrap_or_default().to_owned()}</span></span>
                        <button type="button" class="iconbtn ghost danger" aria-label=aria title="Supprimer"
                            on:click=move |_| remove(p.id, label.clone())>{icon(glyph::TRASH)}</button>
                    </div>
                }
            }
        </For>
        <button type="button" class="line" aria-expanded=move || adding.get().to_string() disabled=move || busy.get()
            on:click=move |_| { let _ = proof.take(); adding.update(|a| *a = !*a); st.set(None); }>
            <span class="pick">{icon(glyph::PLUS)}</span>
            "Ajouter une passkey"
        </button>
        <Show when=move || adding.get()>
            <form on:submit=add>
                <label class="line">
                    <span class="line-label">"Nom"</span>
                    <input type="text" placeholder="Téléphone" maxlength="64"
                        prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/>
                </label>
                {proof.password_line("Mot de passe")}
                {proof.totp_line()}
                <div class="line end">
                    <button type="button" class="secondary" disabled=move || busy.get()
                        on:click=move |_| { let _ = proof.take(); adding.set(false); }>"Annuler"</button>
                    <button type="submit" disabled=move || busy.get()>"Ajouter"</button>
                </div>
            </form>
        </Show>
    }
}

#[derive(Clone, PartialEq)]
enum Load {
    Pending,
    Failed(String),
    Ready,
}

fn theme_label(t: &str) -> &str {
    match t {
        "sombre" => "Sombre",
        "clair" => "Clair",
        "solarise" => "Solarisé",
        "dracula" => "Dracula",
        "nord" => "Nord",
        "alerte" => "Alerte",
        other => other,
    }
}

/// Même combinaison : mêmes octets envoyés (`Ctrl+C` et `ctrl+c`), comme le compte le serveur, qui refuse
/// les doublons. `Alt+B` et `Alt+b` restent distinctes.
fn same_combo(a: &str, b: &str) -> bool {
    a == b || matches!((Combo::parse(a), Combo::parse(b)), (Some(x), Some(y)) if x.bytes() == y.bytes())
}

/// Combinaisons sans doublon, dans l'ordre, premier libellé gardé : chacune sert de clé à sa vignette.
fn unique(combos: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(combos.len());
    for c in combos {
        if !out.iter().any(|o| same_combo(o, &c)) {
            out.push(c);
        }
    }
    out
}

/// Thème par défaut du terminal SSH (un hôte peut avoir le sien) et combinaisons de la barre de touches.
#[component]
fn Terminal() -> impl IntoView {
    let session = Session::get();
    let theme = RwSignal::new(String::new());
    let combos = RwSignal::new(Vec::<String>::new());
    let draft = RwSignal::new(String::new());
    let combo_err = RwSignal::new(None::<String>);
    let load = RwSignal::new(Load::Pending);
    let busy = RwSignal::new(false);
    let st = status();

    // Le formulaire reste fermé tant que les préférences ne sont pas là : sinon la réponse
    // écraserait la saisie, ou un envoi partirait avec un thème vide.
    let fetch = move || {
        load.set(Load::Pending);
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            // Une lecture qui ne revient pas ne doit pas laisser le formulaire fermé sans « Réessayer ».
            match crate::within(15_000, api::get::<TerminalPrefs>("/api/account/terminal")).await {
                Some(Ok(p)) => {
                    theme.set(p.theme);
                    combos.set(unique(p.combos));
                    load.set(Load::Ready);
                }
                Some(Err(e)) => {
                    session.handle(epoch, &e);
                    load.set(Load::Failed(e.to_string()));
                }
                None => load.set(Load::Failed("le serveur ne répond pas".into())),
            }
        });
    };
    fetch();
    // Rien ne change pendant l'envoi : le message de réussite doit décrire ce qui est affiché.
    let locked = move || busy.get() || load.get() != Load::Ready;

    // Ajoute la combinaison saisie ; faux si elle est refusée (message affiché).
    let add = move || -> bool {
        let c = draft.get_untracked().trim().to_owned();
        if c.is_empty() {
            // Champ vidé : l'erreur visait une saisie qui n'est plus là.
            combo_err.set(None);
            return true;
        }
        if Combo::parse(&c).is_none() {
            combo_err.set(Some(format!(
                "« {c} » n'est pas une combinaison valide : Ctrl+C, Alt+B ou Ctrl+Alt+D."
            )));
            return false;
        }
        if !combos.with_untracked(|v| v.iter().any(|x| same_combo(x, &c))) {
            if combos.with_untracked(Vec::len) >= MAX_COMBOS {
                combo_err.set(Some(format!("{MAX_COMBOS} combinaisons au plus.")));
                return false;
            }
            combos.update(|v| v.push(c));
        }
        draft.set(String::new());
        combo_err.set(None);
        true
    };
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        if locked() || !add() {
            return;
        }
        busy.set(true);
        let body = TerminalPrefs { theme: theme.get_untracked(), combos: combos.get_untracked() };
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            let r = api::send::<_, TerminalPrefs>("PUT", "/api/account/terminal", &body).await;
            if let Err(e) = &r {
                session.handle(epoch, e);
            }
            st.set(Some(
                r.map(|_| "Préférences du terminal enregistrées.".into()).map_err(|e| e.to_string()),
            ));
            busy.set(false);
        });
    };

    view! {
        <section>
            <h2 class="group-title">"Terminal"</h2>
            {move || match load.get() {
                Load::Failed(m) => Some(view! {
                    <div class="banner error" role="alert">
                        <span>{crate::sentence(&m)}</span>
                        <button type="button" on:click=move |_| fetch()>"Réessayer"</button>
                    </div>
                }),
                _ => None,
            }}
            <form on:submit=submit aria-busy=move || (load.get() == Load::Pending).to_string()>
                <div class="group">
                    <fieldset>
                        <legend>"Thème par défaut"</legend>
                        <div class="themes">
                            {TERMINAL_THEMES.iter().map(|t| {
                                let t: &'static str = t;
                                view! {
                                    <label class="theme">
                                        <input type="radio" name="theme" value=t disabled=locked
                                            prop:checked=move || theme.get() == t
                                            on:change=move |_| theme.set(t.to_owned())/>
                                        <span class=format!("prev t-{t}") aria-hidden="true">"$ ls"<br/><b>"srv/"</b>" app.js"</span>
                                        <span class="nm">{theme_label(t)}</span>
                                    </label>
                                }
                            }).collect_view()}
                        </div>
                    </fieldset>
                    <fieldset>
                        <legend>"Barre de touches"</legend>
                        <div class="tags">
                            <For each=move || combos.get() key=|c| c.clone() let(c)>
                                {
                                    let label = c.clone();
                                    let aria = format!("Retirer {c}");
                                    view! {
                                        <span class="tag">{c}
                                            <button type="button" aria-label=aria title="Retirer" disabled=locked
                                                on:click=move |_| combos.update(|v| v.retain(|x| *x != label))>{icon(CROSS)}</button>
                                        </span>
                                    }
                                }
                            </For>
                            <label class="sr-only" for="combo-new">"Nouvelle combinaison"</label>
                            <input id="combo-new" type="text" placeholder="Ctrl+…" disabled=locked autocomplete="off" autocapitalize="off"
                                prop:value=move || draft.get()
                                on:input=move |ev| draft.set(event_target_value(&ev))
                                on:keydown=move |ev| if ev.key() == "Enter" { ev.prevent_default(); add(); }/>
                        </div>
                        {move || combo_err.get().map(|m| view! { <p class="alert" role="alert">{m}</p> })}
                    </fieldset>
                </div>
                {show_status(st)}
                <div class="actions"><button type="submit" disabled=locked>"Enregistrer"</button></div>
            </form>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::{same_combo, unique};

    #[test]
    fn loaded_duplicate_combos_are_shown_once() {
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(unique(v(&["Ctrl+C", "Ctrl+C", "Alt+B"])), v(&["Ctrl+C", "Alt+B"]));
        assert_eq!(unique(v(&["Alt+B", "Ctrl+C", "Alt+B"])), v(&["Alt+B", "Ctrl+C"]));
    }

    #[test]
    fn combos_that_send_the_same_bytes_are_one() {
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Premier libellé gardé.
        assert_eq!(unique(v(&["Ctrl+C", "ctrl+c", "CTRL+C"])), v(&["Ctrl+C"]));
        assert_eq!(unique(v(&["Ctrl+Alt+D", "Alt+Ctrl+d"])), v(&["Ctrl+Alt+D"]));
        // Octets différents : Alt+B (ESC B) et Alt+b (ESC b).
        assert_eq!(unique(v(&["Alt+B", "Alt+b"])), v(&["Alt+B", "Alt+b"]));
        assert!(same_combo("Ctrl+r", "Ctrl+R"));
        assert!(!same_combo("Alt+r", "Alt+R"));
    }
}
