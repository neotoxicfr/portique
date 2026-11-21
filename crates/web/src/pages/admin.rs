use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use portique_proto::{
    ConnectionAdmin, ConnectionInput, ServiceKey, SshInput, TERMINAL_THEMES, UserAdmin, UserInput,
};
use wasm_bindgen::JsCast;

use crate::{Session, api, glyph, icon, sentence};

/// Commande de réveil proposée pour un routeur MikroTik (RouterOS).
const MIKROTIK_COMMAND: &str = "/tool wol interface=ether1 mac={mac}";

const CHECK: &str = r#"<path d="M5 12l5 5 9-10"/>"#;
const RESET: &str = r#"<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>"#;
const STAR: &str = r#"<path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/>"#;
const SHIELD_OK: &str = r#"<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>"#;
const SHIELD_NO: &str =
    r#"<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M12 9v4M12 16v.5"/>"#;

#[component]
pub fn Admin() -> impl IntoView {
    let session = Session::get();
    let users = RwSignal::new(Vec::<UserAdmin>::new());
    let conns = RwSignal::new(Vec::<ConnectionAdmin>::new());
    let load_err = RwSignal::new(None::<String>);
    // Seul le dernier rechargement publie : une reprise lente lancée avant une suppression réafficherait
    // la machine supprimée.
    let generation = StoredValue::new(0u32);
    let reload = move || {
        // Page quittée : rien à recharger.
        let Some(mine) = generation.try_update_value(|g| {
            *g = g.wrapping_add(1);
            *g
        }) else {
            return;
        };
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            let current = || generation.try_get_value() == Some(mine);
            let mut failure = None;
            let r = api::get("/api/admin/users").await;
            if !current() {
                return;
            }
            match r {
                Ok(u) => users.set(u),
                Err(e) => {
                    session.handle(epoch, &e);
                    failure = Some(e.to_string());
                }
            }
            let r = api::get("/api/admin/connections").await;
            if !current() {
                return;
            }
            match r {
                Ok(c) => conns.set(c),
                Err(e) => {
                    session.handle(epoch, &e);
                    failure = Some(e.to_string());
                }
            }
            load_err.set(failure);
        })
    };
    reload();
    let f = Form::default();
    f.fill(None);
    let open = RwSignal::new(false);
    view! {
        <h1 class="sr-only">"Administration"</h1>
        {move || load_err.get().map(|m| view! {
            <div class="banner error" role="alert">
                <span>{sentence(&m)}</span>
                <button type="button" on:click=move |_| reload()>"Réessayer"</button>
            </div>
        })}
        <div class="admin">
            <div>
                <Machines conns f open/>
                <Users users reload/>
                <ServiceKeyPanel/>
            </div>
            <Editor conns users f open reload/>
        </div>
    }
}

fn input(sig: RwSignal<String>) -> impl Fn(leptos::ev::Event) + Copy {
    move |ev| sig.set(event_target_value(&ev))
}

/// Interrupteur dont le vrai contrôle (`role="switch"`) est sous l'habillage.
fn switch(sig: RwSignal<bool>) -> impl IntoView {
    view! {
        <span class="switch">
            <input type="checkbox" role="switch" prop:checked=move || sig.get()
                on:change=move |ev| sig.set(event_target_checked(&ev))/>
            <span class="track"></span>
        </span>
    }
}

fn confirm(msg: &str) -> bool {
    window().confirm_with_message(msg).unwrap_or(false)
}

#[component]
fn Users(users: RwSignal<Vec<UserAdmin>>, reload: impl Fn() + Copy + Send + Sync + 'static) -> impl IntoView {
    let session = Session::get();
    let name = RwSignal::new(String::new());
    let pw = RwSignal::new(String::new());
    let admin = RwSignal::new(false);
    let adding = RwSignal::new(false);
    let err = RwSignal::new(None::<String>);
    let me_id = move || session.me.with(|m| m.as_ref().map(|m| m.id));

    let create = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = UserInput {
            username: name.get_untracked(),
            password: Some(pw.get_untracked()),
            is_admin: admin.get_untracked(),
        };
        spawn_local(async move {
            match api::send_empty("POST", "/api/admin/users", Some(&body)).await {
                Ok(()) => {
                    name.set(String::new());
                    pw.set(String::new());
                    admin.set(false);
                    adding.set(false);
                    err.set(None);
                    reload();
                }
                Err(e) => err.set(Some(e.to_string())),
            }
        });
    };
    let act = move |method: &'static str, u: &UserAdmin, body: Option<UserInput>| {
        let url = format!("/api/admin/users/{}", u.id);
        spawn_local(async move {
            match api::send_empty(method, &url, body.as_ref()).await {
                Ok(()) => reload(),
                Err(e) => err.set(Some(e.to_string())),
            }
        });
    };
    let reset_2fa = move |u: UserAdmin| {
        if !confirm(&format!("Supprimer TOTP et passkeys de {} ?", u.username)) {
            return;
        }
        spawn_local(async move {
            let url = format!("/api/admin/users/{}/reset-2fa", u.id);
            match api::send_empty::<()>("POST", &url, None).await {
                Ok(()) => reload(),
                Err(e) => err.set(Some(e.to_string())),
            }
        });
    };

    view! {
        <section>
            <div class="group-head">
                <h2 class="group-title">"Comptes"</h2>
                <Show when=move || !session.is_proxy()>
                    <button type="button" class="iconbtn" aria-label="Créer un compte" title="Créer un compte"
                        aria-expanded=move || adding.get().to_string() on:click=move |_| adding.update(|a| *a = !*a)>
                        {icon(glyph::PLUS)}
                    </button>
                </Show>
            </div>
            <Show when=move || adding.get() && !session.is_proxy()>
                <form on:submit=create>
                    <div class="group">
                        <label class="line"><span class="line-label">"Identifiant"</span>
                            <input type="text" required autocomplete="off" prop:value=move || name.get() on:input=input(name)/></label>
                        <label class="line"><span class="line-label">"Mot de passe"</span>
                            <input type="password" required minlength="12" autocomplete="new-password" placeholder="12 caractères minimum"
                                prop:value=move || pw.get() on:input=input(pw)/></label>
                        <label class="line"><span class="line-label grow">"Administrateur"</span>{switch(admin)}</label>
                    </div>
                    <div class="actions">
                        <button type="button" class="secondary" on:click=move |_| adding.set(false)>"Annuler"</button>
                        <button type="submit">"Créer"</button>
                    </div>
                </form>
            </Show>
            <div class="group">
                <For each=move || users.get() key=|u| (u.id, u.is_admin, u.totp_enabled, u.passkeys) let(u)>
                    {
                        let is_me = me_id() == Some(u.id);
                        let initial = u.username.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default();
                        let twofa = match (u.totp_enabled, u.passkeys) {
                            (false, 0) => "Pas de double authentification".to_string(),
                            (t, p) => [t.then(|| "TOTP".to_string()), (p > 0).then(|| format!("{p} passkey(s)"))]
                                .into_iter().flatten().collect::<Vec<_>>().join(" + "),
                        };
                        let has_2fa = u.totp_enabled || u.passkeys > 0;
                        let editable = !is_me && !u.external;
                        let (u_toggle, u_reset, u_del) = (u.clone(), u.clone(), u.clone());
                        let toggle_label = if u.is_admin {
                            format!("Retirer les droits admin de {}", u.username)
                        } else {
                            format!("Rendre {} admin", u.username)
                        };
                        let reset_label = format!("Réinitialiser la double authentification de {}", u.username);
                        let del_label = format!("Supprimer le compte {}", u.username);
                        view! {
                            <div class="line urow">
                                <span class="avatar" aria-hidden="true">{initial}</span>
                                <span class="name">{u.username.clone()} {u.external.then_some(view! { <span class="badge">" proxy"</span> })}</span>
                                <span class="role">{if u.is_admin { "admin" } else { "utilisateur" }}</span>
                                <span class=if has_2fa { "mfa on" } else { "mfa" } role="img" aria-label=twofa.clone() title=twofa>
                                    {icon(if has_2fa { SHIELD_OK } else { SHIELD_NO })}
                                </span>
                                {editable.then(|| view! {
                                    <button type="button" class="iconbtn ghost" aria-label=toggle_label.clone() title=toggle_label
                                        on:click=move |_| act("PUT", &u_toggle, Some(UserInput {
                                            username: u_toggle.username.clone(), password: None, is_admin: !u_toggle.is_admin,
                                        }))>{icon(STAR)}</button>
                                })}
                                {(!u.external && has_2fa).then(|| view! {
                                    <button type="button" class="iconbtn ghost" aria-label=reset_label.clone() title="Réinitialiser la double authentification"
                                        on:click=move |_| reset_2fa(u_reset.clone())>{icon(RESET)}</button>
                                })}
                                {(!is_me).then(|| view! {
                                    <button type="button" class="iconbtn ghost danger" aria-label=del_label title="Supprimer le compte"
                                        on:click=move |_| if confirm(&format!("Supprimer le compte {} ?", u_del.username)) { act("DELETE", &u_del, None) }>
                                        {icon(glyph::TRASH)}
                                    </button>
                                })}
                            </div>
                        }
                    }
                </For>
            </div>
            {move || err.get().map(|e| view! { <p class="alert" role="alert">{e}</p> })}
        </section>
    }
}

/// Formulaire de connexion : `editing = None` pour une création.
#[derive(Clone, Copy, Default)]
struct Form {
    name: RwSignal<String>,
    rdp: RwSignal<bool>,
    host: RwSignal<String>,
    port: RwSignal<String>,
    username: RwSignal<String>,
    domain: RwSignal<String>,
    password: RwSignal<String>,
    wol_mac: RwSignal<String>,
    wol_target: RwSignal<String>,
    allowed: RwSignal<Vec<i64>>,
    editing: RwSignal<Option<i64>>,
    /// Compteur d'ouvertures : une réponse tardive ne touche pas le formulaire d'une autre machine.
    serial: RwSignal<u32>,
    /// Erreur de l'enregistrement ou de la suppression en cours.
    err: RwSignal<Option<String>>,
    /// Enregistrement ou suppression en vol : le formulaire est figé jusqu'à la réponse, sinon une saisie
    /// faite entre-temps serait perdue à la fermeture.
    busy: RwSignal<bool>,
    /// Réveil activé (adresse MAC et mode).
    wol: RwSignal<bool>,
    has_password: RwSignal<bool>,
    fingerprint: RwSignal<Option<String>>,
    forget_cert: RwSignal<bool>,
    /// Mode de réveil : direct (UDP) ou par commande SSH.
    wol_by_command: RwSignal<bool>,
    cmd_host: RwSignal<String>,
    cmd_user: RwSignal<String>,
    cmd_password: RwSignal<String>,
    cmd_command: RwSignal<String>,
    cmd_has_password: RwSignal<bool>,
    cmd_hostkey: RwSignal<Option<String>>,
    cmd_pending: RwSignal<Option<String>>,
    cmd_approve: RwSignal<bool>,
    /// Hôte SSH déclaré par lequel passe la commande ; vide = adresse saisie.
    cmd_via: RwSignal<String>,
    ssh: RwSignal<bool>,
    ssh_port: RwSignal<String>,
    ssh_user: RwSignal<String>,
    ssh_password: RwSignal<String>,
    ssh_has_password: RwSignal<bool>,
    /// Identifiant de l'hôte de rebond ; vide = connexion directe.
    ssh_jump: RwSignal<String>,
    /// Thème propre à l'hôte ; vide = thème du compte.
    ssh_theme: RwSignal<String>,
    ssh_hostkey: RwSignal<Option<String>>,
    ssh_forget: RwSignal<bool>,
}

impl Form {
    fn fill(&self, c: Option<&ConnectionAdmin>) {
        let s = |v: Option<&str>| v.unwrap_or_default().to_owned();
        self.serial.update(|n| *n += 1);
        self.err.set(None);
        self.busy.set(false);
        self.name.set(s(c.map(|c| c.name.as_str())));
        self.rdp.set(c.is_none_or(|c| c.rdp));
        self.host.set(s(c.map(|c| c.host.as_str())));
        self.port.set(c.map(|c| c.port.to_string()).unwrap_or_default());
        self.username.set(s(c.map(|c| c.username.as_str())));
        self.domain.set(s(c.map(|c| c.domain.as_str())));
        self.password.set(String::new());
        self.wol_mac.set(s(c.and_then(|c| c.wol_mac.as_deref())));
        self.wol_target.set(s(c.and_then(|c| c.wol_target.as_deref())));
        self.allowed.set(c.map(|c| c.allowed_users.clone()).unwrap_or_default());
        self.editing.set(c.map(|c| c.id));
        self.has_password.set(c.is_some_and(|c| c.has_password));
        self.fingerprint.set(c.and_then(|c| c.cert_fingerprint.clone()));
        self.forget_cert.set(false);
        let w = c.and_then(|c| c.wol_command.as_ref());
        self.wol.set(c.is_some_and(|c| c.wol_mac.is_some()) || w.is_some());
        self.wol_by_command.set(w.is_some());
        self.cmd_host.set(s(w.map(|w| w.host.as_str())));
        self.cmd_user.set(s(w.map(|w| w.user.as_str())));
        self.cmd_command.set(w.map(|w| w.command.clone()).unwrap_or_else(|| MIKROTIK_COMMAND.into()));
        self.cmd_password.set(String::new());
        self.cmd_has_password.set(w.is_some_and(|w| w.has_password));
        self.cmd_hostkey.set(w.and_then(|w| w.hostkey.clone()));
        self.cmd_pending.set(w.and_then(|w| w.pending_hostkey.clone()));
        self.cmd_approve.set(false);
        self.cmd_via.set(w.and_then(|w| w.via_id).map(|v| v.to_string()).unwrap_or_default());
        let h = c.and_then(|c| c.ssh.as_ref());
        self.ssh.set(h.is_some());
        self.ssh_port.set(h.map(|h| h.port.to_string()).unwrap_or_default());
        self.ssh_user.set(s(h.map(|h| h.user.as_str())));
        self.ssh_password.set(String::new());
        self.ssh_has_password.set(h.is_some_and(|h| h.has_password));
        self.ssh_jump.set(h.and_then(|h| h.jump_id).map(|j| j.to_string()).unwrap_or_default());
        self.ssh_theme.set(s(h.and_then(|h| h.theme.as_deref())));
        self.ssh_hostkey.set(h.and_then(|h| h.hostkey.clone()));
        self.ssh_forget.set(false);
    }

    fn input(&self) -> ConnectionInput {
        let opt = |s: RwSignal<String>| Some(s.get_untracked()).filter(|v| !v.trim().is_empty());
        let wol = self.wol.get_untracked();
        let by_command = wol && self.wol_by_command.get_untracked();
        ConnectionInput {
            name: self.name.get_untracked(),
            rdp: self.rdp.get_untracked(),
            host: self.host.get_untracked(),
            port: self.port.get_untracked().trim().parse().ok(),
            username: self.username.get_untracked(),
            domain: self.domain.get_untracked(),
            // Champ vide en modification = garder l'ancien mot de passe.
            password: opt(self.password),
            wol_mac: opt(self.wol_mac).filter(|_| wol),
            // Champ masqué en mode commande : sa valeur ne doit pas faire refuser le formulaire.
            wol_target: opt(self.wol_target).filter(|_| wol && !by_command),
            allowed_users: self.allowed.get_untracked(),
            forget_certificate: self.forget_cert.get_untracked(),
            wol_command: by_command.then(|| portique_proto::WolCommandInput {
                via_id: self.cmd_via.get_untracked().parse().ok(),
                host: self.cmd_host.get_untracked(),
                user: self.cmd_user.get_untracked(),
                command: self.cmd_command.get_untracked(),
                password: Some(self.cmd_password.get_untracked()).filter(|p| !p.is_empty()),
                approve_hostkey: self
                    .cmd_approve
                    .get_untracked()
                    .then(|| self.cmd_pending.get_untracked())
                    .flatten(),
            }),
            ssh: self.ssh.get_untracked().then(|| SshInput {
                port: self.ssh_port.get_untracked().trim().parse().ok(),
                user: self.ssh_user.get_untracked(),
                password: opt(self.ssh_password),
                jump_id: self.ssh_jump.get_untracked().parse().ok(),
                theme: opt(self.ssh_theme),
                forget_hostkey: self.ssh_forget.get_untracked(),
            }),
        }
    }
}

#[component]
fn Machines(conns: RwSignal<Vec<ConnectionAdmin>>, f: Form, open: RwSignal<bool>) -> impl IntoView {
    view! {
        <section>
            <div class="group-head">
                <h2 class="group-title">"Machines"</h2>
                <button type="button" class="iconbtn" aria-label="Ajouter une machine" title="Ajouter une machine"
                    on:click=move |_| { f.fill(None); open.set(true); }>{icon(glyph::PLUS)}</button>
            </div>
            <ul class="mlist">
                <For each=move || conns.get() key=|c| format!("{c:?}") let(c)>
                    {
                        let id = c.id;
                        let caps = [("SSH", c.ssh.is_some()), ("bureau", c.rdp), ("réveil", c.wol_mac.is_some())]
                            .iter().filter(|(_, on)| *on).map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
                        let alert = c.ssh.as_ref().and_then(|s| s.theme.as_deref()) == Some("alerte");
                        let (tone, glyph_d) = super::home::pastille(alert, c.rdp, c.ssh.is_some());
                        let tint = format!("pastille {tone}");
                        let (ssh, rdp, wol) = (c.ssh.is_some(), c.rdp, c.wol_mac.is_some());
                        let c_edit = c.clone();
                        view! {
                            <li>
                                <button type="button" class="mrow"
                                    aria-current=move || (open.get() && f.editing.get() == Some(id)).then_some("true")
                                    on:click=move |_| {
                                        if !(open.get_untracked() && f.editing.get_untracked() == Some(id)) {
                                            f.fill(Some(&c_edit));
                                            open.set(true);
                                        }
                                    }>
                                    <span class=tint>{icon(glyph_d)}</span>
                                    <span class="who"><b>{c.name.clone()}</b><span>{c.host.clone()}</span></span>
                                    <span class="caps" role="img" aria-label=caps>
                                        <span class=if ssh { "" } else { "off" }>{icon(glyph::TERMINAL)}</span>
                                        <span class=if rdp { "" } else { "off" }>{icon(glyph::SCREEN)}</span>
                                        <span class=if wol { "" } else { "off" }>{icon(glyph::POWER)}</span>
                                    </span>
                                    {icon(glyph::CHEVRON)}
                                </button>
                            </li>
                        }
                    }
                </For>
            </ul>
        </section>
    }
}

/// Éditeur de la machine sélectionnée (ou nouvelle).
#[component]
fn Editor(
    conns: RwSignal<Vec<ConnectionAdmin>>,
    users: RwSignal<Vec<UserAdmin>>,
    f: Form,
    open: RwSignal<bool>,
    reload: impl Fn() + Copy + Send + Sync + 'static,
) -> impl IntoView {
    // Machines dont une écriture est en vol, suivies hors du brouillon : `fill` remet `busy` à faux, et une
    // machine rouverte pendant l'écriture pourrait sinon repartir, sur l'ancien instantané, dans un second
    // envoi que le serveur appliquerait peut-être avant le premier.
    let writes = RwSignal::new(Vec::<i64>::new());
    let locked = move || f.busy.get() || f.editing.get().is_some_and(|id| writes.with(|w| w.contains(&id)));
    let save = move |ev: SubmitEvent| {
        ev.prevent_default();
        if locked() {
            return;
        }
        let body = f.input();
        let target = f.editing.get_untracked();
        let (method, url) = match target {
            Some(id) => ("PUT", format!("/api/admin/connections/{id}")),
            None => ("POST", "/api/admin/connections".to_string()),
        };
        let mine = f.serial.get_untracked();
        f.busy.set(true);
        if let Some(id) = target {
            writes.update(|w| w.push(id));
        }
        spawn_local(async move {
            let r = api::send::<_, ConnectionAdmin>(method, &url, &body).await;
            // Le formulaire n'est touché que s'il est encore celui qui a lancé la requête (page quittée comprise).
            let same = f.serial.try_get_untracked() == Some(mine);
            if same {
                f.busy.set(false);
            }
            if let Ok(c) = &r {
                // Instantané à jour dès la réponse, sans attendre le rechargement.
                conns.update(|l| match l.iter_mut().find(|x| x.id == c.id) {
                    Some(x) => *x = c.clone(),
                    None => l.push(c.clone()),
                });
                // Rouverte pendant l'écriture, la machine était figée, donc sans saisie : on la recharge.
                if !same && f.editing.try_get_untracked() == Some(Some(c.id)) {
                    f.fill(Some(c));
                }
            }
            // Échec (réponse perdue comprise) alors que la machine a été rouverte : le serveur a pu écrire et le
            // formulaire montre l'ancien instantané. Il reste figé jusqu'à une relecture de l'état serveur.
            let mut keep_lock = false;
            if let (Err(_), Some(id)) = (&r, target)
                && !same
                && f.editing.try_get_untracked() == Some(Some(id))
            {
                match api::get::<Vec<ConnectionAdmin>>("/api/admin/connections").await {
                    Ok(list) => {
                        // L'état relu devient l'instantané de la liste AVANT de lever le verrou : rouverte plus
                        // tard, la machine repart de lui et non de l'ancien.
                        if let Some(c) = list.iter().find(|c| c.id == id) {
                            conns.update(|l| match l.iter_mut().find(|x| x.id == id) {
                                Some(x) => *x = c.clone(),
                                None => l.push(c.clone()),
                            });
                            if f.editing.try_get_untracked() == Some(Some(id)) {
                                f.fill(Some(c));
                            }
                        }
                    }
                    Err(e) => {
                        keep_lock = true;
                        f.err.set(Some(format!("état de la machine à relire (recharge la page) : {e}")));
                    }
                }
            }
            if let Some(id) = target
                && !keep_lock
            {
                writes.update(|w| w.retain(|x| *x != id));
            }
            match r {
                Ok(_) if same => {
                    open.set(false);
                    f.err.set(None);
                }
                Err(e) if same => f.err.set(Some(e.to_string())),
                _ => {}
            }
            // Même en cas de refus : le serveur a pu écrire avant de refuser.
            reload();
        });
    };
    let remove = move |_| {
        if locked() {
            return;
        }
        let Some(id) = f.editing.get_untracked() else { return };
        let name = conns
            .with_untracked(|l| l.iter().find(|c| c.id == id).map(|c| c.name.clone()))
            .unwrap_or_else(|| f.name.get_untracked());
        if !confirm(&format!("Supprimer la connexion « {name} » ?")) {
            return;
        }
        let mine = f.serial.get_untracked();
        f.busy.set(true);
        writes.update(|w| w.push(id));
        spawn_local(async move {
            let r = api::send_empty::<()>("DELETE", &format!("/api/admin/connections/{id}"), None).await;
            let same = f.serial.try_get_untracked() == Some(mine);
            if same {
                f.busy.set(false);
            }
            writes.update(|w| w.retain(|x| *x != id));
            match r {
                Ok(()) => {
                    conns.update(|l| l.retain(|c| c.id != id));
                    // Fermé aussi s'il a été rouvert sur cette machine pendant la suppression.
                    if same || f.editing.try_get_untracked() == Some(Some(id)) {
                        open.set(false);
                    }
                }
                Err(e) if same => f.err.set(Some(e.to_string())),
                _ => {}
            }
            reload();
        });
    };

    let non_admins = move || users.get().into_iter().filter(|u| !u.is_admin).collect::<Vec<_>>();
    // Hôtes SSH proposables comme rebond ou comme relais de réveil (jamais la machine elle-même).
    let ssh_hosts = move || {
        conns
            .get()
            .into_iter()
            .filter(|c| c.ssh.is_some() && Some(c.id) != f.editing.get())
            .collect::<Vec<_>>()
    };
    // Rebond ou relais qui n'est plus proposé (supprimé, SSH retiré) : vidé, pour que la valeur envoyée
    // reste celle qu'affiche le sélecteur.
    Effect::new(move || {
        let ids: Vec<String> = ssh_hosts().iter().map(|c| c.id.to_string()).collect();
        for sel in [f.ssh_jump, f.cmd_via] {
            if sel.with(|v| !v.is_empty() && !ids.contains(v)) {
                sel.set(String::new());
            }
        }
    });

    view! {
        <Show when=move || open.get()>
            <form on:submit=save>
                <fieldset class="editor" disabled=locked>
                    <div class="group">
                        <label class="line"><span class="line-label">"Nom"</span>
                            <input type="text" required prop:value=move || f.name.get() on:input=input(f.name)/></label>
                        <label class="line"><span class="line-label">"Hôte"</span>
                            <input type="text" class="mono" required placeholder="192.0.2.11" prop:value=move || f.host.get() on:input=input(f.host)/></label>
                    </div>

                    <div class="group">
                        <label class="line sect">
                            <span class="pastille green">{icon(glyph::TERMINAL)}</span>
                            <span class="line-label grow">"Terminal SSH"</span>{switch(f.ssh)}
                        </label>
                        <Show when=move || f.ssh.get()>
                            <label class="line"><span class="line-label">"Port"</span>
                                <input type="number" min="1" max="65535" placeholder="22" prop:value=move || f.ssh_port.get() on:input=input(f.ssh_port)/></label>
                            <label class="line"><span class="line-label">"Utilisateur"</span>
                                <input type="text" autocomplete="off" prop:value=move || f.ssh_user.get() on:input=input(f.ssh_user)/></label>
                            <label class="line"><span class="line-label">"Mot de passe"</span>
                                <input type="password" autocomplete="new-password"
                                    placeholder=move || if f.ssh_has_password.get() { "inchangé" } else { "facultatif : clé du service" }
                                    prop:value=move || f.ssh_password.get() on:input=input(f.ssh_password)/></label>
                            <label class="line"><span class="line-label">"Rebond"</span>
                                <select prop:value=move || f.ssh_jump.get() on:change=input(f.ssh_jump)>
                                    <option value="">"direct"</option>
                                    // Options recréées à chaque rechargement : chacune reprend sa sélection, sinon le
                                    // navigateur retombe sur « direct » sans que la valeur change.
                                    {move || ssh_hosts().into_iter()
                                        .map(|c| {
                                            let v = c.id.to_string();
                                            view! { <option value=v.clone() prop:selected=move || f.ssh_jump.with(|j| *j == v)>{format!("par {}", c.name)}</option> }
                                        })
                                        .collect_view()}
                                </select></label>
                            <label class="line"><span class="line-label">"Thème"</span>
                                <select prop:value=move || f.ssh_theme.get() on:change=input(f.ssh_theme)>
                                    <option value="">"celui du compte"</option>
                                    {TERMINAL_THEMES.iter().map(|t| view! { <option value=*t>{*t}</option> }).collect_view()}
                                </select></label>
                            {move || f.ssh_hostkey.get().map(|k| view! {
                                <div class="line col"><span>"Clé d'hôte approuvée"</span><span class="val">{k}</span></div>
                                <label class="line"><span class="line-label grow">"Oublier la clé (machine réinstallée : à réapprouver)"</span>{switch(f.ssh_forget)}</label>
                            })}
                        </Show>
                    </div>

                    <div class="group">
                        <label class="line sect">
                            <span class="pastille orange">{icon(glyph::SCREEN)}</span>
                            <span class="line-label grow">"Bureau à distance"</span>{switch(f.rdp)}
                        </label>
                        <Show when=move || f.rdp.get()>
                            <label class="line"><span class="line-label">"Port"</span>
                                <input type="number" min="1" max="65535" placeholder="3389" prop:value=move || f.port.get() on:input=input(f.port)/></label>
                            <label class="line"><span class="line-label">"Utilisateur Windows"</span>
                                <input type="text" autocomplete="off" prop:value=move || f.username.get() on:input=input(f.username)/></label>
                            <label class="line"><span class="line-label">"Domaine"</span>
                                <input type="text" autocomplete="off" prop:value=move || f.domain.get() on:input=input(f.domain)/></label>
                            <label class="line"><span class="line-label">"Mot de passe"</span>
                                <input type="password" autocomplete="new-password"
                                    placeholder=move || if f.has_password.get() { "inchangé" } else { "" }
                                    prop:value=move || f.password.get() on:input=input(f.password)/></label>
                        </Show>
                    </div>

                    <div class="group">
                        <label class="line sect">
                            <span class="pastille gray">{icon(glyph::POWER)}</span>
                            <span class="line-label grow">"Réveil"</span>{switch(f.wol)}
                        </label>
                        <Show when=move || f.wol.get()>
                            <label class="line"><span class="line-label">"Adresse MAC"</span>
                                <input type="text" class="mono" required placeholder="00:11:22:33:44:55" prop:value=move || f.wol_mac.get() on:input=input(f.wol_mac)/></label>
                            <div class="line wake-mode"><span class="line-label grow">"Mode"</span>
                                <div class="seg" role="group" aria-label="Mode de réveil">
                                    <button type="button" aria-pressed=move || (!f.wol_by_command.get()).to_string()
                                        title="Paquet magique UDP : même réseau, ou broadcast dirigé"
                                        on:click=move |_| f.wol_by_command.set(false)>"UDP direct"</button>
                                    <button type="button" aria-pressed=move || f.wol_by_command.get().to_string()
                                        title="Commande SSH sur un hôte du réseau du PC (routeur MikroTik…) : indispensable à travers un VPN"
                                        on:click=move |_| f.wol_by_command.set(true)>"Commande SSH"</button>
                                </div></div>
                            <Show
                                when=move || f.wol_by_command.get()
                                fallback=move || view! {
                                    <label class="line"><span class="line-label">"Cible UDP"</span>
                                        <input type="text" class="mono" placeholder="255.255.255.255:9" prop:value=move || f.wol_target.get() on:input=input(f.wol_target)/></label>
                                }
                            >
                                <label class="line"><span class="line-label">"Passer par"</span>
                                    <select prop:value=move || f.cmd_via.get() on:change=input(f.cmd_via)>
                                        <option value="">"une adresse saisie ci-dessous"</option>
                                        {move || ssh_hosts().into_iter()
                                            .map(|c| {
                                                let v = c.id.to_string();
                                                view! { <option value=v.clone() prop:selected=move || f.cmd_via.with(|j| *j == v)>{format!("l'hôte SSH « {} »", c.name)}</option> }
                                            })
                                            .collect_view()}
                                    </select></label>
                                <Show when=move || f.cmd_via.get().is_empty()>
                                    <label class="line"><span class="line-label">"Hôte SSH"</span>
                                        <input type="text" class="mono" placeholder="192.0.2.254" prop:value=move || f.cmd_host.get() on:input=input(f.cmd_host)/></label>
                                    <label class="line"><span class="line-label">"Utilisateur"</span>
                                        <input type="text" autocomplete="off" prop:value=move || f.cmd_user.get() on:input=input(f.cmd_user)/></label>
                                    <label class="line"><span class="line-label">"Mot de passe"</span>
                                        <input type="password" autocomplete="new-password"
                                            placeholder=move || if f.cmd_has_password.get() { "inchangé" } else { "facultatif : clé du service" }
                                            prop:value=move || f.cmd_password.get() on:input=input(f.cmd_password)/></label>
                                </Show>
                                <label class="line col"><span>"Commande ({mac} est remplacé)"</span>
                                    <input type="text" class="mono" prop:value=move || f.cmd_command.get() on:input=input(f.cmd_command)/></label>
                                {move || f.cmd_hostkey.get().map(|k| view! {
                                    <div class="line col"><span>"Clé SSH approuvée"</span><span class="val">{k}</span></div>
                                })}
                                {move || f.cmd_pending.get().map(|k| view! {
                                    <div class="line col">
                                        <span>"Clé présentée par l'hôte, à comparer avec la sienne (MikroTik : " <code>"/ip ssh print"</code> ")"</span>
                                        <span class="val">{k}</span>
                                    </div>
                                    <label class="line"><span class="line-label grow">"Elle est identique : approuver"</span>{switch(f.cmd_approve)}</label>
                                })}
                            </Show>
                        </Show>
                    </div>

                    <Show when=move || f.fingerprint.with(Option::is_some)>
                        <div class="group">
                            <div class="line sect">
                                <span class="pastille gray">{icon(glyph::SHIELD)}</span>
                                <span class="line-label grow">"Certificat épinglé"</span>
                            </div>
                            <div class="line col"><span class="val">{move || f.fingerprint.get().unwrap_or_default()}</span></div>
                            <label class="line"><span class="line-label grow">"Oublier (PC réinstallé ou certificat renouvelé : à réapprouver)"</span>{switch(f.forget_cert)}</label>
                        </div>
                    </Show>

                    <Show when=move || !non_admins().is_empty()>
                        <div class="group">
                            <div class="line sect"><span class="line-label">"Comptes autorisés"</span><span class="sub">"(les admins voient tout)"</span></div>
                            <For each=non_admins key=|u| u.id let(u)>
                                <label class="line">
                                    <span class="line-label grow">{u.username.clone()}</span>
                                    <input type="checkbox"
                                        prop:checked=move || f.allowed.with(|a| a.contains(&u.id))
                                        on:change=move |ev| {
                                            let on = event_target_checked(&ev);
                                            f.allowed.update(|a| { a.retain(|x| *x != u.id); if on { a.push(u.id) } });
                                        }/>
                                </label>
                            </For>
                        </div>
                    </Show>

                    {move || f.err.get().map(|e| view! { <p class="alert" role="alert">{e}</p> })}
                    <div class="actions">
                        <Show when=move || f.editing.get().is_some()>
                            <button type="button" class="link danger" on:click=remove>"Supprimer"</button>
                        </Show>
                        <span class="spacer"></span>
                        <button type="button" class="secondary" on:click=move |_| open.set(false)>"Annuler"</button>
                        <button type="submit">"Enregistrer"</button>
                    </div>
                </fieldset>
            </form>
        </Show>
    }
}

/// Copie dans le presse-papier ; faux s'il est indisponible (hors HTTPS) ou refusé.
async fn copy_text(text: &str) -> bool {
    let nav = window().navigator();
    let Ok(cb) = js_sys::Reflect::get(&nav, &"clipboard".into()) else { return false };
    if cb.is_undefined() {
        return false;
    }
    let cb: web_sys::Clipboard = cb.unchecked_into();
    wasm_bindgen_futures::JsFuture::from(cb.write_text(text)).await.is_ok()
}

/// Adresse, réseau ou nom acceptable dans `from="…"` d'authorized_keys (jamais de guillemet).
fn valid_from(a: &str) -> bool {
    a.chars().all(|c| c.is_ascii_alphanumeric() || ".:/*?!_-".contains(c))
}

/// Liste `from="…"` d'authorized_keys ; `None` pour le champ vide (clé nue, voulue). Une restriction saisie
/// doit être valide en entier : une adresse mal écrite, ou des séparateurs sans aucune adresse, ne doivent
/// jamais retomber sur la clé nue, qui s'ouvre depuis n'importe où.
fn restriction(from: &str) -> Result<Option<String>, String> {
    if from.is_empty() {
        return Ok(None);
    }
    let addrs: Vec<&str> = from.split([',', ' ']).filter(|a| !a.is_empty()).collect();
    if let Some(a) = addrs.iter().find(|a| !valid_from(a)) {
        return Err(format!("Adresse ou réseau invalide : « {a} »."));
    }
    if addrs.is_empty() {
        return Err("Indique au moins une adresse ou un réseau, ou vide le champ.".into());
    }
    Ok(Some(addrs.join(",")))
}

/// Clé publique du service, à poser dans `authorized_keys` ; `from="…"` facultatif.
#[component]
fn ServiceKeyPanel() -> impl IntoView {
    let key = RwSignal::new(None::<String>);
    let from = RwSignal::new(String::new());
    let copied = RwSignal::new(None::<String>);
    let refused = RwSignal::new(false);
    spawn_local(async move {
        if let Ok(k) = api::get::<ServiceKey>("/api/admin/ssh-key").await {
            key.set(Some(k.public));
        }
    });
    let problem = move || restriction(&from.get()).err();
    let line = move || {
        let k = key.get()?;
        Some(match restriction(&from.get()).ok()? {
            None => k,
            Some(list) => format!("from=\"{list}\" {k}"),
        })
    };
    let copy = move |_| {
        let Some(l) = line() else { return };
        spawn_local(async move {
            let ok = copy_text(&l).await;
            refused.set(!ok);
            copied.set(ok.then_some(l));
        });
    };
    let done = move || line().is_some() && copied.get() == line();
    view! {
        <section>
            <h2 class="group-title">"Clé SSH du service"</h2>
            <div class="group">
                <div class="line keyline">
                    <code title="Ligne à ajouter dans ~/.ssh/authorized_keys de chaque hôte SSH (Windows, compte administrateur : C:\\ProgramData\\ssh\\administrators_authorized_keys)">
                        {move || line().unwrap_or_else(|| "—".into())}
                    </code>
                    <button type="button" class="iconbtn" aria-label="Copier la ligne authorized_keys" title="Copier"
                        disabled=move || line().is_none() on:click=copy>
                        {move || icon(if done() { CHECK } else { glyph::COPY })}
                    </button>
                </div>
                <label class="line">
                    <span class="line-label">"Restreindre à"</span>
                    <input type="text" class="mono" placeholder="192.0.2.10, 198.51.100.0/24" autocomplete="off"
                        prop:value=move || from.get() on:input=input(from)/>
                </label>
            </div>
            <span class="sr-only" role="status">{move || done().then_some("Ligne copiée")}</span>
            {move || problem().map(|m| view! { <p class="alert" role="alert">{m}</p> })}
            {move || refused.get().then(|| view! { <p class="alert" role="alert">"Le navigateur a refusé la copie : sélectionne la ligne et copie-la à la main."</p> })}
        </section>
    }
}

#[cfg(test)]
mod tests {
    use leptos::prelude::Set;

    use super::{Form, restriction};

    #[test]
    fn hidden_udp_target_is_not_sent_in_command_mode() {
        let f = Form::default();
        f.fill(None);
        f.wol.set(true);
        f.wol_mac.set("00:11:22:33:44:55".into());
        f.wol_target.set("pas une cible".into());
        f.wol_by_command.set(true);
        let i = f.input();
        assert_eq!(i.wol_target, None);
        assert!(i.wol_command.is_some());
        f.wol_by_command.set(false);
        let i = f.input();
        assert_eq!(i.wol_target.as_deref(), Some("pas une cible"));
        assert!(i.wol_command.is_none());
    }

    #[test]
    fn restriction_without_any_address_is_refused() {
        assert_eq!(restriction(""), Ok(None));
        assert_eq!(restriction("192.0.2.10, 198.51.100.0/24"), Ok(Some("192.0.2.10,198.51.100.0/24".into())));
        for bad in [",", " , ", " ", ",,", "192.0.2.10\"", "192.0.2.10,a\"b"] {
            assert!(restriction(bad).is_err(), "{bad:?}");
        }
    }
}
