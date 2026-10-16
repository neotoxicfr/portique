use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use yawrdp_proto::{ConnectionAdmin, ConnectionInput, Protocol, UserAdmin, UserInput};

use crate::{Session, api};

/// Commande de réveil proposée pour un routeur MikroTik (RouterOS).
const MIKROTIK_COMMAND: &str = "/tool wol interface=ether1 mac={mac}";

#[component]
pub fn Admin() -> impl IntoView {
    let session = Session::get();
    let users = RwSignal::new(Vec::<UserAdmin>::new());
    let conns = RwSignal::new(Vec::<ConnectionAdmin>::new());
    let reload = move || {
        spawn_local(async move {
            match api::get("/api/admin/users").await {
                Ok(u) => users.set(u),
                Err(e) => session.handle(&e),
            }
            if let Ok(c) = api::get("/api/admin/connections").await {
                conns.set(c);
            }
        })
    };
    reload();
    view! {
        <h1>"Administration"</h1>
        <Connections conns users reload/>
        <Users users reload/>
    }
}

fn input(sig: RwSignal<String>) -> impl Fn(leptos::ev::Event) + Copy {
    move |ev| sig.set(event_target_value(&ev))
}

#[component]
fn Users(users: RwSignal<Vec<UserAdmin>>, reload: impl Fn() + Copy + Send + Sync + 'static) -> impl IntoView {
    let session = Session::get();
    let name = RwSignal::new(String::new());
    let pw = RwSignal::new(String::new());
    let admin = RwSignal::new(false);
    let err = RwSignal::new(None::<String>);
    let me_id = move || session.me.with(|m| m.as_ref().map(|m| m.id));

    let create = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = UserInput {
            username: name.get_untracked(),
            password: Some(pw.get_untracked()),
            is_admin: admin.get_untracked(),
            reset_2fa: false,
        };
        spawn_local(async move {
            match api::send_empty("POST", "/api/admin/users", Some(&body)).await {
                Ok(()) => {
                    name.set(String::new());
                    pw.set(String::new());
                    admin.set(false);
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
    let confirm = |msg: &str| web_sys_confirm(msg);

    view! {
        <section class="card">
            <h2>"Comptes"</h2>
            <div class="table-wrap"><table>
                <thead><tr><th>"Identifiant"</th><th>"Rôle"</th><th>"2FA"</th><th></th></tr></thead>
                <tbody>
                    <For each=move || users.get() key=|u| (u.id, u.is_admin, u.totp_enabled, u.passkeys) let(u)>
                        {
                            let is_me = me_id() == Some(u.id);
                            let u_toggle = u.clone();
                            let u_reset = u.clone();
                            let u_del = u.clone();
                            let twofa = match (u.totp_enabled, u.passkeys) {
                                (false, 0) => "—".to_string(),
                                (t, p) => [t.then(|| "TOTP".to_string()), (p > 0).then(|| format!("{p} passkey(s)"))]
                                    .into_iter().flatten().collect::<Vec<_>>().join(" + "),
                            };
                            view! {
                                <tr>
                                    <td>{u.username.clone()} {u.external.then_some(view! { <span class="badge">"proxy"</span> })}</td>
                                    <td>{if u.is_admin { "admin" } else { "utilisateur" }}</td>
                                    <td>{twofa}</td>
                                    <td class="cell-actions">
                                        <Show when=move || !is_me && !u.external>
                                            {
                                                let u = u_toggle.clone();
                                                view! { <button class="link" on:click=move |_| act("PUT", &u, Some(UserInput {
                                                    username: u.username.clone(), password: None, is_admin: !u.is_admin, reset_2fa: false,
                                                }))>{if u_toggle.is_admin { "Retirer admin" } else { "Rendre admin" }}</button> }
                                            }
                                        </Show>
                                        <Show when=move || !u_reset.external && (u_reset.totp_enabled || u_reset.passkeys > 0)>
                                            {
                                                let u = u_reset.clone();
                                                view! { <button class="link" on:click=move |_| {
                                                    if confirm(&format!("Supprimer TOTP et passkeys de {} ?", u.username)) {
                                                        act("PUT", &u, Some(UserInput { username: u.username.clone(), password: None, is_admin: u.is_admin, reset_2fa: true }));
                                                    }
                                                }>"Réinitialiser 2FA"</button> }
                                            }
                                        </Show>
                                        <Show when=move || !is_me>
                                            {
                                                let u = u_del.clone();
                                                view! { <button class="link danger" on:click=move |_| {
                                                    if confirm(&format!("Supprimer le compte {} ?", u.username)) { act("DELETE", &u, None) }
                                                }>"Supprimer"</button> }
                                            }
                                        </Show>
                                    </td>
                                </tr>
                            }
                        }
                    </For>
                </tbody>
            </table></div>
            <Show when=move || !session.is_proxy()>
                <form on:submit=create class="row wrap">
                    <input type="text" placeholder="Identifiant" required prop:value=move || name.get() on:input=input(name)/>
                    <input type="password" placeholder="Mot de passe (12+)" minlength="12" required autocomplete="new-password"
                        prop:value=move || pw.get() on:input=input(pw)/>
                    <label class="check"><input type="checkbox" prop:checked=move || admin.get()
                        on:change=move |ev| admin.set(event_target_checked(&ev))/>"admin"</label>
                    <button type="submit">"Créer"</button>
                </form>
            </Show>
            {move || err.get().map(|e| view! { <p class="error">{e}</p> })}
        </section>
    }
}

fn web_sys_confirm(msg: &str) -> bool {
    leptos::prelude::window().confirm_with_message(msg).unwrap_or(false)
}

/// Formulaire de connexion : `editing = None` pour une création.
#[derive(Clone, Default)]
struct Form {
    name: RwSignal<String>,
    protocol: RwSignal<String>,
    host: RwSignal<String>,
    port: RwSignal<String>,
    username: RwSignal<String>,
    domain: RwSignal<String>,
    password: RwSignal<String>,
    wol_mac: RwSignal<String>,
    wol_target: RwSignal<String>,
    allowed: RwSignal<Vec<i64>>,
    editing: RwSignal<Option<i64>>,
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
}

impl Form {
    fn fill(&self, c: Option<&ConnectionAdmin>) {
        let s = |v: Option<&str>| v.unwrap_or_default().to_owned();
        self.name.set(s(c.map(|c| c.name.as_str())));
        self.protocol.set(
            match c.map(|c| c.protocol) {
                Some(Protocol::Ssh) => "ssh",
                _ => "rdp",
            }
            .into(),
        );
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
        self.wol_by_command.set(w.is_some());
        self.cmd_host.set(s(w.map(|w| w.host.as_str())));
        self.cmd_user.set(s(w.map(|w| w.user.as_str())));
        self.cmd_command.set(w.map(|w| w.command.clone()).unwrap_or_else(|| MIKROTIK_COMMAND.into()));
        self.cmd_password.set(String::new());
        self.cmd_has_password.set(w.is_some_and(|w| w.has_password));
        self.cmd_hostkey.set(w.and_then(|w| w.hostkey.clone()));
    }

    fn input(&self) -> ConnectionInput {
        let opt = |s: RwSignal<String>| Some(s.get_untracked()).filter(|v| !v.trim().is_empty());
        ConnectionInput {
            name: self.name.get_untracked(),
            protocol: Some(if self.protocol.get_untracked() == "ssh" {
                Protocol::Ssh
            } else {
                Protocol::Rdp
            }),
            host: self.host.get_untracked(),
            port: self.port.get_untracked().trim().parse().ok(),
            username: self.username.get_untracked(),
            domain: self.domain.get_untracked(),
            // Champ vide en modification = garder l'ancien mot de passe.
            password: opt(self.password),
            wol_mac: opt(self.wol_mac),
            wol_target: opt(self.wol_target),
            allowed_users: self.allowed.get_untracked(),
            forget_certificate: self.forget_cert.get_untracked(),
            wol_command: self.wol_by_command.get_untracked().then(|| yawrdp_proto::WolCommandInput {
                host: self.cmd_host.get_untracked(),
                user: self.cmd_user.get_untracked(),
                command: self.cmd_command.get_untracked(),
                password: Some(self.cmd_password.get_untracked()).filter(|p| !p.is_empty()),
            }),
        }
    }
}

#[component]
fn Connections(
    conns: RwSignal<Vec<ConnectionAdmin>>,
    users: RwSignal<Vec<UserAdmin>>,
    reload: impl Fn() + Copy + Send + Sync + 'static,
) -> impl IntoView {
    let f = Form::default();
    f.fill(None);
    let err = RwSignal::new(None::<String>);
    let open = RwSignal::new(false);

    let f2 = f.clone();
    let save = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = f2.input();
        let (method, url) = match f2.editing.get_untracked() {
            Some(id) => ("PUT", format!("/api/admin/connections/{id}")),
            None => ("POST", "/api/admin/connections".to_string()),
        };
        spawn_local(async move {
            match api::send::<_, ConnectionAdmin>(method, &url, &body).await {
                Ok(_) => {
                    open.set(false);
                    err.set(None);
                    reload();
                }
                Err(e) => err.set(Some(e.to_string())),
            }
        });
    };
    let remove = move |c: &ConnectionAdmin| {
        if !web_sys_confirm(&format!("Supprimer la connexion « {} » ?", c.name)) {
            return;
        }
        let url = format!("/api/admin/connections/{}", c.id);
        spawn_local(async move {
            match api::send_empty::<()>("DELETE", &url, None).await {
                Ok(()) => reload(),
                Err(e) => err.set(Some(e.to_string())),
            }
        });
    };

    let non_admins = move || users.get().into_iter().filter(|u| !u.is_admin).collect::<Vec<_>>();
    let fe = f.clone();
    let fn_new = f.clone();
    let ff = f.clone();
    view! {
        <section class="card">
            <div class="row spread">
                <h2>"Connexions"</h2>
                <button on:click=move |_| { fn_new.fill(None); open.set(true); }>"Ajouter"</button>
            </div>
            <div class="table-wrap"><table>
                <thead><tr><th>"Nom"</th><th>"Cible"</th><th>"Compte"</th><th>"WoL"</th><th></th></tr></thead>
                <tbody>
                    <For each=move || conns.get() key=|c| format!("{c:?}") let(c)>
                        {
                            let fe = fe.clone();
                            let c_edit = c.clone();
                            let c_del = c.clone();
                            view! {
                                <tr>
                                    <td>{c.name.clone()}</td>
                                    <td class="mono">{format!("{}:{}", c.host, c.port)}</td>
                                    <td>{if c.domain.is_empty() { c.username.clone() } else { format!("{}\\{}", c.domain, c.username) }}
                                        {(!c.has_password).then_some(view! { <span class="badge">"sans mot de passe"</span> })}</td>
                                    <td class="mono">{c.wol_mac.clone().unwrap_or_else(|| "—".into())}</td>
                                    <td class="cell-actions">
                                        <button class="link" on:click=move |_| { fe.fill(Some(&c_edit)); open.set(true); }>"Modifier"</button>
                                        <button class="link danger" on:click=move |_| remove(&c_del)>"Supprimer"</button>
                                    </td>
                                </tr>
                            }
                        }
                    </For>
                </tbody>
            </table></div>
            <Show when=move || open.get()>
                {
                    let f = ff.clone();
                    let save = save.clone();
                    view! {
                        <form on:submit=save class="grid">
                            <label>"Nom"<input type="text" required prop:value=move || f.name.get() on:input=input(f.name)/></label>
                            <label>"Protocole"
                                <select prop:value=move || f.protocol.get() on:change=input(f.protocol)>
                                    <option value="rdp">"RDP"</option>
                                    <option value="ssh">"SSH (plus tard)"</option>
                                </select>
                            </label>
                            <label>"Hôte"<input type="text" required placeholder="10.8.0.2" prop:value=move || f.host.get() on:input=input(f.host)/></label>
                            <label>"Port"<input type="number" min="1" max="65535" placeholder="3389" prop:value=move || f.port.get() on:input=input(f.port)/></label>
                            <label>"Utilisateur Windows"<input type="text" autocomplete="off" prop:value=move || f.username.get() on:input=input(f.username)/></label>
                            <label>"Domaine"<input type="text" autocomplete="off" prop:value=move || f.domain.get() on:input=input(f.domain)/></label>
                            <label>"Mot de passe"
                                <input type="password" autocomplete="new-password"
                                    placeholder=move || if f.has_password.get() { "inchangé" } else { "" }
                                    prop:value=move || f.password.get() on:input=input(f.password)/>
                            </label>
                            <label>"MAC (WoL)"<input type="text" placeholder="00:1A:2B:3C:4D:5E" prop:value=move || f.wol_mac.get() on:input=input(f.wol_mac)/></label>
                            <fieldset class="full">
                                <legend>"Réveil (Wake-on-LAN) — MAC ci-dessus"</legend>
                                <label class="check">
                                    <input type="radio" name="wolmode" prop:checked=move || !f.wol_by_command.get()
                                        on:change=move |_| f.wol_by_command.set(false)/>
                                    "Direct : paquet magique UDP (même réseau, ou broadcast dirigé)"
                                </label>
                                <label class="check">
                                    <input type="radio" name="wolmode" prop:checked=move || f.wol_by_command.get()
                                        on:change=move |_| f.wol_by_command.set(true)/>
                                    "Par commande SSH sur un hôte du réseau du PC (routeur MikroTik…), indispensable à travers un VPN"
                                </label>
                                <Show
                                    when=move || f.wol_by_command.get()
                                    fallback=move || view! {
                                        <label class="full">"Cible UDP"<input type="text" placeholder="255.255.255.255:9" prop:value=move || f.wol_target.get() on:input=input(f.wol_target)/></label>
                                    }
                                >
                                    <div class="grid full">
                                        <label>"Hôte SSH"<input type="text" placeholder="10.0.0.254" prop:value=move || f.cmd_host.get() on:input=input(f.cmd_host)/></label>
                                        <label>"Utilisateur SSH"<input type="text" autocomplete="off" prop:value=move || f.cmd_user.get() on:input=input(f.cmd_user)/></label>
                                        <label>"Mot de passe SSH"
                                            <input type="password" autocomplete="new-password"
                                                placeholder=move || if f.cmd_has_password.get() { "inchangé" } else { "" }
                                                prop:value=move || f.cmd_password.get() on:input=input(f.cmd_password)/>
                                        </label>
                                        <label class="full">"Commande ({mac} est remplacé)"
                                            <input type="text" class="mono" prop:value=move || f.cmd_command.get() on:input=input(f.cmd_command)/>
                                        </label>
                                    </div>
                                    {move || f.cmd_hostkey.get().map(|k| view! { <p class="muted mono">"Clé SSH épinglée : " {k}</p> })}
                                </Show>
                            </fieldset>
                            <Show when=move || f.fingerprint.with(Option::is_some)>
                                <fieldset class="full">
                                    <legend>"Certificat du PC (épinglé)"</legend>
                                    <span class="mono">{move || f.fingerprint.get().unwrap_or_default()}</span>
                                    <label class="check">
                                        <input type="checkbox" prop:checked=move || f.forget_cert.get()
                                            on:change=move |ev| f.forget_cert.set(event_target_checked(&ev))/>
                                        "Oublier (PC réinstallé ou certificat renouvelé : il faudra réapprouver)"
                                    </label>
                                </fieldset>
                            </Show>
                            <fieldset class="full">
                                <legend>"Comptes autorisés (les admins voient tout)"</legend>
                                <For each=non_admins key=|u| u.id let(u)>
                                    <label class="check">
                                        <input type="checkbox"
                                            prop:checked=move || f.allowed.with(|a| a.contains(&u.id))
                                            on:change=move |ev| {
                                                let on = event_target_checked(&ev);
                                                f.allowed.update(|a| { a.retain(|x| *x != u.id); if on { a.push(u.id) } });
                                            }/>
                                        {u.username.clone()}
                                    </label>
                                </For>
                            </fieldset>
                            {move || err.get().map(|e| view! { <p class="error full">{e}</p> })}
                            <div class="row full">
                                <button type="submit">"Enregistrer"</button>
                                <button type="button" class="secondary" on:click=move |_| open.set(false)>"Annuler"</button>
                            </div>
                        </form>
                    }
                }
            </Show>
        </section>
    }
}
