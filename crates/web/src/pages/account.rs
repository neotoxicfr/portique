use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use portique_proto::{
    ChangePassword, PasskeyInfo, ReAuth, TERMINAL_THEMES, TerminalPrefs, TotpConfirm, TotpSetup,
};

use crate::{Session, api};

#[component]
pub fn Account() -> impl IntoView {
    let session = Session::get();
    let external = move || session.me.with(|m| m.as_ref().is_some_and(|m| m.external));
    view! {
        <h1>"Mon compte"</h1>
        <Show
            when=move || !external()
            fallback=|| view! { <p class="muted">"Compte géré par le proxy d'authentification : mot de passe et double authentification se règlent là-bas."</p> }
        >
            <Password/>
            <Totp/>
            <Passkeys/>
        </Show>
        <Terminal/>
    }
}

/// Thème par défaut du terminal SSH (un hôte peut avoir le sien) et combinaisons de la barre de touches.
#[component]
fn Terminal() -> impl IntoView {
    let theme = RwSignal::new(String::new());
    let combos = RwSignal::new(String::new());
    let st = status();
    spawn_local(async move {
        if let Ok(p) = api::get::<TerminalPrefs>("/api/account/terminal").await {
            theme.set(p.theme);
            combos.set(p.combos.join(", "));
        }
    });
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = TerminalPrefs {
            theme: theme.get_untracked(),
            combos: combos
                .get_untracked()
                .split(',')
                .map(|c| c.trim().to_owned())
                .filter(|c| !c.is_empty())
                .collect(),
        };
        spawn_local(async move {
            let r = api::send::<_, TerminalPrefs>("PUT", "/api/account/terminal", &body).await;
            st.set(Some(
                r.map(|_| "Préférences du terminal enregistrées.".into()).map_err(|e| e.to_string()),
            ));
        });
    };
    view! {
        <section class="card">
            <h2>"Terminal SSH"</h2>
            <form on:submit=submit class="stack">
                <label>"Thème par défaut"
                    <select prop:value=move || theme.get() on:change=move |ev| theme.set(event_target_value(&ev))>
                        {TERMINAL_THEMES.iter().map(|t| view! { <option value=*t>{*t}</option> }).collect_view()}
                    </select>
                </label>
                <label>"Combinaisons de la barre de touches (séparées par des virgules)"
                    <input type="text" class="mono" placeholder="Ctrl+C, Ctrl+D, Ctrl+Z, Ctrl+R, Ctrl+L"
                        prop:value=move || combos.get() on:input=move |ev| combos.set(event_target_value(&ev))/>
                </label>
                <p class="muted">"Ctrl+lettre, Alt+lettre ou Ctrl+Alt+lettre, 12 au plus. La barre apparaît en bas de l'écran sur téléphone et tablette, au-dessus du clavier."</p>
                <button type="submit">"Enregistrer"</button>
            </form>
            {show_status(st)}
        </section>
    }
}

fn status() -> RwSignal<Option<Result<String, String>>> {
    RwSignal::new(None)
}

fn show_status(s: RwSignal<Option<Result<String, String>>>) -> impl IntoView {
    move || {
        s.get().map(|r| match r {
            Ok(m) => view! { <p class="notice">{m}</p> }.into_any(),
            Err(m) => view! { <p class="error">{m}</p> }.into_any(),
        })
    }
}

fn totp_enabled() -> bool {
    Session::get().me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled))
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

    /// Lit puis efface les champs : un secret ne reste pas affiché après envoi.
    fn take(&self) -> ReAuth {
        let proof = ReAuth {
            password: self.password.get_untracked(),
            totp: Some(self.totp.get_untracked()).filter(|c| !c.is_empty()),
        };
        self.password.set(String::new());
        self.totp.set(String::new());
        proof
    }

    fn view(self, label: &'static str) -> impl IntoView {
        let p = self;
        view! {
            <label>{label}
                <input type="password" autocomplete="current-password" required
                    prop:value=move || p.password.get() on:input=move |ev| p.password.set(event_target_value(&ev))/>
            </label>
            <Show when=totp_enabled>
                <label>"Code TOTP"
                    <input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required
                        prop:value=move || p.totp.get() on:input=move |ev| p.totp.set(event_target_value(&ev))/>
                </label>
            </Show>
        }
    }
}

#[component]
fn Password() -> impl IntoView {
    let proof = Proof::new();
    let new = RwSignal::new(String::new());
    let st = status();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = ChangePassword { auth: proof.take(), new: new.get_untracked() };
        new.set(String::new());
        spawn_local(async move {
            let r = api::send_empty("POST", "/api/account/password", Some(&body)).await;
            st.set(Some(
                r.map(|_| "Mot de passe changé, les autres sessions sont fermées.".into())
                    .map_err(|e| e.to_string()),
            ));
        });
    };
    view! {
        <section class="card">
            <h2>"Mot de passe"</h2>
            <form on:submit=submit class="stack">
                {proof.view("Actuel")}
                <label>"Nouveau (12 caractères minimum)"<input type="password" autocomplete="new-password" minlength="12" required
                    prop:value=move || new.get() on:input=move |ev| new.set(event_target_value(&ev))/></label>
                {show_status(st)}
                <button type="submit">"Changer"</button>
            </form>
        </section>
    }
}

#[component]
fn Totp() -> impl IntoView {
    let session = Session::get();
    let setup = RwSignal::new(None::<TotpSetup>);
    let proof = Proof::new();
    let code = RwSignal::new(String::new());
    let st = status();

    let set_enabled = move |on: bool| {
        session.me.update(|m| {
            if let Some(m) = m {
                m.totp_enabled = on;
            }
        })
    };

    // Étape 1 : mot de passe → graine et QR code.
    let start = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = proof.take();
        spawn_local(async move {
            match api::send::<_, TotpSetup>("POST", "/api/account/totp/setup", &body).await {
                Ok(s) => {
                    setup.set(Some(s));
                    st.set(None);
                }
                Err(e) => st.set(Some(Err(e.to_string()))),
            }
        });
    };
    // Étape 2 : premier code de l'appli → activation.
    let confirm = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = TotpConfirm { code: code.get_untracked() };
        code.set(String::new());
        spawn_local(async move {
            match api::send_empty("POST", "/api/account/totp/confirm", Some(&body)).await {
                Ok(()) => {
                    set_enabled(true);
                    setup.set(None);
                    st.set(Some(Ok("TOTP activé.".into())));
                }
                Err(e) => st.set(Some(Err(e.to_string()))),
            }
        });
    };
    let disable = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = proof.take();
        spawn_local(async move {
            match api::send_empty("POST", "/api/account/totp/disable", Some(&body)).await {
                Ok(()) => {
                    set_enabled(false);
                    st.set(Some(Ok("TOTP désactivé.".into())));
                }
                Err(e) => st.set(Some(Err(e.to_string()))),
            }
        });
    };

    view! {
        <section class="card">
            <h2>"Double authentification (TOTP)"</h2>
            {move || if totp_enabled() {
                view! {
                    <p>"Activée."</p>
                    <form on:submit=disable class="stack">
                        {proof.view("Mot de passe")}
                        <button type="submit" class="secondary">"Désactiver"</button>
                    </form>
                }.into_any()
            } else if let Some(s) = setup.get() {
                view! {
                    <p>"Scanne ce QR code avec ton appli d'authentification, puis saisis le code affiché."</p>
                    <div class="qr" inner_html=s.qr_svg></div>
                    <p class="muted mono">{s.secret_base32}</p>
                    <form on:submit=confirm class="row">
                        <input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required
                            prop:value=move || code.get() on:input=move |ev| code.set(event_target_value(&ev))/>
                        <button type="submit">"Activer"</button>
                    </form>
                }.into_any()
            } else {
                view! {
                    <p>"Non activée."</p>
                    <form on:submit=start class="stack">
                        {proof.view("Mot de passe")}
                        <button type="submit">"Configurer"</button>
                    </form>
                }.into_any()
            }}
            {show_status(st)}
        </section>
    }
}

#[component]
fn Passkeys() -> impl IntoView {
    let list = RwSignal::new(Vec::<PasskeyInfo>::new());
    let name = RwSignal::new(String::new());
    let proof = Proof::new();
    let st = status();
    let reload = move || {
        spawn_local(async move {
            if let Ok(l) = api::get("/api/account/passkeys").await {
                list.set(l);
            }
        })
    };
    reload();

    let add = move |ev: SubmitEvent| {
        ev.prevent_default();
        let n = name.get_untracked();
        let body = proof.take();
        spawn_local(async move {
            match api::passkey_register(n, body).await {
                Ok(()) => {
                    st.set(Some(Ok("Passkey ajoutée.".into())));
                    name.set(String::new());
                    reload();
                }
                Err(e) => st.set(Some(Err(e.to_string()))),
            }
        });
    };
    let remove = move |id: i64| {
        spawn_local(async move {
            match api::send_empty::<()>("DELETE", &format!("/api/account/passkeys/{id}"), None).await {
                Ok(()) => reload(),
                Err(e) => st.set(Some(Err(e.to_string()))),
            }
        });
    };

    view! {
        <section class="card">
            <h2>"Passkeys"</h2>
            <p class="muted">"Connexion par empreinte, visage ou clé de sécurité, sans mot de passe."</p>
            <ul class="list">
                <For each=move || list.get() key=|p| p.id let(p)>
                    <li class="row spread">
                        <span>{p.name.clone()} <span class="muted">" · " {p.created_at.get(..10).unwrap_or_default().to_owned()}</span></span>
                        <button class="link danger" on:click=move |_| remove(p.id)>"Supprimer"</button>
                    </li>
                </For>
            </ul>
            <form on:submit=add class="stack">
                <label>"Nom"
                    <input type="text" placeholder="ex. Téléphone" maxlength="64"
                        prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/>
                </label>
                {proof.view("Mot de passe")}
                <button type="submit">"Ajouter une passkey"</button>
            </form>
            {show_status(st)}
        </section>
    }
}
