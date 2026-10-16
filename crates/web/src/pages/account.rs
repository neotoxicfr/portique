use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use yawrdp_proto::{ChangePassword, PasskeyInfo, TotpConfirm, TotpSetup};

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

#[component]
fn Password() -> impl IntoView {
    let current = RwSignal::new(String::new());
    let new = RwSignal::new(String::new());
    let st = status();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = ChangePassword { current: current.get_untracked(), new: new.get_untracked() };
        spawn_local(async move {
            let r = api::send_empty("POST", "/api/account/password", Some(&body)).await;
            st.set(Some(
                r.map(|_| "Mot de passe changé, les autres sessions sont fermées.".into())
                    .map_err(|e| e.to_string()),
            ));
            current.set(String::new());
            new.set(String::new());
        });
    };
    view! {
        <section class="card">
            <h2>"Mot de passe"</h2>
            <form on:submit=submit class="stack">
                <label>"Actuel"<input type="password" autocomplete="current-password" required
                    prop:value=move || current.get() on:input=move |ev| current.set(event_target_value(&ev))/></label>
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
    let enabled = move || session.me.with(|m| m.as_ref().is_some_and(|m| m.totp_enabled));
    let setup = RwSignal::new(None::<TotpSetup>);
    let code = RwSignal::new(String::new());
    let st = status();

    let set_enabled = move |on: bool| {
        session.me.update(|m| {
            if let Some(m) = m {
                m.totp_enabled = on;
            }
        })
    };

    let start = move |_| {
        spawn_local(async move {
            match api::send::<_, TotpSetup>("POST", "/api/account/totp/setup", &()).await {
                Ok(s) => setup.set(Some(s)),
                Err(e) => st.set(Some(Err(e.to_string()))),
            }
        });
    };
    let confirm = move |ev: SubmitEvent| {
        ev.prevent_default();
        let body = TotpConfirm { code: code.get_untracked() };
        let url = if enabled() { "/api/account/totp/disable" } else { "/api/account/totp/confirm" };
        let turning_on = !enabled();
        spawn_local(async move {
            match api::send_empty("POST", url, Some(&body)).await {
                Ok(()) => {
                    set_enabled(turning_on);
                    setup.set(None);
                    st.set(Some(Ok(if turning_on { "TOTP activé." } else { "TOTP désactivé." }.into())));
                }
                Err(e) => st.set(Some(Err(e.to_string()))),
            }
            code.set(String::new());
        });
    };

    let code_form = move |label: &'static str| {
        view! {
            <form on:submit=confirm class="row">
                <input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required
                    prop:value=move || code.get() on:input=move |ev| code.set(event_target_value(&ev))/>
                <button type="submit">{label}</button>
            </form>
        }
    };

    view! {
        <section class="card">
            <h2>"Double authentification (TOTP)"</h2>
            {move || if enabled() {
                view! { <p>"Activée. Saisis un code pour la désactiver."</p> {code_form("Désactiver")} }.into_any()
            } else if let Some(s) = setup.get() {
                view! {
                    <p>"Scanne ce QR code avec ton appli d'authentification, puis saisis le code affiché."</p>
                    <div class="qr" inner_html=s.qr_svg></div>
                    <p class="muted mono">{s.secret_base32}</p>
                    {code_form("Activer")}
                }.into_any()
            } else {
                view! { <p>"Non activée."</p> <button on:click=start>"Configurer"</button> }.into_any()
            }}
            {show_status(st)}
        </section>
    }
}

#[component]
fn Passkeys() -> impl IntoView {
    let list = RwSignal::new(Vec::<PasskeyInfo>::new());
    let name = RwSignal::new(String::new());
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
        spawn_local(async move {
            match api::passkey_register(n).await {
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
            <form on:submit=add class="row">
                <input type="text" placeholder="Nom (ex. Téléphone)" maxlength="64"
                    prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/>
                <button type="submit">"Ajouter"</button>
            </form>
            {show_status(st)}
        </section>
    }
}
