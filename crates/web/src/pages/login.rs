use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use yawrdp_proto::{LoginRequest, LoginResponse};

use crate::{Session, api};

#[component]
pub fn Login() -> impl IntoView {
    let session = Session::get();
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let totp = RwSignal::new(String::new());
    let need_totp = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);

    let done = move |r: api::Result<LoginResponse>| {
        busy.set(false);
        match r {
            Ok(LoginResponse::Ok { me }) => session.me.set(Some(me)),
            Ok(LoginResponse::TotpRequired) => {
                need_totp.set(true);
                error.set(None);
            }
            Err(api::Error::Unauthorized) => error.set(Some("identifiant ou mot de passe incorrect".into())),
            Err(e) => error.set(Some(e.to_string())),
        }
    };

    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        busy.set(true);
        let req = LoginRequest {
            username: username.get_untracked(),
            password: password.get_untracked(),
            totp: need_totp.get_untracked().then(|| totp.get_untracked()),
        };
        spawn_local(async move { done(api::send("POST", "/api/auth/login", &req).await) });
    };

    let passkey = move |_| {
        let name = username.get_untracked();
        if name.trim().is_empty() {
            error.set(Some("saisis d'abord ton identifiant".into()));
            return;
        }
        busy.set(true);
        spawn_local(async move { done(api::passkey_login(&name).await) });
    };

    view! {
        <main class="center">
            <form class="card login" on:submit=submit>
                <h1>"yawrdp"</h1>
                <label>"Identifiant"
                    <input type="text" autocomplete="username webauthn" required
                        prop:value=move || username.get()
                        on:input=move |ev| username.set(event_target_value(&ev))/>
                </label>
                <Show when=move || !need_totp.get()>
                    <label>"Mot de passe"
                        <input type="password" autocomplete="current-password"
                            prop:value=move || password.get()
                            on:input=move |ev| password.set(event_target_value(&ev))/>
                    </label>
                </Show>
                <Show when=move || need_totp.get()>
                    <label>"Code à 6 chiffres"
                        <input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus
                            prop:value=move || totp.get()
                            on:input=move |ev| totp.set(event_target_value(&ev))/>
                    </label>
                </Show>
                {move || error.get().map(|e| view! { <p class="error">{e}</p> })}
                <button type="submit" disabled=move || busy.get()>"Se connecter"</button>
                <Show when=move || !need_totp.get()>
                    <button type="button" class="secondary" disabled=move || busy.get() on:click=passkey>
                        "Utiliser une passkey"
                    </button>
                </Show>
            </form>
        </main>
    }
}
