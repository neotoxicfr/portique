use leptos::{ev::SubmitEvent, prelude::*, task::spawn_local};
use portique_proto::{LoginRequest, LoginResponse};

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

    // Retour à la saisie du mot de passe : le défi TOTP et les secrets saisis sont effacés.
    let reset = move || {
        need_totp.set(false);
        password.set(String::new());
        totp.set(String::new());
    };

    let done = move |r: api::Result<LoginResponse>| {
        busy.set(false);
        match r {
            Ok(LoginResponse::Ok { me }) => session.me.set(Some(me)),
            Ok(LoginResponse::TotpRequired) => {
                need_totp.set(true);
                error.set(None);
            }
            // Mot de passe refusé, y compris pendant le défi TOTP (changé entre les deux envois) : il faut le
            // ressaisir. Un code TOTP faux arrive autrement (400, message du serveur).
            Err(api::Error::Unauthorized) => {
                reset();
                error.set(Some("identifiant ou mot de passe incorrect".into()));
            }
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

    let change_account = move |_| {
        reset();
        error.set(None);
    };

    view! {
        <main class="center">
            <form class="login" on:submit=submit>
                <img class="login-icon" src="/icon.svg" alt=""/>
                <h1>"Portique"</h1>
                <div class="group">
                    <label class="line">
                        <span class="line-label">"Identifiant"</span>
                        // Figés pendant l'envoi : le défi TOTP qui revient vaut pour le compte envoyé.
                        <input type="text" autocomplete="username webauthn" required
                            readonly=move || need_totp.get() || busy.get()
                            prop:value=move || username.get()
                            on:input=move |ev| username.set(event_target_value(&ev))/>
                    </label>
                    <Show when=move || !need_totp.get()>
                        <label class="line">
                            <span class="line-label">"Mot de passe"</span>
                            <input type="password" autocomplete="current-password" readonly=move || busy.get()
                                prop:value=move || password.get()
                                on:input=move |ev| password.set(event_target_value(&ev))/>
                        </label>
                    </Show>
                    <Show when=move || need_totp.get()>
                        <label class="line">
                            <span class="line-label">"Code à 6 chiffres"</span>
                            <input type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus
                                prop:value=move || totp.get()
                                on:input=move |ev| totp.set(event_target_value(&ev))/>
                        </label>
                    </Show>
                </div>
                {move || error.get().map(|e| view! { <p class="alert" role="alert">{crate::sentence(&e)}</p> })}
                <button type="submit" class="block" disabled=move || busy.get()>"Se connecter"</button>
                <Show
                    when=move || !need_totp.get()
                    fallback=move || view! {
                        <button type="button" class="secondary block" disabled=move || busy.get() on:click=change_account>
                            "Changer de compte"
                        </button>
                    }
                >
                    <button type="button" class="secondary block" disabled=move || busy.get() on:click=passkey>
                        "Utiliser une passkey"
                    </button>
                </Show>
            </form>
        </main>
    }
}
