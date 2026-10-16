mod api;
mod pages;
mod session;

use leptos::{prelude::*, task::spawn_local};
use leptos_router::{
    components::{A, Route, Router, Routes},
    path,
};
use yawrdp_proto::{AuthMode, Me, ServerInfo};

/// État d'authentification partagé par toutes les pages.
#[derive(Clone, Copy)]
pub struct Session {
    pub info: RwSignal<Option<ServerInfo>>,
    pub me: RwSignal<Option<Me>>,
    /// Vrai une fois le premier `/api/me` revenu (succès ou 401).
    pub checked: RwSignal<bool>,
}

impl Session {
    pub fn get() -> Self {
        expect_context()
    }

    /// À appeler sur une erreur d'API : un 401 renvoie à l'écran de connexion.
    pub fn handle(&self, e: &api::Error) {
        if *e == api::Error::Unauthorized {
            self.me.set(None);
        }
    }

    pub fn is_proxy(&self) -> bool {
        self.info.with(|i| i.as_ref().is_some_and(|i| i.auth_mode == AuthMode::Proxy))
    }
}

fn main() {
    console_error_panic_hook::set_once();
    // PWA : appli installable (le service worker ne met jamais l'API ni la session en cache).
    if let Ok(sw) = js_sys::Reflect::get(&window().navigator(), &"serviceWorker".into())
        && !sw.is_undefined()
        && let Ok(register) = js_sys::Reflect::get(&sw, &"register".into())
        && let Some(f) = wasm_bindgen::JsCast::dyn_ref::<js_sys::Function>(&register)
    {
        let _ = f.call1(&sw, &"/sw.js".into());
    }
    leptos::mount::mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    let session =
        Session { info: RwSignal::new(None), me: RwSignal::new(None), checked: RwSignal::new(false) };
    provide_context(session);
    spawn_local(async move {
        if let Ok(info) = api::get::<ServerInfo>("/api/info").await {
            session.info.set(Some(info));
        }
        session.me.set(api::get::<Me>("/api/me").await.ok());
        session.checked.set(true);
    });

    view! {
        <Router>
            <Show when=move || session.checked.get() fallback=|| view! { <main class="center muted">"Chargement…"</main> }>
                <Show
                    when=move || session.me.with(Option::is_some)
                    fallback=move || if session.is_proxy() {
                        view! { <main class="center"><p>"Accès refusé : passe par le proxy d'authentification."</p></main> }.into_any()
                    } else {
                        view! { <pages::login::Login/> }.into_any()
                    }
                >
                    <Routes fallback=|| view! { <Shell><p>"Page introuvable."</p></Shell> }>
                        <Route path=path!("/session/:id") view=session::SessionPage/>
                        <Route path=path!("/") view=|| view! { <Shell><pages::home::Home/></Shell> }/>
                        <Route path=path!("/compte") view=|| view! { <Shell><pages::account::Account/></Shell> }/>
                        <Route path=path!("/admin") view=|| view! { <Shell><pages::admin::Admin/></Shell> }/>
                    </Routes>
                </Show>
            </Show>
        </Router>
    }
}

#[component]
fn Shell(children: Children) -> impl IntoView {
    let session = Session::get();
    let is_admin = move || session.me.with(|m| m.as_ref().is_some_and(|m| m.is_admin));
    let logout = move |_| {
        spawn_local(async move {
            let _ = api::send_empty::<()>("POST", "/api/auth/logout", None).await;
            session.me.set(None);
        });
    };
    view! {
        <header class="topbar">
            <A href="/" attr:class="brand">"yawrdp"</A>
            <nav>
                <A href="/">"Connexions"</A>
                <A href="/compte">"Compte"</A>
                <Show when=is_admin><A href="/admin">"Admin"</A></Show>
                <Show when=move || !session.is_proxy()>
                    <button class="link" on:click=logout>"Déconnexion"</button>
                </Show>
            </nav>
        </header>
        <main>{children()}</main>
        <footer class="footer">
            // Lien volontairement discret vers les réglages Windows (étape 7).
            <a href="/setup/" class="muted">"Préparer un PC"</a>
        </footer>
    }
}
