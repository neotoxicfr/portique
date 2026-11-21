mod api;
mod pages;
mod session;
mod ssh;

use leptos::{prelude::*, task::spawn_local};
use leptos_router::{
    components::{A, Route, Router, Routes},
    path,
};
use portique_proto::{AuthMode, Me, ServerInfo};

/// État d'authentification partagé par toutes les pages.
#[derive(Clone, Copy)]
pub struct Session {
    pub info: RwSignal<Option<ServerInfo>>,
    pub me: RwSignal<Option<Me>>,
    /// Vrai une fois le premier `/api/me` revenu (succès ou 401).
    pub checked: RwSignal<bool>,
    /// Échec de déconnexion : gardé ici et non dans `Shell`, recréé à chaque page, pour qu'une réponse
    /// arrivée après un changement de page reste affichée.
    pub logout_error: RwSignal<Option<String>>,
    /// Génération de session, avancée à chaque fin de session : une réponse de déconnexion d'une session
    /// précédente ne doit rien afficher dans la suivante.
    pub epoch: RwSignal<u32>,
}

impl Session {
    pub fn get() -> Self {
        expect_context()
    }

    /// À appeler sur une erreur d'API, avec la génération `epoch` relevée à l'émission de la requête : un 401
    /// renvoie à l'écran de connexion, sauf s'il répond à une session déjà terminée (il fermerait la suivante).
    pub fn handle(&self, epoch: u32, e: &api::Error) {
        if *e == api::Error::Unauthorized && self.epoch.get_untracked() == epoch {
            self.me.set(None);
        }
    }

    pub fn is_proxy(&self) -> bool {
        self.info.with(|i| i.as_ref().is_some_and(|i| i.auth_mode == AuthMode::Proxy))
    }
}

/// Message serveur affiché comme une phrase : majuscule initiale et point final.
pub fn sentence(s: &str) -> String {
    let mut c = s.trim().chars();
    let Some(first) = c.next() else { return String::new() };
    let mut out: String = first.to_uppercase().chain(c).collect();
    if !out.ends_with(['.', '!', '?', '…', ':']) {
        out.push('.');
    }
    out
}

/// `fut`, ou `None` s'il n'aboutit pas en `ms` millisecondes.
pub async fn within<F: std::future::Future>(ms: i32, fut: F) -> Option<F::Output> {
    let timer = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
        let _ = window().set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
    }));
    match futures::future::select(std::pin::pin!(fut), timer).await {
        futures::future::Either::Left((v, _)) => Some(v),
        futures::future::Either::Right(_) => None,
    }
}

/// Icône en ligne (trait 2, bouts ronds, couleur du texte : voir `.ico` dans style.css).
/// `d` : éléments SVG de la grille 24x24.
pub fn icon(d: &'static str) -> impl IntoView {
    view! { <svg class="ico" viewBox="0 0 24 24" aria-hidden="true" inner_html=d></svg> }
}

/// Glyphes partagés par les pages (certains ne servent qu'aux pages de compte, d'admin et de terminal).
#[allow(dead_code)]
pub mod glyph {
    pub const HOUSE: &str = r#"<path d="M4 20V9l8-5 8 5v11"/><path d="M9 20v-6h6v6"/>"#;
    pub const SCREEN: &str =
        r#"<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>"#;
    pub const TERMINAL: &str = r#"<path d="M5 8l4 4-4 4M12 16h7"/>"#;
    pub const POWER: &str = r#"<path d="M12 3v9"/><path d="M6.3 7.3a8 8 0 1 0 11.4 0"/>"#;
    pub const LOGOUT: &str = r#"<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>"#;
    pub const SEARCH: &str = r#"<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>"#;
    pub const WARN: &str = r#"<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17v.5"/>"#;
    pub const SHIELD: &str = r#"<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>"#;
    pub const PERSON: &str = r#"<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>"#;
    pub const TRASH: &str = r#"<path d="M4 7h16M10 11v6M14 11v6"/><path d="M6 7l1 13h10l1-13M9 7V4h6v3"/>"#;
    pub const PLUS: &str = r#"<path d="M12 5v14M5 12h14"/>"#;
    pub const COPY: &str =
        r#"<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>"#;
    pub const CHEVRON: &str = r#"<path d="M9 5l7 7-7 7"/>"#;
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
    let session = Session {
        info: RwSignal::new(None),
        me: RwSignal::new(None),
        checked: RwSignal::new(false),
        logout_error: RwSignal::new(None),
        epoch: RwSignal::new(0),
    };
    provide_context(session);
    // L'erreur ne survit pas à la session qu'elle concernait (sinon elle reviendrait après reconnexion).
    Effect::new(move || {
        if session.me.with(Option::is_none) {
            session.logout_error.set(None);
            session.epoch.update(|e| *e = e.wrapping_add(1));
        }
    });
    // Panne réseau ou serveur (hors 401) : on le dit et on propose de réessayer. Une requête qui ne revient
    // pas ne doit pas laisser l'écran de chargement sans bouton.
    let failure = RwSignal::new(None::<String>);
    let load = move || {
        failure.set(None);
        spawn_local(async move {
            let check = async {
                // Sans le mode d'authentification, pas de démarrage : un compte du proxy verrait sinon les
                // commandes du mode intégré. Un 401 ici n'est pas une absence de session.
                if session.info.with_untracked(Option::is_none) {
                    let info = api::get::<ServerInfo>("/api/info")
                        .await
                        .map_err(|e| api::Error::Message(e.to_string()))?;
                    session.info.set(Some(info));
                }
                api::get::<Me>("/api/me").await
            };
            match within(15_000, check).await {
                Some(Ok(me)) => {
                    session.me.set(Some(me));
                    session.checked.set(true);
                }
                Some(Err(api::Error::Unauthorized)) => {
                    session.me.set(None);
                    session.checked.set(true);
                }
                Some(Err(e)) => failure.set(Some(e.to_string())),
                None => failure.set(Some("le serveur ne répond pas".into())),
            }
        });
    };
    load();

    view! {
        <Router>
            <Show
                when=move || session.checked.get()
                fallback=move || view! {
                    <main class="center">
                        {move || match failure.get() {
                            Some(m) => view! {
                                <p class="alert" role="alert">{sentence(&m)}</p>
                                <button on:click=move |_| load()>"Réessayer"</button>
                            }.into_any(),
                            None => view! { <div class="spinner" role="status"><span class="sr-only">"Chargement"</span></div> }.into_any(),
                        }}
                    </main>
                }
            >
                <Show
                    when=move || session.me.with(Option::is_some)
                    fallback=move || if session.is_proxy() {
                        view! { <main class="center"><p class="alert" role="alert">"Accès refusé : passe par le proxy d'authentification."</p></main> }.into_any()
                    } else {
                        view! { <pages::login::Login/> }.into_any()
                    }
                >
                    <Routes fallback=|| view! { <Shell><p>"Page introuvable."</p></Shell> }>
                        <Route path=path!("/session/:id") view=session::SessionPage/>
                        <Route path=path!("/ssh/:id") view=ssh::SshPage/>
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
    // Échec de déconnexion : la session reste ouverte côté serveur, on le dit et on laisse réessayer.
    let logout_error = session.logout_error;
    let logout = move || {
        logout_error.set(None);
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            let result = api::send_empty::<()>("POST", "/api/auth/logout", None).await;
            // Session déjà terminée (double clic, reconnexion entre-temps) : réponse périmée, ignorée.
            if session.epoch.get_untracked() != epoch {
                return;
            }
            match result {
                Ok(()) | Err(api::Error::Unauthorized) => session.me.set(None),
                Err(e) => logout_error.set(Some(e.to_string())),
            }
        });
    };
    view! {
        <header class="topbar">
            <A href="/" attr:class="brand">
                <span class="pastille blue">{icon(glyph::HOUSE)}</span>
                "Portique"
            </A>
            <nav class="seg" aria-label="Navigation">
                <A href="/" exact=true>{icon(glyph::SCREEN)}<span>"Connexions"</span></A>
                <Show when=is_admin><A href="/admin">{icon(glyph::SHIELD)}<span>"Admin"</span></A></Show>
                <A href="/compte">{icon(glyph::PERSON)}<span>"Compte"</span></A>
            </nav>
            <Show when=move || !session.is_proxy()>
                <button class="iconbtn" aria-label="Déconnexion" title="Déconnexion" on:click=move |_| logout()>
                    {icon(glyph::LOGOUT)}
                </button>
            </Show>
        </header>
        <main>
            {move || logout_error.get().map(|m| view! {
                <div class="banner error" role="alert">
                    <span>{sentence(&m)}</span>
                    <button on:click=move |_| logout()>"Réessayer"</button>
                </div>
            })}
            {children()}
        </main>
        <footer class="footer">
            // Lien volontairement discret vers les réglages Windows (étape 7).
            // rel="external" : page statique, le routeur ne doit pas intercepter le lien.
            <a href="/setup/" rel="external">"Préparer un PC"</a>
        </footer>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_401_from_an_ended_session_keeps_the_next_one() {
        let session = Session {
            info: RwSignal::new(None),
            me: RwSignal::new(None),
            checked: RwSignal::new(true),
            logout_error: RwSignal::new(None),
            epoch: RwSignal::new(1),
        };
        let me = |name: &str| Me {
            id: 1,
            username: name.into(),
            is_admin: false,
            totp_enabled: false,
            external: false,
        };
        session.me.set(Some(me("alice")));
        let sent_by_alice = session.epoch.get_untracked();
        // Fin de la session d'alice (l'effet d'`App` avance la génération), puis connexion de bob.
        session.epoch.update(|e| *e += 1);
        session.me.set(Some(me("bob")));
        session.handle(sent_by_alice, &api::Error::Unauthorized);
        assert_eq!(session.me.get_untracked(), Some(me("bob")));
        // Un refus d'une autre nature ne ferme rien ; un 401 d'une requête de bob, si.
        let sent_by_bob = session.epoch.get_untracked();
        session.handle(sent_by_bob, &api::Error::Message("refus".into()));
        assert!(session.me.with_untracked(Option::is_some));
        session.handle(sent_by_bob, &api::Error::Unauthorized);
        assert_eq!(session.me.get_untracked(), None);
    }
}
