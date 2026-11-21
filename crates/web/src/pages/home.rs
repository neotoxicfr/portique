use leptos::{prelude::*, task::spawn_local};
use portique_proto::ConnectionSummary;

use crate::{Session, api, glyph, icon};

/// Pastille de la carte : couleur et glyphe selon les protocoles (rouge si l'hôte est sensible).
pub(crate) fn pastille(alert: bool, rdp: bool, ssh: bool) -> (&'static str, &'static str) {
    match (alert, rdp, ssh) {
        (true, ..) => ("red", glyph::WARN),
        (_, true, true) => (
            "indigo",
            concat!(
                r#"<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>"#,
                r#"<path d="M7 9l2 1.5L7 12"/>"#
            ),
        ),
        (_, false, true) => ("green", glyph::TERMINAL),
        _ => ("orange", glyph::SCREEN),
    }
}

/// Un des trois emplacements fixes de la carte : le bouton, ou un rond vide qui garde la place.
fn slot(present: bool, label: String, href: String, d: &'static str, tone: &'static str) -> impl IntoView {
    if present {
        view! {
            <a class=format!("iconbtn big {tone}") href=href aria-label=label.clone() title=label>{icon(d)}</a>
        }
        .into_any()
    } else {
        view! { <span class="iconbtn big empty" aria-hidden="true"></span> }.into_any()
    }
}

#[component]
pub fn Home() -> impl IntoView {
    let session = Session::get();
    let list = RwSignal::new(None::<Vec<ConnectionSummary>>);
    // Échec du chargement (hors 401) : message et reprise, au lieu d'un « Chargement » sans fin.
    let failed = RwSignal::new(None::<String>);
    // Message de réveil : (est une erreur, texte).
    let notice = RwSignal::new(None::<(bool, String)>);
    let query = RwSignal::new(String::new());

    let load = move || {
        failed.set(None);
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            match api::get("/api/connections").await {
                Ok(l) => list.set(Some(l)),
                Err(e) => {
                    session.handle(epoch, &e);
                    failed.set(Some(e.to_string()));
                }
            }
        });
    };
    load();

    let wake = move |c: ConnectionSummary| {
        notice.set(Some((false, format!("Réveil de « {} »…", c.name))));
        let epoch = session.epoch.get_untracked();
        spawn_local(async move {
            let r = api::send_empty::<()>("POST", &format!("/api/connections/{}/wake", c.id), None).await;
            notice.set(Some(match r {
                Ok(()) => (false, format!("Paquet de réveil envoyé à « {} ».", c.name)),
                Err(e) => {
                    session.handle(epoch, &e);
                    (true, crate::sentence(&e.to_string()))
                }
            }));
        });
    };

    view! {
        <h1 class="sr-only">"Connexions"</h1>
        {move || notice.get().map(|(is_err, n)| view! {
            <div class=if is_err { "banner error" } else { "banner" } role=if is_err { "alert" } else { "status" }>{n}</div>
        })}
        {move || match (failed.get(), list.get()) {
            (Some(m), _) => view! {
                <div class="banner error" role="alert">
                    <span>{crate::sentence(&m)}</span>
                    <button on:click=move |_| load()>"Réessayer"</button>
                </div>
            }.into_any(),
            (None, None) => view! { <div class="spinner" role="status"><span class="sr-only">"Chargement"</span></div> }.into_any(),
            (None, Some(l)) if l.is_empty() => view! {
                <p class="muted">"Aucune connexion. Un admin doit t'en ouvrir une."</p>
            }.into_any(),
            (None, Some(l)) => view! {
                <label class="search">
                    {icon(glyph::SEARCH)}
                    <span class="sr-only">"Rechercher une machine"</span>
                    <input type="search" placeholder="Rechercher" autocomplete="off"
                        prop:value=move || query.get()
                        on:input=move |ev| query.set(event_target_value(&ev))/>
                </label>
                <ul class="hosts">
                    {l.into_iter().map(|c| {
                        let name = c.name.clone();
                        let shown = move || {
                            let q = query.with(|q| q.trim().to_lowercase());
                            q.is_empty() || name.to_lowercase().contains(&q)
                        };
                        let (tone, glyph_d) = pastille(c.alert, c.rdp, c.ssh);
                        let c2 = c.clone();
                        view! {
                            <li class="host" class:alert-host=c.alert hidden=move || !shown()>
                                <div class="host-head">
                                    <span class=format!("pastille {tone}")>{icon(glyph_d)}</span>
                                    <h2 class="host-name" title=c.name.clone()>{c.name.clone()}</h2>
                                </div>
                                <div class="host-actions">
                                    {slot(c.ssh, format!("Terminal de {}", c.name), format!("/ssh/{}", c.id), glyph::TERMINAL, if c.alert { "red" } else { "blue" })}
                                    {slot(c.rdp, format!("Bureau de {}", c.name), format!("/session/{}", c.id), glyph::SCREEN, if c.alert { "red" } else { "blue" })}
                                    {if c.can_wake {
                                        let label = format!("Réveiller {}", c.name);
                                        view! {
                                            <button class="iconbtn big" aria-label=label.clone() title=label
                                                on:click=move |_| wake(c2.clone())>{icon(glyph::POWER)}</button>
                                        }.into_any()
                                    } else {
                                        view! { <span class="iconbtn big empty" aria-hidden="true"></span> }.into_any()
                                    }}
                                </div>
                            </li>
                        }
                    }).collect_view()}
                </ul>
            }.into_any(),
        }}
    }
}
