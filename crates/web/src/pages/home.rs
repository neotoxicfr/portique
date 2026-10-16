use leptos::{prelude::*, task::spawn_local};
use yawrdp_proto::{ConnectionSummary, Protocol};

use crate::{Session, api};

#[component]
pub fn Home() -> impl IntoView {
    let session = Session::get();
    let list = RwSignal::new(None::<Vec<ConnectionSummary>>);
    let notice = RwSignal::new(None::<String>);
    spawn_local(async move {
        match api::get("/api/connections").await {
            Ok(l) => list.set(Some(l)),
            Err(e) => {
                session.handle(&e);
                notice.set(Some(e.to_string()));
            }
        }
    });

    let wake = move |c: ConnectionSummary| {
        notice.set(Some(format!("Réveil de « {} »…", c.name)));
        spawn_local(async move {
            let r = api::send_empty::<()>("POST", &format!("/api/connections/{}/wake", c.id), None).await;
            notice.set(Some(match r {
                Ok(()) => format!("Paquet de réveil envoyé à « {} ».", c.name),
                Err(e) => e.to_string(),
            }));
        });
    };

    view! {
        <h1>"Connexions"</h1>
        {move || notice.get().map(|n| view! { <p class="notice">{n}</p> })}
        {move || match list.get() {
            None => view! { <p class="muted">"Chargement…"</p> }.into_any(),
            Some(l) if l.is_empty() => view! {
                <p class="muted">"Aucune connexion. Un admin doit t'en ouvrir une."</p>
            }.into_any(),
            Some(l) => view! {
                <ul class="tiles">
                    {l.into_iter().map(|c| {
                        let proto = match c.protocol { Protocol::Rdp => "RDP", Protocol::Ssh => "SSH" };
                        let can_wake = c.can_wake;
                        let c2 = c.clone();
                        view! {
                            <li class="card tile">
                                <div class="tile-head">
                                    <strong>{c.name.clone()}</strong>
                                    <span class="badge">{proto}</span>
                                </div>
                                <div class="actions">
                                    <a class="button" href=format!("/session/{}", c.id)>"Ouvrir"</a>
                                    <Show when=move || can_wake>
                                        {
                                            let c = c2.clone();
                                            view! { <button class="secondary" on:click=move |_| wake(c.clone())>"Réveiller"</button> }
                                        }
                                    </Show>
                                </div>
                            </li>
                        }
                    }).collect_view()}
                </ul>
            }.into_any(),
        }}
    }
}
