# Politique de sécurité

## Versions suivies

| Version | Correctifs de sécurité |
|---|---|
| 0.4.x | oui |
| < 0.4 | non : mets à jour vers la dernière version |

## Signaler une faille

**N'ouvre pas d'issue publique.** Passe par le signalement privé de GitHub : onglet *Security*, puis
*Report a vulnerability*. Indique :

- la version ou le commit concerné ;
- le scénario : qui attaque (navigateur, PC distant, réseau), ce qu'il obtient ;
- une preuve de concept minimale, sans données réelles.

Tu reçois une réponse sous 7 jours. Le correctif et l'avis de sécurité sont publiés ensemble, avec ton nom
si tu le souhaites.

## Périmètre

Dans le périmètre : le serveur (authentification, sessions, relais, Wake-on-LAN), la pile RDP (un PC
malveillant ne doit pas pouvoir compromettre le navigateur ni le serveur), les scripts de `/setup/`.

Hors périmètre : une faille de Windows ou du serveur RDP lui-même, ou une configuration qui contredit la
documentation (par exemple un mode proxy sans `PORTIQUE_TRUSTED_PROXIES`).
