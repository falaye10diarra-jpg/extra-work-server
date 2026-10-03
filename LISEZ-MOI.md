# Extra Work — serveur prêt pour Render

Concepteur : Lefa Services. Paquet du 3 octobre 2026.

## État réel

Ce paquet contient le serveur compatible avec les APK Extra Work 0.1 et sa configuration pour Render. **Ce n’est pas encore un serveur en ligne : aucune URL n’a été créée ni vérifiée.** Connecter Render permet de poursuivre le déploiement avec le compte de son propriétaire. La source doit être disponible pour Render par un dépôt Git connecté, un dépôt public ou une image Docker compatible.

## Déploiement manuel

1. Décompressez ce paquet et placez son contenu à la racine d’un dépôt Git que vous contrôlez. N’y mettez ni clés privées ni jetons.
2. Dans Render, créez un Web Service depuis ce dépôt.
3. Choisissez Python et le plan Free pour les essais.
4. Commande de construction : `python -m py_compile server.py start_render.py`.
5. Commande de démarrage : `python start_render.py`.
6. Contrôle de disponibilité : `/health`.
7. Une fois le déploiement réussi, copiez l’adresse HTTPS réelle fournie par Render.
8. Ouvrez cette adresse suivie de `/health`. La réponse doit contenir `status: ok`.
9. Entrez l’adresse HTTPS de base, sans `/health`, dans les deux applications Android.
10. Créez un code sur Assistance, saisissez-le sur Opérateur, puis acceptez sur le téléphone assisté.

Le fichier `render.yaml` permet aussi une installation par Blueprint, avec un plan Free explicitement indiqué. L’adresse exacte est attribuée par Render ; ne devinez pas son sous-domaine.

## Restrictions importantes

- HTTPS est assuré par Render jusqu’à son proxy ; le lanceur reçoit les requêtes sur le port interne donné par `PORT`.
- Le serveur ne chiffre pas les images de bout en bout : le relais peut les voir temporairement en mémoire.
- Sessions et images disparaissent lorsque le processus redémarre ; c’est voulu pour ce prototype.
- Gardez une seule instance. Les sessions ne sont pas partagées entre plusieurs processus.
- Les noms d’opérateurs sont déclaratifs, sans compte authentifié.
- Le plan gratuit se met en veille après 15 minutes sans trafic. Son réveil peut prendre environ une minute : avant le premier essai, ouvrez `/health` et attendez sa réponse. Les APK ont des délais d’attente plus courts et peuvent demander de réessayer après le réveil.
- Le plan gratuit a des limites de trafic et peut être interrompu. Ne le présentez pas comme un service commercial permanent. Vérifiez les conditions de facturation du compte avant d’activer des ressources payantes.
- La limitation des requêtes utilise l’adresse TCP, qui peut être partagée derrière le proxy. Cette version sert à de petits essais.

## Vérifications

La logique du serveur a passé 11 tests, dont un transfert réel d’image JPEG via HTTPS local, la pause et l’arrêt. Le lanceur spécifique Render a été compilé et son refus hors Render a été vérifié. Aucun déploiement public ni essai sur deux téléphones n’est inclus dans cette validation.

Exécuter les tests avec `python -m unittest -v test_server`. Le test HTTPS nécessite OpenSSL et utilise un certificat temporaire uniquement pour ce test.

Documentation officielle :
- https://render.com/docs/web-services
- https://render.com/docs/free
- https://render.com/docs/your-first-deploy
