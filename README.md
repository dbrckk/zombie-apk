# zombie-apk — catalogue central de références Android

Ce dépôt contient des **analyses de références** et des releases historiques d'APK. Pour toute nouvelle création/refonte d'application Android, appliquer le [workflow REA](https://github.com/dbrckk/repo-standards/blob/feature/app-reference-rea-20261012/skills/app-reference-rea/SKILL.md) : chercher plusieurs applications comparables, obtenir lorsque c'est autorisé une version de provenance traçable, analyser avec [REA](https://github.com/morluto/rea), puis réimplémenter une solution **originale** plus adaptée aux objectifs.

## Contenu et protection des binaires

- `references/catalog.json` : fiches, empreintes SHA-256, versions, canaux et liens vers les rapports. Les entrées historiques sont distinguées des APK nouvellement vérifiés.
- `analysis/` : rapports non propriétaires (fonctionnalités, permissions, architecture observée, preuves et limites).
- `reference-apks/` et `private-evidence/` : **dossiers locaux ignorés par Git**. Conserver les APK et les sorties brutes de REA ici, ou dans un stockage privé autorisé.
- Releases historiques `zombie-apk.1.0.0` et `idle-bank.1.0.0` : présence de fichiers APK constatée, mais **les droits de redistribution ne sont pas attestés par le catalogue**. Ne pas y ajouter d'APK propriétaires sans autorisation de diffusion.

Ce dépôt est **public**. La possibilité d'analyser légalement un binaire ne donne pas automatiquement l'autorisation de le republier. Aucune collecte systématique depuis des miroirs non officiels ; ne pas contourner la distribution du Play Store ou une protection technique.

## Procédure reproductible (une application)

1. Chercher 3 à 5 alternatives et relever les **pages officielles éditeur / store** (fonctionnalités, UX, version, différenciation). Une page Google Play n'est **pas** un lien direct vers un APK.
2. Si l'éditeur fournit un APK public et utilisable légalement : le télécharger depuis l'éditeur, noter l'URL réelle du téléchargement, un SHA-256 publié indépendamment ou un certificat de signature connu. Sinon, renseigner le blocage dans la fiche [modèle](https://github.com/dbrckk/repo-standards/blob/feature/app-reference-rea-20261012/templates/app-reference-intake.md) et utiliser la documentation, les captures autorisées, une alternative libre ou un export de son propre appareil si autorisé.
3. **Téléchargement privé facultatif depuis une URL de l'éditeur réellement vérifiée :** un script accepte uniquement HTTPS avec hôtes de redirection explicitement approuvés et un SHA-256 attendu fourni de manière indépendante. Il refuse les adresses internes, le changement de protocole et un fichier de contenu différent ; il écrit exclusivement dans `reference-apks/` (exclu par Git). La vérification SHA ne confirme pas à elle seule l'identité de l'éditeur.

```sh
python3 scripts/fetch_official_apk.py \
  --url 'https://publisher.example/official.apk' \
  --sha256 '<sha256_publie_par_une_source_fiable>' \
  --slug application-exemple --dry-run
# Retirer --dry-run uniquement lorsque URL, droits, hash et éventuel CDN sont confirmés.
```

4. Contrôler le fichier local téléchargé et l'inscrire au catalogue :

```sh
# Exemple uniquement : source APK fournie réellement par l'éditeur
curl --fail --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --output reference.apk 'https://publisher.example/official.apk'
python3 scripts/reference_intake.py \
  --apk reference.apk --slug application-exemple --name 'Application Exemple' \
  --publisher 'Éditeur vérifié' --package 'org.example.application' \
  --version '1.0' --listing-url 'https://publisher.example/app' \
  --download-url 'https://publisher.example/official.apk' \
  --source-type publisher_direct --expected-sha256 '<sha256 fiable>' \
  --expected-cert-sha256 '<certificat_sha256_editeur>' \
  --store-local
```

Le script vérifie la structure APK, les empreintes annoncées, le package via `aapt` si présent et la signature avec `apksigner` si son empreinte attendue est fournie. **Il ne certifie pas seul qu'un domaine appartient à l'éditeur** et marque toujours cette attribution comme déclarative. Les valeurs d'exemple ne constituent pas des preuves réelles.

5. Pour l'analyse automatisée **si REA, JDK 17+ et JADX headless compatible sont installés** :

```sh
rea doctor --json
python3 scripts/reference_intake.py \
  --apk reference.apk --slug application-exemple --name 'Application Exemple' \
  --publisher 'Éditeur vérifié' --package 'org.example.application' \
  --version '1.0' --listing-url 'https://publisher.example/app' \
  --source-type publisher_direct --store-local --run-rea
```

Les sorties REA restent dans `private-evidence/` ; seules des **synthèses originales**, avec des citations techniques et les limites, vont dans `analysis/<slug>/REPORT.md`.

6. Documenter pour le projet cible : **fonction observée → preuve → principe général → conception propre → amélioration → validation fonctionnelle**. Ne pas copier code désassemblé, assets, noms commerciaux, clés, API privées ni mécanismes de sécurité.

## Vérification rapide

Le workflow [Reference intake smoke](.github/workflows/reference-intake-smoke.yml) exécute un parcours fonctionnel d'ingestion avec un APK de démonstration **original créé en CI**, l'absence d'enregistrement de binaire dans Git et un refus de hash incorrect. Ce contrôle **ne remplace pas** un véritable REA+JADX sur un APK officiel, qui nécessite les outils correspondants et une source légitime.
