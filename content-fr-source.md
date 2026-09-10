# Contenu textuel du site — source FR

Relevé du texte d'interface visible (titres, sous-titres, intros, labels de
boutons, instructions, pied de page), page par page.

**Portée.** Ce document ne couvre pas encore tout le site. Il décrit
l'accueil et le tirage, la création de motifs, l'impression, les fonds
d'écran et le contact. Restent à relever : `galerie-884-patterns-unifies.html`,
`unified-patterns.html`, `lexique.html`, `a-propos.html`, `profil.html`,
`articles.html` et les six articles, `pro.html` et ses pages de retour,
`encodeur.html`, la liseuse `book-viewer/`, les pages de vente du livre
(`fr/livre/`, `en/book/`, `es/libro/`, `th/book/`) et les 64 pages
d'hexagrammes.

**Hors périmètre.** La base des 64 hexagrammes — noms, jugements, images,
commentaires de traits — n'est pas reprise ici : elle vit dans `index.html`
(objets `HEX_KW`, `IMAGE_FR`, `LINE_COMMENT`) et dans
`creation-motifs-yi-king.html` (objet `HEX_FR`).

---

## Page : Accueil / Tirage Yi King (`index.html`, `tirage-livree-hermes.html`)

### En-tête
- Logo (texte alternatif) : « La Livrée d'Hermès »
- Eyebrow (masqué) : « La Livrée d'Hermès »
- Titre : « Tirage — Ordre chronologique des 64 mutations »
- Sous le titre vient directement le texte de la barre du livre (voir
  ci-dessous). L'ancien sous-titre « Trigramme supérieur (poids 32·16·8) /
  trigramme inférieur (poids 4·2·1) — construction du bas vers le haut »
  a été retiré de la page ; la même information subsiste dans la note d'axes
  sous l'échiquier.

### Barre du livre
- « Lire le livre »
- « Langue du livre » (titre du sélecteur de drapeaux)
- Drapeaux disponibles : Français, English, Español, ไทย — titres « 中文 — bientôt », « Русский — bientôt »
- « Télécharger le PDF du livre »
- « Télécharger la traduction du Yi-King »
- « Archive 360 motifs »

### Échiquier / grille
- « Échiquier »
- « 00 → 63 »
- Note d'axes : « Lignes = trigramme **supérieur** (0 à 7, haut en bas) · Colonnes = trigramme **inférieur** (0 à 7, gauche à droite) · N° = ligne×8 + colonne »
- « Tirer aux pièces (6 traits) »

### Légende des traits
- « Traits — symbolique traditionnelle »
- « Yang fixe »
- « Yang mutant — va se briser »
- « Yin fixe »
- « Yin mutant — va se remplir »

### État vide (avant tirage)
- « Cliquez une case de l'échiquier pour consulter un hexagramme, ou tirez aux pièces pour une lecture — avec, le cas échéant, ses traits mutants et l'hexagramme qui en résulte. »

### Détail d'un hexagramme (labels d'interface)
- « ORDRE CHRONOLOGIQUE »
- « n° King Wen (traditionnel) : »
- « Image »
- « Jugement »
- « Supérieur » / « Inférieur »
- « Binôme (retourné) »
- « Opposé (inversé) »
- « Pavage — traits fixes uniquement »
- « Pavage — reproduit sous le départ »
- « Trait mutant — position »
- Positions des trigrammes : « Terre (base) », « Terre (achèvement) », « Homme (base) », « Homme (achèvement) », « Ciel (base) », « Ciel (achèvement) »
- « Copier le lien » / « Copié »

### Section mutation (avant → après)
- « Hexagramme antérieur » / « Hexagramme postérieur »
- « Traits mutants : » … « — ce sont les seuls traits qui basculent entre les deux situations. »
- « Pavage — situation antérieure » / « Pavage — situation postérieure »
- « Ce que devient la situation »

### Pied de page
- « Numérotation chronologique binaire (votre système, p.067) — le nom et le jugement restent ceux du Yi-king traditionnel, à titre de repère. »
- « Pavage : transcription réelle en carré de 144, calculée à partir de vos calques 1-6. Les quatre jeux — **Yang fixe**, **Yin fixe**, **Yang mutant** et **Yin mutant** — sont désormais tous intégrés. »
- « Un tirage effectué est encodé dans l'URL (`?tire=`) — copiez le lien pour le partager ou le retrouver tel quel. »

### Navigation du pied de page
- « Créer un motif »
- « Unified Patterns »
- « Galerie 884 »
- « Fond d'écran »
- « Impression »
- « Contact »
- « À propos »
- « Lexique »
- « Articles »
- « Devenir Partenaire »

### Bloc copyright
- « © 2026 Anibal Edelberto Amiot — Tous droits réservés »
- « Créé en collaboration avec Claude »
- « Hébergé par https://gk2.net – l'internet des créatifs »

---

## Page : Création de motifs (`creation-motifs-yi-king.html`)

L'ancienne adresse `motifs (4).html` n'est plus qu'une redirection vers
cette page, côté HTML et dans `.htaccess`.

### En-tête
- Logo (texte alternatif) : « La Livrée d'Hermès »
- Titre : « Création de motifs »
- Sous-titre : « 60 natures, 6 niveaux de traits, un échiquier d'images à chaque croisement »

### Catégories
Onglets, sans sous-titre : « Bases », « Par 2 », « Par 3 », « Par 4 »,
« Les 60 ». Les sous-titres de comptage qui les accompagnaient
(« 16 images · 4 axes de base » et suivants) ont disparu de la page.

### Textes d'introduction par catégorie
- « Les 60 natures » : « Les 60 natures réunies, toutes catégories confondues. Choisis 2 images, où qu'elles se trouvent : l'image la plus « yang » joue le rôle du Créateur, l'autre celui du Réceptif, et l'échiquier des 64 hexagrammes se construit par correspondance de position — exactement comme dans l'app Tirage. »
- Autres catégories (gabarit) : « Catégorie « {label} » ({sous-titre}) — choisis 2 images. La plus « yang » des deux joue le rôle du Créateur, l'autre celui du Réceptif, et l'échiquier des 64 hexagrammes se construit par correspondance de position, avec les vrais calques de chaque image. »

### Grille de sélection
- « Choisis une première image »
- « Choisis une seconde image »
- « Deux images choisies — résultat ci-dessous »
- Titres de groupe (mode « Les 60 ») : « Bases », « Par 2 », « Par 3 », « Par 4 »
- « Recommencer la sélection »

### Panneau d'attente (combinaison pas encore activée)
- « Échiquier pas encore activé pour cette combinaison »
- « « {motif} » ({catégorie}) attend encore ses calques trait par trait. »

### En-tête de l'échiquier généré
- « {image} — rôle Créateur (yang) »
- « {image} — rôle Réceptif (yin) »
- « 64 croisements · {n} motif(s) visuellement distinct(s) »
- « (égalité de score yang — attribution arbitraire) »
- « {n} motif(s) de cet échiquier apparaissent/apparaît deux fois (couleurs échangées entre le Créateur et le Réceptif) — chaque case concernée le signale et indique l'hexagramme jumeau. »
- « Numérotation ci-dessous : ordre de lecture 1 (haut-gauche) → 64 (bas-droite) — clique une case pour la numérotation King Wen traditionnelle · {n} échiquiers différents possibles au total avec les 60 natures (C(60,2)) »

### Panneau détail d'une case
- « ← Retour à l'échiquier »
- « N° {kw} / 64 — TRADITION KING WEN »
- « Image »
- « Jugement »

### Section paire complémentaire
- « Même motif, couleurs inversées — Créateur et Réceptif échangés »
- « Case complémentaire de cet échiquier — n° {a} + n° {b} = 65 »
- Texte (motif jumeau visuel) : « Ce dessin est rigoureusement le même pour les deux hexagrammes : le Créateur et le Réceptif choisis pour cet échiquier se correspondent par inversion des couleurs, donc chaque motif y figure deux fois — une fois pour chacun des deux hexagrammes qu'il représente. »
- Texte (cases distinctes) : « Sur cet échiquier, chaque case n° N a pour vis-à-vis la case n° (65-N) — les deux extrémités d'un même mélange entre le Créateur et le Réceptif choisis. Ici les deux motifs restent distincts (l'échiquier compte 64 dessins différents), mais leur position les relie toujours l'un à l'autre. »

### Navigation du pied de page
- « Accueil »
- « Tirage »
- « Impression »
- « Unified Patterns »
- « Galerie 884 »
- « Fond d'écran »
- « Contact »
- « À propos »
- « Lexique »
- « Articles »
- « Devenir Partenaire »

### Bloc copyright
- « © 2026 Anibal Edelberto Amiot — Tous droits réservés »
- « Créé en collaboration avec Claude »
- « Hébergé par https://gk2.net – l'internet des créatifs »

---

## Chrome commun (`impression.html`, `fonds-ecran.html`, `contact.html`)

Ces trois pages partagent la même navigation et le même pied de page. Elles
étaient auparavant servies par une coquille unique, `pages.html`, alimentée
par `content.json` ; cette architecture a disparu — `pages.html` n'est plus
qu'une redirection vers `fonds-ecran.html`, et chaque page est aujourd'hui un
fichier HTML autonome.

### Navigation
- « Accueil »
- « Tirage »
- « Créer un motif »
- « Unified Patterns »
- « Galerie 884 »
- « Fond d'écran »
- « Impression »
- « À propos »
- « Lexique »
- « Articles »
- « Devenir Partenaire »
- « Devenir Soutien »

### Pied de page
- « © 2026 Anibal Edelberto Amiot — Tous droits réservés »
- « Créé en collaboration avec Claude »
- « Hébergé par https://gk2.net – l'internet des créatifs »

### Barre du livre (`impression.html`, `fonds-ecran.html`)
- « La Livrée d'Hermès est un livre de philosophie et de mathématiques, disponible en accès libre au lien ci-dessous. Il est centré sur la construction des carrés magiques et leur transcription en tissage Jacquard. »
- « Lire le livre »
- Drapeaux : 🇫🇷 🇬🇧 🇪🇸 🇹🇭 🇨🇳 🇷🇺
- « Télécharger le PDF du livre »
- « Télécharger la traduction du Yi-King »

---

## Page : Impression (`impression.html`)

### En-tête
- Titre du document : « La Livrée d'Hermès — Impression »
- Marque : « La Livrée d'Hermès »
- Titre : « Impression — tirage & calques »
- Sous-titre : « Choisissez une catégorie, effectuez le tirage, téléchargez le calque prêt à découper ou imprimer. »

### Catégories
- « Catégorie I » — « Bases » — « 16 motifs · tirage direct »
- « Catégorie II » — « Comb. par 2 axes » — « 24 motifs · 6 familles × 4 teintes »
- « Catégorie III » — « Comb. par 3 axes »
- « Catégorie IV » — « Comb. par 4 axes » — « 64 motifs · tirage par position »
- « 🎲 Choisir la catégorie au hasard »

---

## Page : Fonds d'écran (`fonds-ecran.html`)

### En-tête
- Titre du document : « La Livrée d'Hermès — Fonds d'écran »
- Marque : « La Livrée d'Hermès »
- Titre : « Fonds d'écran »
- Sous-titre : « Choisissez une catégorie de motifs unifiés, en plein écran, réactifs au son ou en mode méditatif. »

### Instructions
- « Choisis une catégorie de motifs unifiés. Une fois lancé, le pavage occupe l'écran entier et change au rythme du son — le tien (micro) ou un fichier que tu proposes. »
- « Options de modulation, une fois la catégorie choisie : »
- « 🎤 Micro » — « le pavage change au rythme du son ambiant réellement entendu. »
- « 📁 Fichier audio » — « même principe, avec un morceau que tu proposes toi-même. »

---

## Page : Contact (`contact.html`)

### En-tête
- Titre du document : « Contact — Anibal Amiot | Designer textile en Thaïlande »
- Titre : « Contact »
- Sous-titre : « Un projet, une collaboration ou une commande de motifs et tirages textiles »

### Corps
- « Pour toute question, projet de motif sur mesure, tirage textile ou collaboration, écrivez directement par email ou retrouvez Anibal Amiot sur les réseaux sociaux : »
- Adresse : « anibaledel@gmail.com »
- Réseaux : « Instagram », « Telegram », « Facebook » (« Temporairement indisponible »), « LinkedIn », « X », « Discussion sur Reddit »

### Bloc « Anibal Amiot — auteur du projet »
- « Anibal Amiot est le concepteur du projet La Livrée d'Hermès, une recherche originale portant sur la construction géométrique de carrés magiques auto-construits (« carrés solaires ») et leur application au tirage du Yi King. Basé en Thaïlande, il développe également un volet textile lié à cette recherche, en lien avec les acteurs locaux du secteur. »
- « Deux brevets français déposés en 2002 et 2004 (FR2840678, FR2865054), et 63 dessins et modèles déposés le 4 juillet 2019 (n° d'enregistrement 20193057) couvrant les principaux carrés d'ordre 12 — le socle géométrique de La Livrée d'Hermès. »
- Liens : « profil documentaire complet », « fiche Wikidata d'Anibal Edelberto Amiot »
- « Inventeur — brevets déposés : FR2865054 (procédé de composition automatisée d'un motif symbolique — précurseur direct de la méthode de La Livrée d'Hermès), FR2840678 (arme transformable pour arts martiaux). »

### Bloc « Gérald Kerma — webmaster »
- « Gérald Kerma, alias Gandalf, est fondateur de CyberMind et contributeur au noyau Linux, avec plus de trente-cinq ans d'expérience en cybersécurité et systèmes embarqués. Il assure le développement et la maintenance technique du site La Livrée d'Hermès. »
