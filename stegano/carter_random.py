# (c) Anibal Edelberto Amiot 2026 - La Livree d'Hermes
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
"""
carter_random.py  v3 — Encodage Carter avec référents aléatoires 6×6

Architecture :
  - Cellule unique : 6×6 (90÷6=15 blocs par côté, 225 blocs, 25 méta-blocs)
  - 10 référents de 256 formes aléatoires bariolées
  - 4 sens de lecture par forme (directions 0-3)
  - Mode individuel OU méta-concentrique (3×3 → 18×18), dérivé de la clé
  - Lecture concentrique dans les méta-blocs : noyau → anneau → coins

Paramètres dérivés de la clé (transparents pour l'appelant) :
  seed ∈ {10 valeurs}  ×  mode ∈ {2}  → 20 configurations globales, toutes
  inaccessibles sans la clé. Direction et forme sont tirées par bloc dans
  la grammaire (entropie de grammaire, non de configuration globale). Le
  mode méta bascule vers le mode individuel si sa capacité est insuffisante
  pour la clé donnée (CR-1, voir _derive_params).

Module autonome : les référents sont générés dynamiquement depuis la clé
(pas de fichier JSON à charger). Réutilise les primitives déjà auditées de
stegano_lib.py (séparation de clé Carter, chiffrement, flux de symboles
base-44 uniforme) plutôt que d'en dupliquer une version propre à ce fichier.
"""

import hashlib
import random, secrets as _sec
from typing import List, Dict, Tuple, Optional

from stegano_lib import (
    ALPHA_LEN, _encrypt, _decrypt, payload_to_symbols, max_message_for,
    _carter_split, _PURE, _STRUCTURED, _MESSAGE,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
from cryptography.hazmat.primitives import hashes as _hh

# ── Constantes ─────────────────────────────────────────────────────────────────
GRID_SIZE  = 90
CELL_SIZE  = 6
N_SIDE     = GRID_SIZE // CELL_SIZE   # 15 blocs par côté
N_BLOCKS   = N_SIDE * N_SIDE          # 225 blocs
META       = 3                         # méta-bloc = 3×3 blocs = 18×18 pixels
N_META     = N_SIDE // META            # 5 méta-blocs par côté
N_META_TOT = N_META * N_META          # 25 méta-blocs
N_DIR      = 4
N_FORMS    = 256

SEEDS = [42, 137, 999, 271, 1337, 31415, 27182, 61803, 65537, 99991]

# Ordre concentrique dans un méta-bloc 3×3
# Noyau (1) → anneau cardinal (4) → coins (4) = 9 blocs
CONC_ORDER = [
    (1, 1),
    (0, 1), (1, 0), (1, 2), (2, 1),
    (0, 0), (0, 2), (2, 0), (2, 2),
]

# ── Masques de position — distribution uniforme sur [0..ALPHA_LEN-1] ──────────
# Même principe que le fix de valeur appliqué à stegano_lib.encode_carter() :
# masquer chaque symbole rend les cellules message indiscernables du bruit
# même si la géométrie des référents générés dynamiquement produit une
# distribution de positions moins régulière que le Référent 256 fixe.

def _derive_masks(grammar_key: bytes, n: int) -> list:
    """
    Dérive n masques ∈ [0..ALPHA_LEN-1] depuis grammar_key.
    Rejection sampling pour uniformité exacte (pas de biais modulo).
    Chaque appel avec les mêmes arguments produit les mêmes masques.
    """
    masks = []
    state = hashlib.sha256(grammar_key + b'position-masks-v1').digest()
    lim   = (256 // ALPHA_LEN) * ALPHA_LEN   # limite pour rejection sampling
    while len(masks) < n:
        for b in state:
            if b < lim:
                masks.append(b % ALPHA_LEN)
                if len(masks) >= n: break
        state = hashlib.sha256(state).digest()
    return masks[:n]

# ── Génération des référents ────────────────────────────────────────────────────
def _generate_form(rng) -> Optional[Dict]:
    """Génère une forme 6×6 aléatoire bariolée (run ≤ 2 en lecture ligne/col)."""
    n_assign = N_DIR * CELL_SIZE  # 24 positions assignées sur 36
    for _ in range(5000):
        cells = [(r, c) for r in range(CELL_SIZE) for c in range(CELL_SIZE)]
        rng.shuffle(cells)
        grid = {pos: -1 for pos in cells}
        for i, pos in enumerate(cells[:n_assign]):
            grid[pos] = i % N_DIR
        # Contrainte bariolé : pas plus de 2 positions consécutives
        # de la même direction en lecture ligne par ligne
        seq = [grid[(r, c)] for r in range(CELL_SIZE)
               for c in range(CELL_SIZE) if grid[(r, c)] >= 0]
        run, ok = 1, True
        for i in range(1, len(seq)):
            run = run + 1 if seq[i] == seq[i-1] else 1
            if run > 2: ok = False; break
        if ok:
            dirs = {d: [] for d in range(N_DIR)}
            for pos, d in grid.items():
                if d >= 0: dirs[d].append(list(pos))
            return dirs
    return None

def _make_referent(seed: int) -> List[Dict]:
    """Génère 256 formes pour un seed donné."""
    rng = random.Random(seed)
    forms = []
    while len(forms) < N_FORMS:
        f = _generate_form(rng)
        if f is not None:
            forms.append(f)
    return forms

_CACHE: Dict[int, List[Dict]] = {}

def get_referent(seed: int) -> List[Dict]:
    """Retourne le référent (depuis le cache ou régénéré)."""
    if seed not in _CACHE:
        _CACHE[seed] = _make_referent(seed)
    return _CACHE[seed]

# ── Dérivation des paramètres clé ───────────────────────────────────────────────
def _derive_params(grammar_key: bytes) -> Tuple[int, bool]:
    """
    Retourne (seed, meta_mode) depuis grammar_key.
    meta_mode=True  : lecture par méta-blocs 18×18 (concentrique)
    meta_mode=False : lecture bloc à bloc 6×6

    CR-1 (audit G. Kerma, rév. 2) : le mode méta ne tire que 25 rôles
    (variance ~35 %) et peut produire une capacité quasi nulle pour
    certaines clés. Si la capacité méta calculée pour cette clé est
    insuffisante, bascule déterministe vers le mode individuel — le
    basculement est reproductible au décodage car il ne dépend que de la
    clé, jamais d'un tirage séparé.
    """
    km = _HKDF(_hh.SHA256(), 4, salt=b'Carter-params-v3',
               info=b'seed-and-mode').derive(grammar_key)
    seed     = SEEDS[km[0] % len(SEEDS)]
    meta_raw = km[1] < 128   # ~50 % de chances

    if meta_raw:
        ref   = get_referent(seed)
        mg    = _grammar_meta(grammar_key, ref)
        n_msg = sum(1 for x in mg if x['role'] == _MESSAGE)
        cap   = max_message_for(n_msg * META * META * CELL_SIZE)
        # Seuil 60 caractères : le mode individuel garantit toujours plus
        # (225 blocs, variance ~12 %). En dessous, on bascule.
        meta_mode = cap >= 60
    else:
        meta_mode = False

    return seed, meta_mode

# ── Grammaire individuelle ──────────────────────────────────────────────────────
def _grammar_individual(grammar_key: bytes,
                        ref: List[Dict],
                        n_side: int = N_SIDE) -> List[Dict]:
    """n_side² blocs, chacun avec rôle + forme + direction."""
    n_blocks = n_side * n_side
    km = _HKDF(_hh.SHA256(), n_blocks * 3,
               salt=b'Carter-random-v3',
               info=b'grammar-individual').derive(grammar_key)
    return [{
        'role':    _PURE if km[i*3] < 85 else (_STRUCTURED if km[i*3] < 170
                   else _MESSAGE),
        'form_id': (km[i*3+1] * N_FORMS) // 256,
        'dir':     km[i*3+2] % N_DIR,
    } for i in range(n_blocks)]

# ── Grammaire méta-blocs ────────────────────────────────────────────────────────
def _grammar_meta(grammar_key: bytes,
                  ref: List[Dict],
                  n_meta_tot: int = N_META_TOT,
                  n_meta: int = N_META) -> List[Dict]:
    """
    25 méta-blocs (5×5), chacun avec rôle + 9 sous-blocs (forme+direction).
    La lecture au sein d'un méta-bloc suit l'ordre concentrique CONC_ORDER.
    """
    km1 = _HKDF(_hh.SHA256(), n_meta_tot * 2,
                salt=b'Carter-meta-v3', info=b'meta-roles').derive(grammar_key)
    km2 = _HKDF(_hh.SHA256(), n_meta_tot * META * META * 2,
                salt=b'Carter-meta-v3', info=b'block-forms').derive(grammar_key)
    grammar = []
    for mi in range(n_meta_tot):
        role = (_PURE if km1[mi*2] < 85
                else (_STRUCTURED if km1[mi*2] < 170 else _MESSAGE))
        sub = [{
            'form_id': (km2[(mi*9+bi)*2] * N_FORMS) // 256,
            'dir':      km2[(mi*9+bi)*2+1] % N_DIR,
        } for bi in range(META * META)]
        grammar.append({'role': role, 'sub': sub, 'n_meta': n_meta})
    return grammar

# ── Encode ──────────────────────────────────────────────────────────────────────
def encode_carter_random(message: str,
                          master_key: bytes,
                          grid_size: int = GRID_SIZE) -> Tuple[List, Dict]:
    """
    Encode un message dans une grille 90×90.
    Tous les paramètres géométriques sont dérivés de master_key.
    """
    xchacha_key, grammar_key = _carter_split(master_key)
    seed, meta_mode = _derive_params(grammar_key)
    ref = get_referent(seed)
    # Calculs dépendants de grid_size
    n_side_g  = grid_size // CELL_SIZE
    n_meta_g  = n_side_g  // META
    n_meta_tot_g = n_meta_g * n_meta_g

    payload = _encrypt(message, xchacha_key)
    # Flux de symboles base-44 uniformes — même fonction que celle utilisée
    # par encode_carter() dans stegano_lib.py, pas une conversion nibbles
    # [0..15] qui trahirait les cellules message dans un bruit [0..43].
    nibbles = payload_to_symbols(payload)

    grid = [[_sec.randbelow(ALPHA_LEN) for _ in range(grid_size)]
            for _ in range(grid_size)]
    masks = _derive_masks(grammar_key, len(nibbles) + 128)
    nib_i = 0

    if not meta_mode:
        # ── Mode individuel : bloc à bloc ──
        grammar = _grammar_individual(grammar_key, ref, n_side_g)
        n_msg   = sum(1 for g in grammar if g['role'] == _MESSAGE)
        cap     = n_msg * CELL_SIZE
        if len(nibbles) > cap:
            raise ValueError(
                f"Message trop long : {len(message)} caractères > "
                f"{max_message_for(cap)} disponibles (n_msg={n_msg})")
        for i, g in enumerate(grammar):
            if g['role'] != _MESSAGE: continue
            br, bc = i // n_side_g, i % n_side_g
            form   = ref[g['form_id']]
            r0, c0 = br * CELL_SIZE, bc * CELL_SIZE
            for pos in form[g['dir']]:
                if nib_i >= len(nibbles): break
                gr, gc = r0 + pos[0], c0 + pos[1]
                if 0 <= gr < grid_size and 0 <= gc < grid_size:
                    grid[gr][gc] = (nibbles[nib_i] + masks[nib_i]) % ALPHA_LEN
                nib_i += 1
        mode_str  = 'individual'
        n_msg_out = n_msg
        n_pos_total = n_msg * CELL_SIZE

    else:
        # ── Mode méta-concentrique : méta-blocs 18×18 ──
        grammar = _grammar_meta(grammar_key, ref, n_meta_tot_g, n_meta_g)
        n_msg   = sum(1 for g in grammar if g['role'] == _MESSAGE)
        cap     = n_msg * META * META * CELL_SIZE
        if len(nibbles) > cap:
            raise ValueError(
                f"Message trop long : {len(message)} caractères > "
                f"{max_message_for(cap)} disponibles (n_msg_meta={n_msg})")
        for mi, mg in enumerate(grammar):
            if mg['role'] != _MESSAGE: continue
            mr, mc = mi // n_meta_g, mi % n_meta_g
            for ci, (br_off, bc_off) in enumerate(CONC_ORDER):
                sg     = mg['sub'][ci]
                form   = ref[sg['form_id']]
                br, bc = mr * META + br_off, mc * META + bc_off
                r0, c0 = br * CELL_SIZE, bc * CELL_SIZE
                for pos in form[sg['dir']]:
                    if nib_i >= len(nibbles): break
                    gr, gc = r0 + pos[0], c0 + pos[1]
                    if 0 <= gr < grid_size and 0 <= gc < grid_size:
                        grid[gr][gc] = (nibbles[nib_i] + masks[nib_i]) % ALPHA_LEN
                    nib_i += 1
        mode_str  = 'meta'
        n_msg_out = n_msg
        n_pos_total = n_msg * META * META * CELL_SIZE

    return grid, {
        'seed': seed, 'mode': mode_str, 'meta_mode': meta_mode,
        'n_msg_blocks': n_msg_out, 'capacity_chars': max_message_for(n_pos_total),
    }

# ── Decode ──────────────────────────────────────────────────────────────────────
def decode_carter_random(grid: List, master_key: bytes,
                          grid_size: int = GRID_SIZE) -> str:
    """Décode une grille 90×90."""
    xchacha_key, grammar_key = _carter_split(master_key)
    seed, meta_mode = _derive_params(grammar_key)
    ref = get_referent(seed)
    n_side_g  = grid_size // CELL_SIZE
    n_meta_g  = n_side_g  // META
    n_meta_tot_g = n_meta_g * n_meta_g

    masks = _derive_masks(grammar_key, grid_size * grid_size)
    vals, nib_i = [], 0

    if not meta_mode:
        grammar = _grammar_individual(grammar_key, ref, n_side_g)
        for i, g in enumerate(grammar):
            if g['role'] != _MESSAGE: continue
            br, bc = i // n_side_g, i % n_side_g
            form   = ref[g['form_id']]
            r0, c0 = br * CELL_SIZE, bc * CELL_SIZE
            for pos in form[g['dir']]:
                gr, gc = r0 + pos[0], c0 + pos[1]
                if 0 <= gr < grid_size and 0 <= gc < grid_size:
                    vals.append((grid[gr][gc] - masks[nib_i]) % ALPHA_LEN)
                nib_i += 1
    else:
        grammar = _grammar_meta(grammar_key, ref, n_meta_tot_g, n_meta_g)
        for mi, mg in enumerate(grammar):
            if mg['role'] != _MESSAGE: continue
            mr, mc = mi // n_meta_g, mi % n_meta_g
            for ci, (br_off, bc_off) in enumerate(CONC_ORDER):
                sg     = mg['sub'][ci]
                form   = ref[sg['form_id']]
                br, bc = mr * META + br_off, mc * META + bc_off
                r0, c0 = br * CELL_SIZE, bc * CELL_SIZE
                for pos in form[sg['dir']]:
                    gr, gc = r0 + pos[0], c0 + pos[1]
                    if 0 <= gr < grid_size and 0 <= gc < grid_size:
                        vals.append((grid[gr][gc] - masks[nib_i]) % ALPHA_LEN)
                    nib_i += 1

    return _decrypt(vals, xchacha_key)

# ── Utilitaires ─────────────────────────────────────────────────────────────────
def random_fits(message: str, master_key: bytes) -> bool:
    """Vérifie si le message tient dans la grille avec la config dérivée."""
    _, grammar_key = _carter_split(master_key)
    seed, meta_mode = _derive_params(grammar_key)
    ref = get_referent(seed)
    if not meta_mode:
        g     = _grammar_individual(grammar_key, ref)
        n_pos = sum(1 for x in g if x['role'] == _MESSAGE) * CELL_SIZE
    else:
        g     = _grammar_meta(grammar_key, ref)
        n_pos = sum(1 for x in g if x['role'] == _MESSAGE) * META * META * CELL_SIZE
    return len(message) <= max_message_for(n_pos)

def random_capacity(master_key: bytes) -> Dict:
    """Retourne la capacité disponible pour une clé donnée."""
    _, grammar_key = _carter_split(master_key)
    seed, meta_mode = _derive_params(grammar_key)
    ref = get_referent(seed)
    if not meta_mode:
        g    = _grammar_individual(grammar_key, ref)
        mult = CELL_SIZE
    else:
        g    = _grammar_meta(grammar_key, ref)
        mult = META * META * CELL_SIZE
    n_msg = sum(1 for x in g if x['role'] == _MESSAGE)
    n_pur = sum(1 for x in g if x['role'] == _PURE)
    n_str = sum(1 for x in g if x['role'] == _STRUCTURED)
    n_pos = n_msg * mult
    return {
        'seed': seed, 'meta_mode': meta_mode,
        'n_msg': n_msg, 'n_pure': n_pur, 'n_struct': n_str,
        'chars_max': max_message_for(n_pos),
        'geometry': f"cell=6×6 ref_seed={seed} mode={'meta' if meta_mode else 'individual'}",
    }

# ── Aliases Carter Random 360 (grille 180×180) ────────────────────────────────
def encode_carter_random_360(message: str, master_key: bytes) -> Tuple[List, Dict]:
    """Carter Random sur grille 180×180 (4× plus de blocs, capacité ~4×)."""
    return encode_carter_random(message, master_key, grid_size=180)

def decode_carter_random_360(grid: List, master_key: bytes) -> str:
    """Décode une grille Carter Random 180×180."""
    return decode_carter_random(grid, master_key, grid_size=180)
