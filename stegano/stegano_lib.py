# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
# Algorithm: IACR ePrint 2026 (CC BY) — Patent: FR2865054
"""
Stéganographie géométrique par double référent — Système 4 clés
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Architecture 4 clés indépendantes :
  Clé A — Mélange du référent  : permutation secrète des 256 formes (2^1684 bits)
  Clé B — Grammaire des blocs  : taille de cellule par bloc 6/12/18/30 (2^50 bits)
  Clé C — Orientations          : 8 transformations diédrales par sous-bloc (2^300 bits)
  Clé 2 — Formes + couleurs     : sélection dans le référent mélangé (2^225 bits)
  ─────────────────────────────────────────────────────────────────────────────
  Total                          : 2^2259 bits (vs AES-256 : 2^256 bits)

Propriété distinctive :
  Une Clé C manquante ou erronée produit une fausse lecture plausible,
  pas une erreur détectable. Le bruit structuré est indiscernable d'un
  message valide sans Clé C.
"""

import json, os, random, math, struct, hashlib
from typing import List, Dict, Tuple, Optional

_DIR = os.path.dirname(os.path.abspath(__file__))
REF256_PATH = os.path.join(_DIR, 'referent_256.json')
REF360_PATH = os.path.join(_DIR, 'referent_360.json')

ALPHABET = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:!?-'
def char_to_num(c): return ALPHABET.index(c.upper()) if c.upper() in ALPHABET else 0
def num_to_char(n): return ALPHABET[int(n)] if 0<=int(n)<len(ALPHABET) else '?'

def load_referents():
    with open(REF256_PATH) as f: r256 = json.load(f)
    with open(REF360_PATH) as f: r360 = json.load(f)
    return r256, r360

# ── CLÉ A : mélange du référent ───────────────────────────────────────────────
def shuffle_referent(ref: List[Dict], seed=None) -> Tuple:
    """
    Permutation secrète des formes du référent.
    Retourne (ref_mélangé, indices_permutation, permutation_inverse).
    """
    rng = random.Random(seed)
    indices = list(range(len(ref)))
    rng.shuffle(indices)
    shuffled = [ref[i] for i in indices]
    inv = [0]*len(ref)
    for new_pos, orig_pos in enumerate(indices):
        inv[new_pos] = orig_pos
    return shuffled, indices, inv

# ── CLÉ C : orientations diédrales (D4) ──────────────────────────────────────
# 8 transformations du carré appliquées aux positions (r,c)
# 0=identité, 1=rot90, 2=rot180, 3=rot270
# 4=miroir-H (horizontal), 5=miroir-V (vertical)
# 6=miroir-D1 (diagonale), 7=miroir-D2 (anti-diagonale)
# Correspond aux 4 sens de remplissage (conformes et miroirs) du livre

ORIENTATIONS = [
    lambda r,c,n: (r,   c  ),    # 0 identité
    lambda r,c,n: (c,   n-r),    # 1 rot 90°
    lambda r,c,n: (n-r, n-c),    # 2 rot 180°
    lambda r,c,n: (n-c, r  ),    # 3 rot 270°
    lambda r,c,n: (r,   n-c),    # 4 miroir horizontal
    lambda r,c,n: (n-r, c  ),    # 5 miroir vertical
    lambda r,c,n: (c,   r  ),    # 6 miroir diagonale principale
    lambda r,c,n: (n-c, n-r),    # 7 miroir diagonale secondaire
]

def apply_orientation(positions: List, orient: int, grid_n: int = 5) -> List:
    """
    Applique une des 8 transformations D4 aux positions (r,c).
    grid_n = taille_grille - 1 (pour 6×6 : grid_n=5).
    """
    t = ORIENTATIONS[orient % 8]
    return [t(r, c, grid_n) for r, c in positions]

# ── CLÉ B : grammaire des tailles de blocs ────────────────────────────────────
# k=1 → 6×6 (1 sous-bloc), k=2 → 12×12 (4 sous-blocs)
# k=3 → 18×18 (9 sous-blocs), k=5 → 30×30 (25 sous-blocs)
VALID_K = {1, 2, 3, 5}

# ── Zigzag boustrophédon (base 6×6) ──────────────────────────────────────────
def zigzag_blocks(B: int) -> List:
    order = []
    for r in range(B):
        cols = range(B-1,-1,-1) if r%2==0 else range(B)
        for c in cols: order.append((r,c))
    return order

# ── Encodeur principal ────────────────────────────────────────────────────────
def encode(message: str, key_a_seed, key_b: List[int], key_c: List[List[int]],
           key_2: List[Dict], ref256: List[Dict],
           grid_size: int = 60, value_range: int = 44, seed=None) -> List[List[int]]:
    """
    Encode un message avec les 4 clés indépendantes.

    key_a_seed : graine (int/str/None) pour le mélange du référent
    key_b[i]   : taille k du bloc i (1=6×6, 2=12×12, 3=18×18, 5=30×30)
    key_c[i]   : liste d'orientations (0-7) par sous-bloc 6×6 du bloc i
    key_2[i]   : {'form_id': int, 'color': 'blue'|'orange'}
    """
    if seed is not None: random.seed(seed)
    N = grid_size; B = N // 6
    assert N % 6 == 0, "grid_size doit être multiple de 6"

    ref_s, _, _ = shuffle_referent(ref256, key_a_seed)
    grid = [[random.randint(1, value_range) for _ in range(N)] for _ in range(N)]
    msg_nums = [char_to_num(c) for c in message.upper()]
    msg_idx = 0

    order = zigzag_blocks(B)
    pos_i = 0; block_i = 0

    while pos_i < len(order) and msg_idx < len(msg_nums) and block_i < len(key_b):
        k       = key_b[block_i]
        fk      = key_2[block_i]
        orients = key_c[block_i]
        form    = ref_s[fk['form_id'] % len(ref_s)]
        base_pos = form[fk.get('color','blue')]

        for sub in range(k*k):
            if pos_i >= len(order) or msg_idx >= len(msg_nums): break
            br, bc = order[pos_i]
            orient = orients[sub % len(orients)]
            transformed = apply_orientation(base_pos, orient)
            for (r, c) in transformed:
                if msg_idx >= len(msg_nums): break
                gr, gc = br*6+r, bc*6+c
                if 0 <= gr < N and 0 <= gc < N:
                    grid[gr][gc] = msg_nums[msg_idx]
                    msg_idx += 1
            pos_i += 1
        block_i += 1

    return grid

# ── Décodeur ──────────────────────────────────────────────────────────────────
def decode(grid: List[List[int]], key_a_seed, key_b: List[int],
           key_c: List[List[int]], key_2: List[Dict],
           ref256: List[Dict], grid_size: int = 60) -> str:
    N = grid_size; B = N // 6
    ref_s, _, _ = shuffle_referent(ref256, key_a_seed)
    nums = []
    order = zigzag_blocks(B)
    pos_i = 0; block_i = 0

    while pos_i < len(order) and block_i < len(key_b):
        k       = key_b[block_i]
        fk      = key_2[block_i]
        orients = key_c[block_i]
        form    = ref_s[fk['form_id'] % len(ref_s)]
        base_pos = form[fk.get('color','blue')]

        for sub in range(k*k):
            if pos_i >= len(order): break
            br, bc = order[pos_i]
            orient = orients[sub % len(orients)]
            transformed = apply_orientation(base_pos, orient)
            for (r, c) in transformed:
                gr, gc = br*6+r, bc*6+c
                if 0 <= gr < N and 0 <= gc < N:
                    nums.append(grid[gr][gc])
            pos_i += 1
        block_i += 1

    return ''.join(num_to_char(n) for n in nums)

# ── Générateur de clés ────────────────────────────────────────────────────────
def make_keys(msg_len: int, ref256: List[Dict], grid_size: int = 60,
              block_size: int = 1, seed=None) -> Tuple:
    """
    Génère les 4 clés pour encoder un message.
    block_size : k par défaut (1=6×6, 2=12×12)
    """
    if seed is not None: random.seed(seed)
    B = grid_size // 6; n_blocks = B * B

    key_a_seed = random.randint(0, 2**31)
    key_b = [block_size] * n_blocks
    key_c = [[random.randint(0,7) for _ in range(block_size**2)]
             for _ in range(n_blocks)]
    key_2 = [{'form_id': random.randint(0, len(ref256)-1),
               'color': random.choice(['blue','orange'])}
              for _ in range(n_blocks)]

    return key_a_seed, key_b, key_c, key_2

# ── Espace de clés ────────────────────────────────────────────────────────────
def compute_keyspace(key_b: List[int], ref256: List[Dict]) -> Dict:
    n_blocks = len(key_b)
    n_sub = sum(k**2 for k in key_b)
    bits_A = math.log2(math.factorial(len(ref256)))
    bits_B = math.log2(4**n_blocks)
    bits_C = math.log2(8) * n_sub
    bits_2 = math.log2(len(ref256)*2) * n_blocks
    total  = bits_A + bits_B + bits_C + bits_2
    return {
        'key_A_bits': round(bits_A), 'key_B_bits': round(bits_B),
        'key_C_bits': round(bits_C), 'key_2_bits': round(bits_2),
        'total_bits': round(total),  'vs_aes256': round(total-256),
    }

# ── CSV ───────────────────────────────────────────────────────────────────────
def grid_to_csv(grid): return '\n'.join(','.join(str(v) for v in row) for row in grid)
def csv_to_grid(s): return [[int(v) for v in row.split(',')] for row in s.strip().split('\n')]

# ── Démo ──────────────────────────────────────────────────────────────────────
def demo():
    print("=== STÉGANOGRAPHIE GÉOMÉTRIQUE 4 CLÉS — La Livrée d'Hermès ===\n")
    ref256, ref360 = load_referents()
    print(f"Référent 256 : {len(ref256)} formes | Référent 360 : {len(ref360)} formes\n")

    message = "ANIBALAMIOTX"
    print(f"Message : '{message}' ({len(message)} caractères)")

    # Test 1 : blocs 6×6
    ka, kb, kc, k2 = make_keys(len(message), ref256, grid_size=60, block_size=1, seed=42)
    grid = encode(message, ka, kb, kc, k2, ref256, grid_size=60, seed=42)
    decoded = decode(grid, ka, kb, kc, k2, ref256)[:len(message)]
    print(f"\n[Blocs 6×6]  Décodé : '{decoded}' | Identique : {decoded==message}")

    # Test 2 : blocs 12×12
    ka2, kb2, kc2, k22 = make_keys(len(message), ref256, grid_size=60, block_size=2, seed=99)
    grid2 = encode(message, ka2, kb2, kc2, k22, ref256, grid_size=60, seed=99)
    decoded2 = decode(grid2, ka2, kb2, kc2, k22, ref256)[:len(message)]
    print(f"[Blocs 12×12] Décodé : '{decoded2}' | Identique : {decoded2==message}")

    # Sécurité
    ks = compute_keyspace(kb2, ref256)
    print(f"\n=== ESPACE DE CLÉS (blocs 12×12, grille 60×60) ===")
    print(f"Clé A (mélange référent)  : 2^{ks['key_A_bits']} bits")
    print(f"Clé B (grammaire tailles) : 2^{ks['key_B_bits']} bits")
    print(f"Clé C (orientations D4)   : 2^{ks['key_C_bits']} bits")
    print(f"Clé 2 (formes+couleurs)   : 2^{ks['key_2_bits']} bits")
    print(f"Total                     : 2^{ks['total_bits']} bits")
    print(f"AES-256                   : 2^256 bits")
    print(f"Avantage                  : +2^{ks['vs_aes256']} bits")
    print(f"\nPropriété : sans Clé C → fausse lecture plausible (pas d'erreur détectable)")

if __name__ == '__main__':
    demo()
