# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
# Algorithm: IACR ePrint 2026 (CC BY) — Patent: FR2865054
"""
Stéganographie géométrique par double référent — Système 4 clés
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

4 clés indépendantes :
  Clé A — Mélange du référent  : permutation secrète des 256 formes
  Clé B — Grammaire des blocs  : taille de cellule par bloc (6/12/18/30)
  Clé C — Orientations D4      : 8 transformations diédrales par sous-bloc
  Clé 2 — Formes + couleurs    : sélection dans le référent mélangé

Format de sortie stégano :
  Les 2 premiers caractères encodés = longueur du message (uint16 big-endian)
  puis le message lui-même.

Sécurité : 2^2259 bits (clés standard) — 2^3984 bits (blocs 12×12)
"""

import json, os, secrets, hmac as _hmac, hashlib, struct, math
from typing import List, Dict, Tuple, Optional

def _find_ref(name: str) -> str:
    _dir = os.path.dirname(os.path.abspath(__file__))
    for path in [
        os.path.join(_dir, name),
        os.path.join(_dir, 'data', name),
        os.path.join(os.path.dirname(_dir), 'data', name),
    ]:
        if os.path.exists(path):
            return path
    raise FileNotFoundError(f"{name} introuvable (cherché dans {_dir} et data/)")

# Alphabet d'encodage
ALPHABET = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:!?-'
ALPHA_LEN = len(ALPHABET)

def char_to_num(c: str) -> int:
    u = c.upper()
    return ALPHABET.index(u) if u in ALPHABET else 0

def num_to_char(n: int) -> str:
    n = int(n) % ALPHA_LEN
    return ALPHABET[n]

# ── Chargement ────────────────────────────────────────────────────────────────
def load_referents() -> Tuple[List, List]:
    with open(_find_ref('referent_256.json')) as f: r256 = json.load(f)
    with open(_find_ref('referent_360.json')) as f: r360 = json.load(f)
    return r256, r360

# ── CLÉ A : mélange du référent ───────────────────────────────────────────────
def shuffle_referent(ref: List[Dict], seed: int) -> Tuple[List, List, List]:
    """
    Permutation secrète des formes du référent via PRNG seedé.
    Retourne (ref_mélangé, perm_directe, perm_inverse).
    perm_directe[i] = indice original de la forme à la position i.
    perm_inverse[orig] = nouvelle position de la forme d'indice orig.
    """
    import random as _rng
    rng = _rng.Random(seed)
    indices = list(range(len(ref)))
    rng.shuffle(indices)
    shuffled = [ref[i] for i in indices]
    # inv[orig_pos] = new_pos   (lookup rapide pour le décodage)
    inv = [0]*len(ref)
    for new_pos, orig_pos in enumerate(indices):
        inv[orig_pos] = new_pos
    return shuffled, indices, inv

# ── CLÉ C : orientations diédrales D4 ────────────────────────────────────────
# 0=id, 1=rot90, 2=rot180, 3=rot270, 4=mir-H, 5=mir-V, 6=mir-D1, 7=mir-D2
ORIENTATIONS = [
    lambda r,c,n: (r,   c  ),
    lambda r,c,n: (c,   n-r),
    lambda r,c,n: (n-r, n-c),
    lambda r,c,n: (n-c, r  ),
    lambda r,c,n: (r,   n-c),
    lambda r,c,n: (n-r, c  ),
    lambda r,c,n: (c,   r  ),
    lambda r,c,n: (n-c, n-r),
]

def apply_orientation(positions: List, orient: int, grid_n: int = 5) -> List:
    t = ORIENTATIONS[orient % 8]
    return [t(r, c, grid_n) for r, c in positions]

# ── CLÉ B : tailles valides de blocs ─────────────────────────────────────────
VALID_K = frozenset({1, 2, 3, 5})  # 6×6, 12×12, 18×18, 30×30

def _validate_k(k: int) -> None:
    if k not in VALID_K:
        raise ValueError(f"Taille de bloc k={k} invalide. Valeurs autorisées : {sorted(VALID_K)}")

# ── Zigzag boustrophédon (base 6×6) ──────────────────────────────────────────
def zigzag_blocks(B: int) -> List[Tuple[int,int]]:
    order = []
    for r in range(B):
        cols = range(B-1, -1, -1) if r % 2 == 0 else range(B)
        for c in cols: order.append((r, c))
    return order

# ── Capacité maximale ────────────────────────────────────────────────────────
def max_capacity(key_b: List[int], grid_size: int = 60) -> int:
    """Nombre maximal de caractères encodables (hors header de longueur)."""
    B = grid_size // 6
    order = zigzag_blocks(B)
    n_positions = 0
    pos_i = 0
    for k in key_b:
        if pos_i >= len(order): break
        n_sub = k * k
        available = min(n_sub, len(order) - pos_i)
        n_positions += available * 6
        pos_i += available
    return max(0, n_positions - 2)   # -2 pour le header uint16

# ── Encodeur ─────────────────────────────────────────────────────────────────
def encode(message: str,
           key_a_seed: int,
           key_b: List[int],
           key_c: List[List[int]],
           key_2: List[Dict],
           ref256: List[Dict],
           grid_size: int = 60,
           seed: Optional[int] = None) -> List[List[int]]:
    """
    Encode un message dans une grille NxN.
    Les 2 premiers caractères encodés = longueur du message (uint16, big-endian).
    Lève ValueError si le message dépasse la capacité de la grille.
    """
    for k in key_b:
        _validate_k(k)

    cap = max_capacity(key_b, grid_size)
    msg_upper = message.upper()
    if len(msg_upper) > cap:
        raise ValueError(
            f"Message trop long : {len(msg_upper)} caractères, "
            f"capacité maximale : {cap}")

    N = grid_size
    B = N // 6
    if N % 6 != 0:
        raise ValueError(f"grid_size {N} doit être multiple de 6")

    ref_s, _, _ = shuffle_referent(ref256, key_a_seed)

    # Grille de bruit cryptographiquement aléatoire
    grid = [
        [secrets.randbelow(ALPHA_LEN) for _ in range(N)]
        for _ in range(N)
    ]

    # Préparer le payload : header longueur en base ALPHA_LEN + message
    # 2 positions suffisent : max = 45²-1 = 1934 > capacité max de la grille
    msg_len_val  = len(msg_upper)
    header_nums  = [msg_len_val // ALPHA_LEN, msg_len_val % ALPHA_LEN]
    msg_nums     = header_nums + [char_to_num(c) for c in msg_upper]

    msg_idx = 0
    order   = zigzag_blocks(B)
    pos_i   = 0
    block_i = 0

    while pos_i < len(order) and msg_idx < len(msg_nums) and block_i < len(key_b):
        k       = key_b[block_i]
        fk      = key_2[block_i]
        orients = key_c[block_i]
        form    = ref_s[fk['form_id'] % len(ref_s)]
        base_pos = form[fk.get('color', 'blue')]

        for sub in range(k * k):
            if pos_i >= len(order) or msg_idx >= len(msg_nums): break
            br, bc   = order[pos_i]
            orient   = orients[sub % len(orients)]
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

# ── Décodeur ─────────────────────────────────────────────────────────────────
def decode(grid: List[List[int]],
           key_a_seed: int,
           key_b: List[int],
           key_c: List[List[int]],
           key_2: List[Dict],
           ref256: List[Dict],
           grid_size: int = 60) -> str:
    """
    Décode un message depuis une grille.
    Lève ValueError si le header de longueur est invalide.
    """
    for k in key_b:
        _validate_k(k)

    N = grid_size; B = N // 6
    ref_s, _, _ = shuffle_referent(ref256, key_a_seed)
    nums  = []
    order = zigzag_blocks(B)
    pos_i = 0; block_i = 0

    while pos_i < len(order) and block_i < len(key_b):
        k       = key_b[block_i]
        fk      = key_2[block_i]
        orients = key_c[block_i]
        form    = ref_s[fk['form_id'] % len(ref_s)]
        base_pos = form[fk.get('color', 'blue')]

        for sub in range(k * k):
            if pos_i >= len(order): break
            br, bc   = order[pos_i]
            orient   = orients[sub % len(orients)]
            transformed = apply_orientation(base_pos, orient)
            for (r, c) in transformed:
                gr, gc = br*6+r, bc*6+c
                if 0 <= gr < N and 0 <= gc < N:
                    nums.append(grid[gr][gc])
            pos_i += 1
        block_i += 1

    if len(nums) < 2:
        raise ValueError("Grille trop petite pour contenir un header de longueur")

    # Lire le header de longueur (encodé en base ALPHA_LEN)
    h0, h1 = nums[0] % ALPHA_LEN, nums[1] % ALPHA_LEN
    msg_len = h0 * ALPHA_LEN + h1

    cap = max_capacity(key_b, grid_size)
    if msg_len > cap:
        raise ValueError(
            f"Longueur décodée {msg_len} > capacité {cap} — clé incorrecte ?")

    return ''.join(num_to_char(n) for n in nums[2:2+msg_len])

# ── Générateur de clés ────────────────────────────────────────────────────────
def make_keys(msg_len: int, ref256: List[Dict],
              grid_size: int = 60, block_size: int = 1) -> Tuple:
    """
    Génère des clés cryptographiquement aléatoires (secrets module).
    Lève ValueError si le message dépasse la capacité.
    """
    if block_size not in VALID_K:
        raise ValueError(f"block_size={block_size} invalide. Valeurs : {sorted(VALID_K)}")

    B        = grid_size // 6
    n_blocks = B * B
    key_a    = secrets.randbits(64)
    key_b    = [block_size] * n_blocks
    key_c    = [[secrets.randbelow(8) for _ in range(block_size**2)]
                 for _ in range(n_blocks)]
    key_2    = [{'form_id': secrets.randbelow(len(ref256)),
                  'color':   secrets.choice(['blue', 'orange'])}
                 for _ in range(n_blocks)]

    cap = max_capacity(key_b, grid_size)
    if msg_len > cap:
        raise ValueError(
            f"Message de {msg_len} chars dépasse la capacité {cap} "
            f"(grille {grid_size}×{grid_size}, k={block_size})")

    return key_a, key_b, key_c, key_2

# ── Espace de clés ────────────────────────────────────────────────────────────
def compute_keyspace(key_b: List[int], ref256: List[Dict]) -> Dict:
    n_blocks = len(key_b)
    n_sub    = sum(k**2 for k in key_b)
    bits_A   = math.log2(math.factorial(len(ref256)))
    bits_B   = math.log2(4**n_blocks)
    bits_C   = math.log2(8) * n_sub
    bits_2   = math.log2(len(ref256) * 2) * n_blocks
    total    = bits_A + bits_B + bits_C + bits_2
    return {
        'key_A_bits' : round(bits_A),
        'key_B_bits' : round(bits_B),
        'key_C_bits' : round(bits_C),
        'key_2_bits' : round(bits_2),
        'total_bits' : round(total),
        'vs_aes256'  : round(total - 256),
    }

# ── CSV ───────────────────────────────────────────────────────────────────────
def grid_to_csv(grid: List[List[int]]) -> str:
    return '\n'.join(','.join(str(v) for v in row) for row in grid)

def csv_to_grid(s: str) -> List[List[int]]:
    return [[int(v) for v in row.split(',')]
            for row in s.strip().split('\n')]

# ── Démo ──────────────────────────────────────────────────────────────────────
def demo():
    print("=== STÉGANOGRAPHIE GÉOMÉTRIQUE 4 CLÉS — La Livrée d'Hermès ===\n")
    ref256, ref360 = load_referents()
    print(f"Ref256 : {len(ref256)} formes | Ref360 : {len(ref360)} formes\n")

    message = "ANIBALAMIOTX"
    print(f"Message : '{message}' ({len(message)} caractères)")

    # Test blocs 6×6
    ka, kb, kc, k2 = make_keys(len(message), ref256, grid_size=60, block_size=1)
    grid = encode(message, ka, kb, kc, k2, ref256, grid_size=60)
    decoded = decode(grid, ka, kb, kc, k2, ref256)
    print(f"\n[6×6]   Décodé : '{decoded}' | OK : {decoded == message}")

    # Test blocs 12×12
    ka2, kb2, kc2, k22 = make_keys(len(message), ref256, grid_size=60, block_size=2)
    grid2 = encode(message, ka2, kb2, kc2, k22, ref256, grid_size=60)
    decoded2 = decode(grid2, ka2, kb2, kc2, k22, ref256)
    print(f"[12×12] Décodé : '{decoded2}' | OK : {decoded2 == message}")

    # Test capacité maximale
    cap = max_capacity(kb, 60)
    print(f"\nCapacité max (6×6, 60×60) : {cap} caractères")
    cap2 = max_capacity(kb2, 60)
    print(f"Capacité max (12×12, 60×60) : {cap2} caractères")

    # Test dépassement de capacité
    try:
        encode("A" * (cap + 1), ka, kb, kc, k2, ref256)
        print("ERREUR : dépassement non détecté")
    except ValueError as e:
        print(f"Dépassement détecté : {e} ✓")

    # Test bruit aléatoire (secrets)
    row0 = grid[0][:10]
    print(f"\nBruit grille[0][:10] : {row0} (secrets.randbelow) ✓")

    ks = compute_keyspace(kb2, ref256)
    print(f"\n=== ESPACE DE CLÉS (12×12, 60×60) ===")
    for k, v in ks.items():
        print(f"  {k:<14} : 2^{v}")

    print(f"\nPropriété : sans Clé C → fausse lecture plausible (pas d'erreur)")

if __name__ == '__main__':
    demo()
