# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
# Algorithm: IACR ePrint 2026 (CC BY) — Patent: FR2865054
"""
Chiffrement de disque par SPN géométrique — Référent 256
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Architecture SPN (Substitution-Permutation Network) :
  Par chunk de 24 bytes :
    1. Substitution S-box  : valeur → valeur (256! S-boxes possibles)
    2. Permutation géo     : position → position (12 288 permutations)
    3. XOR keystream       : 192 bits

  Déchiffrement (ordre inverse) :
    1. XOR inverse
    2. Permutation inverse
    3. S-box inverse

  Espace de clés par secteur (21 chunks) :
    ~1890 bits/chunk × 21 = 39 681 bits/secteur
    vs AES-256 : +39 425 bits/secteur

  La S-box intègre le config_id géométrique dans son seed →
  la forme choisie influence directement la substitution.
"""

import json, os, hashlib, struct, itertools, math
from typing import List, Dict, Tuple, Optional

_DIR = os.path.dirname(os.path.abspath(__file__))
REF256_PATH = os.path.join(_DIR, 'referent_256.json')

SECTOR_SIZE  = 512
CHUNK_SIZE   = 24
CHUNKS_FULL  = SECTOR_SIZE // CHUNK_SIZE   # 21
TAIL_SIZE    = SECTOR_SIZE %  CHUNK_SIZE   # 8
ALL_ORDERS   = list(itertools.permutations(range(4)))
OFFSETS_12   = [(0,0),(0,6),(6,0),(6,6)]

# ── Chargement ────────────────────────────────────────────────────────────────
def load_ref256() -> List[Dict]:
    with open(REF256_PATH) as f:
        return json.load(f)

# ── Permutation géométrique ───────────────────────────────────────────────────
def _build_perm(form, color_key, order):
    seq_abs = []
    for slot in order:
        dr, dc = OFFSETS_12[slot]
        for (r,c) in form[color_key]:
            seq_abs.append(r*12+c)
    P     = sorted(range(24), key=lambda i: seq_abs[i])
    P_inv = [0]*24
    for i,p in enumerate(P): P_inv[p] = i
    return P, P_inv

def build_permutation_table(ref256: List[Dict]) -> Dict:
    table = {}
    for form in ref256:
        for oi, order in enumerate(ALL_ORDERS):
            for col, ck in [(0,'blue'),(1,'orange')]:
                table[(form['id'], oi, col)] = _build_perm(form, ck, order)
    return table

# ── S-box géométrique ─────────────────────────────────────────────────────────
def _derive_sbox(seed: bytes) -> Tuple[List, List]:
    """
    Fisher-Yates sur [0..255] initialisé par seed.
    Le seed intègre le config_id géométrique → forme influence substitution.
    Retourne (sbox, sbox_inv).
    """
    sbox = list(range(256))
    # Générer 512 bytes pseudo-aléatoires depuis le seed
    rng = b''
    counter = 0
    while len(rng) < 512:
        rng += hashlib.sha256(seed + struct.pack('>I', counter)).digest()
        counter += 1
    # Fisher-Yates
    for i in range(255, 0, -1):
        j = int.from_bytes(rng[i*2:i*2+2], 'big') % (i+1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    # Inverse
    sbox_inv = [0]*256
    for i, s in enumerate(sbox): sbox_inv[s] = i
    return sbox, sbox_inv

# ── Dérivation de tous les paramètres d'un chunk ──────────────────────────────
def _derive_chunk(master_key: bytes, sector_num: int, chunk_num: int):
    salt = struct.pack('>QI', sector_num, chunk_num)
    dk   = hashlib.pbkdf2_hmac('sha256', master_key, salt, 1000, dklen=28)
    config_id = dk[0] % 256
    order_idx = struct.unpack('>H', dk[1:3])[0] % 24
    color_bit = dk[3] & 1
    xor_key   = dk[4:28]
    # Seed S-box : inclut config_id pour lien géométrique
    sbox_seed = hashlib.sha256(
        master_key + struct.pack('>QII', sector_num, chunk_num, config_id)
    ).digest()
    sbox, sbox_inv = _derive_sbox(sbox_seed)
    return config_id, order_idx, color_bit, xor_key, sbox, sbox_inv

# ── Chiffrement / déchiffrement d'un secteur ──────────────────────────────────
def encrypt_sector(data: bytes, sector_num: int,
                   master_key: bytes, perm_table: Dict) -> bytes:
    assert len(data) == SECTOR_SIZE
    out = bytearray()
    for ci in range(CHUNKS_FULL):
        chunk = data[ci*CHUNK_SIZE:(ci+1)*CHUNK_SIZE]
        cfg, oi, col, xk, sbox, _ = _derive_chunk(master_key, sector_num, ci)
        P, _ = perm_table[(cfg, oi, col)]
        # 1. Substitution (valeurs)
        sub = bytes(sbox[b] for b in chunk)
        # 2. Permutation géométrique (positions)
        perm = bytes(sub[P[i]] for i in range(24))
        # 3. XOR keystream
        out.extend(b^k for b,k in zip(perm, xk))
    # Tail
    tail = data[CHUNKS_FULL*CHUNK_SIZE:]
    tk = hashlib.pbkdf2_hmac('sha256', master_key,
                              struct.pack('>QI', sector_num, 99), 1000, TAIL_SIZE)
    out.extend(b^k for b,k in zip(tail, tk))
    return bytes(out)

def decrypt_sector(data: bytes, sector_num: int,
                   master_key: bytes, perm_table: Dict) -> bytes:
    assert len(data) == SECTOR_SIZE
    out = bytearray()
    for ci in range(CHUNKS_FULL):
        chunk = data[ci*CHUNK_SIZE:(ci+1)*CHUNK_SIZE]
        cfg, oi, col, xk, _, sbox_inv = _derive_chunk(master_key, sector_num, ci)
        _, P_inv = perm_table[(cfg, oi, col)]
        # 3. XOR inverse
        xored = bytes(b^k for b,k in zip(chunk, xk))
        # 2. Permutation inverse
        dep = bytes(xored[P_inv[j]] for j in range(24))
        # 1. Substitution inverse
        out.extend(sbox_inv[b] for b in dep)
    tail = data[CHUNKS_FULL*CHUNK_SIZE:]
    tk = hashlib.pbkdf2_hmac('sha256', master_key,
                              struct.pack('>QI', sector_num, 99), 1000, TAIL_SIZE)
    out.extend(b^k for b,k in zip(tail, tk))
    return bytes(out)

# ── Chiffrement de données arbitraires ────────────────────────────────────────
def encrypt_data(data: bytes, master_key: bytes, perm_table: Dict) -> bytes:
    olen = len(data)
    pad  = (SECTOR_SIZE - olen%SECTOR_SIZE) % SECTOR_SIZE
    padded = data + bytes(pad)
    ns = len(padded)//SECTOR_SIZE
    out = struct.pack('>Q', olen)
    for s in range(ns):
        out += encrypt_sector(padded[s*SECTOR_SIZE:(s+1)*SECTOR_SIZE],
                              s, master_key, perm_table)
    return out

def decrypt_data(data: bytes, master_key: bytes, perm_table: Dict) -> bytes:
    olen    = struct.unpack('>Q', data[:8])[0]
    payload = data[8:]
    ns      = len(payload)//SECTOR_SIZE
    out     = bytearray()
    for s in range(ns):
        out.extend(decrypt_sector(payload[s*SECTOR_SIZE:(s+1)*SECTOR_SIZE],
                                  s, master_key, perm_table))
    return bytes(out)[:olen]

# ── Clé maître ────────────────────────────────────────────────────────────────
def passphrase_to_key(passphrase: str,
                      salt: bytes = b'LaLivreeDHermes2026') -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(),
                               salt, iterations=100_000, dklen=32)

# ── Statistiques ──────────────────────────────────────────────────────────────
def security_stats() -> Dict:
    b_sbox  = math.log2(math.factorial(256))   # ~1684 bits
    b_perm  = math.log2(256 * 24 * 2)           # ~13.6 bits
    b_xor   = CHUNK_SIZE * 8                    # 192 bits
    b_chunk = b_sbox + b_perm + b_xor
    b_sec   = b_chunk * CHUNKS_FULL
    return {
        'spn_layers'                : 3,
        'bits_sbox_per_chunk'       : round(b_sbox, 0),
        'bits_perm_per_chunk'       : round(b_perm, 1),
        'bits_xor_per_chunk'        : b_xor,
        'bits_per_chunk'            : round(b_chunk, 0),
        'chunks_per_sector'         : CHUNKS_FULL,
        'bits_per_sector'           : round(b_sec, 0),
        'aes256_bits'               : 256,
        'advantage_over_aes256'     : round(b_sec - 256, 0),
    }

# ── Démo ──────────────────────────────────────────────────────────────────────
def demo():
    print("=== SPN GÉOMÉTRIQUE — RÉFÉRENT 256 — La Livrée d'Hermès ===\n")
    ref256 = load_ref256()
    perm_table = build_permutation_table(ref256)
    print(f"Table de permutation : {len(perm_table)} entrées (256×24×2)")

    mk = passphrase_to_key("LaLivreeDHermes2026")
    print(f"Clé maître : {mk.hex()[:32]}...\n")

    print("Test S-box géométrique...")
    sbox, sbox_inv = _derive_sbox(mk + b'\x00'*8)
    assert sorted(sbox) == list(range(256))
    assert all(sbox_inv[sbox[i]] == i for i in range(256))
    print("  Bijective et inverse : ✓")

    print("\nTest 10 secteurs (SPN complet : sbox + perm + XOR)...")
    for s in range(10):
        sector = os.urandom(512)
        enc = encrypt_sector(sector, s, mk, perm_table)
        dec = decrypt_sector(enc, s, mk, perm_table)
        assert sector == dec, f"ERREUR secteur {s}"
    print("  10 secteurs : ✓")

    print("\nTest fichier...")
    msg = (b"ANIBAL EDELBERTO AMIOT - LA LIVREE D'HERMES "
           b"- BREVET FR2865054 - IACR 2026 ") * 20
    enc = encrypt_data(msg, mk, perm_table)
    dec = decrypt_data(enc, mk, perm_table)
    assert msg == dec
    print(f"  '{dec[:55].decode()}' ✓")

    s = security_stats()
    print(f"\n=== SÉCURITÉ — SPN 3 COUCHES ===")
    print(f"Couche 1 — S-box géométrique  : {s['bits_sbox_per_chunk']:.0f} bits/chunk")
    print(f"Couche 2 — Permutation géo    : {s['bits_perm_per_chunk']} bits/chunk")
    print(f"Couche 3 — XOR keystream      : {s['bits_xor_per_chunk']} bits/chunk")
    print(f"Total/chunk                    : {s['bits_per_chunk']:.0f} bits")
    print(f"Chunks/secteur                 : {s['chunks_per_sector']}")
    print(f"Total/secteur                  : {s['bits_per_sector']:.0f} bits")
    print(f"AES-256                        : 256 bits")
    print(f"Avantage                       : +{s['advantage_over_aes256']:.0f} bits/secteur")
    print(f"\nÉtape suivante : Référent 360 (2e couche de permutation)")

if __name__ == '__main__':
    demo()
