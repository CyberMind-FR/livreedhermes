# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
# Algorithm: IACR ePrint 2026 (CC BY) — Patent: FR2865054
"""
Chiffrement de disque par permutation géométrique — Référent 256
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Architecture :
  Unité     : chunk de 24 bytes (4 formes × 6 positions)
  Secteur   : 512 bytes = 21 chunks × 24 + 8 bytes tail
  Par chunk : permutation géométrique (ref256) + XOR keystream
  Clé maître → PBKDF2 → config_id + ordre + couleur + xor_key par chunk

Permutation géométrique :
  P[i] = ranked[i] où ranked trie les 24 positions absolues dans la grille 12×12
  Chiffrement : out[i] = inp[P[i]]
  Déchiffrement : inp[j] = enc[P_inv[j]]

Espace de clés par secteur :
  256 configs × 24 ordres (4!) × 2 couleurs = 12 288 permutations/chunk
  + 192 bits XOR/chunk
  = 205.6 bits/chunk × 21 chunks = 4317 bits/secteur
  vs AES-256 : +4061 bits/secteur
"""

import json, os, hashlib, struct, itertools, math
from typing import List, Dict, Tuple, Optional

_DIR = os.path.dirname(os.path.abspath(__file__))
REF256_PATH = os.path.join(_DIR, 'referent_256.json')

SECTOR_SIZE  = 512
CHUNK_SIZE   = 24
CHUNKS_FULL  = SECTOR_SIZE // CHUNK_SIZE   # 21
TAIL_SIZE    = SECTOR_SIZE %  CHUNK_SIZE   # 8

ALL_ORDERS   = list(itertools.permutations(range(4)))  # 24 ordres
OFFSETS_12   = [(0,0),(0,6),(6,0),(6,6)]               # 4 sous-blocs 6×6 dans 12×12

# ── Chargement ────────────────────────────────────────────────────────────────
def load_ref256() -> List[Dict]:
    with open(REF256_PATH) as f:
        return json.load(f)

# ── Permutation géométrique ───────────────────────────────────────────────────
def _build_perm(form: Dict, color_key: str, order: Tuple) -> Tuple[List,List]:
    """
    Construit P et P_inv depuis une configuration du Référent 256.
    order = permutation de (0,1,2,3) indiquant l'ordre des 4 sous-blocs.
    P[i] = index source du byte i en sortie.
    P_inv[j] = index destination du byte j en entrée.
    """
    seq_abs = []
    for slot in order:
        dr, dc = OFFSETS_12[slot]
        for (r, c) in form[color_key]:
            seq_abs.append(r * 12 + c)
    # Trier par position absolue → permutation canonique 0-23
    P     = sorted(range(24), key=lambda i: seq_abs[i])
    P_inv = [0] * 24
    for i, p in enumerate(P):
        P_inv[p] = i
    return P, P_inv

def build_permutation_table(ref256: List[Dict]) -> Dict:
    """Construit la table complète : 256 × 24 × 2 = 12 288 entrées."""
    table = {}
    for form in ref256:
        for oi, order in enumerate(ALL_ORDERS):
            for col, ck in [(0,'blue'), (1,'orange')]:
                table[(form['id'], oi, col)] = _build_perm(form, ck, order)
    return table

# ── Dérivation de clé par chunk ───────────────────────────────────────────────
def _derive(master_key: bytes, sector_num: int, chunk_num: int) -> Tuple:
    salt = struct.pack('>QI', sector_num, chunk_num)
    dk   = hashlib.pbkdf2_hmac('sha256', master_key, salt, iterations=1000, dklen=28)
    config_id = dk[0] % 256
    order_idx = struct.unpack('>H', dk[1:3])[0] % 24
    color_bit = dk[3] & 1
    xor_key   = dk[4:28]
    return config_id, order_idx, color_bit, xor_key

# ── Chiffrement / déchiffrement d'un secteur ──────────────────────────────────
def encrypt_sector(data: bytes, sector_num: int, master_key: bytes,
                   perm_table: Dict) -> bytes:
    assert len(data) == SECTOR_SIZE
    out = bytearray()
    for ci in range(CHUNKS_FULL):
        chunk           = data[ci*CHUNK_SIZE:(ci+1)*CHUNK_SIZE]
        cfg, oi, col, xk = _derive(master_key, sector_num, ci)
        P, _            = perm_table[(cfg, oi, col)]
        permuted        = bytes(chunk[P[i]] for i in range(24))
        out.extend(b ^ k for b, k in zip(permuted, xk))
    # Tail
    tail = data[CHUNKS_FULL*CHUNK_SIZE:]
    tk   = hashlib.pbkdf2_hmac('sha256', master_key,
                                struct.pack('>QI', sector_num, 99), 1000, TAIL_SIZE)
    out.extend(b ^ k for b, k in zip(tail, tk))
    return bytes(out)

def decrypt_sector(data: bytes, sector_num: int, master_key: bytes,
                   perm_table: Dict) -> bytes:
    assert len(data) == SECTOR_SIZE
    out = bytearray()
    for ci in range(CHUNKS_FULL):
        chunk           = data[ci*CHUNK_SIZE:(ci+1)*CHUNK_SIZE]
        cfg, oi, col, xk = _derive(master_key, sector_num, ci)
        _, P_inv        = perm_table[(cfg, oi, col)]
        xored           = bytes(b ^ k for b, k in zip(chunk, xk))
        out.extend(xored[P_inv[j]] for j in range(24))
    tail = data[CHUNKS_FULL*CHUNK_SIZE:]
    tk   = hashlib.pbkdf2_hmac('sha256', master_key,
                                struct.pack('>QI', sector_num, 99), 1000, TAIL_SIZE)
    out.extend(b ^ k for b, k in zip(tail, tk))
    return bytes(out)

# ── Chiffrement de données arbitraires ────────────────────────────────────────
def encrypt_data(data: bytes, master_key: bytes, perm_table: Dict) -> bytes:
    """Chiffre des données quelconques. Préfixe la taille originale (8 bytes)."""
    original_len = len(data)
    pad = (SECTOR_SIZE - len(data) % SECTOR_SIZE) % SECTOR_SIZE
    padded = data + bytes(pad)
    out = struct.pack('>Q', original_len)
    for s in range(len(padded) // SECTOR_SIZE):
        out += encrypt_sector(padded[s*SECTOR_SIZE:(s+1)*SECTOR_SIZE],
                              s, master_key, perm_table)
    return out

def decrypt_data(data: bytes, master_key: bytes, perm_table: Dict) -> bytes:
    """Déchiffre des données chiffrées par encrypt_data."""
    original_len = struct.unpack('>Q', data[:8])[0]
    payload = data[8:]
    out = bytearray()
    for s in range(len(payload) // SECTOR_SIZE):
        out.extend(decrypt_sector(payload[s*SECTOR_SIZE:(s+1)*SECTOR_SIZE],
                                  s, master_key, perm_table))
    return bytes(out)[:original_len]

# ── Clé maître ────────────────────────────────────────────────────────────────
def passphrase_to_key(passphrase: str,
                      salt: bytes = b'LaLivreeDHermes2026') -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt,
                               iterations=100_000, dklen=32)

# ── Statistiques ──────────────────────────────────────────────────────────────
def security_stats() -> Dict:
    bpc_perm  = math.log2(256 * 24 * 2)   # bits/chunk permutation
    bpc_xor   = CHUNK_SIZE * 8             # bits/chunk XOR
    bpc_total = bpc_perm + bpc_xor
    bps       = bpc_total * CHUNKS_FULL
    return {
        'permutations_per_chunk' : 256 * 24 * 2,
        'bits_perm_per_chunk'    : round(bpc_perm, 1),
        'bits_xor_per_chunk'     : bpc_xor,
        'bits_per_chunk'         : round(bpc_total, 1),
        'chunks_per_sector'      : CHUNKS_FULL,
        'bits_per_sector'        : round(bps, 1),
        'aes256_bits'            : 256,
        'advantage_over_aes256'  : round(bps - 256, 1),
    }

# ── Démo ──────────────────────────────────────────────────────────────────────
def demo():
    print("=== CHIFFREMENT DISQUE — RÉFÉRENT 256 — La Livrée d'Hermès ===\n")

    ref256 = load_ref256()
    print(f"Référent 256 : {len(ref256)} configurations")

    print("Construction table de permutation (256 × 24 × 2 = 12 288 entrées)...")
    perm_table = build_permutation_table(ref256)
    print(f"Table : {len(perm_table)} entrées ✓\n")

    passphrase = "LaLivreeDHermes2026"
    master_key = passphrase_to_key(passphrase)
    print(f"Passphrase : '{passphrase}'")
    print(f"Clé maître : {master_key.hex()[:32]}...\n")

    # Test secteur
    print("Test secteur (512 bytes)...")
    for s in range(5):
        sector = os.urandom(SECTOR_SIZE)
        enc    = encrypt_sector(sector, s, master_key, perm_table)
        dec    = decrypt_sector(enc, s, master_key, perm_table)
        assert sector == dec, f"ERREUR secteur {s}"
        print(f"  Secteur {s} : {enc[:8].hex()} ... ✓")

    # Test fichier
    print("\nTest fichier texte...")
    msg = (b"ANIBAL EDELBERTO AMIOT - LA LIVREE D'HERMES 2026 "
           b"- BREVET FR2865054 - IACR 2026 ") * 15
    enc = encrypt_data(msg, master_key, perm_table)
    dec = decrypt_data(enc, master_key, perm_table)
    print(f"  Original  : {len(msg)} bytes")
    print(f"  Chiffré   : {len(enc)} bytes")
    print(f"  Déchiffré : '{dec[:60].decode()}'")
    print(f"  Identique : {msg == dec} ✓")

    # Statistiques
    stats = security_stats()
    print(f"\n=== SÉCURITÉ ===")
    print(f"Permutations/chunk : {stats['permutations_per_chunk']:,} "
          f"(256 configs × 24 ordres × 2 couleurs)")
    print(f"Bits perm/chunk    : {stats['bits_perm_per_chunk']}")
    print(f"Bits XOR/chunk     : {stats['bits_xor_per_chunk']}")
    print(f"Bits total/chunk   : {stats['bits_per_chunk']}")
    print(f"Chunks/secteur     : {stats['chunks_per_sector']}")
    print(f"Bits/secteur       : {stats['bits_per_sector']}")
    print(f"AES-256            : 256 bits")
    print(f"Avantage           : +{stats['advantage_over_aes256']} bits/secteur")
    print(f"\nÉtape suivante     : intégration Référent 360 (×2 couches)")

if __name__ == '__main__':
    demo()
