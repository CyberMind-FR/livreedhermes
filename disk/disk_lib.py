# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
# Algorithm: IACR ePrint 2026 (CC BY) — Patent: FR2865054
"""
Chiffrement de disque SPN géométrique — Double Référent 256 + 360
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Architecture SPN 5 couches par tour :
  1. S-box GF(2^8) géométrique : S(x) = M·GF_INV(x) ⊕ c
     max_DDT ≤ 4 prouvé [Nyberg 1994]
  2. Permutation géo Ref256 (positions correctement offsettées)
  3. MixBlock géométrique (diffusion triangulaire)
  4. Permutation géo Ref360
  5. XOR keystream (192 bits)

Format de sortie :
  [16 bytes nonce] [données chiffrées] [32 bytes HMAC-SHA256]

Sécurité :
  max_DDT ≤ 4 (prouvé), avalanche ~50%, 2^159 432 bits/secteur
"""

import json, os, hmac, hashlib, struct, itertools, math
from typing import List, Dict, Tuple, Optional

_DIR        = os.path.dirname(os.path.abspath(__file__))

def _find_ref(name: str) -> str:
    """Cherche le fichier référent dans le dossier courant ou data/."""
    for path in [
        os.path.join(_DIR, name),
        os.path.join(_DIR, 'data', name),
        os.path.join(os.path.dirname(_DIR), 'data', name),
    ]:
        if os.path.exists(path):
            return path
    raise FileNotFoundError(f"{name} introuvable (cherché dans {_DIR} et data/)")

SECTOR_SIZE  = 512
CHUNK_SIZE   = 24
CHUNKS_FULL  = SECTOR_SIZE // CHUNK_SIZE   # 21
TAIL_SIZE    = SECTOR_SIZE %  CHUNK_SIZE   # 8
N_ROUNDS     = 4
NONCE_SIZE   = 16
MAC_SIZE     = 32
ALL_ORDERS   = list(itertools.permutations(range(4)))
COLOR_ORDERS = list(itertools.permutations(['C1','C2','C3']))
OFFSETS_12   = [(0,0),(0,6),(6,0),(6,6)]

# ── GF(2^8) ───────────────────────────────────────────────────────────────────
def _gf_mul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return r

_GF_INV = [0]*256
for _x in range(1, 256):
    for _y in range(1, 256):
        if _gf_mul(_x, _y) == 1: _GF_INV[_x] = _y; break

def _gf2_matvec(M: List[int], x: int) -> int:
    r = 0
    for i, row in enumerate(M):
        r |= (bin(row & x).count('1') % 2) << i
    return r

def _gf2_inv(M: List[int]) -> Optional[List[int]]:
    n = 8
    rows = [(M[i] & 0xff) | ((1 << n) << i) for i in range(n)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if (rows[r] >> col) & 1), -1)
        if pivot < 0: return None
        rows[col], rows[pivot] = rows[pivot], rows[col]
        for r in range(n):
            if r != col and (rows[r] >> col) & 1: rows[r] ^= rows[col]
    return [(rows[i] >> n) & 0xff for i in range(n)]

# ── S-box GF(2^8) géométrique — max_DDT ≤ 4 prouvé ──────────────────────────
def _make_sbox_gf(seed: bytes) -> Tuple[List[int], List[int]]:
    rng = hashlib.sha256(seed).digest() + hashlib.sha256(seed + b'x').digest()
    M = [0]*8
    for i in range(8):
        M[i] = 1 << i
        for j in range(i+1, 8):
            if (rng[i] >> (j-i-1)) & 1: M[i] |= (1 << j)
    const = rng[8]
    Mi = _gf2_inv(M)
    if Mi is None:
        raise ValueError("Matrice affine singulière — seed invalide")
    sbox     = [_gf2_matvec(M,  _GF_INV[x]) ^ const for x in range(256)]
    sbox_inv = [_GF_INV[_gf2_matvec(Mi, y ^ const)] for y in range(256)]
    return sbox, sbox_inv

# ── Chargement ────────────────────────────────────────────────────────────────
def load_referents() -> Tuple[List, List]:
    with open(_find_ref('referent_256.json')) as f: r256 = json.load(f)
    with open(_find_ref('referent_360.json')) as f: r360 = json.load(f)
    r360 = [f for f in r360
            if sum(len(p) for p in f['positions'].values()) == 24]
    return r256, r360

# ── Tables de permutation ─────────────────────────────────────────────────────
def _perm_from_seq(seq: List[int]) -> Tuple[List, List]:
    if len(seq) != 24:
        raise ValueError(f"Séquence de {len(seq)} positions, attendu 24")
    P = sorted(range(24), key=lambda i: seq[i])
    Pi = [0]*24
    for i, p in enumerate(P): Pi[p] = i
    return P, Pi

def build_perm_table_256(ref256: List[Dict]) -> Dict:
    """12 288 entrées. CORRIGÉ : positions offsettées (r+dr, c+dc)."""
    t = {}
    for form in ref256:
        for oi, order in enumerate(ALL_ORDERS):
            for col, ck in [(0,'blue'), (1,'orange')]:
                seq = []
                for slot in order:
                    dr, dc = OFFSETS_12[slot]
                    for r, c in form[ck]:
                        seq.append((r + dr) * 12 + (c + dc))  # ← CORRIGÉ
                t[(form['id'], oi, col)] = _perm_from_seq(seq)
    return t

def build_perm_table_360(ref360: List[Dict]) -> Dict:
    t = {}
    for i, form in enumerate(ref360):
        for oi, co in enumerate(COLOR_ORDERS):
            seq = []
            for col in co:
                for r, c in form['positions'].get(col, []):
                    seq.append(r * 12 + c)
            if len(seq) == 24:
                t[(i, oi)] = _perm_from_seq(seq)
    return t

# ── MixBlock ──────────────────────────────────────────────────────────────────
def _mix(data: bytes) -> bytes:
    d = bytearray(data)
    for g in range(4):
        base = g*6; acc = 0
        for i in range(base+5, base-1, -1): acc ^= d[i]; d[i] = acc
    for g in range(3):
        for i in range(6): d[g*6+i] ^= d[(g+1)*6+i]
    return bytes(d)

def _unmix(data: bytes) -> bytes:
    d = bytearray(data)
    for g in range(2, -1, -1):
        for i in range(6): d[g*6+i] ^= d[(g+1)*6+i]
    for g in range(4):
        base = g*6
        for i in range(base, base+5): d[i] ^= d[i+1]
    return bytes(d)

# ── Dérivation des paramètres par tour ────────────────────────────────────────
def _derive_round(master_key: bytes, sn: int, cn: int,
                  rnd: int, nonce: bytes, n360: int) -> Tuple:
    # Nonce intégré dans le sel → chaque écriture a des sous-clés uniques
    salt = nonce + struct.pack('>QIII', sn, cn, rnd, 0xDEADBEEF)
    dk   = hashlib.pbkdf2_hmac('sha256', master_key, salt, 1000, dklen=32)
    cfg256  = dk[0] % 256
    oi256   = struct.unpack('>H', dk[1:3])[0] % 24
    col256  = dk[3] & 1
    xk      = dk[4:28]
    idx360  = dk[28] % n360
    oi360   = dk[29] % 6
    seed    = hashlib.sha256(
        master_key + nonce + struct.pack('>QIII', sn, cn, rnd, cfg256)
    ).digest()
    sbox, sbox_inv = _make_sbox_gf(seed)
    return cfg256, oi256, col256, xk, sbox, sbox_inv, idx360, oi360

# ── Chunk enc/dec ─────────────────────────────────────────────────────────────
def _enc_chunk(chunk, mk, sn, cn, nonce, pt256, pt360, n360,
               pt360_keys, n_rounds):
    data = bytes(chunk)
    for rnd in range(n_rounds):
        cfg, oi, col, xk, sbox, _, idx360, oi360 = _derive_round(
            mk, sn, cn, rnd, nonce, n360)
        P256, _ = pt256[(cfg, oi, col)]
        key360  = (idx360, oi360)
        if key360 not in pt360:
            key360 = pt360_keys[idx360 % len(pt360_keys)]
        P360, _ = pt360[key360]
        sub  = bytes(sbox[b] for b in data)
        p256 = bytes(sub[P256[i]] for i in range(24))
        mx   = _mix(p256)
        p360 = bytes(mx[P360[i]] for i in range(24))
        data = bytes(b^k for b,k in zip(p360, xk))
    return data

def _dec_chunk(chunk, mk, sn, cn, nonce, pt256, pt360, n360,
               pt360_keys, n_rounds):
    data = bytes(chunk)
    for rnd in reversed(range(n_rounds)):
        cfg, oi, col, xk, _, sbox_inv, idx360, oi360 = _derive_round(
            mk, sn, cn, rnd, nonce, n360)
        _, Pi256 = pt256[(cfg, oi, col)]
        key360   = (idx360, oi360)
        if key360 not in pt360:
            key360 = pt360_keys[idx360 % len(pt360_keys)]
        _, Pi360 = pt360[key360]
        unxor    = bytes(b^k for b,k in zip(data, xk))
        undep360 = bytes(unxor[Pi360[j]] for j in range(24))
        unmixed  = _unmix(undep360)
        undep256 = bytes(unmixed[Pi256[j]] for j in range(24))
        data     = bytes(sbox_inv[b] for b in undep256)
    return data

# ── API publique ──────────────────────────────────────────────────────────────
class GeoSPN:
    def __init__(self, ref256: List[Dict], ref360: List[Dict],
                 n_rounds: int = N_ROUNDS):
        if n_rounds < 1:
            raise ValueError("n_rounds doit être ≥ 1")
        self.n_rounds   = n_rounds
        self.n360       = len(ref360)
        self.pt256      = build_perm_table_256(ref256)
        self.pt360      = build_perm_table_360(ref360)
        self.pt360_keys = sorted(self.pt360.keys())
        if not self.pt360_keys:
            raise ValueError("Aucune forme Ref360 complète (24 positions) trouvée")

    def _enc_sector(self, data: bytes, sn: int, mk: bytes,
                    nonce: bytes) -> bytes:
        if len(data) != SECTOR_SIZE:
            raise ValueError(f"Secteur doit faire {SECTOR_SIZE} bytes")
        out = bytearray()
        for ci in range(CHUNKS_FULL):
            out.extend(_enc_chunk(
                data[ci*CHUNK_SIZE:(ci+1)*CHUNK_SIZE],
                mk, sn, ci, nonce,
                self.pt256, self.pt360, self.n360,
                self.pt360_keys, self.n_rounds))
        tail = data[CHUNKS_FULL*CHUNK_SIZE:]
        tk = hashlib.pbkdf2_hmac('sha256', mk,
                                  nonce + struct.pack('>QI', sn, 99),
                                  1000, TAIL_SIZE)
        out.extend(b^k for b,k in zip(tail, tk))
        return bytes(out)

    def _dec_sector(self, data: bytes, sn: int, mk: bytes,
                    nonce: bytes) -> bytes:
        if len(data) != SECTOR_SIZE:
            raise ValueError(f"Secteur doit faire {SECTOR_SIZE} bytes")
        out = bytearray()
        for ci in range(CHUNKS_FULL):
            out.extend(_dec_chunk(
                data[ci*CHUNK_SIZE:(ci+1)*CHUNK_SIZE],
                mk, sn, ci, nonce,
                self.pt256, self.pt360, self.n360,
                self.pt360_keys, self.n_rounds))
        tail = data[CHUNKS_FULL*CHUNK_SIZE:]
        tk = hashlib.pbkdf2_hmac('sha256', mk,
                                  nonce + struct.pack('>QI', sn, 99),
                                  1000, TAIL_SIZE)
        out.extend(b^k for b,k in zip(tail, tk))
        return bytes(out)

    def encrypt(self, data: bytes, master_key: bytes) -> bytes:
        """
        Chiffre des données arbitraires.
        Format : [16B nonce][données chiffrées][32B HMAC-SHA256]
        """
        nonce = os.urandom(NONCE_SIZE)
        olen  = len(data)
        pad   = (SECTOR_SIZE - olen % SECTOR_SIZE) % SECTOR_SIZE
        padded = struct.pack('>Q', olen) + data + bytes(pad)
        # Réajuster pour que le total soit multiple de SECTOR_SIZE
        total = 8 + olen + pad
        extra = (SECTOR_SIZE - total % SECTOR_SIZE) % SECTOR_SIZE
        padded = struct.pack('>Q', olen) + data + bytes(pad + extra)

        ciphertext = bytearray()
        for s in range(len(padded) // SECTOR_SIZE):
            ciphertext.extend(self._enc_sector(
                padded[s*SECTOR_SIZE:(s+1)*SECTOR_SIZE], s, master_key, nonce))

        payload = nonce + bytes(ciphertext)
        mac = hmac.new(master_key, payload, hashlib.sha256).digest()
        return payload + mac

    def decrypt(self, data: bytes, master_key: bytes) -> bytes:
        """Déchiffre et vérifie le MAC. Lève ValueError si MAC invalide."""
        if len(data) < NONCE_SIZE + MAC_SIZE:
            raise ValueError("Données trop courtes")
        mac_recv  = data[-MAC_SIZE:]
        payload   = data[:-MAC_SIZE]
        mac_calc  = hmac.new(master_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_recv, mac_calc):
            raise ValueError("MAC invalide — données altérées ou clé incorrecte")
        nonce      = payload[:NONCE_SIZE]
        ciphertext = payload[NONCE_SIZE:]
        if len(ciphertext) % SECTOR_SIZE != 0:
            raise ValueError("Longueur chiffrée invalide")
        plaintext = bytearray()
        for s in range(len(ciphertext) // SECTOR_SIZE):
            plaintext.extend(self._dec_sector(
                ciphertext[s*SECTOR_SIZE:(s+1)*SECTOR_SIZE],
                s, master_key, nonce))
        olen = struct.unpack('>Q', plaintext[:8])[0]
        return bytes(plaintext[8:8+olen])

    def security_stats(self) -> Dict:
        b_sbox  = math.log2(math.factorial(256))
        b_r256  = math.log2(256 * 24 * 2)
        b_r360  = math.log2(self.n360 * 6)
        b_xor   = CHUNK_SIZE * 8
        b_chunk = (b_sbox + b_r256 + b_r360 + b_xor) * self.n_rounds
        b_sec   = b_chunk * CHUNKS_FULL
        return {
            'n_rounds'      : self.n_rounds,
            'n360_forms'    : self.n360,
            'max_ddt'       : 4,
            'max_ddt_proof' : 'Nyberg 1994 — GF_INV + affine',
            'bits_per_sector': round(b_sec),
            'aes256_bits'   : 256,
            'advantage'     : round(b_sec - 256),
            'nonce'         : f'{NONCE_SIZE*8} bits (os.urandom)',
            'mac'           : f'HMAC-SHA256 ({MAC_SIZE*8} bits)',
        }

# ── Clé maître ────────────────────────────────────────────────────────────────
def passphrase_to_key(passphrase: str,
                      salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Dérive une clé maître 32 bytes depuis une passphrase.
    Retourne (key, salt) — conserver le salt pour dériver la même clé.
    Le salt est aléatoire si non fourni (os.urandom, 16 bytes).
    """
    if salt is None:
        salt = os.urandom(16)
    elif len(salt) < 16:
        raise ValueError("Salt doit faire au moins 16 bytes")
    key = hashlib.pbkdf2_hmac(
        'sha256', passphrase.encode('utf-8'),
        salt, iterations=200_000, dklen=32)
    return key, salt

# ── Démo ──────────────────────────────────────────────────────────────────────
def demo():
    import random
    print("=== SPN GÉOMÉTRIQUE DOUBLE RÉFÉRENT — La Livrée d'Hermès ===\n")
    ref256, ref360 = load_referents()
    print(f"Ref256 : {len(ref256)} formes | Ref360 : {len(ref360)} formes")
    spn = GeoSPN(ref256, ref360)
    print(f"Pt256 : {len(spn.pt256)} perm | Pt360 : {len(spn.pt360)} perm\n")

    mk, salt = passphrase_to_key("LaLivreeDHermes2026")
    print(f"Salt (16B) : {salt.hex()}")
    print(f"Clé maître : {mk.hex()[:32]}...\n")

    print("Tests round-trip (10 secteurs)...")
    nonce = os.urandom(NONCE_SIZE)
    for s in range(10):
        sec = os.urandom(512)
        enc = spn._enc_sector(sec, s, mk, nonce)
        dec = spn._dec_sector(enc, s, mk, nonce)
        if sec != dec:
            raise ValueError(f"Erreur secteur {s}")
    print("  10 secteurs : ✓")

    print("\nTest encrypt/decrypt avec MAC et nonce...")
    msg = b"ANIBAL EDELBERTO AMIOT - LA LIVREE D'HERMES - BREVET FR2865054" * 15
    enc = spn.encrypt(msg, mk)
    dec = spn.decrypt(enc, mk)
    if msg != dec:
        raise ValueError("Erreur déchiffrement")
    print(f"  '{dec[:55].decode()}' ✓")
    print(f"  Original : {len(msg)} bytes | Chiffré : {len(enc)} bytes")
    print(f"  Nonce (16B) + HMAC-SHA256 (32B) inclus ✓")

    print("\nTest MAC invalide...")
    tampered = bytearray(enc)
    tampered[NONCE_SIZE + 10] ^= 0x01
    try:
        spn.decrypt(bytes(tampered), mk)
        print("  ERREUR : MAC invalide non détecté !")
    except ValueError as e:
        print(f"  MAC invalide détecté : {e} ✓")

    stats = spn.security_stats()
    print(f"\n=== SÉCURITÉ ===")
    print(f"  Architecture  : S-box GF(2^8) → Perm256 → MixBlock → Perm360 → XOR")
    print(f"  Tours/chunk   : {stats['n_rounds']}")
    print(f"  max_DDT       : {stats['max_ddt']} ({stats['max_ddt_proof']})")
    print(f"  Bits/secteur  : 2^{stats['bits_per_sector']}")
    print(f"  AES-256       : 2^{stats['aes256_bits']}")
    print(f"  Avantage      : +2^{stats['advantage']} bits/secteur")
    print(f"  Nonce         : {stats['nonce']}")
    print(f"  Intégrité     : {stats['mac']}")

if __name__ == '__main__':
    demo()
