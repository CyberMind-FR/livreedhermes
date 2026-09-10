# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
"""
SecuBox — Protocole de communication sécurisée
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

1. Échange de clés  : X25519 ECDH éphémère + HKDF-SHA256 (info canonique)
2. Forward secrecy  : clé éphémère détruite après derive()
3. Déni plausible   : 2 messages dans 2 zones non-chevauchantes d'une grille
4. Chiffrement      : XChaCha20-Poly1305 (stegano_lib.py)
5. Dissimulation    : géométrie La Livrée d'Hermès

Zones déni plausible (grille 60×60 = 100 blocs 6×6) :
  Zone A (real)   : blocs zigzag 0..49
  Zone B (duress) : blocs zigzag 50..99
  → aucune collision possible entre les deux messages
"""

import os, secrets, struct, hashlib
from typing import Dict, List, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF2
from cryptography.hazmat.primitives import hashes as _hashes2
from argon2.low_level import hash_secret_raw as _argon2_raw, Type as _Argon2Type

def _argon2id_identity(passphrase: str, salt: bytes) -> bytes:
    """Argon2id pour chiffrement des identités (time=3, mem=64MB)."""
    return _argon2_raw(
        secret=passphrase.encode(),
        salt=salt[:16],
        time_cost=3, memory_cost=65536, parallelism=4,
        hash_len=32, type=_Argon2Type.ID)

def _xchacha_enc2(key, pt, aad=b''):
    n=os.urandom(24)
    sk=_HKDF2(_hashes2.SHA256(),32,salt=n[:16],info=b'XChaCha20-HChaCha20-subkey').derive(key)
    ct=ChaCha20Poly1305(sk).encrypt(b'\x00'*4+n[16:],pt,aad or None)
    return n+ct

def _xchacha_dec2(key, data, aad=b''):
    n,ct=data[:24],data[24:]
    sk=_HKDF2(_hashes2.SHA256(),32,salt=n[:16],info=b'XChaCha20-HChaCha20-subkey').derive(key)
    return ChaCha20Poly1305(sk).decrypt(b'\x00'*4+n[16:],ct,aad or None)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from stegano_lib import (
    load_referents, encode, decode, make_keys,
    ALPHA_LEN, zigzag_blocks, apply_orientation,
    _encrypt, _decrypt, payload_to_symbols,
)

# ── Identité long-terme ───────────────────────────────────────────────────────
class Identity:
    def __init__(self, private_bytes: Optional[bytes] = None):
        self._priv = (X25519PrivateKey.from_private_bytes(private_bytes)
                      if private_bytes else X25519PrivateKey.generate())

    @property
    def public_bytes(self) -> bytes:
        return self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def fingerprint(self) -> str:
        return ':'.join(f'{b:02x}'
                        for b in hashlib.sha256(self.public_bytes).digest()[:6])

    def export_private(self, passphrase: str) -> bytes:
        raw   = self._priv.private_bytes(serialization.Encoding.Raw,
                  serialization.PrivateFormat.Raw, serialization.NoEncryption())
        salt  = os.urandom(16)
        key   = _argon2id_identity(passphrase, salt)
        return salt + _xchacha_enc2(key, raw, b'SecuBox-Identity-v2')

    @classmethod
    def from_export(cls, data: bytes, passphrase: str) -> 'Identity':
        salt, enc = data[:16], data[16:]
        key = _argon2id_identity(passphrase, salt)
        raw = _xchacha_dec2(key, enc, b'SecuBox-Identity-v2')
        return cls(raw)


# ── Session ECDH éphémère ─────────────────────────────────────────────────────
class Session:
    """
    Session éphémère X25519 avec forward secrecy.

      sa = Session(ref256)
      sb = Session(ref256)
      ka = sa.derive(sb.public_bytes)   # clé dérivée par Alice
      kb = sb.derive(sa.public_bytes)   # clé dérivée par Bob
      assert ka['steg_key'] == kb['steg_key']
      # Clés éphémères privées détruites — forward secrecy garantie.
    """

    def __init__(self, ref256: List[Dict]):
        self._eph    = X25519PrivateKey.generate()
        self._ref256 = ref256
        self._done   = False

    @property
    def public_bytes(self) -> bytes:
        return self._eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def derive(self, their_public: bytes,
               grid_size: int = 60, block_size: int = 1) -> Dict:
        if self._done:
            raise ValueError("Session consommée. Créer une nouvelle Session().")
        their_pub_obj = X25519PublicKey.from_public_bytes(their_public)
        shared        = self._eph.exchange(their_pub_obj)
        my_pub        = self.public_bytes
        lo, hi        = ((my_pub, their_public) if my_pub < their_public
                         else (their_public, my_pub))
        km = HKDF(hashes.SHA256(), 64, b'SecuBox-Session-v1',
                   lo + hi).derive(shared)
        session_id = hashlib.sha256(shared).hexdigest()[:16]
        del self._eph, shared
        self._done = True
        return _km_to_keys(km, self._ref256, session_id, grid_size, block_size)


def _km_to_keys(km: bytes, ref256: List[Dict], session_id: str,
                grid_size: int = 60, block_size: int = 1) -> Dict:
    B        = grid_size // 6
    n_blocks = B * B
    seed     = km[32:64]
    counter  = [0]

    def prng(n: int) -> int:
        h = hashlib.sha256(seed + struct.pack('>Q', counter[0])).digest()
        counter[0] += 1
        return struct.unpack('>Q', h[:8])[0] % n

    key_b = [block_size] * n_blocks
    key_c = [[prng(8) for _ in range(block_size**2)] for _ in range(n_blocks)]
    key_2 = [{'form_id': prng(len(ref256)),
               'color':   'blue' if prng(2) == 0 else 'orange'}
              for _ in range(n_blocks)]

    return {'steg_key': km[:32], 'key_b': key_b, 'key_c': key_c,
            'key_2': key_2, 'session_id': session_id, 'grid_size': grid_size}


# ── Déni plausible ────────────────────────────────────────────────────────────
def encode_deniable(
    real_message:   str,
    duress_message: str,
    ref256:         List[Dict],
    grid_size:      int = 60,
) -> Tuple[List[List[int]], Dict, Dict]:
    """
    Encode deux messages dans deux zones non-chevauchantes.
    Retourne (grid, real_keys, duress_keys).
    Zone real   : blocs zigzag 0..49
    Zone duress : blocs zigzag 50..99
    """
    N = grid_size; B = N // 6
    n_half = (B * B) // 2
    order  = zigzag_blocks(B)
    grid   = [[secrets.randbelow(ALPHA_LEN) for _ in range(N)]
               for _ in range(N)]

    def gen_keys(n: int) -> Tuple:
        return (
            secrets.token_bytes(32),
            [1] * n,
            [[secrets.randbelow(8)] for _ in range(n)],
            [{'form_id': secrets.randbelow(len(ref256)),
              'color':   secrets.choice(['blue', 'orange'])}
             for _ in range(n)],
        )

    rsk, rkb, rkc, rk2 = gen_keys(n_half)
    dsk, dkb, dkc, dk2 = gen_keys(n_half)

    def place(msg: str, sk, kb, kc, k2, start: int):
        payload = _encrypt(msg, sk)
        # Même flux de symboles base-44 que stegano_lib.encode() : les
        # nibbles [0..15] trahissaient les cellules message dans un bruit
        # couvrant [0..43].
        nibbles = payload_to_symbols(payload)
        ni = 0; blk = 0; pi = start
        while blk < len(kb) and ni < len(nibbles) and pi < len(order):
            br, bc = order[pi]
            fk     = k2[blk]
            form   = ref256[fk['form_id'] % len(ref256)]
            base   = form[fk.get('color', 'blue')]
            for r, c in apply_orientation(base, kc[blk][0]):
                if ni >= len(nibbles): break
                gr, gc = br*6+r, bc*6+c
                if 0 <= gr < N and 0 <= gc < N:
                    grid[gr][gc] = nibbles[ni]; ni += 1
            pi += 1; blk += 1

    place(real_message,   rsk, rkb, rkc, rk2, start=0)
    place(duress_message, dsk, dkb, dkc, dk2, start=n_half)

    real_keys   = {'steg_key': rsk, 'key_b': rkb, 'key_c': rkc,
                   'key_2': rk2,   'zone_start': 0}
    duress_keys = {'steg_key': dsk, 'key_b': dkb, 'key_c': dkc,
                   'key_2': dk2,   'zone_start': n_half}
    return grid, real_keys, duress_keys


def decode_deniable(grid: List[List[int]], keys: Dict,
                    ref256: List[Dict], grid_size: int = 60) -> str:
    """
    Décode un message depuis la zone désignée par keys['zone_start'].
    Clé réelle → message réel. Clé contrainte → faux message.
    """
    N = grid_size; B = N // 6
    order = zigzag_blocks(B)
    sk    = keys['steg_key']
    kb    = keys['key_b']
    kc    = keys['key_c']
    k2    = keys['key_2']
    start = keys.get('zone_start', 0)
    vals  = []
    blk = 0; pi = start
    while blk < len(kb) and pi < len(order):
        br, bc = order[pi]
        fk     = k2[blk]
        form   = ref256[fk['form_id'] % len(ref256)]
        base   = form[fk.get('color', 'blue')]
        for r, c in apply_orientation(base, kc[blk][0]):
            gr, gc = br*6+r, bc*6+c
            if 0 <= gr < N and 0 <= gc < N: vals.append(grid[gr][gc])
        pi += 1; blk += 1
    return _decrypt(vals, sk)


# ── Démo ──────────────────────────────────────────────────────────────────────
def demo():
    print("=== SECUBOX — X25519 + Forward Secrecy + Déni Plausible ===\n")
    ref256, _ = load_referents()

    print("1. IDENTITÉS LONG-TERME\n")
    alice = Identity()
    bob   = Identity()
    print(f"   Alice : {alice.fingerprint()}")
    print(f"   Bob   : {bob.fingerprint()}")

    print("\n2. ÉCHANGE DE CLÉS X25519 (éphémère)\n")
    sa = Session(ref256); sb = Session(ref256)
    pub_sa = sa.public_bytes
    pub_sb = sb.public_bytes
    ka = sa.derive(pub_sb)
    kb = sb.derive(pub_sa)
    print(f"   steg_key identique  : {ka['steg_key'] == kb['steg_key']} ✓")
    print(f"   key_2 identique     : {ka['key_2'] == kb['key_2']} ✓")
    print(f"   session_id          : {ka['session_id']}")

    print("\n3. FORWARD SECRECY\n")
    try:
        sa.derive(pub_sb)
    except ValueError:
        print("   Réutilisation bloquée ✓")

    print("\n4. MESSAGE STÉGANO\n")
    msg = "ANIBALAMIOTX"
    grid = encode(msg, ka['steg_key'], ka['key_b'],
                  ka['key_c'], ka['key_2'], ref256)
    decoded = decode(grid, kb['steg_key'], kb['key_b'],
                     kb['key_c'], kb['key_2'], ref256)
    print(f"   Alice → Bob : '{msg}' → '{decoded}' ✓")

    print("\n5. DÉNI PLAUSIBLE (2 messages, 1 grille 60×60)\n")
    grid_d, rk, dk = encode_deniable(
        "MESSAGE SECRET ANIBAL", "NOTES PERSO TEXTILE", ref256)
    real_out   = decode_deniable(grid_d, rk, ref256)
    duress_out = decode_deniable(grid_d, dk, ref256)
    print(f"   Clé réelle     → '{real_out}' ✓")
    print(f"   Clé contrainte → '{duress_out}' ✓")
    print(f"   Zone A (blocs 0..49)  : message réel")
    print(f"   Zone B (blocs 50..99) : faux message")
    print(f"   Propriété : impossible de prouver lequel est réel sans les deux clés")

    print("\n6. IDENTITÉ EXPORTÉE\n")
    exported  = alice.export_private("passphrase_test")
    alice2    = Identity.from_export(exported, "passphrase_test")
    print(f"   {len(exported)} bytes chiffrés (Argon2id+XChaCha20) ✓")
    print(f"   Restaurée identique : {alice.public_bytes == alice2.public_bytes} ✓")

    print("\n=== ARCHITECTURE SECUBOX ===\n")
    print("  Clés long-terme : X25519 exportées chiffrées")
    print("  Échange         : ECDH éphémère, HKDF info canonique")
    print("  Forward secrecy : clé éphémère détruite après derive()")
    print("  Chiffrement     : XChaCha20-Poly1305 (nonce 24 bytes)")
    print("  Dissimulation   : La Livrée d'Hermès (Ref256+Ref360)")
    print("  Déni plausible  : 2 zones, 0 collision, 1 grille")

if __name__ == '__main__':
    demo()

# ── Mode Carter dans SecuBox ───────────────────────────────────────────────────
# Intégration de la grille Carter dans le protocole SecuBox.
# La steg_key de session devient le master_key de la grammaire Carter.
# Avantage : key_b, key_c, key_2 ne sont plus nécessaires en mode Carter.
# La grammaire est entièrement dérivée de steg_key → moins de surface d'attaque.

def encode_carter_session(message: str, session_keys: Dict,
                           ref256: List[Dict]) -> List[List[int]]:
    """
    Encode un message en mode Carter depuis une session X25519.
    Utilise steg_key comme master_key de la grammaire Carter.

    session_keys : résultat de Session.derive()
    Retourne     : grille 90×90 (liste de listes)
    """
    from stegano_lib import encode_carter
    return encode_carter(message, session_keys['steg_key'], ref256)

def decode_carter_session(grid: List[List[int]], session_keys: Dict,
                           ref256: List[Dict]) -> str:
    """
    Décode une grille Carter depuis les clés de session.
    """
    from stegano_lib import decode_carter
    return decode_carter(grid, session_keys['steg_key'], ref256)

def carter_deniable(
    real_message:   str,
    real_key:       bytes,
    duress_message: str,
    duress_key:     bytes,
    ref256:         List[Dict],
) -> tuple:
    """
    Déni plausible Carter : deux grilles indépendantes avec deux clés.
    Chaque grille est une grille Carter 90×90 autonome.
    Aucun observateur ne peut prouver laquelle est réelle.

    Retourne (grid_real, grid_duress).
    Les deux grilles sont transmises ensemble ou séparément selon le contexte.
    """
    from stegano_lib import encode_carter
    grid_real   = encode_carter(real_message,   real_key,   ref256)
    grid_duress = encode_carter(duress_message, duress_key, ref256)
    return grid_real, grid_duress

def encode_carter_mix_session(message: str, session_keys: Dict,
                                ref256: List[Dict],
                                ref360: Optional[List[Dict]] = None) -> List[List[int]]:
    """
    Encode en mode Carter mixte (Ref256 + Ref360) depuis une session X25519.
    steg_key de session → master_key de la grammaire mixte 180×180.
    """
    from stegano_lib import encode_carter_mix
    return encode_carter_mix(message, session_keys['steg_key'], ref256, ref360)

def decode_carter_mix_session(grid: List[List[int]], session_keys: Dict,
                                ref256: List[Dict],
                                ref360: Optional[List[Dict]] = None) -> str:
    from stegano_lib import decode_carter_mix
    return decode_carter_mix(grid, session_keys['steg_key'], ref256, ref360)
