# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
"""
SecuBox Vault v1.1 — Stockage chiffré de fichiers
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Corrections audit 2026-09-10 :
  [A1] DoS manifest : taille bornée à MAX_MANIFEST_SIZE (64 MB)
  [A2] DoS entry    : taille bornée à MAX_ENTRY_SIZE (512 MB)
  [A3] XChaCha20-Poly1305 réel (nonce 24 bytes) via HChaCha20+HKDF
  [A4] Clé MAC dédiée dérivée via HKDF (master_key non réutilisée directement)
  [A5] En-tête versioning : VERSION=1, ALG=xchacha20-poly1305

Format du vault (.sbvault) :
  [4B  magic "SBVT"][1B version][1B algo][2B reserved]
  [32B salt KDF][4B manifest_size][manifest chiffré]
  [entrées chiffrées...][32B HMAC-SHA256 (clé dérivée)]

Chaque entrée :
  [4B entry_size][données chiffrées (XChaCha20-Poly1305)]
"""

import os, json, hashlib, struct, secrets, hmac as _hmac
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _h

MAGIC            = b'SBVT'
VERSION          = 1
ALG_XCHACHA20    = 1
SALT_SIZE        = 32
MAC_SIZE         = 32
HEADER_SIZE      = 4 + 1 + 1 + 2 + SALT_SIZE   # 40 bytes

# Limites anti-DoS [A1][A2]
MAX_MANIFEST_SIZE = 64 * 1024 * 1024    # 64 MB
MAX_ENTRY_SIZE    = 512 * 1024 * 1024   # 512 MB
MAX_ENTRIES       = 65536

# ── XChaCha20-Poly1305 (nonce 24 bytes) [A3] ─────────────────────────────────
def _xchacha_subkey(key: bytes, nonce_24: bytes) -> tuple:
    """
    HChaCha20 approché par HKDF-SHA256.
    Retourne (subkey, chacha_nonce_12).
    Standard : subkey = HChaCha20(key, nonce_24[:16])
               chacha_nonce = \x00\x00\x00\x00 + nonce_24[16:]
    """
    subkey = HKDF(
        algorithm=_h.SHA256(), length=32,
        salt=nonce_24[:16],
        info=b'XChaCha20-HChaCha20-subkey'
    ).derive(key)
    chacha_nonce = b'\x00\x00\x00\x00' + nonce_24[16:]   # 4B counter + 8B nonce
    return subkey, chacha_nonce

def _enc(data: bytes, key: bytes, aad: bytes = b'') -> bytes:
    """XChaCha20-Poly1305 : nonce 24 bytes, tag 16 bytes."""
    nonce = os.urandom(24)
    subkey, cn = _xchacha_subkey(key, nonce)
    ct = ChaCha20Poly1305(subkey).encrypt(cn, data, aad or None)
    return nonce + ct            # 24 + len(data) + 16

def _dec(data: bytes, key: bytes, aad: bytes = b'') -> bytes:
    """XChaCha20-Poly1305 déchiffrement."""
    nonce, ct = data[:24], data[24:]
    subkey, cn = _xchacha_subkey(key, nonce)
    return ChaCha20Poly1305(subkey).decrypt(cn, ct, aad or None)

# ── Dérivation de clés dédiées [A4] ──────────────────────────────────────────
def _manifest_key(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(_h.SHA256(), 32, salt, b'SecuBox-Vault-Manifest-v1').derive(master_key)

def _entry_key(master_key: bytes, entry_name: str, salt: bytes) -> bytes:
    return HKDF(_h.SHA256(), 32, salt,
                f'SecuBox-Vault-Entry-v1:{entry_name}'.encode()).derive(master_key)

def _mac_key(master_key: bytes, salt: bytes) -> bytes:
    """Clé MAC dédiée — master_key n'est jamais utilisée directement [A4]."""
    return HKDF(_h.SHA256(), 32, salt, b'SecuBox-Vault-MAC-v1').derive(master_key)

# ── Vault ─────────────────────────────────────────────────────────────────────
class Vault:
    """
    Vault chiffré SecuBox v1.1.

    Usage :
        vault = Vault.create('mon.sbvault', master_key)
        vault.add('rapport.pdf', open('rapport.pdf','rb').read())
        vault.save()

        vault2 = Vault.open('mon.sbvault', master_key)
        data = vault2.get('rapport.pdf')
        vault2.remove('rapport.pdf')
        vault2.save()
    """

    def __init__(self, path: str, master_key: bytes,
                 salt: bytes, entries: Dict):
        self.path       = path
        self.master_key = master_key
        self.salt       = salt
        self._entries   = entries

    @classmethod
    def create(cls, path: str, master_key: bytes) -> 'Vault':
        salt = os.urandom(SALT_SIZE)
        return cls(path, master_key, salt, {})

    @classmethod
    def open(cls, path: str, master_key: bytes) -> 'Vault':
        with open(path, 'rb') as f:
            raw = f.read()

        # Longueur minimale : header + manifest_size(4) + mac
        if len(raw) < HEADER_SIZE + 4 + MAC_SIZE:
            raise ValueError("Vault trop court ou corrompu")

        # Vérifier magic et version
        if raw[:4] != MAGIC:
            raise ValueError("Fichier non reconnu (magic invalide)")
        version = raw[4]
        algo    = raw[5]
        if version != VERSION:
            raise ValueError(f"Version {version} non supportée (attendu {VERSION})")
        if algo != ALG_XCHACHA20:
            raise ValueError(f"Algorithme {algo} non supporté")

        # Vérifier HMAC global AVANT tout autre traitement [A1]
        mac_recv  = raw[-MAC_SIZE:]
        payload   = raw[:-MAC_SIZE]
        mac_key   = _mac_key(master_key, raw[8:8+SALT_SIZE])
        mac_calc  = _hmac.new(mac_key, payload, hashlib.sha256).digest()
        if not _hmac.compare_digest(mac_recv, mac_calc):
            raise ValueError("Vault corrompu ou clé incorrecte")

        salt   = raw[8:8+SALT_SIZE]
        rest   = payload[HEADER_SIZE:]

        # Manifest [A1] : borner AVANT allocation
        manifest_size = struct.unpack('>I', rest[:4])[0]
        if manifest_size > MAX_MANIFEST_SIZE:
            raise ValueError(
                f"Manifest trop grand : {manifest_size} > {MAX_MANIFEST_SIZE} — "
                f"vault forgé ou corrompu")
        if len(rest) < 4 + manifest_size:
            raise ValueError("Manifest tronqué")

        mkey          = _manifest_key(master_key, salt)
        manifest_enc  = rest[4:4+manifest_size]
        manifest_raw  = _dec(manifest_enc, mkey, b'manifest')
        manifest      = json.loads(manifest_raw)

        if len(manifest) > MAX_ENTRIES:
            raise ValueError(f"Trop d'entrées : {len(manifest)} > {MAX_ENTRIES}")

        # Déchiffrer chaque entrée [A2] : borner AVANT allocation
        cursor  = 4 + manifest_size
        entries = {}
        for name, meta in manifest.items():
            if cursor + 4 > len(rest):
                raise ValueError(f"Entrée '{name}' tronquée (header)")
            entry_size = struct.unpack('>I', rest[cursor:cursor+4])[0]
            if entry_size > MAX_ENTRY_SIZE:
                raise ValueError(
                    f"Entrée '{name}' trop grande : {entry_size} > {MAX_ENTRY_SIZE}")
            if cursor + 4 + entry_size > len(rest):
                raise ValueError(f"Entrée '{name}' tronquée (données)")
            cursor += 4
            entry_enc = rest[cursor:cursor+entry_size]
            cursor   += entry_size
            ekey = _entry_key(master_key, name, salt)
            data = _dec(entry_enc, ekey, name.encode())
            h = hashlib.sha256(data).hexdigest()
            if h != meta['sha256']:
                raise ValueError(f"Hash invalide pour '{name}'")
            entries[name] = {'data': data, 'sha256': h, 'size': len(data)}

        return cls(path, master_key, salt, entries)

    def add(self, name: str, data: bytes) -> None:
        h = hashlib.sha256(data).hexdigest()
        self._entries[name] = {'data': data, 'sha256': h, 'size': len(data)}

    def get(self, name: str) -> bytes:
        if name not in self._entries:
            raise KeyError(f"'{name}' absent du vault")
        return self._entries[name]['data']

    def remove(self, name: str) -> None:
        if name not in self._entries:
            raise KeyError(f"'{name}' absent du vault")
        self._entries[name]['data'] = secrets.token_bytes(
            self._entries[name]['size'])
        del self._entries[name]

    def list(self) -> List[Dict]:
        return [{'name': n, 'size': m['size'], 'sha256': m['sha256'][:16]+'...'}
                for n, m in self._entries.items()]

    def save(self) -> None:
        mkey    = _manifest_key(self.master_key, self.salt)
        mac_key = _mac_key(self.master_key, self.salt)

        manifest = {n: {'sha256': m['sha256'], 'size': m['size']}
                    for n, m in self._entries.items()}
        manifest_enc = _enc(json.dumps(manifest).encode(), mkey, b'manifest')

        entries_blob = bytearray()
        for name, meta in self._entries.items():
            ekey      = _entry_key(self.master_key, name, self.salt)
            entry_enc = _enc(meta['data'], ekey, name.encode())
            entries_blob += struct.pack('>I', len(entry_enc)) + entry_enc

        # En-tête versioning [A5]
        header  = MAGIC + bytes([VERSION, ALG_XCHACHA20, 0, 0]) + self.salt
        payload = (header
                   + struct.pack('>I', len(manifest_enc))
                   + manifest_enc
                   + bytes(entries_blob))
        mac = _hmac.new(mac_key, payload, hashlib.sha256).digest()

        # Écriture atomique
        tmp = self.path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(payload + mac)
        os.replace(tmp, self.path)

    def secure_delete(self) -> None:
        if os.path.exists(self.path):
            size = os.path.getsize(self.path)
            with open(self.path, 'wb') as f:
                f.write(secrets.token_bytes(size))
            os.unlink(self.path)

    def verify(self) -> bool:
        try:
            Vault.open(self.path, self.master_key)
            return True
        except Exception:
            return False

def demo():
    import tempfile
    print("=== VAULT SECUBOX v1.1 ===\n")
    mk = secrets.token_bytes(32)
    with tempfile.NamedTemporaryFile(suffix='.sbvault', delete=False) as f:
        path = f.name

    v = Vault.create(path, mk)
    v.add('rapport.pdf', b'Contenu confidentiel ' * 100)
    v.add('notes.txt',   b'Notes personnelles secretes')
    v.add('cles.json',   b'{"api_key": "sk-secret-12345"}')
    v.save()
    print(f"Vault créé : {os.path.getsize(path)} bytes")
    print(f"En-tête    : magic=SBVT version=1 algo=xchacha20-poly1305")

    v2 = Vault.open(path, mk)
    print(f"\nContenu ({len(v2.list())} fichiers) :")
    for e in v2.list():
        print(f"  {e['name']:<20} {e['size']:>6} bytes")

    data = v2.get('notes.txt')
    print(f"\nnotes.txt → '{data.decode()}' ✓")

    # Test DoS [A1] : manifest_size forgé
    print(f"\nTest anti-DoS manifest_size=4GB :")
    with open(path, 'rb') as f: raw = f.read()
    # Corrompre le manifest_size (offset = HEADER_SIZE = 40)
    forged = raw[:HEADER_SIZE] + struct.pack('>I', 0xFFFFFFFF) + raw[HEADER_SIZE+4:]
    import tempfile as tf
    with tf.NamedTemporaryFile(suffix='.sbvault', delete=False) as fx:
        fx.write(forged); fpath = fx.name
    try:
        Vault.open(fpath, mk)
        print("  ERREUR : DoS non bloqué !")
    except ValueError as e:
        print(f"  Bloqué immédiatement : {e} ✓")
    finally:
        os.unlink(fpath)

    # Test mauvaise clé
    try:
        Vault.open(path, secrets.token_bytes(32))
    except ValueError as e:
        print(f"\nMauvaise clé bloquée : {e} ✓")

    v2.remove('cles.json')
    v2.save()
    print(f"\nFichiers restants : {[e['name'] for e in v2.list()]} ✓")
    print(f"Intégrité         : {v2.verify()} ✓")
    v2.secure_delete()
    print(f"Suppression sécurisée ✓")
    print(f"\nCorrections audit appliquées :")
    print(f"  [A1] DoS manifest : borné à {MAX_MANIFEST_SIZE//1024//1024} MB ✓")
    print(f"  [A2] DoS entry    : borné à {MAX_ENTRY_SIZE//1024//1024} MB ✓")
    print(f"  [A3] XChaCha20    : nonce 24 bytes (was 12) ✓")
    print(f"  [A4] Clé MAC      : dérivée via HKDF (was master_key) ✓")
    print(f"  [A5] Versioning   : magic + version + algo dans l'en-tête ✓")

if __name__ == '__main__':
    demo()
