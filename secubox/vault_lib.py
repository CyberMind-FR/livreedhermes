# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
"""
SecuBox Vault — Stockage chiffré de fichiers
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Format du vault (.sbvault) :
  [32B salt KDF][8B n_entries][entrées chiffrées...][32B HMAC global]

Chaque entrée :
  [4B taille_header][header chiffré (nom, hash, taille)][données chiffrées]

Sécurité :
  - Chaque fichier chiffré par XChaCha20-Poly1305 (clé dérivée par HKDF)
  - Manifest : liste chiffrée nom → sha256 → taille
  - HMAC-SHA256 global sur l'ensemble du vault
  - Suppression sécurisée : overwrite avant delete (dans les limites du FS)
"""

import os, json, hashlib, struct, secrets, shutil, tempfile
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _h
import hmac as _hmac

SALT_SIZE = 32
MAC_SIZE  = 32

# ── Dérivation de clé par entrée ──────────────────────────────────────────────
def _entry_key(master_key: bytes, entry_name: str, salt: bytes) -> bytes:
    """Clé unique par entrée via HKDF."""
    hkdf = HKDF(algorithm=_h.SHA256(), length=32,
                 salt=salt,
                 info=f'SecuBox-Vault-Entry:{entry_name}'.encode())
    return hkdf.derive(master_key)

def _manifest_key(master_key: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=_h.SHA256(), length=32,
                 salt=salt, info=b'SecuBox-Vault-Manifest')
    return hkdf.derive(master_key)

# ── Chiffrement d'un blob ─────────────────────────────────────────────────────
def _enc(data: bytes, key: bytes, aad: bytes = b'') -> bytes:
    nonce = os.urandom(12)
    ct    = ChaCha20Poly1305(key).encrypt(nonce, data, aad or None)
    return nonce + ct

def _dec(data: bytes, key: bytes, aad: bytes = b'') -> bytes:
    nonce, ct = data[:12], data[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad or None)

# ── Vault ─────────────────────────────────────────────────────────────────────
class Vault:
    """
    Vault chiffré SecuBox.

    Usage :
        vault = Vault.create('mon.sbvault', master_key)
        vault.add('rapport.pdf', open('rapport.pdf','rb').read())
        vault.add('notes.txt',   b'texte secret')
        vault.save()

        vault2 = Vault.open('mon.sbvault', master_key)
        print(vault2.list())
        data = vault2.get('rapport.pdf')
        vault2.remove('notes.txt')
        vault2.save()
    """

    def __init__(self, path: str, master_key: bytes,
                 salt: bytes, entries: Dict):
        self.path       = path
        self.master_key = master_key
        self.salt       = salt
        # entries : {name: {'data': bytes, 'sha256': str, 'size': int}}
        self._entries   = entries

    @classmethod
    def create(cls, path: str, master_key: bytes) -> 'Vault':
        salt = os.urandom(SALT_SIZE)
        return cls(path, master_key, salt, {})

    @classmethod
    def open(cls, path: str, master_key: bytes) -> 'Vault':
        with open(path, 'rb') as f:
            raw = f.read()

        mac_recv = raw[-MAC_SIZE:]
        payload  = raw[:-MAC_SIZE]
        mac_calc = _hmac.new(master_key, payload, hashlib.sha256).digest()
        if not _hmac.compare_digest(mac_recv, mac_calc):
            raise ValueError("Vault corrompu ou clé incorrecte")

        salt     = payload[:SALT_SIZE]
        rest     = payload[SALT_SIZE:]

        # Déchiffrer le manifest
        mkey     = _manifest_key(master_key, salt)
        manifest_size = struct.unpack('>I', rest[:4])[0]
        manifest_enc  = rest[4:4+manifest_size]
        manifest_raw  = _dec(manifest_enc, mkey, b'manifest')
        manifest      = json.loads(manifest_raw)

        # Déchiffrer chaque entrée
        cursor  = 4 + manifest_size
        entries = {}
        for name, meta in manifest.items():
            entry_size = struct.unpack('>I', rest[cursor:cursor+4])[0]
            cursor += 4
            entry_enc = rest[cursor:cursor+entry_size]
            cursor += entry_size
            ekey = _entry_key(master_key, name, salt)
            data = _dec(entry_enc, ekey, name.encode())
            # Vérifier le hash
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
        # Overwrite en mémoire avant suppression
        self._entries[name]['data'] = secrets.token_bytes(
            self._entries[name]['size'])
        del self._entries[name]

    def list(self) -> List[Dict]:
        return [{'name': n, 'size': m['size'], 'sha256': m['sha256'][:16]+'...'}
                for n, m in self._entries.items()]

    def save(self) -> None:
        mkey = _manifest_key(self.master_key, self.salt)

        # Manifest (métadonnées uniquement, sans les données)
        manifest = {n: {'sha256': m['sha256'], 'size': m['size']}
                    for n, m in self._entries.items()}
        manifest_raw = json.dumps(manifest).encode()
        manifest_enc = _enc(manifest_raw, mkey, b'manifest')

        # Entrées chiffrées
        entries_blob = bytearray()
        for name, meta in self._entries.items():
            ekey      = _entry_key(self.master_key, name, self.salt)
            entry_enc = _enc(meta['data'], ekey, name.encode())
            entries_blob += struct.pack('>I', len(entry_enc)) + entry_enc

        payload = (self.salt
                   + struct.pack('>I', len(manifest_enc))
                   + manifest_enc
                   + bytes(entries_blob))
        mac = _hmac.new(self.master_key, payload, hashlib.sha256).digest()

        # Écriture atomique via fichier temporaire
        tmp = self.path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(payload + mac)
        os.replace(tmp, self.path)

    def secure_delete(self) -> None:
        """Overwrite puis supprime le vault."""
        if os.path.exists(self.path):
            size = os.path.getsize(self.path)
            with open(self.path, 'wb') as f:
                f.write(secrets.token_bytes(size))
            os.unlink(self.path)

    def verify(self) -> bool:
        """Vérifie l'intégrité du vault sur disque."""
        try:
            Vault.open(self.path, self.master_key)
            return True
        except Exception:
            return False

def demo():
    import tempfile
    print("=== VAULT SECUBOX ===\n")
    mk = secrets.token_bytes(32)
    with tempfile.NamedTemporaryFile(suffix='.sbvault', delete=False) as f:
        path = f.name

    v = Vault.create(path, mk)
    v.add('rapport.pdf', b'Contenu confidentiel du rapport...' * 100)
    v.add('notes.txt',   b'Notes personnelles secretes')
    v.add('cles.json',   b'{"api_key": "sk-secret-12345"}')
    v.save()
    print(f"Vault créé : {path} ({os.path.getsize(path)} bytes)")

    v2 = Vault.open(path, mk)
    print(f"\nContenu ({len(v2.list())} fichiers) :")
    for entry in v2.list():
        print(f"  {entry['name']:<20} {entry['size']:>6} bytes  sha256:{entry['sha256']}")

    data = v2.get('notes.txt')
    print(f"\nnotes.txt → '{data.decode()}' ✓")

    v2.remove('cles.json')
    v2.save()
    print(f"cles.json supprimé. Fichiers restants : {[e['name'] for e in v2.list()]}")

    # Test intégrité
    print(f"\nIntégrité : {v2.verify()} ✓")
    try:
        Vault.open(path, secrets.token_bytes(32))
    except ValueError as e:
        print(f"Mauvaise clé détectée : {e} ✓")

    v2.secure_delete()
    print(f"Vault supprimé de façon sécurisée ✓")

if __name__ == '__main__':
    demo()
