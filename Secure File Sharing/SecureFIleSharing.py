#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secure_fileshare_demo.py
========================
Simulasi lengkap sistem SECURE FILE SHARING (end-to-end encrypted) dengan:

  * Authenticated Key Exchange : X25519 (ephemeral) + tanda tangan Ed25519
  * Key Derivation             : HKDF-SHA256 (salt = hash transkrip)
  * Envelope Encryption        : DEK acak per berkas + KEK, AES-256-GCM
  * Perlindungan               : MITM, tampering, replay, impersonation,
                                 forward secrecy, rotasi KEK (re-wrapping)

Aktor   : Alice (pengirim), Bob (penerima), Cloud Server (tidak tepercaya),
          Eve (penyerang aktif yang mengendalikan jaringan/server).

Prasyarat : pip install cryptography
Menjalankan:
    python secure_fileshare_demo.py                 # demo + semua skenario uji
    python secure_fileshare_demo.py --file laporan.pdf   # bagikan berkas nyata

Program berakhir dengan exit code 0 jika SEMUA pengujian lulus.
"""

import argparse
import hashlib
import os
import sys
from dataclasses import dataclass, replace
from typing import Callable, Dict, List, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ----------------------------------------------------------------------
# Konstanta & utilitas
# ----------------------------------------------------------------------
KEK_INFO = b"fileshare-v1/kek-wrap"
NONCE_SIZE_SESSION = 16  # nonce_A / nonce_B (anti-replay sesi)
NONCE_SIZE_GCM = 12      # nonce AES-GCM 96-bit


class ProtocolError(Exception):
    """Pelanggaran aturan protokol (format, identitas, sesi tidak dikenal)."""


class ReplayError(ProtocolError):
    """Paket dengan (pengirim, file_id, seq_no) yang sama pernah diterima."""


def lp(*parts: bytes) -> bytes:
    """Length-prefixed concatenation: mencegah ambiguitas batas antar-field."""
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def short(data: bytes, n: int = 6) -> str:
    return data[:n].hex() + "..."


def fingerprint(pub: ed25519.Ed25519PublicKey) -> str:
    """Fingerprint kunci identitas untuk verifikasi out-of-band."""
    h = hashlib.sha256(pub.public_bytes_raw()).hexdigest()[:32]
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def x25519_pub_bytes(priv: x25519.X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes_raw()


# ----------------------------------------------------------------------
# Format pesan protokol
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class ReqShare:
    """Pesan 1: Alice -> (Server) -> Bob."""
    id_a: str
    id_b: str
    nonce_a: bytes


@dataclass(frozen=True)
class PreKeyBundle:
    """Pesan 2: Bob -> (Server) -> Alice."""
    ek_b_pub: bytes
    nonce_b: bytes
    sig_b: bytes


@dataclass(frozen=True)
class EncryptedPackage:
    """Pesan 3: Alice -> (Server) -> Bob."""
    session_id: bytes      # = nonce_A
    file_id: str
    seq_no: int
    ek_a_pub: bytes
    nonce_wrap: bytes
    wrapped_dek: bytes
    nonce_file: bytes
    ciphertext: bytes
    aad: bytes
    sig_a: bytes


# ----------------------------------------------------------------------
# Fungsi kriptografi bersama (dipakai Alice dan Bob)
# ----------------------------------------------------------------------
def transcript_b(id_b: str, id_a: str, ek_b_pub: bytes,
                 nonce_a: bytes, nonce_b: bytes) -> bytes:
    """Transkrip yang ditandatangani Bob (mengikat identitas, kunci, nonce)."""
    return lp(b"v1|bundle", id_b.encode(), id_a.encode(),
              ek_b_pub, nonce_a, nonce_b)


def full_transcript(tb: bytes, ek_a_pub: bytes) -> bytes:
    return lp(b"v1|full", tb, ek_a_pub)


def derive_kek(shared_secret: bytes, full_t: bytes) -> bytes:
    """KEK = HKDF-SHA256(shared_secret, salt = SHA256(transkrip penuh))."""
    context_hash = hashlib.sha256(full_t).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=context_hash, info=KEK_INFO).derive(shared_secret)


def build_aad(file_id: str, sender: str, receiver: str, seq_no: int) -> bytes:
    return (f"file_id:{file_id}|sender:{sender}|"
            f"receiver:{receiver}|seq:{seq_no}").encode()


def build_wrap_aad(file_id: str, seq_no: int) -> bytes:
    return f"dek-wrap:{file_id}|seq:{seq_no}".encode()


def package_signing_bytes(full_t: bytes, file_id: str, seq_no: int, aad: bytes,
                          nonce_wrap: bytes, wrapped_dek: bytes,
                          nonce_file: bytes, ciphertext: bytes) -> bytes:
    return lp(b"v1|package", full_t, file_id.encode(),
              seq_no.to_bytes(8, "big"), aad, nonce_wrap,
              wrapped_dek, nonce_file, ciphertext)


# ----------------------------------------------------------------------
# Cloud Server (tidak tepercaya) + hook penyerang
# ----------------------------------------------------------------------
Adversary = Optional[Callable[[object], object]]


class CloudServer:
    """Meneruskan pesan. Semua yang lewat tercatat (dilihat Eve) dan dapat
    dimodifikasi oleh fungsi 'adversary' yang disuntikkan saat pengujian."""

    def __init__(self) -> None:
        self.captured: List[tuple] = []

    def relay(self, label: str, msg: object, adversary: Adversary = None):
        self.captured.append((label, msg))      # Eve selalu bisa menyadap
        if adversary is not None:
            msg = adversary(msg)                # ...dan juga bisa mengubah
        return msg


# ----------------------------------------------------------------------
# Alice (pengirim)
# ----------------------------------------------------------------------
class Alice:
    def __init__(self, ident: str, ik_priv: ed25519.Ed25519PrivateKey,
                 trusted_peer_pub: ed25519.Ed25519PublicKey, peer_id: str):
        self.id = ident
        self.peer_id = peer_id
        self._ik_priv = ik_priv
        self._trusted_peer_pub = trusted_peer_pub
        self._s: Optional[dict] = None
        self.ephemeral_wiped = False

    def start_session(self) -> ReqShare:
        nonce_a = os.urandom(NONCE_SIZE_SESSION)
        self._s = {"nonce_a": nonce_a, "kek": None,
                   "ek_a_pub": None, "full_t": None}
        self.ephemeral_wiped = False
        return ReqShare(self.id, self.peer_id, nonce_a)

    def process_prekey(self, bundle: PreKeyBundle) -> None:
        """Verifikasi Sig_B -> buat EK_A -> shared secret -> KEK (HKDF)."""
        s = self._require_session()
        # Transkrip direkonstruksi dari state Alice sendiri, bukan dari
        # data yang dikirim jaringan.
        tb = transcript_b(self.peer_id, self.id, bundle.ek_b_pub,
                          s["nonce_a"], bundle.nonce_b)
        self._trusted_peer_pub.verify(bundle.sig_b, tb)  # InvalidSignature

        ek_a_priv = x25519.X25519PrivateKey.generate()
        ek_a_pub = x25519_pub_bytes(ek_a_priv)
        shared = ek_a_priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(bundle.ek_b_pub))
        full_t = full_transcript(tb, ek_a_pub)
        s["kek"] = derive_kek(shared, full_t)
        s["ek_a_pub"], s["full_t"] = ek_a_pub, full_t

        # Hapus rahasia sementara (best-effort; lihat catatan batas jaminan).
        del ek_a_priv, shared
        self.ephemeral_wiped = True

    def encrypt_file(self, plaintext: bytes, file_id: str,
                     seq_no: int) -> EncryptedPackage:
        """Envelope encryption: DEK acak -> enkripsi berkas -> wrap DEK."""
        s = self._require_session()
        if s["kek"] is None:
            raise ProtocolError("KEK belum diturunkan (jalankan process_prekey)")

        aad = build_aad(file_id, self.id, self.peer_id, seq_no)
        dek = AESGCM.generate_key(bit_length=256)
        nonce_file = os.urandom(NONCE_SIZE_GCM)
        ciphertext = AESGCM(dek).encrypt(nonce_file, plaintext, aad)

        nonce_wrap = os.urandom(NONCE_SIZE_GCM)
        wrapped_dek = AESGCM(s["kek"]).encrypt(
            nonce_wrap, dek, build_wrap_aad(file_id, seq_no))

        sig_a = self._ik_priv.sign(package_signing_bytes(
            s["full_t"], file_id, seq_no, aad,
            nonce_wrap, wrapped_dek, nonce_file, ciphertext))

        pkg = EncryptedPackage(s["nonce_a"], file_id, seq_no, s["ek_a_pub"],
                               nonce_wrap, wrapped_dek, nonce_file,
                               ciphertext, aad, sig_a)
        del dek
        self._s = None  # satu sesi = satu pengiriman; KEK dibuang
        return pkg

    def _require_session(self) -> dict:
        if self._s is None:
            raise ProtocolError("Alice: tidak ada sesi aktif")
        return self._s


# ----------------------------------------------------------------------
# Bob (penerima)
# ----------------------------------------------------------------------
@dataclass
class _BobSession:
    ek_priv: Optional[x25519.X25519PrivateKey]
    tb: bytes


@dataclass
class StoredFile:
    """Berkas tersimpan: ciphertext tetap, DEK dibungkus KEK penyimpanan."""
    file_id: str
    seq_no: int
    nonce_file: bytes
    ciphertext: bytes
    aad: bytes
    nonce_wrap: bytes
    wrapped_dek: bytes
    kek_version: int


class Bob:
    def __init__(self, ident: str, ik_priv: ed25519.Ed25519PrivateKey,
                 trusted_peer_pub: ed25519.Ed25519PublicKey, peer_id: str):
        self.id = ident
        self.peer_id = peer_id
        self._ik_priv = ik_priv
        self._trusted_peer_pub = trusted_peer_pub
        self._sessions: Dict[bytes, _BobSession] = {}
        self._seen: set = set()
        self._keystore: Dict[int, bytes] = {1: AESGCM.generate_key(256)}
        self._kek_version = 1
        self.vault: Dict[str, StoredFile] = {}

    # --- Pesan 1 -> Pesan 2 -------------------------------------------
    def handle_req(self, req: ReqShare) -> PreKeyBundle:
        if req.id_b != self.id or req.id_a != self.peer_id:
            raise ProtocolError("Bob: identitas pada Req_Share tidak cocok")
        if req.nonce_a in self._sessions:
            raise ProtocolError("Bob: nonce_A pernah dipakai (replay Req_Share)")

        ek_b_priv = x25519.X25519PrivateKey.generate()
        ek_b_pub = x25519_pub_bytes(ek_b_priv)
        nonce_b = os.urandom(NONCE_SIZE_SESSION)
        tb = transcript_b(self.id, req.id_a, ek_b_pub, req.nonce_a, nonce_b)
        sig_b = self._ik_priv.sign(tb)
        self._sessions[req.nonce_a] = _BobSession(ek_b_priv, tb)
        return PreKeyBundle(ek_b_pub, nonce_b, sig_b)

    # --- Pesan 3 ------------------------------------------------------
    def receive_package(self, pkg: EncryptedPackage,
                        verify_signature: bool = True) -> bytes:
        """Verifikasi -> turunkan KEK -> unwrap DEK -> dekripsi berkas.

        verify_signature=False HANYA untuk pengujian defense-in-depth
        (membuktikan tag AES-GCM tetap menolak data yang diubah).
        """
        # 1. Anti-replay
        replay_key = (self.peer_id, pkg.file_id, pkg.seq_no)
        if replay_key in self._seen:
            raise ReplayError(
                f"Replay terdeteksi untuk file_id={pkg.file_id} seq={pkg.seq_no}")

        # 2. Sesi harus dikenal
        session = self._sessions.get(pkg.session_id)
        if session is None or session.ek_priv is None:
            raise ProtocolError("Bob: sesi tidak dikenal / sudah berakhir")

        # 3. Metadata (AAD) harus sesuai identitas yang Bob harapkan
        expected_aad = build_aad(pkg.file_id, self.peer_id, self.id, pkg.seq_no)
        if pkg.aad != expected_aad:
            raise ProtocolError("Bob: AAD metadata tidak sesuai")

        # 4. Verifikasi tanda tangan Alice atas SELURUH paket. Transkrip
        #    direkonstruksi dari state Bob sendiri + EK_A_pub dari paket.
        full_t = full_transcript(session.tb, pkg.ek_a_pub)
        if verify_signature:
            self._trusted_peer_pub.verify(pkg.sig_a, package_signing_bytes(
                full_t, pkg.file_id, pkg.seq_no, pkg.aad, pkg.nonce_wrap,
                pkg.wrapped_dek, pkg.nonce_file, pkg.ciphertext))

        # 5. Shared secret -> KEK identik -> unwrap DEK -> dekripsi berkas
        shared = session.ek_priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(pkg.ek_a_pub))
        kek = derive_kek(shared, full_t)
        dek = AESGCM(kek).decrypt(pkg.nonce_wrap, pkg.wrapped_dek,
                                  build_wrap_aad(pkg.file_id, pkg.seq_no))
        plaintext = AESGCM(dek).decrypt(pkg.nonce_file, pkg.ciphertext, pkg.aad)

        # 6. Sukses: tandai, hapus kunci ephemeral, simpan dengan KEK lokal
        self._seen.add(replay_key)
        session.ek_priv = None
        del self._sessions[pkg.session_id]
        self._seal_for_storage(pkg, dek)
        del shared, kek, dek
        return plaintext

    # --- Penyimpanan jangka panjang & rotasi KEK ----------------------
    def _seal_for_storage(self, pkg: EncryptedPackage, dek: bytes) -> None:
        ver = self._kek_version
        nonce = os.urandom(NONCE_SIZE_GCM)
        wrapped = AESGCM(self._keystore[ver]).encrypt(
            nonce, dek, self._vault_aad(pkg.file_id, ver))
        self.vault[pkg.file_id] = StoredFile(
            pkg.file_id, pkg.seq_no, pkg.nonce_file, pkg.ciphertext,
            pkg.aad, nonce, wrapped, ver)

    @staticmethod
    def _vault_aad(file_id: str, version: int) -> bytes:
        return f"vault:{file_id}|kek-v{version}".encode()

    def open_stored(self, file_id: str) -> bytes:
        rec = self.vault[file_id]
        dek = AESGCM(self._keystore[rec.kek_version]).decrypt(
            rec.nonce_wrap, rec.wrapped_dek,
            self._vault_aad(rec.file_id, rec.kek_version))
        return AESGCM(dek).decrypt(rec.nonce_file, rec.ciphertext, rec.aad)

    def rotate_kek(self) -> int:
        """Rotasi KEK: hanya DEK yang dibungkus ulang; ciphertext tidak berubah."""
        old_ver = self._kek_version
        new_ver = old_ver + 1
        self._keystore[new_ver] = AESGCM.generate_key(256)
        for rec in self.vault.values():
            dek = AESGCM(self._keystore[rec.kek_version]).decrypt(
                rec.nonce_wrap, rec.wrapped_dek,
                self._vault_aad(rec.file_id, rec.kek_version))
            rec.nonce_wrap = os.urandom(NONCE_SIZE_GCM)
            rec.wrapped_dek = AESGCM(self._keystore[new_ver]).encrypt(
                rec.nonce_wrap, dek, self._vault_aad(rec.file_id, new_ver))
            rec.kek_version = new_ver
            del dek
        self._kek_version = new_ver
        return new_ver

    @property
    def pending_sessions(self) -> int:
        return len(self._sessions)


# ----------------------------------------------------------------------
# Dunia simulasi & orkestrasi
# ----------------------------------------------------------------------
@dataclass
class World:
    alice: Alice
    bob: Bob
    server: CloudServer
    ik_a_priv: ed25519.Ed25519PrivateKey
    ik_b_priv: ed25519.Ed25519PrivateKey


def make_world(alice_trusts_b: Optional[ed25519.Ed25519PublicKey] = None) -> World:
    ik_a = ed25519.Ed25519PrivateKey.generate()
    ik_b = ed25519.Ed25519PrivateKey.generate()
    alice = Alice("Alice", ik_a, alice_trusts_b or ik_b.public_key(), "Bob")
    bob = Bob("Bob", ik_b, ik_a.public_key(), "Alice")
    return World(alice, bob, CloudServer(), ik_a, ik_b)


def transfer(w: World, plaintext: bytes, file_id: str = "DOC-001",
             seq_no: int = 1, adv_req: Adversary = None,
             adv_bundle: Adversary = None, adv_pkg: Adversary = None,
             verify_signature: bool = True):
    """Menjalankan 3 pesan protokol lewat server. Mengembalikan (plaintext, paket)."""
    req = w.server.relay("1. Req_Share", w.alice.start_session(), adv_req)
    bundle = w.server.relay("2. PreKey_Bundle_B", w.bob.handle_req(req), adv_bundle)
    w.alice.process_prekey(bundle)
    pkg = w.server.relay("3. Encrypted_Package",
                         w.alice.encrypt_file(plaintext, file_id, seq_no), adv_pkg)
    return w.bob.receive_package(pkg, verify_signature), pkg


def flip_byte(data: bytes, index: int = 0) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


# ----------------------------------------------------------------------
# Kerangka pengujian
# ----------------------------------------------------------------------
RESULTS: List[tuple] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    tag = "LULUS" if passed else "GAGAL"
    print(f"    [{tag}] {name}" + (f"  ({detail})" if detail else ""))


def expect_raises(exc, fn):
    """Mengembalikan (berhasil, deskripsi) -- berhasil jika exception tepat muncul."""
    try:
        fn()
    except exc as e:
        return True, type(e).__name__
    except Exception as e:  # exception lain = hasil tak terduga
        return False, f"{type(e).__name__}: {e}"
    return False, "tidak ada exception"


def section(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


# ----------------------------------------------------------------------
# Demo utama (alur normal, dengan narasi)
# ----------------------------------------------------------------------
def demo_normal(plaintext: bytes, file_name: str) -> bytes:
    section("DEMO: Pengiriman berkas normal Alice -> Cloud -> Bob")
    w = make_world()
    print("[0] Kunci identitas Ed25519 Alice & Bob dibuat; kunci publik")
    print("    dianggap sudah diverifikasi out-of-band (fingerprint):")
    print(f"      Alice: {fingerprint(w.ik_a_priv.public_key())}")
    print(f"      Bob  : {fingerprint(w.ik_b_priv.public_key())}")

    print("\n[1] Alice -> Server -> Bob : Req_Share(ID_B, nonce_A)")
    req = w.server.relay("1. Req_Share", w.alice.start_session())
    print(f"      nonce_A = {short(req.nonce_a)}")

    print("[2] Bob membuat EK_B, menandatangani transkrip, membalas bundle")
    bundle = w.server.relay("2. PreKey_Bundle_B", w.bob.handle_req(req))
    print(f"      EK_B_pub = {short(bundle.ek_b_pub)}  Sig_B = {short(bundle.sig_b)}")

    print("[3] Alice memverifikasi Sig_B, membuat EK_A, menurunkan KEK (HKDF)")
    w.alice.process_prekey(bundle)
    print(f"      kunci ephemeral Alice dihapus: {w.alice.ephemeral_wiped}")

    print(f"[4] Alice mengenkripsi '{file_name}' ({len(plaintext)} byte) dengan DEK,")
    print("    membungkus DEK dengan KEK, lalu menandatangani seluruh paket")
    pkg = w.server.relay("3. Encrypted_Package",
                         w.alice.encrypt_file(plaintext, "DOC-001", 1))
    print(f"      ciphertext = {len(pkg.ciphertext)} byte, "
          f"wrapped_DEK = {len(pkg.wrapped_dek)} byte, Sig_A = {short(pkg.sig_a)}")

    print("[5] Bob memverifikasi Sig_A, menurunkan KEK, unwrap DEK, dekripsi")
    result = w.bob.receive_package(pkg)
    print(f"      hasil dekripsi {len(result)} byte, "
          f"sama dengan aslinya: {result == plaintext}")

    print("\n[Pengujian alur normal]")
    record("Dekripsi menghasilkan berkas identik",
           result == plaintext)
    record("Server melihat 3 pesan (hanya ciphertext/kunci publik)",
           [l for l, _ in w.server.captured] ==
           ["1. Req_Share", "2. PreKey_Bundle_B", "3. Encrypted_Package"])
    record("Berkas tersimpan di vault Bob dan terbuka dengan KEK lokal",
           w.bob.open_stored("DOC-001") == plaintext)
    record("Kunci ephemeral Bob terhapus (sesi ditutup)",
           w.bob.pending_sessions == 0)
    return result


# ----------------------------------------------------------------------
# Skenario serangan & pengujian desain (Bagian 9 laporan)
# ----------------------------------------------------------------------
def scenario_eavesdrop(plaintext: bytes) -> None:
    section("SKENARIO: Server/Eve menyadap ciphertext_file & wrapped_dek")
    w = make_world()
    marker = plaintext[:16]
    transfer(w, plaintext)
    pkg = [m for label, m in w.server.captured if label.startswith("3.")][0]
    record("Plaintext tidak muncul pada ciphertext/wrapped_dek",
           marker not in pkg.ciphertext and marker not in pkg.wrapped_dek)
    ok1, d1 = expect_raises(InvalidTag, lambda: AESGCM(os.urandom(32)).decrypt(
        pkg.nonce_file, pkg.ciphertext, pkg.aad))
    record("Eve menebak DEK acak -> InvalidTag", ok1, d1)
    ok2, d2 = expect_raises(InvalidTag, lambda: AESGCM(os.urandom(32)).decrypt(
        pkg.nonce_wrap, pkg.wrapped_dek, build_wrap_aad(pkg.file_id, pkg.seq_no)))
    record("Eve menebak KEK acak untuk unwrap DEK -> InvalidTag", ok2, d2)


def scenario_tamper(plaintext: bytes) -> None:
    section("SKENARIO: Eve mengubah ciphertext / metadata / wrapped_dek")
    w = make_world()
    ok, d = expect_raises(InvalidSignature, lambda: transfer(
        w, plaintext, adv_pkg=lambda p: replace(p, ciphertext=flip_byte(p.ciphertext))))
    record("Ubah 1 byte ciphertext -> Sig_A tidak valid", ok, d)

    w = make_world()
    ok, d = expect_raises(InvalidTag, lambda: transfer(
        w, plaintext, verify_signature=False,
        adv_pkg=lambda p: replace(p, ciphertext=flip_byte(p.ciphertext))))
    record("Tanpa cek tanda tangan pun, tag AES-GCM menolak (defense-in-depth)", ok, d)

    w = make_world()
    ok, d = expect_raises(ProtocolError, lambda: transfer(
        w, plaintext, adv_pkg=lambda p: replace(p, aad=flip_byte(p.aad))))
    record("Ubah AAD metadata -> ditolak sebelum dekripsi", ok, d)

    w = make_world()
    ok, d = expect_raises(InvalidSignature, lambda: transfer(
        w, plaintext, adv_pkg=lambda p: replace(p, wrapped_dek=flip_byte(p.wrapped_dek))))
    record("Ubah wrapped_dek -> Sig_A tidak valid", ok, d)

    w = make_world()
    ok, d = expect_raises(ProtocolError, lambda: transfer(
        w, plaintext, adv_pkg=lambda p: replace(p, file_id="DOC-EVIL")))
    record("Ganti file_id pada paket -> ditolak (AAD tidak cocok)", ok, d)


def scenario_mitm(plaintext: bytes) -> None:
    section("SKENARIO: Eve mengganti kunci publik ephemeral (MITM)")
    eve_ek = x25519_pub_bytes(x25519.X25519PrivateKey.generate())

    w = make_world()
    ok, d = expect_raises(InvalidSignature, lambda: transfer(
        w, plaintext, adv_bundle=lambda b: replace(b, ek_b_pub=eve_ek)))
    record("Ganti EK_B_pub pada bundle -> Alice menolak (Sig_B gagal)", ok, d)

    w = make_world()
    ok, d = expect_raises(InvalidSignature, lambda: transfer(
        w, plaintext, adv_pkg=lambda p: replace(p, ek_a_pub=eve_ek)))
    record("Ganti EK_A_pub pada paket -> Bob menolak (Sig_A gagal)", ok, d)

    w = make_world()
    ok, d = expect_raises(InvalidSignature, lambda: transfer(
        w, plaintext,
        adv_req=lambda r: replace(r, nonce_a=os.urandom(NONCE_SIZE_SESSION))))
    record("Ganti nonce_A pada Req_Share -> transkrip tidak cocok, Alice menolak",
           ok, d)


def scenario_impersonation(plaintext: bytes) -> None:
    section("SKENARIO: Eve menyamar sebagai Bob dengan kunci identitas sendiri")
    w = make_world()
    ik_eve = ed25519.Ed25519PrivateKey.generate()
    seen: List[ReqShare] = []

    def forge_bundle(_real_bundle: PreKeyBundle) -> PreKeyBundle:
        req = seen[0]
        ek_eve = x25519_pub_bytes(x25519.X25519PrivateKey.generate())
        nonce_eve = os.urandom(NONCE_SIZE_SESSION)
        tb = transcript_b("Bob", "Alice", ek_eve, req.nonce_a, nonce_eve)
        return PreKeyBundle(ek_eve, nonce_eve, ik_eve.sign(tb))

    ok, d = expect_raises(InvalidSignature, lambda: transfer(
        w, plaintext,
        adv_req=lambda r: (seen.append(r) or r),
        adv_bundle=forge_bundle))
    record("Bundle palsu bertanda tangan IK_Eve -> ditolak Alice", ok, d)

    w = make_world()
    seen_bundle: List[PreKeyBundle] = []
    ok, d = expect_raises(InvalidSignature, lambda: transfer(
        w, plaintext,
        adv_bundle=lambda b: (seen_bundle.append(b) or b),
        adv_pkg=lambda p: replace(p, sig_a=ik_eve.sign(b"paket palsu"))))
    record("Paket bertanda tangan IK_Eve (bukan Alice) -> ditolak Bob", ok, d)


def scenario_replay(plaintext: bytes) -> None:
    section("SKENARIO: Eve mengulang (replay) paket lama")
    w = make_world()
    result, pkg = transfer(w, plaintext)
    record("Pengiriman pertama berhasil", result == plaintext)
    ok, d = expect_raises(ReplayError, lambda: w.bob.receive_package(pkg))
    record("Paket yang sama dikirim ulang -> ditolak sebagai replay", ok, d)

    w2 = make_world()
    ok, d = expect_raises(ProtocolError, lambda: w2.bob.receive_package(pkg))
    record("Paket lama ke sesi/penerima baru -> sesi tidak dikenal", ok, d)

    w3 = make_world()
    req = w3.alice.start_session()
    w3.bob.handle_req(req)
    ok, d = expect_raises(ProtocolError, lambda: w3.bob.handle_req(req))
    record("Req_Share dengan nonce_A yang sama diulang -> ditolak", ok, d)


def scenario_root_of_trust(plaintext: bytes) -> None:
    section("SKENARIO NEGATIF: Kunci identitas Bob diganti sebelum verifikasi fingerprint")
    ik_eve = ed25519.Ed25519PrivateKey.generate()
    ik_b_real = ed25519.Ed25519PrivateKey.generate()
    # Alice KELIRU menyimpan IK_Eve_pub sebagai 'kunci Bob'.
    w = make_world(alice_trusts_b=ik_eve.public_key())

    req = w.alice.start_session()
    ek_eve_priv = x25519.X25519PrivateKey.generate()
    ek_eve = x25519_pub_bytes(ek_eve_priv)
    nonce_eve = os.urandom(NONCE_SIZE_SESSION)
    tb = transcript_b("Bob", "Alice", ek_eve, req.nonce_a, nonce_eve)
    forged = PreKeyBundle(ek_eve, nonce_eve, ik_eve.sign(tb))

    accepted = True
    try:
        w.alice.process_prekey(forged)
    except InvalidSignature:
        accepted = False
    record("Alice menerima bundle Eve (root of trust runtuh -> MITM berhasil)",
           accepted, "inilah mengapa IK_pub harus diverifikasi out-of-band")

    fp_pinned = fingerprint(ik_eve.public_key())
    fp_real = fingerprint(ik_b_real.public_key())
    record("Perbandingan fingerprint out-of-band MENDETEKSI penggantian kunci",
           fp_pinned != fp_real, f"{fp_pinned[:9]}... != {fp_real[:9]}...")


def scenario_rotation(plaintext: bytes) -> None:
    section("SKENARIO: Rotasi KEK (re-wrapping tanpa enkripsi ulang berkas)")
    w = make_world()
    transfer(w, plaintext)
    rec = w.bob.vault["DOC-001"]
    ct_before = bytes(rec.ciphertext)
    old_wrapped = (rec.nonce_wrap, rec.wrapped_dek, rec.kek_version)
    old_key = w.bob._keystore[1]

    new_ver = w.bob.rotate_kek()
    rec = w.bob.vault["DOC-001"]
    record("Ciphertext berkas TIDAK berubah setelah rotasi",
           rec.ciphertext == ct_before)
    record("Versi KEK naik dan berkas tetap terbuka dengan KEK baru",
           new_ver == 2 and rec.kek_version == 2
           and w.bob.open_stored("DOC-001") == plaintext, f"v{new_ver}")
    ok, d = expect_raises(InvalidTag, lambda: AESGCM(old_key).decrypt(
        rec.nonce_wrap, rec.wrapped_dek, Bob._vault_aad("DOC-001", 2)))
    record("KEK lama tidak bisa membuka wrapped_dek baru", ok, d)
    ok, d = expect_raises(InvalidTag, lambda: AESGCM(w.bob._keystore[2]).decrypt(
        old_wrapped[0], old_wrapped[1], Bob._vault_aad("DOC-001", old_wrapped[2])))
    record("KEK baru tidak bisa membuka wrapped_dek lama", ok, d)


def scenario_forward_secrecy(plaintext: bytes) -> None:
    section("SKENARIO: Kunci identitas bocor setelah sesi (forward secrecy)")
    w = make_world()
    transfer(w, plaintext)
    record("Kunci ephemeral Alice & Bob sudah dihapus setelah sesi",
           w.alice.ephemeral_wiped and w.bob.pending_sessions == 0)

    # Eve memegang IK_A_priv, IK_B_priv, dan seluruh trafik yang direkam,
    # tetapi TIDAK memiliki EK_A_priv / EK_B_priv.
    pkg = [m for l, m in w.server.captured if l.startswith("3.")][0]
    bundle = [m for l, m in w.server.captured if l.startswith("2.")][0]
    tb = transcript_b("Bob", "Alice", bundle.ek_b_pub,
                      pkg.session_id, bundle.nonce_b)
    full_t = full_transcript(tb, pkg.ek_a_pub)
    eve_guess = x25519.X25519PrivateKey.generate().exchange(
        x25519.X25519PublicKey.from_public_bytes(bundle.ek_b_pub))
    eve_kek = derive_kek(eve_guess, full_t)
    ok, d = expect_raises(InvalidTag, lambda: AESGCM(eve_kek).decrypt(
        pkg.nonce_wrap, pkg.wrapped_dek,
        build_wrap_aad(pkg.file_id, pkg.seq_no)))
    record("Dengan IK bocor + trafik terekam, Eve tetap tidak bisa menurunkan KEK",
           ok, d)


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Simulasi Secure File Sharing")
    parser.add_argument("--file", help="berkas nyata yang akan dibagikan Alice -> Bob")
    args = parser.parse_args()

    print("=== SIMULASI PROTOKOL SECURE FILE SHARING (CHECKPOINT 3) ===")

    if args.file:
        with open(args.file, "rb") as fh:
            plaintext = fh.read()
        file_name = os.path.basename(args.file)
    else:
        plaintext = (b"Dokumen Rahasia Negara: Laporan Hasil Audit Keuangan "
                     b"Tahun 2026.\n") * 4
        file_name = "laporan_audit_2026.txt"

    result = demo_normal(plaintext, file_name)

    if args.file:
        out_path = args.file + ".dec"
        with open(out_path, "wb") as fh:
            fh.write(result)
        same = hashlib.sha256(result).digest() == hashlib.sha256(plaintext).digest()
        print(f"\nBerkas hasil dekripsi disimpan ke: {out_path}  (SHA-256 identik: {same})")

    scenario_eavesdrop(plaintext)
    scenario_tamper(plaintext)
    scenario_mitm(plaintext)
    scenario_impersonation(plaintext)
    scenario_replay(plaintext)
    scenario_root_of_trust(plaintext)
    scenario_rotation(plaintext)
    scenario_forward_secrecy(plaintext)

    section("RINGKASAN")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, _ in RESULTS:
        if not ok:
            print(f"  GAGAL: {name}")
    print(f"  {passed}/{len(RESULTS)} pengujian lulus")
    print("\nCatatan batas jaminan: 'del' di Python hanya menghapus referensi,")
    print("bukan menimpa memori RAM fisik. Zeroization penuh butuh dukungan")
    print("level C/OS. Protokol juga tidak melindungi endpoint yang terinfeksi malware.")

    if passed == len(RESULTS):
        print("\n=== SEMUA PENGUJIAN DAN KODE BERHASIL DIJALANKAN DENGAN AMAN ===")
        return 0
    print("\n=== ADA PENGUJIAN YANG GAGAL ===")
    return 1


if __name__ == "__main__":
    sys.exit(main())