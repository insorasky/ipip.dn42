# Shamelessly stolen from https://github.com/HuJK/DN42-AutoPeer/blob/main/DN42AutoPeer.py

import pathlib
import pgpy
import os
import random
import string
from subprocess import PIPE, Popen

remove_empty_line = lambda s: "\n".join(
    filter(lambda x: len(x) > 0, s.replace("\r\n", "\n").replace("\r", "\n").split("\n")))


def verify_signature_pgp(plaintext, fg, pub_key, raw_signature):
    pub = pgpy.PGPKey.from_blob(remove_empty_line(pub_key).encode("utf8"))[0]
    fg_in = fg.replace(" ", "")
    fg_p = pub.fingerprint.replace(" ", "")
    if fg_in != fg_p:
        raise ValueError("fingerprint not match")
    sig = pgpy.PGPSignature.from_blob(remove_empty_line(raw_signature).encode("utf8"))
    if not pub.verify(plaintext, sig):
        raise ValueError("signature verification failed")
    return True


def verify_signature_pgpn8(plaintext, fg, pub_key, raw_signature):
    pub = pgpy.PGPKey.from_blob(remove_empty_line(pub_key).encode("utf8"))[0]
    fg_in = fg.replace(" ", "")
    fg_p = pub.fingerprint.replace(" ", "")
    if fg_in != fg_p:
        raise ValueError("fingerprint not match")
    sig = pgpy.PGPSignature.from_blob(remove_empty_line(raw_signature).encode("utf8"))
    if not pub.verify(plaintext, sig):
        raise ValueError("signature verification failed")
    return True


def verify_signature_ssh_rsa(plaintext, pub_key, raw_signature):
    sess = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    pathlib.Path("ssh").mkdir(parents=True, exist_ok=True)
    sigfile_path = "ssh/tmp" + sess + ".sig"
    pubfile_path = "ssh/tmp" + sess + ".pub"
    open(sigfile_path, "w").write(raw_signature)
    open(pubfile_path, "w").write(sess + " ssh-rsa " + pub_key)
    command = 'ssh-keygen', "-Y", "verify", "-f", pubfile_path, "-n", "dn42ap", "-I", sess, "-s", sigfile_path
    p = Popen(command, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    stdout_data = p.communicate(input=plaintext.encode())[0]
    os.remove(sigfile_path)
    os.remove(pubfile_path)
    if stdout_data.startswith(b"Good"):
        return True
    else:
        raise ValueError(stdout_data)


def verify_signature_ssh_ed25519(plaintext, pub_key, raw_signature):
    sess = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    pathlib.Path("ssh").mkdir(parents=True, exist_ok=True)
    sigfile_path = "ssh/tmp" + sess + ".sig"
    pubfile_path = "ssh/tmp" + sess + ".pub"
    open(sigfile_path, "w").write(raw_signature)
    open(pubfile_path, "w").write(sess + " ssh-ed25519 " + pub_key)
    command = 'ssh-keygen', "-Y", "verify", "-f", pubfile_path, "-n", "dn42ap", "-I", sess, "-s", sigfile_path
    p = Popen(command, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    stdout_data = p.communicate(input=plaintext.encode())[0]
    os.remove(sigfile_path)
    os.remove(pubfile_path)
    if stdout_data.startswith(b"Good"):
        return True
    else:
        raise ValueError(stdout_data)


def verify_signature(plaintext, pub_key, pub_key_pgp, raw_signature, method):
    if method == "pgp-fingerprint":
        return verify_signature_pgp(plaintext, pub_key, pub_key_pgp, raw_signature)
    elif method == "PGPKEY":
        return verify_signature_pgpn8(plaintext, pub_key, pub_key_pgp, raw_signature)
    elif method == "ssh-rsa":
        return verify_signature_ssh_rsa(plaintext, pub_key, raw_signature)
    elif method == "ssh-ed25519":
        return verify_signature_ssh_ed25519(plaintext, pub_key, raw_signature)
    raise NotImplementedError("method not implement")
