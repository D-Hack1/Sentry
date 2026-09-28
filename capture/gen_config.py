import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Path(__file__).resolve().parent / "templates"

load_dotenv(ROOT / ".env")

MODES = ("tunnel", "transport")
CIPHERS = ("aes128cbc", "aes256cbc", "aes128gcm", "aes256gcm")
DH_GROUPS = ("group2", "group5", "group14", "group19", "group20")
CONN_NAME = "sentry"

CIPHER_PROPOSALS = {
    "aes128cbc": ("aes128", "sha256"),
    "aes256cbc": ("aes256", "sha256"),
    "aes128gcm": ("aes128gcm16", None),
    "aes256gcm": ("aes256gcm16", None),
}
DH_PROPOSALS = {
    "group2": "modp1024",
    "group5": "modp1536",
    "group14": "modp2048",
    "group19": "ecp256",
    "group20": "ecp384",
}


def env_required(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"missing required env var: {name}")
    return value


def build_params(role, mode, cipher, dh_group, pfs):
    initiator_ip = env_required("INITIATOR_IP")
    responder_ip = env_required("RESPONDER_IP")
    left_ip, right_ip = (
        (initiator_ip, responder_ip) if role == "initiator" else (responder_ip, initiator_ip)
    )
    enc, integ = CIPHER_PROPOSALS[cipher]
    dh = DH_PROPOSALS[dh_group]
    ike_proposal = f"{enc}-{integ or 'sha256'}-{dh}"
    esp_proposal = f"{enc}-{integ}" if integ else enc
    if pfs == "yes":
        esp_proposal = f"{esp_proposal}-{dh}"
    return {
        "conn_name": CONN_NAME,
        "mode": mode,
        "left_ip": left_ip,
        "right_ip": right_ip,
        "ike_proposal": ike_proposal,
        "esp_proposal": esp_proposal,
        "psk": env_required("IPSEC_PSK"),
    }


def render(role, mode, cipher, dh_group, pfs):
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    params = build_params(role, mode, cipher, dh_group, pfs)
    return (
        env.get_template("ipsec.conf.j2").render(**params),
        env.get_template("ipsec.secrets.j2").render(**params),
    )


REQUIRED_CONF_KEYS = (
    "keyexchange", "type", "authby", "left", "right",
    "leftid", "rightid", "ike", "esp", "auto",
)


def validate_conf(conf):
    lines = [l.strip() for l in conf.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not any(l.startswith(f"conn {CONN_NAME}") for l in lines):
        sys.exit(f"invalid ipsec.conf: missing 'conn {CONN_NAME}' section")
    found = {}
    for l in lines:
        if "=" in l:
            key, _, value = l.partition("=")
            found[key.strip()] = value.strip()
    missing = [k for k in REQUIRED_CONF_KEYS if k not in found]
    if missing:
        sys.exit(f"invalid ipsec.conf: missing keys {missing}")
    empty = [k for k in REQUIRED_CONF_KEYS if not found[k]]
    if empty:
        sys.exit(f"invalid ipsec.conf: empty values for {empty}")


def validate_secrets(secrets, left_ip, right_ip):
    if not secrets.strip():
        sys.exit("invalid ipsec.secrets: file is empty")
    if left_ip not in secrets or right_ip not in secrets:
        sys.exit("invalid ipsec.secrets: missing expected peer IPs")
    if "PSK" not in secrets:
        sys.exit("invalid ipsec.secrets: missing PSK entry")


def write_config(role, out_dir, mode, cipher, dh_group, pfs):
    conf, secrets = render(role, mode, cipher, dh_group, pfs)
    params = build_params(role, mode, cipher, dh_group, pfs)
    validate_conf(conf)
    validate_secrets(secrets, params["left_ip"], params["right_ip"])

    target = Path(out_dir) / role
    target.mkdir(parents=True, exist_ok=True)
    (target / "ipsec.conf").write_text(conf)
    secrets_path = target / "ipsec.secrets"
    secrets_path.write_text(secrets)
    secrets_path.chmod(0o600)
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("initiator", "responder", "both"), default="both")
    parser.add_argument("--mode", choices=MODES, default=os.environ.get("IPSEC_MODE", "tunnel"))
    parser.add_argument("--cipher", choices=CIPHERS, default=os.environ.get("CIPHER", "aes256gcm"))
    parser.add_argument("--dh-group", choices=DH_GROUPS, default=os.environ.get("DH_GROUP", "group14"))
    parser.add_argument("--pfs", choices=("yes", "no"), default=os.environ.get("PFS", "yes"))
    parser.add_argument("--out-dir", default=os.environ.get("CONFIG_DIR", "capture/configs"))
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir

    roles = ("initiator", "responder") if args.role == "both" else (args.role,)
    for role in roles:
        write_config(role, out_dir, args.mode, args.cipher, args.dh_group, args.pfs)


if __name__ == "__main__":
    main()
