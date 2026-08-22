#!/usr/bin/env python3
"""fetch_creds.py - Frische Geraete-Zugangsdaten aus der Quvii-Cloud holen.

`dynamic_password` und `data_encode_key` rotieren ~woechentlich; ohne frische
Werte scheitert der P2P-LOGIN (bzw. laesst sich der Strom nicht entschluesseln).
Dieses Skript meldet sich mit dem Cloud-Konto an, liest die Geraeteliste und
schreibt die Werte in eine creds.json, die live_viewer.py / p2p_opener.py lesen.

    python tools/fetch_creds.py                      # Konto aus login.md
    python tools/fetch_creds.py --email a@b.c --password geheim
    BALTER_EMAIL=... BALTER_PASSWORD=... python tools/fetch_creds.py

Es werden ausschliesslich lesende Cloud-Aufrufe gemacht (login, get-device-list,
get-subdev-list). Nichts wird am Geraet geschaltet.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ROOT = os.path.dirname(REPO)
PKG_DIR = os.path.join(REPO, "custom_components", "balter_evo")

# Die Integration als Paket bereitstellen, ohne __init__.py (zieht Home Assistant).
_pkg = types.ModuleType("balter_evo")
_pkg.__path__ = [PKG_DIR]
sys.modules["balter_evo"] = _pkg
api = importlib.import_module("balter_evo.api")

# Die P2P-Schicht meldet sich mit DIESER client-id am Geraet an (byte-verifiziert
# aus live_real.pcap) -- fuer die Cloud dieselbe verwenden, wie es die App tut.
P2P_CLIENT_ID = "e4d73be5e26e9a83"


def account_from_login_md() -> tuple[str, str] | None:
    path = os.path.join(ROOT, "login.md")
    if not os.path.exists(path):
        return None
    txt = open(path, encoding="utf-8").read()
    user = re.search(r"username:\s*(\S+)", txt)
    pw = re.search(r"pw:\s*(\S+)", txt)
    if user and pw:
        return user.group(1), pw.group(1)
    return None


async def run(email: str, password: str, duid: str | None, out: str) -> int:
    import aiohttp

    async with aiohttp.ClientSession() as session:
        client = api.BalterCloudClient(session, email, password, client_id=P2P_CLIENT_ID)
        print(f"[1/3] Login als {email} ...")
        await client.login()
        print(f"      OK (userapp-Endpoint via Discovery aufgeloest)")

        print("[2/3] Geraeteliste ...")
        devices = await client.get_device_list()
        if not devices:
            print("      [FEHLER] Keine Geraete am Konto.")
            return 1
        for d in devices:
            print(f"      duid={d['duid']}  name={d['name']!r}  model={d['model']!r}")

        dev = None
        if duid:
            dev = next((d for d in devices if d["duid"] == duid), None)
            if dev is None:
                print(f"      [FEHLER] duid {duid} nicht am Konto.")
                return 1
        else:
            dev = devices[0]
            if len(devices) > 1:
                print(f"      -> nehme das erste ({dev['duid']}); sonst --duid setzen")

        dynpw = dev.get("dynamic_password") or ""
        key = dev.get("data_encode_key") or ""
        auth = dev.get("out_auth_code") or ""
        print(f"      dynamic_password: {len(dynpw)} Zeichen "
              f"({dynpw[:12]}...{dynpw[-6:] if len(dynpw) > 18 else ''})")
        print(f"      data_encode_key : {len(key)} Zeichen ({key[:6]}...)")
        print(f"      out_auth_code   : {len(auth)} Zeichen ({auth[:12]}...)")
        if len(key) != 32:
            print(f"      [WARNUNG] data_encode_key sollte 32 Zeichen haben!")
        if not dynpw:
            print(f"      [FEHLER] Kein dynamic_password geliefert.")
            return 1

        print("[3/3] Schloesser (door/locknumber) ...")
        locks = []
        try:
            locks = await client.get_subdev_list(dev["duid"])
            for lk in locks:
                print(f"      {lk['code']}  name={lk['name']!r}  door={lk['door']} lock={lk['locknumber']}")
        except Exception as err:
            print(f"      [WARNUNG] get-subdev-list fehlgeschlagen: {err}")

        payload = {
            "duid": dev["duid"],
            "name": dev["name"],
            "client_id": P2P_CLIENT_ID,
            "oem": "G0028G0126",
            "dynamic_password": dynpw,
            "data_encode_key": key,
            "out_auth_code": auth,
            "locks": locks,
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\nGeschrieben: {os.path.abspath(out)}")
        print("Diese Datei enthaelt Geheimnisse -- nicht committen (tools/creds.json "
              "steht in .gitignore).")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--email")
    ap.add_argument("--password")
    ap.add_argument("--duid", help="Geraet auswaehlen, wenn mehrere am Konto haengen")
    ap.add_argument("-o", "--out", default=os.path.join(HERE, "creds.json"))
    args = ap.parse_args()

    email = args.email or os.environ.get("BALTER_EMAIL")
    password = args.password or os.environ.get("BALTER_PASSWORD")
    if not (email and password):
        acc = account_from_login_md()
        if not acc:
            ap.error("Kein Konto: --email/--password, $BALTER_EMAIL/$BALTER_PASSWORD "
                     "oder login.md im Projektstamm.")
        email, password = acc
        print(f"(Konto aus login.md)")
    return asyncio.run(run(email, password, args.duid, args.out))


if __name__ == "__main__":
    sys.exit(main())
