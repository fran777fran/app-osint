import os
import hashlib

import requests

from modules.dominio import registros_dns  # <- reutilizamos tu modulo de dominio

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}

PROVEEDORES = {
    "gmail.com": "Google Gmail",
    "googlemail.com": "Google Gmail",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live",
    "yahoo.com": "Yahoo",
    "icloud.com": "Apple iCloud",
    "protonmail.com": "Proton Mail",
    "proton.me": "Proton Mail",
}


def _md5(email):
    # usedforsecurity=False: no es criptografia, solo el identificador que usa Gravatar
    return hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()


def proveedor(email):
    dominio = email.split("@")[-1].lower()
    return PROVEEDORES.get(dominio, f"Otro / propio ({dominio})")


def gravatar(email):
    h = _md5(email)
    info = {"hash": h, "tiene_avatar": False, "perfil": None}

    # ¿Existe avatar? d=404 hace que Gravatar responda 404 si no hay foto.
    try:
        r = requests.get(f"https://www.gravatar.com/avatar/{h}?d=404", headers=HEADERS, timeout=10)
        info["tiene_avatar"] = (r.status_code == 200)
    except requests.RequestException:
        pass

    # ¿Hay perfil publico? El .json devuelve datos si el perfil existe.
    try:
        r = requests.get(f"https://www.gravatar.com/{h}.json", headers=HEADERS, timeout=10)
        if r.status_code == 200:
            entradas = r.json().get("entry", [])
            if entradas:
                e = entradas[0]
                info["perfil"] = {
                    "nombre": e.get("displayName"),
                    "ubicacion": e.get("currentLocation"),
                    "sobre_mi": e.get("aboutMe"),
                    "url_perfil": e.get("profileUrl"),
                    "cuentas": [
                        {"red": a.get("shortname"), "url": a.get("url")}
                        for a in e.get("accounts", [])
                    ],
                }
    except (requests.RequestException, ValueError):
        pass

    return info


def dominio_correo(email):
    dominio = email.split("@")[-1]
    mx = registros_dns(dominio).get("MX", [])
    return {"dominio": dominio, "mx": mx, "puede_recibir": len(mx) > 0}


def hibp_brechas(email):
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        return {"consultado": False, "motivo": "sin clave API (HIBP_API_KEY)"}

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    cabeceras = {**HEADERS, "hibp-api-key": key}
    try:
        r = requests.get(url, headers=cabeceras, timeout=15)
    except requests.RequestException:
        return {"consultado": True, "brechas": [], "error": "fallo de red"}

    if r.status_code == 404:
        return {"consultado": True, "brechas": []}          # sin brechas
    if r.status_code == 200:
        return {"consultado": True, "brechas": [b.get("Name") for b in r.json()]}
    return {"consultado": True, "brechas": [], "error": f"HTTP {r.status_code}"}


def _mostrar(email, d):
    print(f"  Proveedor:        {d['proveedor']}")
    g = d["gravatar"]
    print(f"  Gravatar avatar:  {'si' if g['tiene_avatar'] else 'no'}")
    if g["perfil"]:
        p = g["perfil"]
        print(f"  Perfil Gravatar:  {p.get('nombre') or '-'} | {p.get('ubicacion') or '-'}")
        for c in p["cuentas"]:
            print(f"     - {c['red']}: {c['url']}")
    c = d["dominio_correo"]
    print(f"  Dominio correo:   {c['dominio']} | recibe correo: {'si' if c['puede_recibir'] else 'no'}")
    b = d["brechas"]
    if not b["consultado"]:
        print(f"  Brechas (HIBP):   no consultado ({b['motivo']})")
    else:
        print(f"  Brechas (HIBP):   {len(b['brechas'])} -> {', '.join(b['brechas']) or 'ninguna'}")


def run(target):
    print(f"\n[*] [email] Investigando '{target}'...\n")
    datos = {
        "proveedor": proveedor(target),
        "gravatar": gravatar(target),
        "dominio_correo": dominio_correo(target),
        "brechas": hibp_brechas(target),
    }
    _mostrar(target, datos)
    return {"modulo": "email", "objetivo": target, "resultados": datos}