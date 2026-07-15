import ipaddress

import requests
import dns.resolver
import dns.reversename

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}


def _valida(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return {"valida": True, "version": obj.version, "privada": obj.is_private}
    except ValueError:
        return {"valida": False, "version": None, "privada": None}


def _vcard_valor(entity, clave):
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for campo in vcard[1]:
        if campo and campo[0] == clave:
            return campo[3]
    return None


def geolocalizacion(ip):
    try:
        r = requests.get(f"https://ipwho.is/{ip}", headers=HEADERS, timeout=10)
        if r.status_code != 200:
            return {}
        d = r.json()
    except (requests.RequestException, ValueError):
        return {}
    if not d.get("success"):
        return {}
    con = d.get("connection") or {}
    return {
        "pais": d.get("country"),
        "region": d.get("region"),
        "ciudad": d.get("city"),
        "latitud": d.get("latitude"),
        "longitud": d.get("longitude"),
        "zona_horaria": (d.get("timezone") or {}).get("id"),
        "asn": con.get("asn"),
        "org": con.get("org"),
        "isp": con.get("isp"),
    }


def rdns(ip):
    """DNS inverso: de la IP al nombre (registro PTR)."""
    try:
        nombre = dns.reversename.from_address(ip)
        respuestas = dns.resolver.resolve(nombre, "PTR")
        return [str(r).rstrip(".") for r in respuestas]
    except Exception:
        return []


def rdap_red(ip):
    """A que rango/organizacion pertenece la IP."""
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return {}
        d = r.json()
    except (requests.RequestException, ValueError):
        return {}

    info = {
        "nombre_red": d.get("name"),
        "rango": f"{d.get('startAddress', '')} - {d.get('endAddress', '')}",
        "tipo": d.get("type"),
        "pais": d.get("country"),
    }
    cidrs = d.get("cidr0_cidrs") or []
    if cidrs:
        c = cidrs[0]
        prefijo = c.get("v4prefix") or c.get("v6prefix")
        if prefijo:
            info["cidr"] = f"{prefijo}/{c.get('length')}"
    for ent in d.get("entities", []):
        if "abuse" in (ent.get("roles") or []):
            correo = _vcard_valor(ent, "email")
            if correo:
                info["abuse_email"] = correo
    return info


def shodan_internetdb(ip):
    """Puertos y CVEs desde la base de datos publica de Shodan (sin clave, pasivo)."""
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", headers=HEADERS, timeout=15)
    except requests.RequestException:
        return {"consultado": False, "motivo": "fallo de red"}

    if r.status_code == 404:   # Shodan no tiene nada de esta IP
        return {"consultado": True, "puertos": [], "vulns": [], "hostnames": [], "tags": []}
    if r.status_code != 200:
        return {"consultado": False, "motivo": f"HTTP {r.status_code}"}
    try:
        d = r.json()
    except ValueError:
        return {"consultado": False, "motivo": "respuesta no JSON"}

    return {
        "consultado": True,
        "puertos": d.get("ports", []),
        "vulns": d.get("vulns", []),
        "hostnames": d.get("hostnames", []),
        "tags": d.get("tags", []),
    }


def _mostrar(ip, d):
    v = d["validacion"]
    if not v["valida"]:
        print("  [!] No es una IP valida.")
        return
    if v["privada"]:
        print("  [!] Es una IP privada (red interna): las fuentes publicas no sabran nada de ella.\n")

    g = d["geo"]
    if g:
        print(f"  Ubicacion:   {g.get('ciudad') or '-'}, {g.get('region') or '-'}, {g.get('pais') or '-'}")
        print(f"  Coordenadas: {g.get('latitud')}, {g.get('longitud')}  ({g.get('zona_horaria') or '-'})")
        print(f"  ASN / Org:   {g.get('asn') or '-'} | {g.get('org') or '-'}")
        print(f"  ISP:         {g.get('isp') or '-'}")
    else:
        print("  Geolocalizacion: (sin datos)")

    print(f"  rDNS (PTR):  {', '.join(d['rdns']) or '(ninguno)'}")

    r = d["rdap"]
    if r:
        print(f"  Red:         {r.get('nombre_red') or '-'} | {r.get('cidr') or r.get('rango') or '-'}")
        if r.get("abuse_email"):
            print(f"  Abuse:       {r['abuse_email']}")

    s = d["shodan"]
    if s.get("consultado"):
        print(f"  Puertos:     {', '.join(str(p) for p in s['puertos']) or '(ninguno conocido)'}")
        if s["vulns"]:
            print(f"  Vulns (CVE): {', '.join(s['vulns'])}")
        if s["hostnames"]:
            print(f"  Hostnames:   {', '.join(s['hostnames'])}")
    else:
        print(f"  Shodan:      no consultado ({s.get('motivo')})")


def run(target):
    print(f"\n[*] [ip] Investigando '{target}'...\n")
    val = _valida(target)
    datos = {"validacion": val}
    if val["valida"]:
        datos["geo"] = geolocalizacion(target)
        datos["rdns"] = rdns(target)
        datos["rdap"] = rdap_red(target)
        datos["shodan"] = shodan_internetdb(target)
    else:
        datos.update({"geo": {}, "rdns": [], "rdap": {},
                      "shodan": {"consultado": False, "motivo": "IP invalida"}})
    _mostrar(target, datos)
    return {"modulo": "ip", "objetivo": target, "resultados": datos}