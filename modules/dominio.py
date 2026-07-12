import requests
import dns.resolver

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}


def subdominios_crtsh(dominio):
    """Subdominios a partir de los logs de Certificate Transparency (crt.sh)."""
    url = f"https://crt.sh/?q=%25.{dominio}&output=json"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=25)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    subs = set()
    for entry in data:
        # name_value puede traer varios nombres separados por saltos de linea
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(dominio):
                subs.add(name)
    return sorted(subs)


def registros_dns(dominio):
    """Consulta los registros DNS mas habituales."""
    registros = {}
    for tipo in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            respuestas = dns.resolver.resolve(dominio, tipo)
            registros[tipo] = [r.to_text() for r in respuestas]
        except Exception:
            registros[tipo] = []
    return registros


def _vcard_fn(entity):
    """Extrae el nombre (fn) de la tarjeta vcard de una entidad RDAP."""
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for campo in vcard[1]:
        if campo and campo[0] == "fn":
            return campo[3]
    return None


def whois_rdap(dominio):
    """Datos de registro del dominio via RDAP (el WHOIS moderno, en JSON)."""
    try:
        resp = requests.get(f"https://rdap.org/domain/{dominio}", headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return {}
        data = resp.json()
    except (requests.RequestException, ValueError):
        return {}

    info = {}
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            nombre = _vcard_fn(ent)
            if nombre:
                info["registrador"] = nombre
    for ev in data.get("events", []):
        accion = ev.get("eventAction")
        if accion in ("registration", "expiration", "last changed"):
            info[accion] = ev.get("eventDate")
    info["nameservers"] = [ns.get("ldhName") for ns in data.get("nameservers", [])]
    return info


def _mostrar(dominio, subs, dns_rec, whois):
    print("--- WHOIS / RDAP ---")
    if whois:
        for k, v in whois.items():
            print(f"  {k}: {v}")
    else:
        print("  (sin datos)")

    print("\n--- Registros DNS ---")
    hay = False
    for tipo, valores in dns_rec.items():
        for v in valores:
            print(f"  {tipo:<5} {v}")
            hay = True
    if not hay:
        print("  (sin datos)")

    print(f"\n--- Subdominios via crt.sh: {len(subs)} encontrados ---")
    for s in subs:
        print(f"  {s}")


def run(target):
    """Interfaz estandar del modulo."""
    print(f"\n[*] [dominio] Investigando '{target}'...\n")
    subs = subdominios_crtsh(target)
    dns_rec = registros_dns(target)
    whois = whois_rdap(target)
    _mostrar(target, subs, dns_rec, whois)
    return {
        "modulo": "dominio",
        "objetivo": target,
        "resultados": {
            "subdominios": subs,
            "dns": dns_rec,
            "whois": whois,
        },
    }