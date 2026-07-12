import random
import string

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}

SITES = {
    "GitHub":     "https://github.com/{}",
    "GitLab":     "https://gitlab.com/{}",
    "Reddit":     "https://www.reddit.com/user/{}",
    "Twitch":     "https://www.twitch.tv/{}",
    "Telegram":   "https://t.me/{}",
    "Steam":      "https://steamcommunity.com/id/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Medium":     "https://medium.com/@{}",
    "Dev.to":     "https://dev.to/{}",
    "Replit":     "https://replit.com/@{}",
    "Pinterest":  "https://www.pinterest.com/{}",
    "YouTube":    "https://www.youtube.com/@{}",
    "Instagram":  "https://www.instagram.com/{}",
    "TikTok":     "https://www.tiktok.com/@{}",
}


def probe(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        return resp.status_code
    except requests.RequestException:
        return None


def random_alias():
    return "zz" + "".join(random.choices(string.ascii_lowercase, k=14))


def check_site(name, url_template, username):
    url = url_template.format(username)
    status = probe(url)

    if status is None:
        return {"sitio": name, "url": url, "estado": "error", "confianza": "-"}
    if status == 404:
        return {"sitio": name, "url": url, "estado": "no encontrado", "confianza": "alta"}
    if status != 200:
        return {"sitio": name, "url": url, "estado": f"bloqueado (HTTP {status})", "confianza": "-"}

    fake_status = probe(url_template.format(random_alias()))
    confianza = "baja" if fake_status == 200 else "alta"
    return {"sitio": name, "url": url, "estado": "encontrado", "confianza": confianza}


def _buscar(username):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(check_site, name, tpl, username)
            for name, tpl in SITES.items()
        ]
        for future in as_completed(futures):
            results.append(future.result())

    prioridad = {("encontrado", "alta"): 0, ("encontrado", "baja"): 1}
    results.sort(key=lambda r: (prioridad.get((r["estado"], r["confianza"]), 2), r["sitio"].lower()))
    return results


def _mostrar(results):
    for r in results:
        mark = "[+]" if r["estado"] == "encontrado" else "[-]"
        conf = f"(confianza: {r['confianza']})" if r["confianza"] != "-" else ""
        print(f"{mark} {r['sitio']:<11} {r['estado']:<22} {conf:<20} {r['url']}")


def run(target):
    """Interfaz estandar de un modulo: recibe el dato, devuelve un dict."""
    print(f"\n[*] [username] Buscando '{target}' en {len(SITES)} sitios...\n")
    results = _buscar(target)
    _mostrar(results)
    return {"modulo": "username", "objetivo": target, "resultados": results}