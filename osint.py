import ipaddress
import argparse
import os
import json
import report
from datetime import datetime

from modules import ip as mod_ip
from modules import username as mod_username
from modules import dominio as mod_dominio
from modules import correo as mod_correo

# Tabla de despacho: tipo de dato -> funcion del modulo.
# Anadir un modulo nuevo = una linea aqui.
MODULOS = {
    "username": mod_username.run,
    "dominio": mod_dominio.run,
    "email": mod_correo.run,
    "ip": mod_ip.run,
}


def detectar_tipo(dato):
    """Adivina el tipo de dato a partir de su forma."""
    if "@" in dato:
        return "email"
    try:
        ipaddress.ip_address(dato)   # ¿es una IP valida? (v4 o v6)
        return "ip"
    except ValueError:
        pass                         # no lo era, seguimos probando
    if "." in dato and " " not in dato:
        return "dominio"
    return "username"


def guardar(resultado):
    os.makedirs("output", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    seguro = resultado["objetivo"].replace("@", "_at_").replace("/", "_")
    ruta = os.path.join("output", f"{seguro}_{resultado['modulo']}_{ts}.json")
    resultado["fecha"] = datetime.now().isoformat(timespec="seconds")
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(resultado, f, ensure_ascii=False, indent=2)
    print(f"\n[*] Resultado guardado en: {ruta}")


def main():
    parser = argparse.ArgumentParser(description="Orquestador OSINT")
    parser.add_argument("dato", help="Dato a investigar (alias, dominio, email...)")
    parser.add_argument("--tipo", choices=["username", "dominio", "email", "ip"],
                        help="Forzar el tipo (si no, se autodetecta)")
    args = parser.parse_args()

    tipo = args.tipo or detectar_tipo(args.dato)
    print(f"[*] Dato: {args.dato}  |  Tipo: {tipo}")

    run = MODULOS.get(tipo)
    if run is None:
        print(f"[!] Aun no hay modulo para el tipo '{tipo}'. Disponibles: {list(MODULOS)}")
        return

    resultado = run(args.dato)
    guardar(resultado)
    ruta_html = report.generar_html(resultado)
    print(f"[*] Informe HTML:   {ruta_html}")


if __name__ == "__main__":
    main()
