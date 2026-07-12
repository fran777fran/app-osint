import os
import html
from datetime import datetime

CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin:0; background:#f5f6f8; color:#1f2329; line-height:1.5; }
.container { max-width: 920px; margin: 0 auto; padding: 32px 24px 64px; }
header.report { border-bottom: 3px solid #2d6cdf; padding-bottom: 16px; margin-bottom: 8px; }
h1 { font-size: 24px; margin: 0 0 4px; }
.meta { color:#6b7280; font-size: 13px; margin: 0; }
h2 { font-size: 15px; margin: 28px 0 12px; color:#2d6cdf; text-transform: uppercase; letter-spacing:.03em; }
table { width:100%; border-collapse: collapse; background:#fff; border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; }
th, td { text-align:left; padding: 10px 14px; border-bottom:1px solid #eef0f2; font-size: 14px; }
th { background:#fafbfc; font-weight:600; color:#374151; }
tr:last-child td { border-bottom: none; }
a { color:#2d6cdf; text-decoration:none; word-break: break-all; }
a:hover { text-decoration: underline; }
.badge { display:inline-block; padding: 2px 9px; border-radius: 999px; font-size:12px; font-weight:600; }
.badge.ok { background:#e6f4ea; color:#137333; }
.badge.warn { background:#fef7e0; color:#b06000; }
.badge.muted { background:#eef0f2; color:#5f6673; }
.badge.err { background:#fce8e6; color:#c5221f; }
.summary { display:flex; gap:16px; flex-wrap:wrap; margin: 16px 0 4px; }
.card { background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:14px 18px; flex:1; min-width:120px; }
.card .n { font-size: 26px; font-weight:700; }
.card .l { font-size:12px; color:#6b7280; text-transform:uppercase; }
dl { background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding: 8px 18px; margin:0; }
dt { font-weight:600; color:#374151; font-size:13px; margin-top:10px; }
dd { margin:0 0 10px; font-size:14px; word-break: break-word; }
ul.subs { columns: 2; list-style:none; margin:0; background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:14px 18px; }
ul.subs li { font-size:13px; padding:3px 0; break-inside: avoid; }
code { font-family: "Cascadia Code", Consolas, monospace; font-size:12px; }
footer { margin-top:40px; color:#9aa0a6; font-size:12px; text-align:center; }
@media (max-width:600px){ ul.subs{columns:1;} }
"""


def _shell(titulo, cuerpo):
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(titulo)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
{cuerpo}
<footer>Generado por tu orquestador OSINT · Solo fuentes publicas</footer>
</div>
</body>
</html>"""


def _cuerpo_username(resultado):
    resultados = resultado["resultados"]
    encontrados = [r for r in resultados if r["estado"] == "encontrado"]
    alta = [r for r in encontrados if r["confianza"] == "alta"]

    filas = ""
    for r in resultados:
        estado, conf = r["estado"], r["confianza"]
        if estado == "encontrado" and conf == "alta":
            cls, texto = "ok", "Encontrado"
        elif estado == "encontrado":
            cls, texto = "warn", "Encontrado (dudoso)"
        elif estado == "no encontrado":
            cls, texto = "muted", "No encontrado"
        else:
            cls, texto = "err", html.escape(estado)
        enlace = (f'<a href="{html.escape(r["url"])}" target="_blank" '
                  f'rel="noopener">{html.escape(r["url"])}</a>')
        conf_txt = html.escape(conf) if conf != "-" else "&mdash;"
        filas += (f"<tr><td>{html.escape(r['sitio'])}</td>"
                  f"<td><span class='badge {cls}'>{texto}</span></td>"
                  f"<td>{conf_txt}</td><td>{enlace}</td></tr>")

    resumen = f"""
    <div class="summary">
      <div class="card"><div class="n">{len(resultados)}</div><div class="l">Sitios revisados</div></div>
      <div class="card"><div class="n">{len(encontrados)}</div><div class="l">Encontrados</div></div>
      <div class="card"><div class="n">{len(alta)}</div><div class="l">Alta confianza</div></div>
    </div>"""

    return resumen + f"""
    <h2>Presencia por sitio</h2>
    <table>
      <tr><th>Sitio</th><th>Estado</th><th>Confianza</th><th>Enlace</th></tr>
      {filas}
    </table>"""


def _cuerpo_dominio(resultado):
    datos = resultado["resultados"]
    whois = datos.get("whois", {})
    dns_rec = datos.get("dns", {})
    subs = datos.get("subdominios", [])

    if whois:
        wh = ""
        for k, v in whois.items():
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            wh += f"<dt>{html.escape(str(k))}</dt><dd>{html.escape(str(v))}</dd>"
        whois_html = f"<dl>{wh}</dl>"
    else:
        whois_html = "<p>(sin datos)</p>"

    dns_filas = ""
    for tipo, valores in dns_rec.items():
        for v in valores:
            dns_filas += (f"<tr><td><code>{html.escape(tipo)}</code></td>"
                          f"<td><code>{html.escape(str(v))}</code></td></tr>")
    if not dns_filas:
        dns_filas = "<tr><td colspan='2'>(sin datos)</td></tr>"

    subs_html = "".join(f"<li>{html.escape(s)}</li>" for s in subs) or "<li>(ninguno)</li>"

    resumen = f"""
    <div class="summary">
      <div class="card"><div class="n">{len(subs)}</div><div class="l">Subdominios</div></div>
      <div class="card"><div class="n">{sum(len(v) for v in dns_rec.values())}</div><div class="l">Registros DNS</div></div>
      <div class="card"><div class="n">{len(whois.get('nameservers', []))}</div><div class="l">Nameservers</div></div>
    </div>"""

    return resumen + f"""
    <h2>WHOIS / RDAP</h2>
    {whois_html}
    <h2>Registros DNS</h2>
    <table><tr><th>Tipo</th><th>Valor</th></tr>{dns_filas}</table>
    <h2>Subdominios (crt.sh) &mdash; {len(subs)}</h2>
    <ul class="subs">{subs_html}</ul>"""


def _cuerpo_email(resultado):
    d = resultado["resultados"]
    grav = d.get("gravatar", {})
    correo = d.get("dominio_correo", {})
    brechas = d.get("brechas", {})
    perfil = grav.get("perfil")

    tiene_grav = "Si" if (grav.get("tiene_avatar") or perfil) else "No"
    br_txt = str(len(brechas.get("brechas", []))) if brechas.get("consultado") else "&mdash;"

    resumen = f"""<div class="summary">
      <div class="card"><div class="n" style="font-size:18px">{html.escape(d.get('proveedor','-'))}</div><div class="l">Proveedor</div></div>
      <div class="card"><div class="n">{tiene_grav}</div><div class="l">Gravatar</div></div>
      <div class="card"><div class="n">{br_txt}</div><div class="l">Brechas</div></div>
    </div>"""

    mx = correo.get("mx", [])
    mx_html = "".join(f"<li><code>{html.escape(str(m))}</code></li>" for m in mx) or "<li>(sin registros MX)</li>"
    dominio_html = f"""<h2>Dominio del correo</h2>
    <dl><dt>Dominio</dt><dd>{html.escape(str(correo.get('dominio','')))}</dd>
    <dt>&iquest;Puede recibir correo?</dt><dd>{'Si' if correo.get('puede_recibir') else 'No'}</dd></dl>
    <ul class="subs">{mx_html}</ul>"""

    if perfil:
        cuentas = perfil.get("cuentas", [])
        cuentas_html = "".join(
            f'<li>{html.escape(str(c.get("red","")))}: '
            f'<a href="{html.escape(str(c.get("url","")))}" target="_blank" rel="noopener">'
            f'{html.escape(str(c.get("url","")))}</a></li>'
            for c in cuentas
        ) or "<li>(ninguna cuenta enlazada)</li>"
        grav_html = f"""<h2>Perfil Gravatar</h2>
        <dl>
          <dt>Nombre</dt><dd>{html.escape(str(perfil.get('nombre') or '-'))}</dd>
          <dt>Ubicacion</dt><dd>{html.escape(str(perfil.get('ubicacion') or '-'))}</dd>
          <dt>Sobre mi</dt><dd>{html.escape(str(perfil.get('sobre_mi') or '-'))}</dd>
        </dl>
        <h2>Cuentas enlazadas en Gravatar</h2>
        <ul class="subs">{cuentas_html}</ul>"""
    else:
        grav_html = "<h2>Perfil Gravatar</h2><p>Sin perfil publico de Gravatar.</p>"

    if not brechas.get("consultado"):
        br_html = f"<h2>Brechas de datos</h2><p>No consultado ({html.escape(str(brechas.get('motivo','')))}).</p>"
    elif brechas.get("brechas"):
        items = "".join(f"<li>{html.escape(str(b))}</li>" for b in brechas["brechas"])
        br_html = f"<h2>Brechas de datos (HIBP)</h2><ul class='subs'>{items}</ul>"
    else:
        br_html = "<h2>Brechas de datos (HIBP)</h2><p>Sin brechas conocidas.</p>"

    return resumen + dominio_html + grav_html + br_html


def generar_html(resultado, carpeta="output"):
    modulo = resultado.get("modulo", "?")
    objetivo = resultado.get("objetivo", "")
    fecha = resultado.get("fecha", datetime.now().isoformat(timespec="seconds"))

    if modulo == "username":
        cuerpo_datos = _cuerpo_username(resultado)
    elif modulo == "dominio":
        cuerpo_datos = _cuerpo_dominio(resultado)
    elif modulo == "dominio":
        cuerpo_datos = _cuerpo_dominio(resultado)
    elif modulo == "email":
        cuerpo_datos = _cuerpo_email(resultado)
    else:
        cuerpo_datos = "<p>Modulo sin plantilla de informe.</p>"

    cabecera = f"""
    <header class="report">
      <h1>Informe OSINT &mdash; {html.escape(objetivo)}</h1>
      <p class="meta">Modulo: {html.escape(modulo)} &middot; Generado: {html.escape(fecha)}</p>
    </header>"""

    os.makedirs(carpeta, exist_ok=True)
    seguro = objetivo.replace("@", "_at_").replace("/", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta = os.path.join(carpeta, f"{seguro}_{modulo}_{ts}.html")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(_shell(f"Informe OSINT - {objetivo}", cabecera + cuerpo_datos))
    return ruta