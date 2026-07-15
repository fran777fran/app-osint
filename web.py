from datetime import datetime

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from osint import MODULOS, detectar_tipo   # <- reutilizamos el orquestador
import report                              # <- reutilizamos el informe

app = FastAPI(title="Orquestador OSINT")

PAGINA_INICIO = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Orquestador OSINT</title>
<style>
  body { font-family:-apple-system,"Segoe UI",Roboto,sans-serif; background:#f5f6f8; color:#1f2329;
         display:flex; min-height:100vh; margin:0; align-items:center; justify-content:center; }
  .wrap { background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:36px 32px; width:min(520px,92vw);
          box-shadow:0 4px 24px rgba(0,0,0,.06); }
  h1 { margin:0 0 6px; font-size:22px; }
  p { color:#6b7280; margin:0 0 22px; font-size:14px; }
  input, select, button { font-size:15px; padding:11px 12px; border:1px solid #d1d5db; border-radius:8px; width:100%; }
  select { margin-top:10px; }
  button { margin-top:14px; background:#2d6cdf; color:#fff; border:none; font-weight:600; cursor:pointer; }
  button:hover { background:#255ac0; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>Orquestador OSINT</h1>
    <p>Introduce un alias, dominio o email y elige el tipo (o deja autodetectar).</p>
    <form action="/buscar" method="post">
      <input name="dato" placeholder="torvalds · espadasymas.com · correo@dominio.com · 8.8.8.8" required autofocus>
      <select name="tipo">
        <option value="auto">Autodetectar tipo</option>
        <option value="username">Username / alias</option>
        <option value="dominio">Dominio</option>
        <option value="email">Email</option>
        <option value="ip">Direccion IP</option>
      </select>
      <button type="submit">Buscar</button>
    </form>
  </div>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def inicio():
    return PAGINA_INICIO


@app.post("/buscar", response_class=HTMLResponse)
def buscar(dato: str = Form(...), tipo: str = Form("auto")):
    if tipo == "auto":
        tipo = detectar_tipo(dato)

    run = MODULOS.get(tipo)
    if run is None:
        return HTMLResponse(f"<p>No hay modulo para el tipo '{tipo}'.</p><a href='/'>&larr; Volver</a>")

    resultado = run(dato)
    resultado["fecha"] = datetime.now().isoformat(timespec="seconds")

    html_informe = report.construir_html(resultado)
    # Inyectamos un enlace para volver al formulario
    html_informe = html_informe.replace(
        '<div class="container">',
        '<div class="container"><p><a href="/">&larr; Nueva busqueda</a></p>',
        1,
    )
    return HTMLResponse(html_informe)