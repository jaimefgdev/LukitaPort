"""
Genera las capturas del README (docs/scan.png y docs/audit.png).

    python scripts/screenshots.py

Solo usa 127.0.0.1: levanta en esta misma máquina unos servicios de prueba
(un servidor web y tres que responden con un banner) y un LukitaPort local, y
escanea ÚNICAMENTE ese rango de puertos del propio equipo. Nunca se escanea
ningún host externo. Los servicios usan sus puertos habituales (21, 22, 25 y
80), así que deben estar libres; en Linux hacen falta permisos para puertos
por debajo de 1024 (p. ej. sudo).

Requiere las dependencias de desarrollo (Playwright) y su Chromium:
    pip install -r requirements-dev.txt && playwright install chromium
"""

from __future__ import annotations

import http.server
import os
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
DOCS = RAIZ / "docs"
TOKEN = "demo-token-solo-para-capturas"  # noqa: S105 - token de un servidor local efímero
RANGO = (20, 90)
HOST_DEMO = "demo-server.lab"

# Configuración de LukitaPort para la demo (antes de importar la app).
os.environ.update({
    "LUKITA_API_TOKEN": TOKEN,
    "ALLOW_PRIVATE_IPS": "true",   # el objetivo es el propio equipo (127.0.0.1)
    "LOG_LEVEL": "WARNING",
})
sys.path.insert(0, str(RAIZ))


class _Banner(socketserver.BaseRequestHandler):
    banner = b""

    def handle(self) -> None:
        self.request.sendall(self.banner)
        time.sleep(0.5)


class _Web(http.server.BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self) -> None:
        cuerpo = b"<!doctype html><title>Demo</title><h1>Servidor de prueba</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    do_HEAD = do_GET

    def log_message(self, *_: object) -> None:
        pass


def _servir(servidor: socketserver.BaseServer) -> None:
    threading.Thread(target=servidor.serve_forever, daemon=True).start()


def servicios_de_prueba() -> list[socketserver.BaseServer]:
    socketserver.TCPServer.allow_reuse_address = True
    servidores: list[socketserver.BaseServer] = []
    for puerto, banner in ((21, b"220 ProFTPD Server (Demo) [127.0.0.1]\r\n"),
                           (22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"),
                           (25, b"220 mail.example.test ESMTP Postfix\r\n")):
        manejador = type(f"Banner{puerto}", (_Banner,), {"banner": banner})
        servidores.append(socketserver.ThreadingTCPServer(("127.0.0.1", puerto), manejador))
    servidores.append(http.server.ThreadingHTTPServer(("127.0.0.1", 80), _Web))
    for s in servidores:
        _servir(s)
    return servidores


def arrancar_lukitaport() -> tuple[str, object]:
    import uvicorn

    sys.modules["playwright.async_api"] = None  # type: ignore[assignment]  # sin capturas internas
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        puerto = s.getsockname()[1]
    servidor = uvicorn.Server(uvicorn.Config("main:app", host="127.0.0.1", port=puerto,
                                             log_level="warning", lifespan="on"))
    threading.Thread(target=servidor.run, daemon=True).start()
    limite = time.time() + 15
    while not servidor.started:
        if time.time() > limite:
            raise SystemExit("LukitaPort no arrancó")
        time.sleep(0.05)
    return f"http://127.0.0.1:{puerto}", servidor


def main() -> None:
    # El nombre real del equipo no debe salir en la captura.
    socket.gethostbyaddr = lambda ip: (HOST_DEMO, [], [ip])
    servicios = servicios_de_prueba()
    base, servidor = arrancar_lukitaport()
    from playwright.sync_api import FloatRect, Page, sync_playwright

    def caja(pagina: Page, selector: str) -> FloatRect:
        rect = pagina.locator(selector).bounding_box()
        if rect is None:
            raise SystemExit(f"No se ve {selector} en la página")
        return rect

    DOCS.mkdir(exist_ok=True)
    try:
        with sync_playwright() as p:
            navegador = p.chromium.launch()
            pagina = navegador.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=2)
            pagina.goto(f"{base}/#token={TOKEN}")
            if pagina.is_visible("#btn-accept"):
                pagina.click("#btn-accept")
            pagina.fill("#target", "127.0.0.1")
            pagina.select_option("#scan-mode", "custom")
            pagina.fill("#port-start", str(RANGO[0]))
            pagina.fill("#port-end", str(RANGO[1]))
            pagina.click("#btn-scan")
            pagina.wait_for_function(
                "() => Number(document.getElementById('st-scanned').textContent) >= "
                f"{RANGO[1] - RANGO[0] + 1}", timeout=60_000)
            pagina.wait_for_timeout(800)
            pagina.get_by_role("button", name="Abiertos", exact=True).click()
            pagina.wait_for_timeout(300)
            # 1) Formulario, resumen y puertos abiertos (hasta el final de la tabla).
            resultados = caja(pagina, "#results-panel")
            pagina.screenshot(path=str(DOCS / "scan.png"), full_page=True, clip=FloatRect(
                x=0, y=0, width=1280, height=resultados["y"] + resultados["height"] + 16))
            # 2) Auditoría HTTP automática del puerto 80 (nota y primeras cabeceras).
            pagina.locator("#audit-panel").get_by_text("Strict-Transport-Security").first.wait_for()
            auditoria = caja(pagina, "#audit-panel")
            pagina.screenshot(path=str(DOCS / "audit.png"), full_page=True, clip=FloatRect(
                x=0, y=auditoria["y"] - 16, width=1280, height=min(auditoria["height"] + 32, 720)))
            navegador.close()
    finally:
        servidor.should_exit = True  # type: ignore[attr-defined]
        for s in servicios:
            s.shutdown()
    print("Capturas generadas en docs/")


if __name__ == "__main__":
    main()
