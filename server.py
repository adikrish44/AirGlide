"""AirGlide experimental Windows companion. LAN-only, temporary pairing."""
import asyncio
import json
import secrets
import socket
from pathlib import Path

from aiohttp import web
import pyautogui

HOST = "0.0.0.0"
PORT = 8765
CODE = f"{secrets.randbelow(1000000):06d}"
CLIENTS = set()
ROOT = Path(__file__).parent
pyautogui.FAILSAFE = True

async def index(request):
    return web.FileResponse(ROOT / "web" / "index.html")

async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=4096, heartbeat=30)
    await ws.prepare(request)
    authorized = False
    try:
        async for message in ws:
            if message.type != web.WSMsgType.TEXT:
                continue
            try:
                data = json.loads(message.data)
                kind = data.get("type")
                if not authorized:
                    if kind == "pair" and secrets.compare_digest(str(data.get("code", "")), CODE):
                        authorized = True
                        await ws.send_json({"type": "paired"})
                    else:
                        await ws.send_json({"type": "error", "message": "Invalid pairing code"})
                        await ws.close()
                    continue
                if kind == "move":
                    dx = max(-100, min(100, float(data.get("dx", 0))))
                    dy = max(-100, min(100, float(data.get("dy", 0))))
                    pyautogui.moveRel(dx, dy, duration=0)
                elif kind == "click":
                    pyautogui.click(button="right" if data.get("button") == "right" else "left")
                elif kind == "scroll":
                    pyautogui.scroll(max(-10, min(10, int(data.get("amount", 0)))))
                elif kind == "text":
                    value = str(data.get("value", ""))[:300]
                    pyautogui.write(value, interval=0.001)
                elif kind == "key":
                    key = data.get("key")
                    if key in {"enter", "esc", "backspace", "space", "tab", "up", "down", "left", "right"}:
                        pyautogui.press(key)
            except (ValueError, TypeError, pyautogui.FailSafeException) as exc:
                await ws.send_json({"type": "error", "message": str(exc)})
    finally:
        CLIENTS.discard(ws)
    return ws

def local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "YOUR_WINDOWS_IP"
    finally:
        sock.close()

app = web.Application()
app.router.add_get("/", index)
app.router.add_get("/ws", ws_handler)
if __name__ == "__main__":
    print(f"AirGlide: http://{local_ip()}:{PORT}")
    print(f"Pairing code: {CODE}")
    print("Use on a trusted private network only. Ctrl+C to stop.")
    web.run_app(app, host=HOST, port=PORT)
