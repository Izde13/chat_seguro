"""
Servidor de Chat Seguro

Este servidor implementa un chat multi-cliente sobre WebSockets con un canal
cifrado simétricamente (Fernet). El flujo es:

1) El servidor genera una clave simétrica (Fernet) al iniciar.
2) Cada cliente se registra enviando {"type":"register","username":...}.
3) El servidor le envía al nuevo cliente la clave simétrica (base64) para que
   cifre/descifre mensajes.
4) Los clientes envían mensajes cifrados; el servidor los valida/descifra y
   vuelve a cifrarlos para retransmitirlos a todos (broadcast).
5) Se aplican medidas de robustez: validación de tamaños, rate limiting simple
   por ventana deslizante, manejo limpio de registro/desregistro y notificaciones
   de entrada/salida de usuarios.

Exponer a través de ngrok (túnel HTTPS/WSS) resuelve el descubrimiento dinámico
para clientes externos. Ejemplo: `ngrok http 8765` y el cliente se conecta con
`wss://<subdominio>.ngrok.app`.
"""

import asyncio
import websockets
import json
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import base64

# --- Configuración de logging (formato con timestamp y nivel) ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("secure-chat-server")

# --- Parámetros de red ---
HOST = "0.0.0.0"  # Escucha en todas las interfaces
PORT = 8765       # Puerto del servidor WebSocket

# --- Límites y cotas defensivas ---
MAX_PLAINTEXT_LEN = 4096            # Máx. caracteres permitidos en mensaje ya descifrado
MAX_ENCRYPTED_LEN = 8 * MAX_PLAINTEXT_LEN  # Cota generosa para el blob cifrado
RATE_WINDOW = 2.0                   # Ventana (seg) para rate limiting
RATE_MAX_MSGS = 10                  # Máx. mensajes por ventana por cliente

# --- Estado global (válido en loop asyncio monohilo; no requiere locks) ---
encryption_key = Fernet.generate_key()  # Clave única por vida del proceso
cipher = Fernet(encryption_key)         # Cifrador simétrico
clients = set()                         # Conjunto de websockets conectados
client_names = {}                       # Mapa websocket -> nombre de usuario
rate_bucket = {}                        # Mapa websocket -> contadores de rate limiting

# --- Utilidades criptográficas y sanitización ---

def encrypt_message(message: str) -> str:
    """
    Cifra un mensaje de texto plano con la clave global y devuelve base64 (str).
    """
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message: str) -> str | None:
    """
    Intenta descifrar un mensaje (base64). Si falla, retorna None.
    Se usa para validar que el cliente envía un cifrado válido.
    """
    try:
        return cipher.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        logger.warning(f"Error al descifrar mensaje: {e}")
        return None

def sanitize_username(name: str | None) -> str:
    """
    Limpia el username: recorta, permite alfanuméricos y _-.' espacios, y limita a 32 chars.
    Retorna 'Anónimo' si viene vacío o inválido.
    """
    if not name:
        return "Anónimo"
    name = name.strip()
    filtrado = "".join(ch for ch in name if ch.isalnum() or ch in " _-.'")
    return (filtrado or "Anónimo")[:32]

async def broadcast_message(message: dict, exclude=None, echo_to_sender: bool = True):
    """
    Envía un JSON (ya listo) a todos los clientes conectados.
    - exclude: websocket a excluir (típicamente el emisor).
    - echo_to_sender: si False, no se le re-envía al emisor.
    Maneja desconexiones silenciosas para limpiar estado.
    """
    if not clients:
        return
    message_json = json.dumps(message)
    disconnected = []
    for client in clients:
        if not echo_to_sender and client == exclude:
            continue
        try:
            await client.send(message_json)
        except websockets.exceptions.ConnectionClosed:
            disconnected.append(client)
        except Exception as e:
            logger.error(f"Error enviando a un cliente: {e}")
            disconnected.append(client)
    # Limpia clientes desconectados
    for client in disconnected:
        await unregister_client(client)

def rate_limit_ok(ws) -> bool:
    """
    Rate limiting por cliente (websocket):
    - Cuenta mensajes dentro de una ventana de RATE_WINDOW segundos.
    - Rechaza si excede RATE_MAX_MSGS.
    """
    now = datetime.now()
    bucket = rate_bucket.get(ws)
    if not bucket:
        rate_bucket[ws] = {"count": 1, "window_start": now}
        return True
    window_start = bucket["window_start"]
    if (now - window_start).total_seconds() > RATE_WINDOW:
        # Reinicia ventana
        bucket["count"] = 1
        bucket["window_start"] = now
        return True
    if bucket["count"] >= RATE_MAX_MSGS:
        return False
    bucket["count"] += 1
    return True

async def register_client(websocket, name: str):
    """
    Registra un nuevo cliente:
    - Lo agrega al conjunto global.
    - Guarda su nombre y arranca su cubeta de rate limiting.
    - Envía la clave simétrica (base64) a ese cliente.
    - Notifica (broadcast) a los demás que se ha unido.
    """
    clients.add(websocket)
    client_names[websocket] = name
    rate_bucket[websocket] = {"count": 0, "window_start": datetime.now()}

    # Entregar clave simétrica (base64) al cliente
    await websocket.send(json.dumps({
        "type": "encryption_key",
        "key": base64.b64encode(encryption_key).decode(),
    }))

    # Notificar a todos menos al que se une (echo_to_sender=False)
    await broadcast_message({
        "type": "user_joined",
        "username": name,
        "timestamp": datetime.now().isoformat(),
        "message": f"{name} se ha unido al chat",
    }, echo_to_sender=False)
    logger.info(f"Cliente conectado: {name}")

async def unregister_client(websocket):
    """
    Desregistra un cliente (si existe) y notifica su salida a todos.
    Limpia estructuras auxiliares.
    """
    if websocket in clients:
        name = client_names.get(websocket, "Usuario desconocido")
        clients.remove(websocket)
        client_names.pop(websocket, None)
        rate_bucket.pop(websocket, None)
        await broadcast_message({
            "type": "user_left",
            "username": name,
            "timestamp": datetime.now().isoformat(),
            "message": f"{name} ha salido del chat",
        })
        logger.info(f"Cliente desconectado: {name}")

async def handle_client(websocket):
    """
    Ciclo principal por cliente:
    1) Espera registro inicial (JSON válido con type=register).
    2) Registra y envía lista actual de usuarios.
    3) Procesa mensajes en loop:
       - Aplica rate limiting.
       - Valida JSON, tipos y tamaños.
       - Descifra `content`, re-cifra y hace broadcast.
    4) Maneja desconexión limpia.
    """
    try:
        # 1) Registro inicial (primer mensaje debe ser el registro)
        try:
            registration_message = await websocket.recv()
            data = json.loads(registration_message)
        except json.JSONDecodeError:
            await websocket.send(json.dumps({"type": "error", "message": "JSON inválido en registro"}))
            return

        if data.get("type") != "register":
            await websocket.send(json.dumps({"type": "error", "message": "Debe registrarse primero"}))
            return

        username = sanitize_username(data.get("username"))
        await register_client(websocket, username)

        # 2) Enviar lista de usuarios conectados al recién llegado
        await websocket.send(json.dumps({"type": "user_list", "users": list(client_names.values())}))

        # 3) Loop de mensajes del cliente
        async for message in websocket:
            # Rate limiting por cliente
            if not rate_limit_ok(websocket):
                await websocket.send(json.dumps({"type": "error", "message": "Rate limit excedido. Intenta más tarde."}))
                continue

            # Validación de JSON por mensaje
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"type": "error", "message": "JSON inválido"}))
                continue

            mtype = data.get("type")
            if mtype == "chat_message":
                enc = data.get("content")
                # Validación de tipo y tamaño del blob cifrado
                if not isinstance(enc, str) or len(enc) == 0 or len(enc) > MAX_ENCRYPTED_LEN:
                    await websocket.send(json.dumps({"type": "error", "message": "Contenido inválido o demasiado grande"}))
                    continue

                # Descifrar y validar tamaño en claro
                dec = decrypt_message(enc)
                if dec is None or len(dec) == 0 or len(dec) > MAX_PLAINTEXT_LEN:
                    await websocket.send(json.dumps({"type": "error", "message": "Mensaje inválido"}))
                    continue

                # Re-cifrar y hacer broadcast (eco al emisor configurable)
                out = encrypt_message(dec)
                await broadcast_message({
                    "type": "chat_message",
                    "username": client_names.get(websocket, "?"),
                    "content": out,
                    "timestamp": datetime.now().isoformat()
                }, exclude=websocket, echo_to_sender=True)
            else:
                # Tipo no soportado en este protocolo
                await websocket.send(json.dumps({"type": "error", "message": "Tipo de mensaje no soportado"}))

    except websockets.exceptions.ConnectionClosed:
        # Desconexión esperada (cierre remoto)
        pass
    except Exception as e:
        # Cualquier otra excepción se registra para diagnóstico
        logger.error(f"Error en handle_client: {e}")
    finally:
        # Limpieza garantizada del estado del cliente
        await unregister_client(websocket)

async def main():
    """
    Punto de entrada asíncrono del servidor:
    - Muestra (solo para debug local) la clave base64.
    - Levanta el servidor WebSocket y permanece corriendo indefinidamente.
    - Sugerencia de comando ngrok para exponer WSS.
    """
    logger.info(f"Clave (solo para debug local; no loguear en prod): {base64.b64encode(encryption_key).decode()}")
    logger.info(f"Iniciando servidor en {HOST}:{PORT}")
    logger.info("Para exponer con ngrok: ngrok http 8765 (cliente debe usar wss://<subdominio>.ngrok.app)")
    async with websockets.serve(
        handle_client,
        HOST,
        PORT,
        ping_interval=20,  # Keepalives
        ping_timeout=10    # Tiempo para considerar caída
    ):
        logger.info("Servidor de chat seguro iniciado")
        await asyncio.Future()  # Mantener vivo el servidor

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Servidor detenido por el usuario")
