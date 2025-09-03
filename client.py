#!/usr/bin/env python3
"""
Cliente de Chat Seguro (mejorado)

Este cliente se conecta a un servidor WebSocket de chat seguro. Características:

- Obliga el uso de WSS cuando el servidor se expone con ngrok, aceptando (solo
  en demo) certificados sin verificación estricta.
- No permite escribir mensajes hasta recibir la clave simétrica del servidor.
- Cifra los mensajes salientes con Fernet y descifra los entrantes.
- UX básica en consola con feedback de eventos (unión/salida/errores).
"""

import asyncio
import websockets
import json
import threading
import base64
from cryptography.fernet import Fernet
from datetime import datetime
import ssl

class SecureChatClient:
    """
    Implementa un cliente de chat seguro:
    - Mantiene el websocket, el cifrador y el loop asyncio del hilo principal.
    - Arranca un hilo de entrada por teclado que envía mensajes al loop.
    - Sin permitir input hasta que llegue la clave del servidor (Event asyncio).
    """
    def __init__(self):
        self.websocket = None          # Conexión WebSocket activa
        self.cipher = None             # Instancia Fernet con la clave compartida
        self.username = ""             # Nombre de usuario local (solo informativo)
        self.running = False           # Bandera de ciclo de vida del cliente
        self.loop = None               # Referencia al loop asyncio principal
        self.key_received = asyncio.Event()  # Sincroniza inicio de input tras recibir clave

    def encrypt_message(self, message: str) -> str:
        """
        Cifra un mensaje de texto plano usando Fernet y lo devuelve base64 (str).
        Si aún no hay cifrador (clave), retorna el texto tal cual (fallback).
        """
        if self.cipher:
            return self.cipher.encrypt(message.encode()).decode()
        return message

    def decrypt_message(self, encrypted_message: str) -> str:
        """
        Descifra un mensaje base64 si hay cifrador; si falla, retorna una marca
        de error legible para el usuario.
        """
        if self.cipher:
            try:
                return self.cipher.decrypt(encrypted_message.encode()).decode()
            except Exception:
                return "[Mensaje cifrado - error al descifrar]"
        return encrypted_message

    async def connect(self, server_url: str, username: str):
        """
        Establece conexión con el servidor:
        - Configura SSL si es wss:// (modo demo: sin verificación estricta).
        - Envía el mensaje de registro con el username.
        - Arranca tarea de escucha y espera la clave antes de permitir input.
        """
        self.username = username
        try:
            print(f"Conectando a {server_url}...")
            ssl_context = None
            if server_url.startswith("wss://"):
                # Contexto SSL para WSS. En demo, se desactiva verificación estricta
                # para facilitar pruebas con ngrok (NO usar así en producción).
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            # Establecer WebSocket
            self.websocket = await websockets.connect(
                server_url,
                ssl=ssl_context,
                ping_interval=20,  # Keepalives
                ping_timeout=10
            )

            # Registro inicial con el servidor
            await self.websocket.send(json.dumps({"type": "register", "username": username}))
            self.loop = asyncio.get_running_loop()
            self.running = True

            print(f"✅ Conectado como {username}")
            print("Esperando clave de cifrado del servidor...\n")

            # Arranca la tarea que escucha mensajes del servidor
            listener = asyncio.create_task(self.listen_messages())

            # Bloquea input hasta que llegue la clave
            await self.key_received.wait()
            print("🔐 Canal seguro establecido. Escribe tu mensaje (o 'exit' para salir).\n")

            # Arranca el hilo de entrada por consola (no bloquea el loop)
            input_thread = threading.Thread(target=self.input_handler, daemon=True)
            input_thread.start()

            # Espera a que el listener termine (por cierre remoto u error)
            await listener

        except Exception as e:
            print(f"❌ Error de conexión: {e}")
            self.running = False

    async def listen_messages(self):
        """
        Loop asíncrono que recibe mensajes del servidor, los parsea como JSON
        y delega el manejo según el tipo ('encryption_key', 'chat_message', etc.).
        """
        try:
            async for message in self.websocket:
                data = json.loads(message)
                await self.handle_server_message(data)
        except websockets.exceptions.ConnectionClosed:
            print("\n🔌 Conexión cerrada por el servidor")
        except Exception as e:
            print(f"\n❌ Error escuchando mensajes: {e}")
        finally:
            self.running = False

    async def handle_server_message(self, data: dict):
        """
        Enruta los mensajes recibidos por tipo:
        - encryption_key: configura Fernet y habilita input.
        - chat_message: descifra contenido y lo imprime formateado.
        - user_joined / user_left: notificaciones de presencia.
        - user_list / error: información auxiliar.
        """
        mtype = data.get("type")

        if mtype == "encryption_key":
            # Configurar cifrador a partir de la clave base64 enviada por el servidor
            key_b64 = data.get("key", "")
            try:
                encryption_key = base64.b64decode(key_b64)
                self.cipher = Fernet(encryption_key)
                self.key_received.set()  # Habilita el input del usuario
            except Exception:
                print("❌ Clave inválida recibida")
            return

        if mtype == "chat_message":
            # Mensaje normal de chat: descifrar, formatear timestamp y mostrar
            username = data.get("username", "?")
            encrypted_content = data.get("content", "")
            timestamp = data.get("timestamp", "")
            content = self.decrypt_message(encrypted_content)
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_str = dt.strftime("%H:%M:%S")
            except Exception:
                time_str = ""
            print(f"[{time_str}] {username}: {content}")
            return

        if mtype == "user_joined":
            print(f"🟢 {data.get('username','?')} se unió al chat")
            return

        if mtype == "user_left":
            print(f"🔴 {data.get('username','?')} salió del chat")
            return

        if mtype == "user_list":
            users = data.get("users", [])
            print(f"👥 Usuarios conectados: {', '.join(users)}")
            return

        if mtype == "error":
            print(f"❌ Error: {data.get('message','Error desconocido')}")
            return

        # Tipo de mensaje no reconocido (útil para depurar)
        print(f"ℹ️ Mensaje desconocido: {data}")

    def input_handler(self):
        """
        Hilo dedicado a leer desde stdin y enviar por WebSocket.
        Usa run_coroutine_threadsafe para postear en el loop asyncio principal.
        Interpreta 'exit' para cerrar el cliente limpamente.
        """
        while self.running:
            try:
                message = input()
                if message.strip().lower() == "exit":
                    self.running = False
                    break
                if not self.cipher:
                    # Todavía no se recibió la clave del servidor
                    print("Aún no se ha establecido la clave. Espera un momento…")
                    continue
                if message.strip() and self.websocket and self.loop:
                    encrypted_content = self.encrypt_message(message)
                    fut = asyncio.run_coroutine_threadsafe(
                        self.websocket.send(json.dumps({"type": "chat_message", "content": encrypted_content})),
                        self.loop
                    )
                    # Espera corta para propagar errores del envío
                    try:
                        fut.result(timeout=5)
                    except Exception as e:
                        print(f"Error enviando mensaje: {e}")
            except (EOFError, KeyboardInterrupt):
                # Fin de entrada o Ctrl+C
                self.running = False
                break
            except Exception as e:
                # Cualquier otro error de input se reporta sin tumbar el cliente
                if self.running:
                    print(f"Error en input: {e}")

    async def disconnect(self):
        """
        Cierra la conexión WebSocket si sigue abierta. Idempotente.
        """
        self.running = False
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception:
                pass

async def main():
    """
    CLI mínima para el cliente:
    - Pregunta si se usará ngrok y normaliza la URL a WSS.
    - Pide username y arranca la sesión.
    """
    print("=== CLIENTE DE CHAT SEGURO ===")
    use_ngrok = input("¿Usar ngrok? (y/n): ").strip().lower() == "y"

    if use_ngrok:
        ngrok_host = input("URL de ngrok (ej: abc123.ngrok.app): ").strip()
        if not ngrok_host.startswith("https://") and not ngrok_host.startswith("wss://"):
            # Construir WSS explícito a partir de host
            server_url = f"wss://{ngrok_host}"
        else:
            # Normalizar a wss (por si pegan https/http)
            server_url = ngrok_host.replace("https://", "wss://").replace("http://", "wss://")
        print(f"👉 Usando WSS obligatorio con ngrok: {server_url}")
    else:
        # Modo local no seguro (ws://) para pruebas en LAN
        server_host = input("Host del servidor (localhost): ").strip() or "localhost"
        server_port = input("Puerto del servidor (8765): ").strip() or "8765"
        server_url = f"ws://{server_host}:{server_port}"

    username = input("Tu nombre de usuario: ").strip() or "Anónimo"
    client = SecureChatClient()

    try:
        await client.connect(server_url, username)
    except KeyboardInterrupt:
        print("\n👋 Desconectando…")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 ¡Hasta luego!")
