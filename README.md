project: Secure Chat (Python, WebSockets, Fernet, ngrok)

description: |
  Chat seguro multi-cliente implementado en Python usando WebSockets.
  El servidor genera una clave Fernet (cifrado simétrico AES-128 + HMAC-SHA256)
  y la comparte con los clientes al registrarse. Todos los mensajes se
  transmiten cifrados. El proyecto puede exponerse en Internet mediante ngrok,
  usando WSS (TLS) para asegurar el transporte.

theory:
  websockets: |
    - Protocolo full-duplex sobre TCP.
    - Permite chat en tiempo real sin abrir múltiples conexiones HTTP.
  fernet: |
    - Cifrado simétrico (AES-128/CBC + HMAC-SHA256).
    - Garantiza confidencialidad e integridad de mensajes.
    - Los mensajes viajan como tokens base64 fáciles de transportar.
  ngrok: |
    - Proporciona URL pública sin configuración de router o DNS.
    - Convierte conexiones locales en https:// → wss:// con TLS habilitado.

workflow:
  steps:
    - Servidor arranca y genera clave Fernet.
    - Cliente se conecta y envía {"type": "register", "username": "..."}.
    - Servidor responde con {"type": "encryption_key","key":"<base64>"}.
    - Cliente cifra mensajes con Fernet y los envía al servidor.
    - Servidor valida, descifra y re-cifra para hacer broadcast.
    - Otros clientes reciben y descifran los mensajes.

example_local:
  server: |
    $ python3 server.py
  client_1: |
    $ python3 client.py
    ¿Usar ngrok? (y/n): n
    Host del servidor: localhost
    Puerto: 8765
    Usuario: Alice
  client_2: |
    $ python3 client.py
    ¿Usar ngrok? (y/n): n
    Host del servidor: localhost
    Puerto: 8765
    Usuario: Bob
  interaction: |
    - Alice escribe: "Hola Bob!"
    - Bob ve: [12:34:56] Alice: Hola Bob!

run_with_ngrok:
  steps:
    - Ejecuta: python3 server.py
    - Abre túnel: ngrok http 8765
    - Copia la URL pública: https://abcd.ngrok.app
    - Cliente: selecciona "¿Usar ngrok? y" e ingresa abcd.ngrok.app

requirements:
  python: ">=3.10"
  dependencies:
    - websockets
    - cryptography
  setup: |
    $ python3 -m venv .venv
    $ source .venv/bin/activate
    $ pip install websockets cryptography

security:
  why_secure: |
    - Mensajes viajan sobre TLS (cuando se usa wss:// con ngrok).
    - Fernet cifra + autentica cada mensaje.
    - Validaciones de tamaño y rate limiting previenen abusos.
  limitation: |
    - El servidor ve los mensajes en claro (no es E2E).
    - Para E2E real se requiere intercambio de claves por cliente
      (ej. X25519) y cifrado adicional extremo a extremo.

diagram:
  architecture: |
    Cliente A ---- WSS/TLS ----> Servidor <---- WSS/TLS ---- Cliente B
       |                                              |
       +--- Mensajes Fernet cifrados -----------------+

  sequence: |
    Cliente → Servidor: {"type":"register","username":"Alice"}
    Servidor → Cliente: {"type":"encryption_key","key":"<b64>"}
    Cliente → Servidor: {"type":"chat_message","content":"<fernet>"}
    Servidor → Todos: {"type":"chat_message","username":"Alice","content":"<fernet>"}

files:
  - server.py: Servidor WebSocket, registro, validaciones, broadcast, cifrado.
  - client.py: Cliente interactivo, conexión segura, cifrado/descifrado, input por consola.

license: |
  Uso educativo y libre. Modifica y distribuye para tus talleres o laboratorios.
