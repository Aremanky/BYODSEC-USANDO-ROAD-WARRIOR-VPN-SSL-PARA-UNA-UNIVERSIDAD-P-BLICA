import socket
import json
import ssl
import getpass
import threading
import sys

HOST = '127.0.0.1' #Dirección del servidor
PORT = 11002 #puerto del servidor
MAX_MSG_LEN = 144

def crate_ssl_connection():
    #Crea y devuelve un socket SSL conectado al servidor
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    #EDU GUAPO AQUÍ VA el certificado de la CA (para validar el del servidor)
    
    #Ahí lo llevas rey 👑
    
    # Te doy una pista context.load_verify_locations(cafile="path/to/ca.crt")
    context.load_verify_locations(cafile="ca.crt") #Certificado del autoridad certificadora

    context.check_hostname = True   #Compara el nombre de server:_hostname
    context.verify_mode = ssl.CERT_REQUIRED # Cuando lo tengas, cámbialo a context.verify_mode = ssl.CERT_REQUIRED

    sock = socket.create_connection((HOST, PORT))
    ssl_sock = context.wrap_socket(sock, server_hostname=HOST)
    print("[Cliente] Conectado al servidor")
    return ssl_sock

def send_message(conn, data):
    #Envía un diccionario JSON al servidor
    msg = json.dumps(data) + "\n"
    conn.sendall(msg.encode())

def receiver_loop(conn, stop_event):
    """
    Hilo receptor: recibe datos del servidor, los concatena en buffer
    y muestra cada mensaje JSON terminado en '\n'.
    """
    buffer = ""
    try:
        while not stop_event.is_set():
            data = conn.recv(4096)
            if not data:
                print("[Cliente] Conexión cerrada por el servidor.")
                stop_event.set()
                break
            buffer += data.decode(errors="ignore")
            while '\n' in buffer:
                mensaje, buffer = buffer.split('\n', 1)
                if not mensaje.strip():
                    continue
                try:
                    obj = json.loads(mensaje)
                    # Si el servidor reenvía mensajes de chat, esperamos campos tipo:
                    # {"tipo":"chat","from":"usuario","texto":"...","ts":"..."}
                    # Si es una respuesta al cliente (status/mensaje) la mostramos igualmente.
                    if obj.get("tipo") == "chat":
                        # Impresión limpia del chat
                        print(f"\n[{obj.get('ts','?')}] {obj.get('from','anon')}: {obj.get('texto')}")
                    else:
                        # Mensajes de control / respuestas
                        if not obj == {}:
                            print(f"\n[Servidor] {obj}")
                except json.JSONDecodeError:
                    # Mensaje no JSON: imprimir crudo
                    print("\n[Servidor] (no-json) " + mensaje)
    except Exception as e:
        if not stop_event.is_set():
            print(f"[Receiver] Error: {e}")
            stop_event.set()


def menu():
    print("""
    @--------CLIENTE VPN SSL ROAD WARRIOR----------@
    |                                              |
    |    [1] Registrarse                           |
    |    [2] Iniciar sesión                        |
    |    [3] Enviar mensaje (chat)                 |
    |    [4] Cerrar sesión                         |
    |    [5] Salir                                 |
    |                                              |           
    @----------------------------------------------@
    """)
    return input("Elige una opción: ")

def chat_mode(conn):
    """
    Modo chat: bucle de entrada continua. Salir con Ctrl+C o escribiendo '/exit'.
    No cierra la conexión ni hace logout; vuelve al menú principal.
    """
    print("\n[Modo chat] Escribe tus mensajes. Salir: Ctrl+C o '/exit'\n")
    try:
        while True:
            texto = input("> ")

            if texto.strip() == "":
                # ignorar líneas vacías
                continue

            # opción alternativa para salir escribiendo un comando
            if texto.strip().lower() == "/exit":
                print("[Saliendo del modo chat]\n")
                break

            if len(texto) > MAX_MSG_LEN:
                print(f"Mensaje demasiado largo. Máximo {MAX_MSG_LEN} caracteres.")
                continue

            # Construimos y enviamos el mensaje de chat
            msg = {"accion": "chat", "texto": texto}
            try:
                send_message(conn, msg)
            except Exception as e:
                print(f"[Error al enviar mensaje] {e}")
                # si hay error grave en socket, salimos del modo chat
                break

    except KeyboardInterrupt:
        # Capturamos Ctrl+C dentro del modo chat para volver al menú sin cerrar el cliente
        print("\n[Saliendo del modo chat]\n")
        # no hacemos logout automático; volvemos al menú
        return

def main():
    
    try:
        s = crate_ssl_connection()
    except Exception as e:
        print(f"Error al conectar/validar certificados: {e}")
        return

    stop_event = threading.Event()
    recv_thread = threading.Thread(target=receiver_loop, args=(s, stop_event), daemon=True)
    recv_thread.start()

    try:
         # ---Bucle para realizar multiples acciones---
        while not stop_event.is_set():
            accion = menu()
            
            #Salir del bucle
            if accion == "5":
                print("[Cliente] Cerrando conexión...")
                stop_event.set()
                break

            #Registro del usuario
            if accion == "1":
                username = input("Nuevo usuario: ")#Pedimos el usuario
                password = getpass.getpass("Contraseña: ")#Pedimos la contraseña
                msg = {"accion": "register", "username": username, "password": password}
                send_message(s, msg)

            #Login del usuario
            elif accion == "2":
                username = input("Usuario: ")#Pedimos el usuario
                password = getpass.getpass("Contraseña: ")#Pedimos la contraseña
                msg = {"accion": "login", "username": username, "password": password}
                send_message(s, msg)

            elif accion == "3":
                # Envío de chat broadcast
                chat_mode(s)

            #Logout del usuario
            elif accion == "4":
                # Logout local: pedimos al servidor cerrar la sesión
                msg = {"accion": "logout"}
                send_message(s, msg)

            else:
                print("Acción no reconocida.")
                continue

    except KeyboardInterrupt:
        print("\n[Cliente] Interrumpido por teclado.")
        stop_event.set()
    finally:
        try:
            s.close()
        except:
            pass
        print("[Cliente] Cerrado. Adiós.")

if __name__ == "__main__":
    main()
