import socket
import threading
import ssl
from user_manager import UserManager
import json
import time
import os
from datetime import datetime

HOST = '0.0.0.0' # Interfaz por la que escucha el servidor (0.0.0.0 indica que en todas)
PORT = 11002 # Puerto por el que escucha

#Archivos externos que usaremos
SESSIONS_LOG = "sessions.log"
ERROR_LOG = "error.log"
FILE_BLOC = 'usuarios_bloqueados.json'
CHAT_HISTORY_FILE = "chat_history.json"

#Gestor de base de datos
user_manager = UserManager()

users_bloq = {} # Almacenamiento de usuarios bloqueados
sesiones = {} # Diccionario para mapear direcciones a usuarios logueados
login_attempts= {} # Diccionario para contar los intentos de login por usuario
intentos = 3 # Número máximo de intentos de login
clients = {}  # addr: conn

# ---Estas son las funciones de log---
def log_session_event(evento: str):
    ahora = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]") # Formato de fecha y hora
    with open(SESSIONS_LOG, "a") as f:
        f.write(ahora + evento + "\n") # Escribimos en el log la hora y el evento

def log_error(error: str):
    ahora = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]") # Formato de fecha y hora
    with open(ERROR_LOG, "a") as f: 
        f.write(ahora + error + "\n") # Escribimos en el log la hora y el error

def almacena_bloqueado():
    try:
        if os.path.exists(FILE_BLOC):
            # abrimos el archivo para escribir
                with open(FILE_BLOC,'w') as f :
                    # vertemos el contenoido en formato json en el archivo a escribir 
                    json.dump(users_bloq, f, indent=2)
    except Exception as e :
        # mensaje de error por fallo
        print(f'Error cargando usuarios bloqueados!!! {e}')

def comprobar_bloqueado(user,):
    desbloqueada = False
    print(os.path.exists(FILE_BLOC))
    try:
        if os.path.exists(FILE_BLOC):
            # abrimos el archivo para escribir
                with open(FILE_BLOC,'r') as f :
                    #print("Aquí")
                    file_js = json.load(f)
                    #print(file_js)
                    if user not in file_js:
                        # si el usuario no está en bloqueos desbloqueo
                        desbloqueada = True
                    else:
                        # comrprobación de si se ha pasado el tiempo de bloqueo
                        ti = file_js[user]
                        tf = time.time()
                        t = tf - ti
                        if t >= 7200 :
                            # usuario desbloqueado
                            desbloqueada = True
                            # eliminamos el usuario bloqueado
                            del file_js[user]
                            try:
                                with open(FILE_BLOC,'w') as f :
                                    json.dump(file_js, f, indent=2)
                            except Exception as e :
                                # mensaje de error por fallo
                                print(f'Error al eliminar usuarios bloqueados!!! {e}')

        return desbloqueada
    except Exception as e :
        # mensaje de error por fallo
        print(f'Error cargando usuarios bloqueados!!! {e}')
        return desbloqueada

def send_message(conn, data):
    #Envía un diccionario JSON al servidor
    msg = json.dumps(data) + "\n"
    conn.sendall(msg.encode())

# ---Manejo de clientes---
def handle_client(conn, addr):

    # Hilo que maneja la conexión con un cliente concreto el de {addr}
    print(f"[+] Cliente con ip {addr} se ha conectado")
    buffer = ""
    try:
        with conn:
            while True:
                # Recibimos la instrucción del cliente
                data = conn.recv(1024)
                if not data: # Si no hay datos, el cliente se ha desconectado
                    break
                buffer += data.decode()

                # Los mensajes vienen al final con un salto de línea. Si se llega al salto de linea es el fin del mensaje
                while '\n' in buffer:

                    #Procesamos el mensaje uno a uno
                    mensaje, buffer = buffer.split('\n',1)

                    if mensaje.strip():
                        try:
                            #Parseamos el mensaje JSON
                            obj = json.loads(mensaje)
                            print(f"[{addr}] Mensaje de JSON: {obj}")

                            accion = obj.get("accion")

                            resp = {}

                            # ---Registro de usuario---
                            if accion == "register":
                                ok, msg = user_manager.register_user(obj["username"], obj["password"]) #Registrar usuario
                                resp = {"status": "OK" if ok else "ERROR", "mensaje": msg}
                                if ok:
                                    resp = {"status": "OK", "mensaje":msg}
                                else:
                                    resp = {"status":"ERROR", "mensaje":msg}
                                    log_error(f"[ERROR] por parte de {addr}: {msg}")

                            # ---Login del usuario---
                            elif accion == "login":
                                # ver que el usuario no está bloqueado
                                
                                if not comprobar_bloqueado(obj["username"]): 

                                    resp = {"status": "ERROR", "mensaje": "Usuario bloqueado"}
                                # en caso contario
                                else:
                                    # ver que el usuario no se ha logeado ya
                                    if addr not in sesiones: 
                                        if obj["username"] not in login_attempts: # si el usuario no lo ha intentado antes 
                                            login_attempts[obj["username"]] = 0 # establecemos el contador de intentos para el usuario a 0
                                            # Log de error 
                                            log_error(f"[ERROR] por parte de {obj['username']} desde {addr}, usuario ya bloqueado")
                                        # establecemos un número de intentos maximo
                                        
                                        # verificamos las credenciales
                                        ok, msg = user_manager.verify_credenciales(obj["username"], obj["password"]) #Verificar si usuario y contraseña son correctos
                                        if ok:
                                                # loggin ecitoso asociamos al addres al username
                                                sesiones[addr] = obj["username"]
                                                login_attempts[addr] = 0 # Contador a 0
                                                #lo añadimos al log de sesion
                                                log_session_event(f"[LOGIN SUCCESS] {obj['username']} desde {addr}")
                                                #La respuesta 
                                                resp = {"status": "OK", "mensaje": msg}
                                                clients[addr] = conn
                                        else:
                                                # incrementamos el contador porque ha fallado
                                                print(login_attempts)
                                                login_attempts[obj["username"]] += 1
                                                # variables de intentos restantes para avisar
                                                intentos_restantes = intentos - login_attempts[obj["username"]]
                                                # si el numero de intentos es mayor 
                                                if intentos_restantes == 0 :
                                                    # Enviamos respuesta
                                                    resp = {"status": "ERROR", "mensaje": "Demasiados intentos fallidos, la cuenta queda bloqueada temporalmente"}
                                                    # Informamos en el log del bloqueo
                                                    log_session_event(f"[Bloqueo] Demasiados intentos fallados desde {addr}")
                                                    # Añadimos al log de errores
                                                    log_error(f"[ERROR] por parte de {obj['username']} desde {addr}, la cuenta queda bloqueada temporalmente")
                                                    # añadimos usuarios al blqueo temporal
                                                    users_bloq[obj['username']] = time.time() 
                                                    almacena_bloqueado()
                                                else : 
                                                    resp = {"status": "ERROR", "mensaje": f"{msg}, Le queda {intentos_restantes} intentos restantes, por favor intentelo de nuevo"}
                                                    # Añadimmos al log de sesion
                                                    log_session_event(f"[LOGIN FAIL] {obj['username']} desde {addr}, {intentos_restantes} intentos restantes")
                                                    # Añadimos al log de errores
                                                    log_error(f"[ERROR] por parte de {obj['username']} desde {addr}, fallo de login {msg}")
                                    else:
                                        resp = {"status": "ERROR", "mensaje": "Ya hay una sesión activa"}
                                        log_error(f"[ERROR] por parte de {obj['username']} desde {addr}, fallo de login {msg}")       
                            
                            #solicitar petición de transacción para generar un nonce
                            elif accion == "chat":
                                if addr in sesiones:
                                    # reenviar a todos los clientes conectados
                                    usuario = sesiones[addr]
                                    texto = obj.get("texto", "").strip()
                                    # Construir mensaje
                                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    msg_obj = {"tipo": "chat", "from": usuario, "texto": texto, "ts": ts}

                                    # Guardar en historial
                                    chat_history = {"from": usuario, "texto": texto, "ts": ts}
                                    try:
                                        with open(CHAT_HISTORY_FILE, "w") as f:
                                            json.dump(chat_history, f, indent=2)
                                    except Exception as e:
                                        log_error(f"[ERROR] Guardando chat: {e}")

                                    # Broadcast a todos los clientes conectados
                                    for c_addr, c_conn in clients.items():
                                        try:
                                            c_conn.sendall((json.dumps(msg_obj) + "\n").encode())
                                        except Exception as e:
                                            log_error(f"[ERROR] enviando chat a {c_addr}: {e}")
                                else:
                                    resp = {"status":"ERROR", "mensaje":"Debes iniciar sesión para chatear"}


                            # ---Logout del usuario---
                            elif accion == "logout":
                                if addr in sesiones:
                                    usuario = sesiones[addr] #Sacamos el usuario que se va a deslogear
                                    del sesiones[addr] #Eliminamos la sesión
                                    log_session_event(f"[LOGOUT] {usuario} desde {addr}") #Guardamos en el log la acción
                                    resp = {"status": "OK", "mensaje": "Sesión cerrada"}
                                    clients.pop(addr, None)

                                else:
                                    resp = {"status": "ERROR", "mensaje": "No estabas logado"}
                                    log_error(f"[ERROR] intento de desloggeo sin estar logeado") #Guardamos en el log el error

                            conn.sendall((json.dumps(resp) + "\n").encode()) # Enviamos la respuesta al cliente

                        except Exception as e2:
                            print(f"[!] Ha sucedido un error JSON con {addr}: {e2}")
                            log_error(f"[FATAL ERROR] Ha sudecido un error JSON con {addr}: {e2}") #Guardamos en el log el error

    except Exception as e:
        print(f"[!] Ha sucedido un error con {addr}: {e}")
        log_error(f"[FATAL ERROR] Ha sudecido un error con {addr}: {e}") #Guardamos en el log el error
    finally:
        usuario = sesiones.pop(addr, None) #Eliminamos la sesión si existe
        clients.pop(addr, None) # Eliminamos el cliente de la lista de clientes conectados
        if usuario:
            log_session_event(f"[LOGOUT] {usuario} (desconexión inesperada) desde {addr}")  #Guardamos en el log del logout inesperado
        print(f"[-] Cliente con ip {addr} se ha desconectado")

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    ## SEÑORITO EDU, aquí hay que poner los certificados
    ##lo he investigado es así, pero quiero que lo mires tu mejor
    #context.load_cert_chain(certfile="path/to/certfile", keyfile="path/to/keyfile")
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass

    #Arranque de servidor y aceptación de conexiones
    #Creamos el socket TCP (AF_INET = IPv4, SOCK_STREAM = TCP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        # Permitimos reutilizar la dirección/puerto inmediatamente tras cerrar el servidor.
        # Sin esto, al reiniciar rápido puede saltar "Address already in use".
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Asociamos el socket a la dirección IP (HOST) y puerto (PORT) definidos en el programa.
        # Esto "reserva" el puerto para nuestro servidor.
        s.bind((HOST, PORT))

        # Ponemos el socket en modo escucha.
        # El argumento "300" es la cola máxima de conexiones pendientes antes de ser aceptadas.
        s.listen(300)
        print(f"[Servidor] Escuchando en {HOST}:{PORT}")

        # ---Bucle principal de aceptación de conexiones---
        with context.wrap_socket(s, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.daemon = True
                thread.start()
                print(f"[=] Clientes activos: {threading.active_count() - 1}")
        



if __name__ == "__main__":
    main()
