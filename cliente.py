import socket
import json
import ssl
import getpass

HOST = '127.0.0.1' #Dirección del servidor
PORT = 11002 #puerto del servidor

def crate_ssl_connection():
    #Crea y devuelve un socket SSL conectado al servidor
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    #EDU GUAPO AQUÍ VA el certificado de la CA (para validar el del servidor)
    # Te doy una pista context.load_verify_locations(cafile="path/to/ca.crt")

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE # Cuando lo tengas, cámbialo a context.verify_mode = ssl.CERT_REQUIRED

    sock = socket.create_connection((HOST, PORT))
    ssl_sock = context.wrap_socket(sock, server_hostname=HOST)
    print("[Cliente] Conectado al servidor")
    return ssl_sock

def send_message(conn, data):
    #Envía un diccionario JSON al servidor
    msg = json.dumps(data) + "\n"
    conn.sendall(msg.encode())

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

def main():
    
    try:
        s = crate_ssl_connection()
        print("[Cliente] Conexión SSL establecida.")

        # ---Bucle para realizar multiples acciones---
        while True:

            accion = menu()

            #Salir del bucle
            if accion == "5":
                print("[Cliente] Cerrando conexión...")
                break

            #Registro del usuario
            if accion == "1":
                username = input("Nuevo usuario: ") #Pedimos el usuario
                password = getpass.getpass("Contraseña: ") #input("Contraseña: ") #Pedimos la contraseña
                msg = {"accion": "register", "username": username, "password": password} 

            #Login del usuario
            elif accion == "2":
                username = input("Usuario: ") #Pedimos el usuario
                password = getpass.getpass("Contraseña: ") #Pedimos la contraseña
                passwd = [] #Limpiamos la lista por si acaso (Por dios que vergüenza)
                passwd.append(password) #Guardamos la contraseña en la lista para usarla luego en el cálculo del hmac
                msg = {"accion": "login", "username": username, "password": password}

            elif accion == "3":
                pass # 

            #Logout del usuario
            elif accion =="4":
                passwd = [] #Si hay deslogueo, limpiamos la lista de la contraseña
                msg = {"accion": "logout"}

            else:
                print("Acción no reconocida.")
                continue
            
            # enviamos el mensaje
            s.sendall((json.dumps(msg)+ '\n').encode())

            # recibimos respuesta
            resp = s.recv(1024)
            print(f"[Cliente] Respuesta del servidor: {resp.decode()}")

    except Exception as e:
        print(f"Error al cargar los certificados: {e}")

        
        


        

if __name__ == "__main__":
    main()