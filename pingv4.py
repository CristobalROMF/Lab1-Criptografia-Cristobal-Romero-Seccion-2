from scapy.all import *
import sys
import time
import random
import time
last_id = random.randint(0, 65535)
def enviar_paquete_icmp(destino, caracter,cont,icmp_id):
    timestamp_int = int(time.time())
    global last_id
    incremento = random.randint(3, 30)  # Generar un incremento aleatorio entre 3 y 30
    new_id = (last_id + incremento) % 65536  # Sumar el incremento y asegurarse de que no se exceda el rango de 16 bits
    last_id = new_id
    payload= "...................... !'#$%&'()*+,-./230!./0123456789!"
    # Construir el paquete ICMP ECHO_REQUEST con el caracter en el campo de datos
    paquete = IP(dst=destino, ttl=64, ihl=5, id=new_id)/ICMP(type=8, code=0, id=icmp_id , seq=cont )/Raw(load=(caracter + payload))
    send(paquete, iface="Ethernet 2")

def enviar_texto_icmp(destino, texto):
    cont = 1
    icmp_id = 9
    for caracter in texto:
        enviar_paquete_icmp(destino, caracter, cont,icmp_id)
        time.sleep(1)  # Esperar 1 segundo entre cada paquete ICMP
        cont += 1
        icmp_id += 1
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4.py 'texto cifrado'")
        sys.exit(1)

    destino = "127.0.0.1"  # IP de loopback
    texto_cifrado = sys.argv[1]

    enviar_texto_icmp(destino, texto_cifrado)
