from scapy.all import *
import string
import time

def cesar(texto, corrimiento):
    alfabeto = string.ascii_lowercase
    cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            indice = (alfabeto.index(caracter.lower()) + corrimiento) % 26
            cifrado += alfabeto[indice].upper() if caracter.isupper() else alfabeto[indice]
        else:
            cifrado += caracter
    return cifrado

def obtener_silabas_comunes():
    return ["ada", "de", "eso", "la", "en", "te", "se", "por", "con", "una", "para", "el","to","bal","cri",
            "que","me","es","omo","mb","nv","para", "el","oso","cion","fia","ro","ta", "ma", "ri", "co", 
            "lo", "to", "ti", "na", "do", "ra", "si", "no", "al", "le", "me", "es", "os", "as", "us", "en",
            "ar", "er", "ir", "or", "un", "re","ri", "ci", "cu", "ca", "mu", "mo", "po", "pa", "pi", "su",
            "fa", "ce", "va"]

def procesar_paquete(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        caracter = chr(pkt[Raw].load[0])
        if caracter == "#":  # Carácter de finalización del mensaje
            mensaje = "".join(caracteres_recibidos)
            print(f"Mensaje completo recibido: {mensaje}")
            sniffing.done = True  # Termina el sniffing
        else:
            caracteres_recibidos.append(caracter)
            sniffing.last_packet_time = time.time()  # Actualiza el tiempo del último paquete recibido

def comparar_mensajes(mensaje):
    silabas_comunes = obtener_silabas_comunes()
    mejor_puntuacion = 0
    mejor_opcion = None
    for corrimiento in range(1, 26):
        mensaje_descifrado = cesar(mensaje, corrimiento)
        puntuacion = sum(silaba in mensaje_descifrado.lower() for silaba in silabas_comunes)
        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejor_opcion = mensaje_descifrado
    print("Posibles mensajes descifrados:")
    for corrimiento in range(1, 26):
        mensaje_descifrado = cesar(mensaje, corrimiento)
        if mensaje_descifrado == mejor_opcion:
            print("\033[92m" + mensaje_descifrado + "\033[0m")  # Marca en verde el mensaje más probable
        else:
            print(mensaje_descifrado)

caracteres_recibidos = []

class Sniffing:
    def __init__(self):
        self.done = False
        self.last_packet_time = time.time()

    def sniff_packets(self):
        while not self.done:
            sniff(filter="dst 127.0.0.1 and icmp", prn=procesar_paquete, iface="Ethernet 2", timeout=1)  # Sniff por 1 segundo
            if time.time() - self.last_packet_time > 5:  # Si no se reciben paquetes en 5 segundos, termina el sniffing
                self.done = True
        print("No se recibieron paquetes durante 5 segundos. Terminando el sniffing.")

if __name__ == "__main__":
    sniffing = Sniffing()
    sniffing.sniff_packets()
    mensaje = "".join(caracteres_recibidos)
    comparar_mensajes(mensaje)