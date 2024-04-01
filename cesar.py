import sys

def cifrar_cesar(texto, corrimiento):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            offset = 65 if caracter.isupper() else 97
            indice = ord(caracter) - offset
            texto_cifrado += chr((indice + corrimiento) % 26 + offset)
        else:
            texto_cifrado += caracter
    return texto_cifrado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py 'texto' <corrimiento>")
        sys.exit(1)

    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])

    texto_cifrado = cifrar_cesar(texto, corrimiento)
    print("Texto cifrado:", texto_cifrado)

