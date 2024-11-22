import subprocess
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def genera_chiavi():
    try:
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-out', 'chiave_privata.pem', '-pkeyopt', 'rsa_keygen_bits:2048'], check=True)
        subprocess.run(['openssl', 'rsa', '-pubout', '-in', 'chiave_privata.pem', '-out', 'chiave_pubblica.pem'], check=True)
        print("Chiavi RSA generate correttamente.")
    except subprocess.CalledProcessError as e:
        print("Errore nella generazione delle chiavi:", str(e))

def carica_chiavi():
    try:
        with open('chiave_privata.pem', 'rb') as file_chiave:
            chiave_privata = serialization.load_pem_private_key(file_chiave.read(), password=None, backend=default_backend())
        with open('chiave_pubblica.pem', 'rb') as file_chiave:
            chiave_pubblica = serialization.load_pem_public_key(file_chiave.read(), backend=default_backend())
        return chiave_privata, chiave_pubblica
    except FileNotFoundError:
        print("File della chiave non trovato. Genera prima le chiavi.")
        return None, None
    except Exception as e:
        print("Errore nel caricamento delle chiavi:", str(e))
        return None, None

def cripta_messaggio(messaggio, chiave_pubblica):
    try:
        criptato = chiave_pubblica.encrypt(messaggio.encode(), padding.PKCS1v15())
        return base64.b64encode(criptato).decode('utf-8')
    except Exception as e:
        print("Errore nella criptazione del messaggio:", str(e))
        return None

def decripta_messaggio(criptato, chiave_privata):
    try:
        decriptato = chiave_privata.decrypt(base64.b64decode(criptato), padding.PKCS1v15())
        return decriptato.decode('utf-8')
    except Exception as e:
        print("Errore nella decriptazione del messaggio:", str(e))
        return None

def firma_messaggio(messaggio, chiave_privata):
    try:
        firma = chiave_privata.sign(messaggio.encode(), padding.PKCS1v15(), hashes.SHA256())
        return base64.b64encode(firma).decode('utf-8')
    except Exception as e:
        print("Errore nella firma del messaggio:", str(e))
        return None

def verifica_firma(messaggio, firma, chiave_pubblica):
    try:
        chiave_pubblica.verify(base64.b64decode(firma), messaggio.encode(), padding.PKCS1v15(), hashes.SHA256())
        print("La firma è valida.")
    except Exception as e:
        print("La firma non è valida:", str(e))

def main():
    while True:
        print("\nMenu:")
        print("1. Genera chiavi RSA")
        print("2. Cripta un messaggio")
        print("3. Decripta un messaggio")
        print("4. Firma un messaggio")
        print("5. Verifica una firma")
        print("6. Esci")
        scelta = input("Scegli un'opzione: ")

        if scelta == '1':
            genera_chiavi()
        elif scelta in ['2', '3', '4', '5']:
            chiavi = carica_chiavi()
            if chiavi == (None, None):
                continue
            chiave_privata, chiave_pubblica = chiavi
            
            if scelta == '2':
                messaggio = input("Inserisci il messaggio da criptare: ")
                risultato = cripta_messaggio(messaggio, chiave_pubblica)
                if risultato:
                    print("Messaggio criptato:", risultato)
            elif scelta == '3':
                criptato = input("Inserisci il messaggio criptato: ")
                risultato = decripta_messaggio(criptato, chiave_privata)
                if risultato:
                    print("Messaggio decriptato:", risultato)
            elif scelta == '4':
                messaggio = input("Inserisci il messaggio da firmare: ")
                risultato = firma_messaggio(messaggio, chiave_privata)
                if risultato:
                    print("Firma:", risultato)
            elif scelta == '5':
                messaggio = input("Inserisci il messaggio originale: ")
                firma = input("Inserisci la firma: ")
                verifica_firma(messaggio, firma, chiave_pubblica)
        elif scelta == '6':
            break
        else:
            print("Opzione non valida, riprova.")

if __name__ == "__main__":
    main()
