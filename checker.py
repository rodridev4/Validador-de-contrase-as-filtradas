import requests
import hashlib
import sys
import getpass

# Solicita los datos a la API de Have I Been Pwned
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error al conectar con la API: {res.status_code}, verifica tu conexión.')
    return res

# Lee la respuesta de la API y buscar nuestro hash
def get_password_leaks_count(hashes, hash_to_check):
    # La API devuelve las líneas como: SUFIJO:CANTIDAD (ej: 00E8B:120)
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Orquesta el hashing y la verificación
def pwned_api_check(password):
    # 1. Hashear la contraseña usando SHA-1 (estándar requerido por HIBP)
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # 2. Separar el hash: primeros 5 caracteres (prefijo) y el resto (sufijo)
    # K-Anonymity: Solo envia los primeros 5 caracteres a la API
    first5_char, tail = sha1password[:5], sha1password[5:]
    
    # 3. Consultar a la API
    response = request_api_data(first5_char)
    
    # 4. Verifica si el sufijo existe en la respuesta
    return get_password_leaks_count(response, tail)

def main():
    print("--- 🛡️  Verificador de Contraseñas Filtradas (HIBP) 🛡️  ---")
    print("Este script utiliza la API de 'Have I Been Pwned' bajo el modelo de k-Anonymity.")
    print("La contraseña NO se envía a internet, solo los primeros 5 caracteres de su hash SHA-1.")
    print("---------------------------------------------------------------")

    try:
        # Getpass para que no se vea lo que se escribe en consola
        password = getpass.getpass("Ingrese la contraseña a verificar: ")
        
        if password:
            count = pwned_api_check(password)
            if count:
                print(f"\n❌ ¡PELIGRO! Esta contraseña ha sido filtrada {count} veces.")
                print("¡Cámbiala inmediatamente!")
            else:
                print(f"\n✅ ¡BUENAS NOTICIAS! Esta contraseña no aparece en las bases de datos de filtraciones conocidas.")
        else:
            print("\n⚠️ No ingresaste ninguna contraseña.")
            
    except KeyboardInterrupt:
        print("\n\nSaliendo del programa...")
        sys.exit()

if __name__ == '__main__':
    main()