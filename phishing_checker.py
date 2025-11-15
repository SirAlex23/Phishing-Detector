import re
from urllib.parse import urlparse
import whois
import datetime
from colorama import Fore, Style, init

# Inicializar colorama (para que los colores funcionen en la terminal)
init(autoreset=True)

# ----------------------------------------------------
# 1. FUNCIÓN PRINCIPAL DE ANÁLISIS
# ----------------------------------------------------

def analyze_url(url):
    """Analiza una URL para detectar características de phishing."""
    risk_score = 0
    anomalies = []
    
    # 1. Verificar el esquema (http vs https)
    if not url.startswith('https://'):
        risk_score += 10
        anomalies.append(f"{Fore.YELLOW}URL no usa HTTPS (Riesgo alto).")
    
    try:
        # Asegurarse de que la URL tiene un esquema para que urlparse funcione bien
        if '://' not in url:
            url_with_scheme = 'http://' + url 
        else:
            url_with_scheme = url
            
        parsed_url = urlparse(url_with_scheme)
        domain = parsed_url.netloc
        
        if not domain:
            raise ValueError("No se pudo extraer el dominio de la URL.")

        # 2. Comprobar la longitud del dominio
        if len(domain) > 30:
            risk_score += 5
            anomalies.append(f"{Fore.YELLOW}Dominio demasiado largo ({len(domain)} caracteres).")
            
        # 3. Caracteres especiales sospechosos (p. ej., @, - repetidos, números)
        if '@' in domain:
            risk_score += 15
            anomalies.append(f"{Fore.RED}Uso del caracter '@' en el dominio (típico de phishing).")
            
        # 4. Número de subdominios (muchos subdominios esconden la URL real)
        # Excluye el 'www' para un conteo más preciso
        clean_domain = domain.replace('www.', '')
        subdomains = clean_domain.split('.')
        
        # Consideramos normal hasta 3 partes (ej: nombre.com.es)
        if len(subdomains) > 3: 
            risk_score += (len(subdomains) - 3) * 3
            anomalies.append(f"{Fore.YELLOW}Demasiados subdominios ({len(subdomains)} encontrados).")
            
        # 5. Comprobar la edad del dominio (con WHOIS)
        try:
            w = whois.whois(domain)
            if w.creation_date:
                
                # Maneja el caso en que la fecha es una lista (varios registros)
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                    
                # Si creation_date no es un objeto datetime.date, lo convertimos
                if not isinstance(creation_date, (datetime.date, datetime.datetime)):
                    # Intentamos parsear si es una cadena de texto
                    creation_date = datetime.datetime.strptime(str(creation_date).split()[0], '%Y-%m-%d').date()
                else:
                    creation_date = creation_date.date()
                    
                age_days = (datetime.date.today() - creation_date).days
                
                # Se considera riesgo alto si el dominio es muy nuevo (menos de 90 días)
                if age_days < 90:
                    risk_score += 10
                    anomalies.append(f"{Fore.RED}Dominio muy joven ({age_days} días), riesgo de ser temporal.")
        except Exception:
            # Si WHOIS falla (a veces pasa en ciertos TLDs), lo ignoramos
            anomalies.append(f"{Fore.CYAN}No se pudo obtener la edad del dominio (WHOIS falló).")
            pass
            
    except ValueError as e:
        anomalies.append(f"{Fore.RED}ERROR: La URL no tiene un formato válido.")
        risk_score += 20 
    except Exception as e:
        anomalies.append(f"{Fore.RED}ERROR al analizar la URL: {e}")
        risk_score += 20 
        
    return risk_score, anomalies

# ----------------------------------------------------
# 2. FUNCIÓN DE EJECUCIÓN E INFORME (AHORA INTERACTIVA)
# ----------------------------------------------------

def main():
    print(f"{Fore.CYAN}{Style.BRIGHT}--- Detector de Phishing de URL ---")
    print(f"{Fore.CYAN}¡Escribe 'salir' para finalizar el análisis!")
    
    while True:
        # Pide la URL al usuario
        user_input = input("\nIntroduce la URL a analizar: ")
        
        if user_input.lower() == 'salir':
            print(f"{Fore.CYAN}Análisis finalizado. ¡Adiós!")
            break
        
        if not user_input.strip():
            continue

        url = user_input.strip()

        score, anomalies = analyze_url(url)
        
        print(f"\n{Style.BRIGHT}Análisis de: {url}{Style.RESET_ALL}")
        
        # Clasificación del riesgo
        if score < 10:
            risk_level = f"{Fore.GREEN}BAJO"
        elif 10 <= score < 25:
            risk_level = f"{Fore.YELLOW}MEDIO"
        else:
            risk_level = f"{Fore.RED}ALTO"
            
        print(f"Puntuación de Riesgo: {Style.BRIGHT}{score}{Style.RESET_ALL}")
        print(f"Nivel de Alerta: {risk_level}{Style.RESET_ALL}")
        
        if anomalies:
            print(f"{Fore.CYAN}Anomalías Encontradas:")
            for anomaly in anomalies:
                print(f" - {anomaly}")
        else:
            print(f"{Fore.GREEN}No se encontraron anomalías evidentes.")

if __name__ == "__main__":
    main()