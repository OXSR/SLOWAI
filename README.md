# SLOWAI
Slowloris combine AI

Slowai es una herramienta que combina el ataque DoS Slowloris con IA para determinar y ajustar el tiempo de ataque para una mayor precisión. 


Junto a la ejecución de scripts avanzados de NMAP, se detecta si el servidor cuenta con un WAF activo o no, en caso de contar con uno, la IA, analiza y toma medidas para su evasión, por lo contrario, la IA continuará con el ataque slowloris supervisando constantemente el ataque para así ajustar la frecuencia y conexiones.


----


Slowai is a tool that combines the Slowloris DoS attack with AI to determine and adjust attack timing for greater precision.

Alongside the execution of advanced NMAP scripts, it detects whether the server has an active WAF (Web Application Firewall). If a WAF is detected, the AI analyzes and takes measures for evasion. Otherwise, the AI continues the Slowloris attack while constantly monitoring it to adjust the frequency and connections as needed.


Uso de ejemplo / Example Usage: python .\main.py -p 80 http://testphp.vulnweb.com/ -f 200 --no-tor
