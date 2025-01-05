# SLOWAI

### **Herramienta Inteligente con IA para Ataques Slowloris**

**Slowai** es una herramienta avanzada que combina el ataque **Slowloris DoS** con **inteligencia artificial (IA)** para optimizar los tiempos de ataque, logrando mayor precisión y eficiencia.

Mediante el uso de **scripts avanzados de NMAP**, Slowai detecta si el servidor tiene un **WAF (Web Application Firewall)** activo. Si detecta un WAF, la IA analiza la situación y aplica medidas de evasión. En caso contrario, continúa con el ataque Slowloris mientras supervisa constantemente el proceso para ajustar dinámicamente la frecuencia y el número de conexiones.

---

## Características

- **Optimización basada en IA**: Ajusta automáticamente los parámetros del ataque en función de la respuesta del servidor y los resultados del monitoreo.
- **Detección y evasión de WAF**: Identifica la presencia de un WAF y ejecuta estrategias avanzadas para sortearlo mediante scripts de NMAP.
- **Monitoreo dinámico**: Supervisa el rendimiento del ataque en tiempo real para garantizar la eficiencia.
- **Parámetros personalizables**: Permite configurar conexiones, frecuencia y según las necesidades del usuario y la IA.

---

## Uso

### Ejemplo de Comando:
```bash
python ./main.py -p 80 http://testphp.vulnweb.com/ -f 200 --no-tor
```
---

### **Intelligent Slowloris Attack Tool**

**Slowai** is a powerful tool that combines the **Slowloris DoS attack** with **AI** to optimize attack timing for greater precision and efficiency.

By leveraging advanced **NMAP scripts**, Slowai can detect if a server has an active **WAF (Web Application Firewall)**. If a WAF is detected, the AI analyzes and takes appropriate measures for evasion. Otherwise, the AI continues the Slowloris attack, constantly monitoring the process to dynamically adjust frequency and connections for maximum effectiveness.

---

## Features

- **AI-Driven Optimization**: Automatically adjusts attack parameters based on server response and monitoring results.
- **WAF Detection and Evasion**: Detects the presence of a WAF and executes evasion strategies using advanced NMAP scripts.
- **Dynamic Monitoring**: Continuously tracks attack performance to ensure efficiency.
- **Customizable Parameters**: Supports user-defined settings for connections, frequency, and more.

---

## Usage

### Example Command:
```bash
python ./main.py -p 80 http://testphp.vulnweb.com/ -f 200 --no-tor
