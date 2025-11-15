# 🎣 Python URL Phishing Detector

## 🛡️ Propósito del Proyecto

Esta es una herramienta de ciberseguridad desarrollada en Python para analizar URLs y calcular una **puntuación de riesgo de phishing** basada en patrones y anomalías conocidas. Es un componente clave de mi portfolio que demuestra mi habilidad para aplicar la lógica de seguridad y el análisis de datos.

## 🚀 Características Clave

- **Análisis de Seguridad:** Evalúa si la URL utiliza HTTPS.
- **Detección de Anomalías:** Puntúa el riesgo basándose en la longitud del dominio, el número de subdominios y la presencia de caracteres sospechosos (@).
- **Inteligencia de Amenazas:** Utiliza la librería `python-whois` para verificar la antigüedad del dominio (los dominios muy jóvenes suelen ser maliciosos y temporales).
- **Informe Interactivo:** Proporciona un informe claro con un nivel de alerta (BAJO, MEDIO, ALTO) y las anomalías específicas encontradas.

## 🛠️ Tecnologías Utilizadas

- **Lenguaje:** Python 3.x
- **Librerías Clave:**
  - `urllib.parse`: Para la extracción y análisis de componentes de la URL.
  - `python-whois`: Para consultar la información de registro del dominio.
  - `colorama`: Para el output con formato de color en la terminal.

## ⚙️ Instalación y Ejecución

Sigue estos pasos para poner en marcha el detector en tu entorno local.

### Requisitos

Necesitas tener **Python 3** instalado en tu sistema.

### 1. Clonar el Repositorio

```bash
git clone [https://docs.github.com/es/repositories/creating-and-managing-repositories/quickstart-for-repositories](https://docs.github.com/es/repositories/creating-and-managing-repositories/quickstart-for-repositories)
cd phishing-detector

```
