# 🎣 Python URL Phishing Detector

[![Python Badge](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Technologies Badge](https://img.shields.io/badge/Techs-WHOIS%2FColorama%2FJS-green?style=for-the-badge)](https://github.com/[tu-usuario]/Phishing-Detector)
[![Repo Size](https://img.shields.io/github/repo-size/[tu-usuario]/Phishing-Detector?style=for-the-badge)](https://github.com/[tu-usuario]/Phishing-Detector)

## 🛡️ Propósito del Proyecto

Esta es una herramienta de ciberseguridad desarrollada en **Python** para analizar URLs y calcular una **puntuación de riesgo de phishing** basada en patrones y anomalías conocidas. Es un componente clave de mi portfolio que demuestra mi habilidad para aplicar la lógica de seguridad y el análisis de datos.

## 🚀 Características Clave

* **Análisis de Seguridad:** Evalúa el uso de HTTPS.
* **Inteligencia de Amenazas (WHOIS):** Utiliza la librería `python-whois` para verificar la antigüedad del dominio (los dominios muy jóvenes suelen ser maliciosos).
* **Detección de Ofuscación:** Puntúa el riesgo basándose en la longitud del dominio, el número de subdominios y la presencia de caracteres sospechosos (`@`).
* **Informe Interactivo (CLI):** Proporciona un informe claro con un nivel de alerta (**BAJO**, **MEDIO**, **ALTO**) utilizando la librería `colorama` para un *output* profesional.

## 🛠️ Tecnologías Utilizadas

* **Lenguaje:** Python 3.x
* **Librerías Clave:**
    * `urllib.parse`: Para la extracción y análisis de componentes de la URL.
    * `python-whois`: Para consultar la información de registro del dominio.
    * `colorama`: Para el *output* con formato de color en la terminal.

## ⚙️ Instalación y Ejecución

Sigue estos pasos para poner en marcha el detector en tu entorno local (CLI).

### Requisitos

Necesitas tener **Python 3** instalado.

### 1. Clonar el Repositorio

```bash
git clone [https://docs.github.com/es/repositories/creating-and-managing-repositories/quickstart-for-repositories](https://docs.github.com/es/repositories/creating-and-managing-repositories/quickstart-for-repositories)
cd Phishing-Detector
