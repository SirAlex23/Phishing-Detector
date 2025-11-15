const riskRules = {
  NO_HTTPS: 10,
  LONG_DOMAIN: 5,
  SUSPICIOUS_AT: 15,
  SUBDOMAIN_PENALTY: 3,
};

function analyzeUrl(url) {
  let riskScore = 0;
  const anomalies = [];

  // 1. Verificar el esquema (http vs https)
  if (!url.startsWith("https://")) {
    riskScore += riskRules.NO_HTTPS;
    anomalies.push("URL no usa HTTPS (Riesgo alto).");
  }

  try {
    // Aseguramos que la URL tiene un protocolo para que el objeto URL funcione
    const urlWithProtocol = url.includes("://") ? url : "https://" + url;
    const urlObj = new URL(urlWithProtocol);
    const domain = urlObj.hostname;

    // 2. Comprobar la longitud del dominio
    if (domain.length > 30) {
      riskScore += riskRules.LONG_DOMAIN;
      anomalies.push(`Dominio demasiado largo (${domain.length} caracteres).`);
    }

    // 3. Caracteres especiales sospechosos (@)
    if (domain.includes("@")) {
      riskScore += riskRules.SUSPICIOUS_AT;
      anomalies.push(
        "Uso del caracter '@' en el dominio (típico de phishing)."
      );
    }

    // 4. Número de subdominios
    const parts = domain.split(".");
    // Consideramos más de 3 partes como sospechoso (ej: sub.domain.com)
    if (parts.length > 3) {
      const extraSubdomains = parts.length - 3;
      riskScore += extraSubdomains * riskRules.SUBDOMAIN_PENALTY;
      anomalies.push(`Demasiados subdominios (${parts.length} encontrados).`);
    }
  } catch (e) {
    anomalies.push("ERROR: La URL no tiene un formato válido.");
    riskScore += 20;
  }

  return { score: riskScore, anomalies: anomalies };
}

// Lógica de interacción y visualización del HTML
function checkPhishing() {
  const urlInput = document.getElementById("url-input").value.trim();
  const resultDiv = document.getElementById("result");

  if (!urlInput) {
    resultDiv.innerHTML =
      '<p style="color: var(--muted);">Por favor, introduce una URL para analizar.</p>';
    return;
  }

  const { score, anomalies } = analyzeUrl(urlInput);

  let riskLevel;
  let color;

  if (score < 10) {
    riskLevel = "BAJO";
    color = "green";
  } else if (score < 25) {
    riskLevel = "MEDIO";
    color = "orange";
  } else {
    riskLevel = "ALTO";
    color = "red";
  }

  let outputHTML = `
        <h3>Análisis de: ${urlInput}</h3>
        <p>Puntuación de Riesgo: <strong>${score}</strong></p>
        <p>Nivel de Alerta: <strong style="color: ${color};">${riskLevel}</strong></p>
    `;

  if (anomalies.length > 0) {
    outputHTML += "<h4>Anomalías Encontradas:</h4><ul>";
    anomalies.forEach((anomaly) => {
      outputHTML += `<li>${anomaly}</li>`;
    });
    outputHTML += "</ul>";
  } else {
    outputHTML +=
      '<p style="color: green;">No se encontraron anomalías evidentes.</p>';
  }

  resultDiv.innerHTML = outputHTML;
}
