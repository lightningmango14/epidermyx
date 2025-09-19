console.log("[app.js] loaded at", new Date().toISOString());

// Small helper to post a FormData and safely parse JSON if present
async function postForm(url, formData) {
  const res = await fetch(url, { method: "POST", body: formData });
  const contentType = res.headers.get("content-type") || "";
  const text = await res.text(); // read the body once

  if (!res.ok) {
    // Show first part of the body to help debugging (404 pages are often HTML)
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  // Return JSON if server sent JSON; otherwise return raw text
  return contentType.includes("application/json") ? JSON.parse(text) : text;
}

async function classifyFile(file) {
  const out = document.getElementById("out");
  out.textContent = "Subiendo y clasificando…";
  

  const fd = new FormData();
  fd.append("imagen", file, file.name);

  try {
    // ⬇️ IMPORTANT: call the API route under /api/
    const json = await postForm("/api/hf-classify", fd);

    if (!json || json.ok === false) {
      throw new Error((json && json.error) || "Respuesta inválida del servidor");
    }

    // Render predictions
    const lines = (json.predictions || []).map(
      (p) => `${p.label}: ${(p.score * 100).toFixed(1)}%`
    );
    out.textContent = [
      `Modelo: ${json.model}`,
      ...(lines.length ? lines : ["(sin predicciones)"]),
    ].join("\n");
  } catch (err) {
    out.textContent = `Error: ${err.message}`;
    console.error(err);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("file");
  const btn = document.getElementById("go");

  btn?.addEventListener("click", () => {
    const f = fileInput?.files?.[0];
    if (!f) return alert("Elige una imagen primero");
    classifyFile(f);
  });
});
