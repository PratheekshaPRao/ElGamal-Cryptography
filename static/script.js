const primeInput = document.getElementById("primeInput");
const messageInput = document.getElementById("messageInput");
const generateButton = document.getElementById("generateButton");
const encryptButton = document.getElementById("encryptButton");
const decryptButton = document.getElementById("decryptButton");
const notice = document.getElementById("notice");

const keyValues = document.getElementById("keyValues");
const keySteps = document.getElementById("keySteps");
const encryptionValues = document.getElementById("encryptionValues");
const encryptionSteps = document.getElementById("encryptionSteps");
const decryptionValues = document.getElementById("decryptionValues");
const decryptionSteps = document.getElementById("decryptionSteps");
const resultPanel = document.getElementById("resultPanel");
const resultValues = document.getElementById("resultValues");

let keys = null;
let encrypted = null;
let decrypted = null;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[character]);
}

function resetResults() {
  keys = null;
  encrypted = null;
  decrypted = null;
  encryptButton.disabled = true;
  decryptButton.disabled = true;
  encryptionValues.innerHTML = '<p class="empty-state">Generate keys, then encrypt.</p>';
  encryptionSteps.innerHTML = "";
  decryptionValues.innerHTML = '<p class="empty-state">Encrypt a message, then decrypt.</p>';
  decryptionSteps.innerHTML = "";
  resultPanel.className = "result-panel";
  resultValues.textContent = "Complete the experiment to compare the original and decrypted messages.";
}

function showRows(container, rows) {
  container.innerHTML = rows.map(([label, value]) =>
    `<div class="value-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`
  ).join("");
}

function showSteps(container, title, steps, characterSteps = null, mode = "encrypt") {
  const list = steps.map(step => `<li>${escapeHtml(step)}</li>`).join("");
  let characterTable = "";

  if (characterSteps && characterSteps.length) {
    const body = characterSteps.map(item => {
      if (mode === "encrypt") {
        return `<tr>
          <td>${escapeHtml(item.character)}</td>
          <td>${escapeHtml(item.ascii)}</td>
          <td>${escapeHtml(item.calculation)}</td>
          <td>${escapeHtml(item.c2)}</td>
        </tr>`;
      }
      return `<tr>
        <td>${escapeHtml(item.c2)}</td>
        <td>${escapeHtml(item.calculation)}</td>
        <td>${escapeHtml(item.ascii)}</td>
        <td>${escapeHtml(item.character)}</td>
      </tr>`;
    }).join("");

    const headings = mode === "encrypt"
      ? "<th>Character</th><th>ASCII</th><th>Calculation</th><th>c2</th>"
      : "<th>c2</th><th>Calculation</th><th>Recovered value</th><th>Character</th>";

    characterTable = `<table class="character-table"><thead><tr>${headings}</tr></thead><tbody>${body}</tbody></table>`;
  }

  container.innerHTML = `
    <details open>
      <summary>${escapeHtml(title)} — show calculations</summary>
      <ol class="step-list">${list}</ol>
      ${characterTable}
    </details>`;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "The request could not be completed.");
  }
  return data;
}

generateButton.addEventListener("click", async () => {
  notice.textContent = "";
  resetResults();
  keyValues.innerHTML = '<p class="empty-state">Generating keys…</p>';
  keySteps.innerHTML = "";
  generateButton.disabled = true;

  try {
    const data = await postJson("/api/keygen", { p: primeInput.value });
    keys = data;

    showRows(keyValues, [
      ["Prime p", data.p],
      ["Generator g", data.g],
      ["Private key x", data.x],
      ["Public key y", data.y],
      ["Public key", `(${data.p}, ${data.g}, ${data.y})`]
    ]);
    showSteps(keySteps, "Key generation", data.steps);
    encryptButton.disabled = false;
  } catch (error) {
    keyValues.innerHTML = '<p class="empty-state">Key generation failed.</p>';
    notice.textContent = error.message;
  } finally {
    generateButton.disabled = false;
  }
});

encryptButton.addEventListener("click", async () => {
  if (!keys) return;

  notice.textContent = "";
  encrypted = null;
  decrypted = null;
  decryptButton.disabled = true;
  decryptionValues.innerHTML = '<p class="empty-state">Encrypt a message, then decrypt.</p>';
  decryptionSteps.innerHTML = "";
  resultPanel.className = "result-panel";
  encryptionValues.innerHTML = '<p class="empty-state">Encrypting…</p>';
  resultValues.textContent = "Complete the experiment to compare the original and decrypted messages.";
  encryptButton.disabled = true;

  try {
    const data = await postJson("/api/encrypt", {
      p: keys.p,
      g: keys.g,
      y: keys.y,
      message: messageInput.value
    });
    encrypted = data;

    showRows(encryptionValues, [
      ["Random key k", data.k],
      ["Shared key y^k mod p", data.shared_key],
      ["Ciphertext c1", data.c1],
      ["Ciphertext c2 values", `[${data.c2_values.join(", ")}]`],
      ["Complete ciphertext", JSON.stringify(data.ciphertext)]
    ]);
    showSteps(encryptionSteps, "Encryption", data.steps, data.character_steps, "encrypt");
    decryptButton.disabled = false;
    updateResult();
  } catch (error) {
    encryptionValues.innerHTML = '<p class="empty-state">Encryption failed.</p>';
    notice.textContent = error.message;
  } finally {
    encryptButton.disabled = false;
  }
});

decryptButton.addEventListener("click", async () => {
  if (!keys || !encrypted) return;

  notice.textContent = "";
  decryptionValues.innerHTML = '<p class="empty-state">Decrypting…</p>';
  decryptButton.disabled = true;

  try {
    const data = await postJson("/api/decrypt", {
      p: keys.p,
      x: keys.x,
      c1: encrypted.c1,
      c2_values: encrypted.c2_values
    });
    decrypted = data;

    showRows(decryptionValues, [
      ["Decryption shared key", data.shared_key],
      ["Modular inverse", data.inverse],
      ["Decrypted message", data.message]
    ]);
    showSteps(decryptionSteps, "Decryption", data.steps, data.character_steps, "decrypt");
    updateResult();
  } catch (error) {
    decryptionValues.innerHTML = '<p class="empty-state">Decryption failed.</p>';
    notice.textContent = error.message;
  } finally {
    decryptButton.disabled = false;
  }
});

function updateResult() {
  const original = messageInput.value;

  if (!encrypted) return;

  const ciphertext = JSON.stringify(encrypted.ciphertext);
  if (!decrypted) {
    resultPanel.className = "result-panel";
    resultValues.innerHTML = `
      <p><strong>Original message:</strong> ${escapeHtml(original)}</p>
      <p><strong>Ciphertext:</strong> ${escapeHtml(ciphertext)}</p>
      <p>Decrypt to verify the recovered message.</p>`;
    return;
  }

  const matches = original === decrypted.message;
  resultPanel.className = `result-panel ${matches ? "success" : "failure"}`;
  resultValues.innerHTML = `
    <p><strong>Original message:</strong> ${escapeHtml(original)}</p>
    <p><strong>Ciphertext:</strong> ${escapeHtml(ciphertext)}</p>
    <p><strong>Decrypted message:</strong> ${escapeHtml(decrypted.message)}</p>
    <p class="${matches ? "success-text" : ""}">${matches
      ? "Decryption successful — original and decrypted messages match."
      : "The messages do not match. Check the inputs and run the experiment again."}</p>`;
}

messageInput.addEventListener("input", () => {
  // A changed message must be encrypted again before comparison.
  if (keys) {
    encrypted = null;
    decrypted = null;
    decryptButton.disabled = true;
    encryptionValues.innerHTML = '<p class="empty-state">Message changed. Encrypt it again.</p>';
    encryptionSteps.innerHTML = "";
    decryptionValues.innerHTML = '<p class="empty-state">Encrypt a message, then decrypt.</p>';
    decryptionSteps.innerHTML = "";
    resultPanel.className = "result-panel";
    resultValues.textContent = "Encrypt the current message, then decrypt it to verify the result.";
  }
});

document.getElementById("menuToggle").addEventListener("click", () => {
  document.getElementById("sidebar").classList.toggle("open");
});

document.querySelectorAll(".side-link").forEach(link => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".side-link").forEach(item => item.classList.remove("active"));
    link.classList.add("active");
    document.getElementById("sidebar").classList.remove("open");
  });
});
