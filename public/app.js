/* ===================================================================
   CipherLens — Client-side JavaScript
   =================================================================== */

/**
 * Call an API endpoint and display the JSON response.
 * @param {string} url       - endpoint URL
 * @param {object} body      - request payload
 * @param {string} resultId  - DOM id of the <pre> to populate
 * @param {string} loaderId  - DOM id of the loader spinner
 */
async function callEndpoint(url, body, resultId, loaderId) {
  const resultEl = document.getElementById(resultId);
  const loaderEl = document.getElementById(loaderId);

  loaderEl.classList.add("active");
  resultEl.innerHTML = '<span class="placeholder">Executing…</span>';

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    resultEl.textContent = JSON.stringify(data, null, 2);

    // Highlight PQC warnings in the output
    resultEl.innerHTML = resultEl.textContent
      .replace(/"pqcWarning":\s*"([^"]+)"/g, '"pqcWarning": "<span style=\'color:#ef4444;font-weight:600\'>$1</span>"')
      .replace(/"pqcStatus":\s*"([^"]+)"/g, '"pqcStatus": "<span style=\'color:#22c55e;font-weight:600\'>$1</span>"')
      .replace(/"verified":\s*true/g, '"verified": <span style="color:#22c55e;font-weight:600">true</span>')
      .replace(/"sharedSecretMatch":\s*true/g, '"sharedSecretMatch": <span style="color:#22c55e;font-weight:600">true</span>')
      .replace(/"error":\s*"([^"]+)"/g, '"error": "<span style=\'color:#ef4444\'>$1</span>"');
  } catch (err) {
    resultEl.innerHTML = `<span style="color:#ef4444">Error: ${err.message}</span>`;
  } finally {
    loaderEl.classList.remove("active");
  }
}

/* --- Endpoint Handlers --- */

function callLogin() {
  const username = document.getElementById("login-user").value || "alice";
  const password = document.getElementById("login-pass").value || "s3cret!";
  callEndpoint("/api/login", { username, password }, "login-result", "login-loader");
}

function callEncrypt() {
  const plaintext = document.getElementById("encrypt-plaintext").value || "Top secret quantum data";
  callEndpoint("/api/encrypt", { plaintext }, "encrypt-result", "encrypt-loader");
}

function callSign() {
  const message = document.getElementById("sign-message").value || "Sign this document";
  callEndpoint("/api/sign", { message }, "sign-result", "sign-loader");
}

function callOkta() {
  const accessToken = document.getElementById("okta-token").value || "";
  callEndpoint("/api/verify-okta", { accessToken }, "okta-result", "okta-loader");
}

/* --- Smooth scroll for nav links --- */
document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', (e) => {
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    link.classList.add('active');
  });
});

/* --- Intersection Observer for active nav --- */
const sections = document.querySelectorAll('.hero, .section');
const navLinks = document.querySelectorAll('.nav-link');

const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const id = entry.target.id;
      navLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
      });
    }
  });
}, { threshold: 0.3 });

sections.forEach(section => {
  if (section.id) observer.observe(section);
});
