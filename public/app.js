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

/* --- Toast Notifications --- */
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  
  container.appendChild(toast);
  
  // Trigger animation
  requestAnimationFrame(() => {
    toast.classList.add('show');
  });

  // Remove after 3 seconds
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

/* --- Auth0 (Okta CIC) SSO Integration --- */
let auth0Client = null;

async function initOkta() {
  try {
    const res = await fetch("/api/config");
    const config = await res.json();

    const domain = new URL(config.issuer).hostname;

    auth0Client = await auth0.createAuth0Client({
      domain: domain,
      clientId: config.clientId,
      authorizationParams: {
        redirect_uri: window.location.origin,
        // Specifying an audience forces Auth0 to return a proper JWT Access Token (JWS)
        // instead of an opaque or encrypted JWE token.
        audience: `https://${domain}/api/v2/`
      }
    });

    // Handle login callback if returning from Auth0
    if (window.location.search.includes("code=") && window.location.search.includes("state=")) {
      try {
        await auth0Client.handleRedirectCallback();
        window.history.replaceState({}, document.title, window.location.pathname);
        showToast("Login Success", "success");
      } catch (err) {
        showToast("Login callback failed: " + err.message, "error");
      }
    }

    // Check if user is authenticated
    const isAuthenticated = await auth0Client.isAuthenticated();
    if (isAuthenticated) {
      document.getElementById('btn-okta-login').style.display = 'none';
      document.getElementById('btn-okta-logout').style.display = 'inline-flex';
      
      const accessToken = await auth0Client.getTokenSilently();
      if (accessToken) {
        document.getElementById('okta-token').value = accessToken;
        // Auto verify
        callOkta();
      }
    }
  } catch (err) {
    console.error("Failed to initialize Auth0:", err);
  }
}

async function loginWithOkta() {
  if (!auth0Client) return;
  document.getElementById('okta-login-loader').classList.add('active');
  try {
    await auth0Client.loginWithRedirect();
  } catch (err) {
    showToast("Redirect failed: " + err.message, "error");
    document.getElementById('okta-login-loader').classList.remove('active');
  }
}

async function logoutOkta() {
  if (!auth0Client) return;
  try {
    await auth0Client.logout({ 
      logoutParams: {
        returnTo: window.location.origin 
      }
    });
  } catch (err) {
    showToast("Logout failed: " + err.message, "error");
  }
}

// Initialize Auth0 on page load
window.addEventListener('load', initOkta);

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
