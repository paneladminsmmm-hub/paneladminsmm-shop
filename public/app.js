
const $ = (selector) => document.querySelector(selector);

let currentUser = null;
let services = [];

const money = (paise) =>
  "₹" + (Number(paise || 0) / 100).toFixed(2);

async function api(url, options = {}) {
  const response = await fetch("/api" + url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...options
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Something went wrong");
  }

  return data;
}

function message(text, success = false) {
  const notice = $("#authNotice");

  if (notice) {
    notice.textContent = text;
    notice.style.color = success ? "#16a34a" : "#ef4444";
  } else {
    alert(text);
  }
}

function openAuth(register = false) {
  $("#authModal").classList.remove("hidden");

  $("#authTitle").textContent = register
    ? "Create your account"
    : "Login to your account";

  $("#authSubmit").textContent = register ? "Register" : "Login";
  $("#nameWrap").classList.toggle("hidden", !register);
  $("#authForm").dataset.mode = register ? "register" : "login";

  $("#authSwitch").innerHTML = register
    ? 'Already registered? <a href="#" id="switchAuth">Login</a>'
    : 'New here? <a href="#" id="switchAuth">Create an account</a>';

  $("#authNotice").textContent = "";
}

function showDashboard() {
  $("header").classList.add("hidden");
  $("main").classList.add("hidden");
  $("footer").classList.add("hidden");

  $("#appShell").classList.remove("hidden");

  $("#sideEmail").textContent = currentUser.email;
  $("#welcome").textContent = "Welcome, " + currentUser.name;
  $("#balanceTop").textContent = money(currentUser.balancePaise);

  loadTab("overview");
}

function showHome() {
  currentUser = null;

  $("#appShell").classList.add("hidden");
  $("header").classList.remove("hidden");
  $("main").classList.remove("hidden");
  $("footer").classList.remove("hidden");
}

async function loadServices() {
  const data = await api("/services");
  services = data.services || [];
}

async function refreshUser() {
  const data = await api("/me");

  currentUser = data.user;
  $("#balanceTop").textContent = money(currentUser.balancePaise);
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function ordersTable(orders) {
  if (!orders || !orders.length) {
    return "<p>No orders found.</p>";
  }

  return `
    <div class="service">
      ${orders.map(o => `
        <article>
          <b>Order #${o.id}</b>
          <p>${escapeHTML(o.service_name)}</p>
          <p>Quantity: ${o.quantity}</p>
          <p>Amount: ${money(o.total_paise)}</p>
          <p>Status: ${escapeHTML(o.status)}</p>
          <hr>
        </article>
      `).join("")}
    </div>
  `;
}

async function loadTab(tab) {
  document.querySelectorAll("[data-tab]").forEach(button => {
    button.classList.toggle("active", button.dataset.tab === tab);
  });

  const area = $("#tabContent");
  area.innerHTML = "<p>Loading...</p>";

  try {
    await refreshUser();

    if (tab === "overview") {
      const data = await api("/orders");

      area.innerHTML = `
        <h2>Overview</h2>
        <div class="service-grid">
          <article class="service">
            <h3>Wallet Balance</h3>
            <h2>${money(currentUser.balancePaise)}</h2>
          </article>
          <article class="service">
            <h3>Total Orders</h3>
            <h2>${data.orders.length}</h2>
          </article>
        </div>
        <h3>Recent Orders</h3>
        ${ordersTable(data.orders.slice(0, 5))}
      `;
    }

    if (tab === "services") {
      await loadServices();

      area.innerHTML = `
        <h2>Our Services</h2>
        <div class="service-grid">
          ${services.map(s => `
            <article class="service">
              <h3>${escapeHTML(s.platform)}</h3>
              <h4>${escapeHTML(s.name)}</h4>
              <p>${escapeHTML(s.description)}</p>
              <p>₹${(s.price_per_1000_paise / 100).toFixed(2)} per 1000</p>
              <p>Minimum: ${s.min_qty} | Maximum: ${s.max_qty}</p>
            </article>
          `).join("")}
        </div>
      `;
    }

    if (tab === "neworder") {
      await loadServices();

      area.innerHTML = `
        <h2>New Order</h2>
        <form id="orderForm" class="service">
          <label>Choose Service
            <select name="serviceId" required>
              ${services.map(s => `
                <option value="${s.id}">
                  ${escapeHTML(s.platform)} - ${escapeHTML(s.name)}
                </option>
              `).join("")}
            </select>
          </label>

          <label>Public Campaign URL
            <input name="targetUrl" type="url"
              placeholder="https://..." required>
          </label>

          <label>Quantity
            <input name="quantity" type="number" min="1" required>
          </label>

          <button class="btn red" type="submit">Place Order</button>
          <p id="orderNotice"></p>
        </form>
      `;
    }

    if (tab === "wallet") {
      const data = await api("/wallet");

      area.innerHTML = `
        <h2>Add Funds</h2>
        <article class="service">
          <h3>Current Balance: ${money(data.balancePaise)}</h3>
          <p>Minimum ₹100, Maximum ₹2000.</p>

          <form id="fundForm">
            <label>Amount in Rupees
              <input name="amount" type="number"
                min="100" max="2000" required>
            </label>
            <button class="btn red" type="submit">
              Continue to Payment
            </button>
          </form>
          <p id="fundNotice"></p>
        </article>

        <h3>Wallet Transactions</h3>
        ${data.transactions.map(t => `
          <article class="service">
            ${escapeHTML(t.note)} — ${money(t.amount_paise)}
            <small>${escapeHTML(t.created_at)}</small>
          </article>
        `).join("") || "<p>No transactions yet.</p>"}
      `;
    }

    if (tab === "orders") {
      const data = await api("/orders");

      area.innerHTML = `
        <h2>Order History</h2>
        ${ordersTable(data.orders)}
      `;
    }

    if (tab === "tickets") {
      const data = await api("/tickets");

      area.innerHTML = `
        <h2>Support Tickets</h2>

        <form id="ticketForm" class="service">
          <label>Subject
            <input name="subject" required>
          </label>

          <label>Message
            <textarea name="message" required></textarea>
          </label>

          <button class="btn red" type="submit">Send Ticket</button>
        </form>

        <h3>Your Tickets</h3>
        ${data.tickets.map(t => `
          <article class="service">
            <b>${escapeHTML(t.subject)}</b>
            <p>${escapeHTML(t.message)}</p>
            <p>Status: ${escapeHTML(t.status)}</p>
            <p>${escapeHTML(t.admin_reply || "")}</p>
          </article>
        `).join("") || "<p>No tickets yet.</p>"}
      `;
    }

  } catch (error) {
    area.innerHTML = `<p>${escapeHTML(error.message)}</p>`;
  }
}

// Header buttons
$("#loginOpen").addEventListener("click", () => openAuth(false));
$("#registerOpen").addEventListener("click", () => openAuth(true));
$("#getStarted").addEventListener("click", () => openAuth(true));

$("#closeModal").addEventListener("click", () => {
  $("#authModal").classList.add("hidden");
});

// Dashboard navigation and login/register switch
document.addEventListener("click", (e) => {
  const switchLink = e.target.closest("#switchAuth");

  if (switchLink) {
    e.preventDefault();
    openAuth($("#authForm").dataset.mode !== "register");
    return;
  }

  const tabButton = e.target.closest("[data-tab]");

  if (tabButton) {
    e.preventDefault();
    loadTab(tabButton.dataset.tab);
  }
});

// Login and registration
$("#authForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const form = new FormData(e.target);
  const mode = e.target.dataset.mode;

  const body = {
    email: form.get("email"),
    password: form.get("password")
  };

  if (mode === "register") {
    body.name = form.get("name");
  }

  $("#authSubmit").disabled = true;

  try {
    const data = await api(
      mode === "register" ? "/auth/register" : "/auth/login",
      {
        method: "POST",
        body: JSON.stringify(body)
      }
    );

    currentUser = data.user;
    $("#authModal").classList.add("hidden");
    showDashboard();

  } catch (error) {
    message(error.message);
  } finally {
    $("#authSubmit").disabled = false;
  }
});

// Handle forms created dynamically inside the dashboard
document.addEventListener("submit", async (e) => {
  const form = e.target;

  if (form.id === "orderForm") {
    e.preventDefault();

    const f = new FormData(form);

    try {
      const result = await api("/orders", {
        method: "POST",
        body: JSON.stringify({
          serviceId: Number(f.get("serviceId")),
          targetUrl: f.get("targetUrl"),
          quantity: Number(f.get("quantity"))
        })
      });

      alert(result.message || "Order submitted.");
      loadTab("orders");

    } catch (error) {
      $("#orderNotice").textContent = error.message;
    }
  }

  if (form.id === "fundForm") {
    e.preventDefault();

    const amount = Number(new FormData(form).get("amount"));

    try {
      const result = await api("/payments/create", {
        method: "POST",
        body: JSON.stringify({ amount })
      });

      if (!window.Razorpay) {
        throw new Error("Payment checkout is not loaded.");
      }

      const checkout = new Razorpay({
        key: result.keyId,
        amount: result.amount,
        currency: result.currency,
        order_id: result.orderId,
        name: "SMM.com",
        description: "Wallet Funds",

        handler: function() {
          alert("Payment submitted. Wallet credit requires verified webhook.");
          loadTab("wallet");
        }
      });

      checkout.open();

    } catch (error) {
      $("#fundNotice").textContent = error.message;
    }
  }

  if (form.id === "ticketForm") {
    e.preventDefault();

    const f = new FormData(form);

    try {
      await api("/tickets", {
        method: "POST",
        body: JSON.stringify({
          subject: f.get("subject"),
          message: f.get("message")
        })
      });

      alert("Support ticket submitted!");
      loadTab("tickets");

    } catch (error) {
      alert(error.message);
    }
  }
});

// Logout
async function logout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch (error) {
    console.error(error);
  }

  showHome();
}

$("#logoutBtn").addEventListener("click", logout);
$("#sideLogout").addEventListener("click", logout);

$("#supportBtn").addEventListener("click", () => openAuth(false));

$("#year").textContent = new Date().getFullYear();

// Load Razorpay checkout library
const razorpayScript = document.createElement("script");
razorpayScript.src = "https://checkout.razorpay.com/v1/checkout.js";
razorpayScript.async = true;
document.head.appendChild(razorpayScript);

// Check existing login session
(async function start() {
  try {
    const data = await api("/me");
    currentUser = data.user;
    showDashboard();
  } catch (error) {
    showHome();
  }
})();
