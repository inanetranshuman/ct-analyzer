const state = {
  days: 30,
  groupBy: "issuer_cn",
  sessionAuthenticated: false,
};

const els = {
  logoutButton: document.querySelector("#logout-button"),
  authStatus: document.querySelector("#auth-status"),
  days: document.querySelector("#window-days"),
  groupBy: document.querySelector("#group-by"),
  metricCards: document.querySelector("#metric-cards"),
  validityStats: document.querySelector("#validity-stats"),
  sanStats: document.querySelector("#san-stats"),
  featureRates: document.querySelector("#feature-rates"),
  sigAlgList: document.querySelector("#sig-alg-list"),
  keyTypeList: document.querySelector("#key-type-list"),
  ekuList: document.querySelector("#eku-list"),
  breakdownTable: document.querySelector("#breakdown-table"),
  anomalyList: document.querySelector("#anomaly-list"),
  metricTemplate: document.querySelector("#metric-card-template"),
};

function setAuthStatus(message, kind = "neutral") {
  els.authStatus.textContent = message;
  els.authStatus.dataset.kind = kind;
}

function authHeaders() {
  return {};
}

async function fetchJson(path) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...authHeaders(),
    },
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${text}`);
  }
  return response.json();
}

function numberFormat(value) {
  return new Intl.NumberFormat().format(value ?? 0);
}

function percentFormat(value) {
  return `${((value ?? 0) * 100).toFixed(2)}%`;
}

function clearNode(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function renderMetricCards(counts) {
  clearNode(els.metricCards);
  for (const [label, value] of Object.entries(counts)) {
    const fragment = els.metricTemplate.content.cloneNode(true);
    fragment.querySelector(".metric-label").textContent = label.replaceAll("_", " ");
    fragment.querySelector(".metric-value").textContent = numberFormat(value);
    els.metricCards.appendChild(fragment);
  }
}

function renderMiniStats(node, stats) {
  clearNode(node);
  for (const [label, value] of Object.entries(stats)) {
    const row = document.createElement("div");
    row.className = "mini-stat-row";
    row.innerHTML = `<span>${label.toUpperCase()}</span><strong>${value.toFixed(2)}</strong>`;
    node.appendChild(row);
  }
}

function renderRateList(node, rates) {
  clearNode(node);
  for (const [label, value] of Object.entries(rates)) {
    const row = document.createElement("div");
    row.className = "rate-row";
    row.innerHTML = `
      <span>${label.replaceAll("_", " ")}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.min((value ?? 0) * 100, 100)}%"></div></div>
      <strong>${percentFormat(value)}</strong>
    `;
    node.appendChild(row);
  }
}

function renderRankList(node, items) {
  clearNode(node);
  for (const item of items) {
    const row = document.createElement("div");
    row.className = "rank-row";
    row.innerHTML = `
      <span class="rank-value">${item.value || "none"}</span>
      <span class="rank-count">${numberFormat(item.count)}</span>
    `;
    node.appendChild(row);
  }
}

function renderBreakdown(payload) {
  const rows = payload.buckets
    .map(
      (bucket) => `
        <tr>
          <td>${bucket.value ?? "none"}</td>
          <td>${numberFormat(bucket.count)}</td>
        </tr>`
    )
    .join("");
  els.breakdownTable.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>${payload.label}</th>
          <th>Count</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderAnomalies(payload) {
  clearNode(els.anomalyList);
  for (const anomaly of payload.top_anomalies.slice(0, 12)) {
    const card = document.createElement("article");
    card.className = "anomaly-card";
    const signals = anomaly.top_signals
      .map((signal) => `<li>${signal.code}: ${signal.weight}</li>`)
      .join("");
    const dnsNames = anomaly.dns_names.slice(0, 3).join(", ");
    card.innerHTML = `
      <div class="anomaly-head">
        <div>
          <p class="cert-hash">${anomaly.cert_hash}</p>
          <h3>${anomaly.subject_cn || "No subject CN"}</h3>
          <p class="dns-sample">${dnsNames || "No DNS names"}</p>
        </div>
        <div class="score-pill">${anomaly.anomaly_score}</div>
      </div>
      <ul class="signal-list">${signals}</ul>
    `;
    els.anomalyList.appendChild(card);
  }
}

async function refreshDashboard() {
  setAuthStatus("Loading data...", "neutral");
  try {
    const [stats, profile, breakdown, anomalies] = await Promise.all([
      fetchJson(`/stats/issuer/godaddy?days=${state.days}`),
      fetchJson(`/profile/issuer/godaddy?days=${state.days}`),
      fetchJson(`/breakdown/issuer/godaddy?group_by=${encodeURIComponent(state.groupBy)}&days=${state.days}&limit=12`),
      fetchJson(`/anomalies/issuer/godaddy?days=${Math.min(state.days, 30)}&limit=12`),
    ]);
    renderMetricCards(stats.aggregated_counts);
    renderMiniStats(els.validityStats, profile.validity_days);
    renderMiniStats(els.sanStats, profile.san_count);
    renderRateList(els.featureRates, profile.feature_rates);
    renderRankList(els.sigAlgList, profile.top_signature_algorithms);
    renderRankList(els.keyTypeList, profile.top_key_types);
    renderRankList(els.ekuList, profile.top_eku_sets);
    renderBreakdown(breakdown);
    renderAnomalies(anomalies);
    setAuthStatus(
      `Loaded ${numberFormat(profile.cert_count)} certificates for the selected window.`,
      "success",
    );
  } catch (error) {
    console.error(error);
    if (String(error.message).includes("401")) {
      setAuthStatus("Your session is not valid. Redirecting to sign-in.", "error");
      window.setTimeout(() => {
        window.location.href = "/login";
      }, 500);
      return;
    }
    setAuthStatus(error.message, "error");
  }
}

els.days.value = String(state.days);
els.groupBy.value = state.groupBy;

els.logoutButton.addEventListener("click", async () => {
  await fetch("/logout", {
    method: "POST",
    credentials: "same-origin",
  });
  window.location.href = "/login";
});

els.days.addEventListener("change", () => {
  state.days = Number(els.days.value);
  refreshDashboard();
});

els.groupBy.addEventListener("change", () => {
  state.groupBy = els.groupBy.value;
  refreshDashboard();
});

async function bootstrap() {
  const authState = await fetchJson("/ui/auth-state");
  state.sessionAuthenticated = authState.session_authenticated;
  if (!state.sessionAuthenticated && authState.auth_enabled) {
    window.location.href = "/login";
    return;
  }
  refreshDashboard();
}

bootstrap();
