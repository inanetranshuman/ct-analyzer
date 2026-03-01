const state = {
  days: 30,
  groupBy: "issuer_cn",
  sessionAuthenticated: false,
  loading: false,
};

const SIGNAL_DESCRIPTIONS = {
  high_san_count: "This certificate has an unusually large number of SAN entries compared with normal leaf certificates.",
  wildcard_san: "The certificate covers one or more wildcard names such as *.example.com.",
  punycode_san: "One or more SAN entries are encoded in punycode. This is common for legitimate internationalized domains, so by itself it is only a weak contextual signal.",
  punycode_entropy_combo: "The certificate combines punycode with a high-entropy label, which is more suspicious than punycode alone and can indicate deceptive or algorithmic naming.",
  high_entropy_label: "A label in the SAN list has unusually high character entropy, which can indicate algorithmically generated or deceptive hostnames.",
  idn_confusable: "The internationalized domain name appears to collapse into a plausible ASCII lookalike or mixes scripts in a way that can mislead a reader.",
  suspicious_keywords: "The SAN list contains words often associated with phishing or impersonation flows, such as login or billing.",
  validity_outlier: "The certificate validity period is longer than the issuer's recent baseline.",
  validity_long: "The certificate validity period is long enough to stand out even without a baseline comparison.",
  rare_san_types: "The certificate includes uncommon SAN types such as IP, URI, or email entries.",
  unusual_eku_set: "The extended key usage set does not match the issuer's common recent EKU profile.",
  issuer_spike: "Recent issuance volume for this issuer is elevated relative to its trailing daily baseline.",
};

const els = {
  logoutButton: document.querySelector("#logout-button"),
  authStatus: document.querySelector("#auth-status"),
  days: document.querySelector("#window-days"),
  groupBy: document.querySelector("#group-by"),
  metricCards: document.querySelector("#metric-cards"),
  validityStats: document.querySelector("#validity-stats"),
  sanStats: document.querySelector("#san-stats"),
  issuanceTemplates: document.querySelector("#issuance-templates"),
  sigAlgList: document.querySelector("#sig-alg-list"),
  keyTypeList: document.querySelector("#key-type-list"),
  ekuList: document.querySelector("#eku-list"),
  breakdownTable: document.querySelector("#breakdown-table"),
  anomalyList: document.querySelector("#anomaly-list"),
  metricTemplate: document.querySelector("#metric-card-template"),
  detailModal: document.querySelector("#detail-modal"),
  detailBackdrop: document.querySelector("#detail-backdrop"),
  detailClose: document.querySelector("#detail-close"),
  detailContent: document.querySelector("#detail-content"),
};

function setAuthStatus(message, kind = "neutral") {
  els.authStatus.textContent = message;
  els.authStatus.dataset.kind = kind;
}

function setLoadingState(isLoading) {
  state.loading = isLoading;
  document.body.classList.toggle("is-loading", isLoading);
  els.days.disabled = isLoading;
  els.groupBy.disabled = isLoading;
  els.logoutButton.disabled = isLoading;
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

function formatShare(count, total) {
  if (!count || !total) {
    return "No recent support";
  }
  return `${numberFormat(count)} certs · ${percentFormat(count / total)}`;
}

function renderIssuanceTemplates(profile) {
  clearNode(els.issuanceTemplates);
  const templates = [
    {
      attribute: "Signature Algorithm",
      value: profile.top_signature_algorithms?.[0]?.value || "Unknown",
      support: formatShare(profile.top_signature_algorithms?.[0]?.count, profile.cert_count),
    },
    {
      attribute: "Key Type",
      value: profile.top_key_types?.[0]?.value || "Unknown",
      support: formatShare(profile.top_key_types?.[0]?.count, profile.cert_count),
    },
    {
      attribute: "Key Size",
      value: profile.top_key_sizes?.[0]?.value ? `${profile.top_key_sizes[0].value} bits` : "Unknown",
      support: formatShare(profile.top_key_sizes?.[0]?.count, profile.cert_count),
    },
    {
      attribute: "EKU Set",
      value: profile.top_eku_sets?.[0]?.value || "Unknown",
      support: formatShare(profile.top_eku_sets?.[0]?.count, profile.cert_count),
    },
    {
      attribute: "Validity Pattern",
      value:
        profile.validity_days?.p50 === profile.validity_days?.p95
          ? `${profile.validity_days.p50.toFixed(0)} days`
          : `p50 ${profile.validity_days?.p50?.toFixed(0) || "0"} days · p95 ${profile.validity_days?.p95?.toFixed(0) || "0"} days`,
      support: "Recent baseline window",
    },
    {
      attribute: "SAN Pattern",
      value:
        profile.san_count?.p50 === profile.san_count?.p95
          ? `${profile.san_count.p50.toFixed(0)} SAN`
          : `p50 ${profile.san_count?.p50?.toFixed(0) || "0"} · p95 ${profile.san_count?.p95?.toFixed(0) || "0"}`,
      support: "Recent baseline window",
    },
  ];
  for (const template of templates) {
    const row = document.createElement("article");
    row.className = "template-row";
    row.innerHTML = `
      <div class="template-copy">
        <span class="template-attribute">${template.attribute}</span>
        <strong class="template-value">${template.value}</strong>
      </div>
      <span class="template-support">${template.support}</span>
    `;
    els.issuanceTemplates.appendChild(row);
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
      .map((signal) => `<li>${signal.code} (${signal.severity}): ${signal.score}</li>`)
      .join("");
    const limitedDnsNames = anomaly.dns_names.slice(0, 3).map((name, index) => ({
      ascii: name,
      unicode: anomaly.dns_names_unicode?.[index] ?? name,
    }));
    const displayTitleSource = limitedDnsNames[0];
    const subjectCn = anomaly.subject_cn || "No subject CN";
    const titleText =
      displayTitleSource && subjectCn === displayTitleSource.ascii && displayTitleSource.unicode !== displayTitleSource.ascii
        ? displayTitleSource.unicode
        : subjectCn;
    const dnsNames = limitedDnsNames
      .filter((entry, index) => index > 0 || entry.ascii !== anomaly.subject_cn)
      .map(({ ascii, unicode }) => {
        if (unicode && unicode !== ascii) {
          return `
            <div class="dns-name-row">
              <span class="dns-ascii">${ascii}</span>
              <span class="dns-unicode">${unicode}</span>
            </div>
          `;
        }
        return `
          <div class="dns-name-row">
            <span class="dns-ascii">${ascii}</span>
          </div>
        `;
      })
      .join("");
    card.innerHTML = `
      <div class="anomaly-head">
        <div class="anomaly-copy">
          <h3>${titleText}</h3>
          <div class="dns-sample">${dnsNames || '<div class="dns-name-row"><span class="dns-ascii">No DNS names</span></div>'}</div>
        </div>
        <div class="score-pill">${anomaly.anomaly_score}</div>
      </div>
      <ul class="signal-list">${signals}</ul>
    `;
    card.addEventListener("click", () => openCertificateDetail(anomaly));
    els.anomalyList.appendChild(card);
  }
}

function renderJson(value) {
  return `<pre class="json-block">${JSON.stringify(value, null, 2)}</pre>`;
}

function signalDescription(code) {
  return SIGNAL_DESCRIPTIONS[code] || "This signal is a rule-based anomaly indicator generated by the scoring pipeline.";
}

async function openCertificateDetail(anomaly) {
  els.detailModal.hidden = false;
  els.detailContent.innerHTML = `<p class="detail-loading">Loading certificate details for ${anomaly.cert_hash}...</p>`;
  try {
    const details = await fetchJson(`/certificates/${encodeURIComponent(anomaly.cert_hash)}`);
    const signalCards = anomaly.top_signals
      .map(
        (signal) => `
          <article class="detail-signal-card">
            <div class="detail-signal-head">
              <strong>${signal.code}</strong>
              <span>${signal.severity} · ${signal.score}</span>
            </div>
            <p>${signalDescription(signal.code)}</p>
            ${signal.evidence ? renderJson(signal.evidence) : ""}
          </article>
        `,
      )
      .join("");
    const findingRows = details.findings
      .map(
        (finding) => `
          <article class="detail-finding-row">
            <div class="detail-finding-head">
              <strong>${finding.finding_code}</strong>
              <span>${finding.severity}</span>
            </div>
            ${renderJson(finding.evidence)}
          </article>
        `,
      )
      .join("");
    const dnsNames = (details.dns_names || [])
      .map((name) => `<li>${name}</li>`)
      .join("");
    els.detailContent.innerHTML = `
      <header class="detail-header">
        <p class="eyebrow">Certificate Detail</p>
        <h2 id="detail-title">${details.subject_cn || "No subject CN"}</h2>
        <p class="cert-hash">${details.cert_hash}</p>
      </header>
      <section class="detail-grid">
        <div class="detail-block">
          <h3>Identity</h3>
          <dl class="detail-dl">
            <div><dt>Issuer CN</dt><dd>${details.issuer_cn || "none"}</dd></div>
            <div><dt>Issuer DN</dt><dd>${details.issuer_dn || "none"}</dd></div>
            <div><dt>Subject DN</dt><dd>${details.subject_dn || "none"}</dd></div>
            <div><dt>Serial</dt><dd>${details.serial_number || "none"}</dd></div>
            <div><dt>Anomaly Score</dt><dd>${details.anomaly_score}</dd></div>
          </dl>
        </div>
        <div class="detail-block">
          <h3>DNS Names</h3>
          <ul class="detail-list">${dnsNames || "<li>None</li>"}</ul>
        </div>
      </section>
      <section class="detail-section">
        <h3>Top Signals</h3>
        <div class="detail-signal-grid">${signalCards || "<p>No anomaly signals available.</p>"}</div>
      </section>
      <section class="detail-section">
        <h3>Findings</h3>
        <div class="detail-finding-grid">${findingRows || "<p>No findings stored for this certificate.</p>"}</div>
      </section>
    `;
  } catch (error) {
    els.detailContent.innerHTML = `<p class="auth-status" data-kind="error">${error.message}</p>`;
  }
}

function closeCertificateDetail() {
  els.detailModal.hidden = true;
  els.detailContent.innerHTML = "";
}

async function refreshDashboard() {
  setLoadingState(true);
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
    renderIssuanceTemplates(profile);
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
  } finally {
    setLoadingState(false);
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

els.detailClose.addEventListener("click", closeCertificateDetail);
els.detailBackdrop.addEventListener("click", closeCertificateDetail);

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
