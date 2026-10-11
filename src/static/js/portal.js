/**
 * Interactive Client Script for The Silent Conch: The Eleventh Seal
 * Kurukshetra Relay Command & Intelligence Gateway
 */

document.addEventListener("DOMContentLoaded", () => {
    loadManifests();
    setupEventListeners();
});

function setupEventListeners() {
    document.getElementById("refresh-manifests-btn")?.addEventListener("click", loadManifests);
    document.getElementById("trigger-download-btn")?.addEventListener("click", handleDownloadRequest);
    document.getElementById("modal-close-btn")?.addEventListener("click", closeModal);
    document.getElementById("send-oracle-query-btn")?.addEventListener("click", handleOracleQuery);
    document.getElementById("redeem-vault-ticket-btn")?.addEventListener("click", handleRedeemTicket);

    window.addEventListener("click", (e) => {
        const modal = document.getElementById("manifest-modal");
        if (e.target === modal) closeModal();
    });
}

async function loadManifests() {
    const tbody = document.getElementById("manifests-tbody");
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Scanning perimeter diagnostic relays...</td></tr>`;

    try {
        const res = await fetch("/api/diagnostics/list");
        const data = await res.json();
        if (data.status === "success" && data.manifests) {
            tbody.innerHTML = "";
            data.manifests.forEach(m => {
                const tr = document.createElement("tr");
                const isRestricted = m.access.includes("RESTRICTED");
                const accessBadge = isRestricted 
                    ? `<span class="badge badge-danger">${m.access}</span>`
                    : `<span class="badge badge-cyan">${m.access}</span>`;

                tr.innerHTML = `
                    <td><code>${escapeHtml(m.ref)}</code></td>
                    <td>
                        <strong>${escapeHtml(m.title)}</strong><br>
                        <small style="color:var(--text-secondary)">${escapeHtml(m.description)}</small>
                    </td>
                    <td>${accessBadge}</td>
                    <td>
                        <button class="btn btn-sm btn-ghost view-btn" data-ref="${escapeHtml(m.ref)}">View</button>
                        <button class="btn btn-sm btn-primary dl-btn" data-ref="${escapeHtml(m.ref)}" data-mac="${escapeHtml(m.mac || '')}">Get</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

            // Bind view & dl buttons
            document.querySelectorAll(".view-btn").forEach(btn => {
                btn.addEventListener("click", () => viewManifest(btn.dataset.ref));
            });
            document.querySelectorAll(".dl-btn").forEach(btn => {
                btn.addEventListener("click", () => {
                    const ref = btn.dataset.ref;
                    const mac = btn.dataset.mac;
                    if (mac) {
                        document.getElementById("download-ref-input").value = `ref=${ref}&mac=${mac}`;
                    } else {
                        document.getElementById("download-ref-input").value = `ref=${ref}`;
                    }
                    handleDownloadRequest();
                });
            });
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" style="color:var(--accent-crimson);">Failed to load diagnostic manifests: ${err.message}</td></tr>`;
    }
}

async function viewManifest(ref) {
    const modal = document.getElementById("manifest-modal");
    const modalTitle = document.getElementById("modal-title");
    const modalContent = document.getElementById("modal-body-content");

    modalTitle.textContent = `Manifest: ${ref}`;
    modalContent.textContent = "Fetching manifest metadata...";
    modal.style.display = "flex";

    try {
        const res = await fetch(`/api/diagnostics/view?ref=${encodeURIComponent(ref)}`);
        const json = await res.json();
        if (res.ok && json.status === "success") {
            const d = json.data;
            modalContent.textContent = `[TITLE] ${d.title}\n[TIMESTAMP] ${d.timestamp}\n[DESCRIPTION] ${d.description}\n\n[LOG CONTENT]\n${d.content}`;
        } else {
            modalContent.textContent = `[SECURITY NOTICE]\nStatus Code: ${res.status}\nError: ${json.message || "Access Denied"}`;
        }
    } catch (err) {
        modalContent.textContent = `Error: ${err.message}`;
    }
}

function closeModal() {
    const modal = document.getElementById("manifest-modal");
    if (modal) modal.style.display = "none";
}

async function handleDownloadRequest() {
    const input = document.getElementById("download-ref-input");
    const feedback = document.getElementById("download-status-feedback");
    const rawVal = input.value.trim();
    if (!rawVal) return;

    feedback.className = "status-feedback";
    feedback.textContent = `Dispatching request for: ${rawVal}...`;

    try {
        // Construct request URL allowing raw query parameters if provided
        let fetchUrl;
        if (rawVal.includes("ref=")) {
            fetchUrl = `/api/diagnostics/download?${rawVal}`;
        } else {
            fetchUrl = `/api/diagnostics/download?ref=${encodeURIComponent(rawVal)}`;
        }

        const res = await fetch(fetchUrl);
        const contentType = res.headers.get("content-type") || "";

        if (res.ok) {
            feedback.className = "status-feedback success";
            feedback.textContent = `[SUCCESS ${res.status}] Artifact retrieved! Initiating browser download...`;
            const blob = await res.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = downloadUrl;
            a.download = rawVal.split("ref=").pop() || "artifact";
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            const errData = await res.json();
            feedback.className = "status-feedback error";
            feedback.textContent = `[HTTP ${res.status}] ${errData.message || "Download Rejected"}`;
        }
    } catch (err) {
        feedback.className = "status-feedback error";
        feedback.textContent = `Connection failure: ${err.message}`;
    }
}

async function handleOracleQuery() {
    const token = document.getElementById("oracle-jwt-token").value.trim();
    const query = document.getElementById("oracle-query-input").value.trim();
    const terminal = document.getElementById("oracle-terminal-output");

    if (!token) {
        terminal.innerHTML = `<div class="terminal-log-row" style="color:var(--accent-crimson);"><span class="terminal-tag">[AUTH ERROR]</span> Missing Officer Authorization Token (ES256 Bearer JWT). Recover signing key to generate token.</div>`;
        return;
    }

    terminal.innerHTML = `
        <div class="terminal-log-row"><span class="terminal-tag">[TX TRANSMIT]</span> Dispatching query to Kurukshetra Oracle Assistant...</div>
        <div class="terminal-log-row" style="color:var(--text-muted);"><span class="terminal-tag">[SEC PROTOCOL]</span> Validating ES256 signature against relay-seal-eleven key...</div>
    `;

    try {
        const res = await fetch("/api/oracle/query", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({ query })
        });

        const data = await res.json();
        if (res.ok && data.status === "success") {
            let toolsHtml = "";
            if (data.tool_invocations && data.tool_invocations.length > 0) {
                toolsHtml = data.tool_invocations.map(t => {
                    const toolName = escapeHtml(t.tool);
                    const toolArgs = JSON.stringify(t.arguments, null, 2);
                    const toolRes = JSON.stringify(t.result, null, 2);
                    return `<div style="margin: 8px 0; padding: 8px; background: rgba(0,0,0,0.4); border-left: 2px solid var(--accent-gold);">
                        <strong style="color:var(--accent-gold);">&gt; Tool Execution: ${toolName}</strong><br>
                        <small style="color:var(--text-muted);">Args: ${escapeHtml(toolArgs)}</small><br>
                        <small style="color:var(--accent-cyan);">Result: ${escapeHtml(toolRes)}</small>
                    </div>`;
                }).join("");
            }

            terminal.innerHTML = `
                <div class="terminal-log-row"><span class="terminal-tag">[AUTHENTICATED]</span> Principal: <code>${escapeHtml(data.principal)}</code> | Case: <code>${escapeHtml(data.case_id)}</code></div>
                ${toolsHtml}
                <div class="terminal-log-row" style="margin-top:10px; color:#ffffff; white-space:pre-wrap;">${escapeHtml(data.oracle_response)}</div>
            `;

            // Auto-populate ticket if issued
            const matchTicket = data.oracle_response.match(/TICKET-SEAL11-[a-f0-9]+/i);
            if (matchTicket) {
                document.getElementById("vault-ticket-input").value = matchTicket[0];
            }
        } else {
            terminal.innerHTML = `
                <div class="terminal-log-row" style="color:var(--accent-crimson);">
                    <span class="terminal-tag">[ORACLE REJECTED ${res.status}]</span> ${escapeHtml(data.message || "Query failed")}
                </div>
            `;
        }
    } catch (err) {
        terminal.innerHTML = `<div class="terminal-log-row" style="color:var(--accent-crimson);"><span class="terminal-tag">[NETWORK ERROR]</span> ${err.message}</div>`;
    }
}

async function handleRedeemTicket() {
    const ticket = document.getElementById("vault-ticket-input").value.trim();
    const caseId = document.getElementById("vault-case-input").value.trim();
    const token = document.getElementById("oracle-jwt-token").value.trim();
    const resultBox = document.getElementById("vault-redemption-result");

    if (!ticket) {
        resultBox.innerHTML = `<div style="color:var(--accent-crimson); font-family:var(--font-mono); font-size:0.85rem;">[VAULT REJECTED] Ticket ID is required.</div>`;
        return;
    }

    resultBox.innerHTML = `<div style="color:var(--accent-gold); font-family:var(--font-mono); font-size:0.85rem;">Validating ticket redemption with archive ledger...</div>`;

    try {
        const res = await fetch("/api/archive/redeem", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({ ticket, case_id: caseId })
        });

        const data = await res.json();
        if (res.ok && data.status === "success") {
            const flag = data.archive_details?.flag || "FLAG_RETRIEVAL_ERROR";
            resultBox.innerHTML = `
                <div class="flag-vault-box">
                    <div class="flag-conch-title">🐚 THE ELEVENTH SEAL IS BROKEN 🐚</div>
                    <p style="margin-bottom:10px; color:#cbd5e1; font-size:0.9rem;">The sacred archive has been released. The silent conch sounds across Kurukshetra.</p>
                    <div class="flag-value">${escapeHtml(flag)}</div>
                </div>
            `;
        } else {
            resultBox.innerHTML = `
                <div style="color:var(--accent-crimson); font-family:var(--font-mono); font-size:0.85rem; padding:10px; background:rgba(255,67,101,0.1); border-radius:6px; border:1px solid rgba(255,67,101,0.3);">
                    [REDEMPTION DENIED ${res.status}] ${escapeHtml(data.message || "Invalid or already redeemed ticket")}
                </div>
            `;
        }
    } catch (err) {
        resultBox.innerHTML = `<div style="color:var(--accent-crimson); font-family:var(--font-mono); font-size:0.85rem;">Connection error: ${err.message}</div>`;
    }
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, m => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    }[m]));
}
