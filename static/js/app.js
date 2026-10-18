/**
 * AI-Based Phishing Detection System
 * Frontend Application Controller (Vanilla JavaScript)
 */

document.addEventListener("DOMContentLoaded", () => {
    // Current analysis mode: 'email' | 'sms' | 'text' | 'url'
    let currentMode = "email";

    // DOM Elements - Navigation & Status
    const tabButtons = document.querySelectorAll(".tab-btn");
    const systemStatusPill = document.getElementById("system-status-pill");
    const systemStatusText = document.getElementById("system-status-text");

    // DOM Elements - Form & Inputs
    const analyzeForm = document.getElementById("analyze-form");
    const groupSubject = document.getElementById("group-subject");
    const groupMessage = document.getElementById("group-message");
    const groupUrl = document.getElementById("group-url");
    const inputSubject = document.getElementById("input-subject");
    const inputMessage = document.getElementById("input-message");
    const inputUrl = document.getElementById("input-url");
    const labelMessage = document.getElementById("label-message");
    const messageCharCount = document.getElementById("message-char-count");
    const btnClear = document.getElementById("btn-clear");
    const btnAnalyze = document.getElementById("btn-analyze");
    const scanSpinner = document.getElementById("scan-spinner");
    const btnAnalyzeText = btnAnalyze.querySelector(".btn-text");

    // DOM Elements - Results Card
    const resultPlaceholder = document.getElementById("result-placeholder");
    const resultContent = document.getElementById("result-content");
    const reportTypeBadge = document.getElementById("report-type-badge");
    const verdictBanner = document.getElementById("verdict-banner");
    const verdictStatus = document.getElementById("verdict-status");
    const verdictSubtitle = document.getElementById("verdict-subtitle");
    const riskPill = document.getElementById("risk-pill");
    const metricConfidence = document.getElementById("metric-confidence");
    const meterFill = document.getElementById("meter-fill");
    const metricEngine = document.getElementById("metric-engine");
    const metricWordcount = document.getElementById("metric-wordcount");
    const indicatorsList = document.getElementById("indicators-list");
    const recommendationText = document.getElementById("recommendation-text");
    const errorBox = document.getElementById("error-box");
    const errorTitle = document.getElementById("error-title");
    const errorMessage = document.getElementById("error-message");

    // DOM Elements - History
    const historyTbody = document.getElementById("history-tbody");
    const btnRefreshHistory = document.getElementById("btn-refresh-history");
    const btnClearHistory = document.getElementById("btn-clear-history");

    // Sample Presets
    const sampleBankPhish = document.getElementById("sample-bank-phish");
    const sampleSmishParcel = document.getElementById("sample-smish-parcel");
    const samplePhishUrl = document.getElementById("sample-phish-url");
    const sampleSafeInvite = document.getElementById("sample-safe-invite");

    // Initialize System Status and Scan History
    checkSystemHealth();
    loadScanHistory();

    // Setup Event Listeners
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => switchMode(btn.dataset.mode));
    });

    inputMessage.addEventListener("input", updateCharCounter);
    btnClear.addEventListener("click", clearInputs);
    analyzeForm.addEventListener("submit", handleAnalysis);
    btnRefreshHistory.addEventListener("click", loadScanHistory);
    btnClearHistory.addEventListener("click", clearScanHistory);

    // Quick Sample Loaders
    sampleBankPhish.addEventListener("click", () => {
        switchMode("email");
        inputSubject.value = "URGENT: Unauthorized access detected on your PayPal Account";
        inputMessage.value = "Dear Customer,\n\nWe detected suspicious login activity from an unknown IP address. Your account has been temporarily restricted. You must confirm your identity and verify your password within 24 hours to prevent permanent account suspension.\n\nClick here immediately to restore full access: http://paypal-security-update.xyz/verify";
        updateCharCounter();
    });

    sampleSmishParcel.addEventListener("click", () => {
        switchMode("sms");
        inputMessage.value = "USPS: Package delivery for tracking #940551020088 is on hold due to incomplete address. Confirm your details within 12 hours to avoid return: http://tinyurl.com/usps-address-confirm";
        updateCharCounter();
    });

    samplePhishUrl.addEventListener("click", () => {
        switchMode("url");
        inputUrl.value = "http://secure.account.billing.update.paypal.com.verify-access.net/login";
    });

    sampleSafeInvite.addEventListener("click", () => {
        switchMode("email");
        inputSubject.value = "Quarterly Architecture Review Meeting Notes";
        inputMessage.value = "Hi Team,\n\nAttached are the summary notes and action items from yesterday's architecture review. Please review the database migration timeline before our sync on Thursday.\n\nBest regards,\nEngineering Team";
        updateCharCounter();
    });

    /**
     * Switch analysis mode (email, sms, text, url)
     */
    function switchMode(mode) {
        currentMode = mode;

        tabButtons.forEach(btn => {
            btn.classList.toggle("active", btn.dataset.mode === mode);
        });

        // Toggle UI fields based on mode
        if (mode === "email") {
            groupSubject.classList.remove("hidden");
            groupMessage.classList.remove("hidden");
            groupUrl.classList.add("hidden");
            labelMessage.textContent = "Email Body Content";
            inputMessage.placeholder = "Paste the complete body of the suspicious email here...";
        } else if (mode === "sms") {
            groupSubject.classList.add("hidden");
            groupMessage.classList.remove("hidden");
            groupUrl.classList.add("hidden");
            labelMessage.textContent = "SMS Message Content";
            inputMessage.placeholder = "e.g. BOA Alert: Your debit card is locked. Verify at http://...";
        } else if (mode === "text") {
            groupSubject.classList.add("hidden");
            groupMessage.classList.remove("hidden");
            groupUrl.classList.add("hidden");
            labelMessage.textContent = "General Message Content";
            inputMessage.placeholder = "Paste any message, social media DM, or communication to inspect...";
        } else if (mode === "url") {
            groupSubject.classList.add("hidden");
            groupMessage.classList.add("hidden");
            groupUrl.classList.remove("hidden");
        }

        clearError();
    }

    /**
     * Update character counter for text areas
     */
    function updateCharCounter() {
        const count = inputMessage.value.length;
        messageCharCount.textContent = `${count.toLocaleString()} character${count === 1 ? '' : 's'}`;
    }

    /**
     * Reset form inputs and results
     */
    function clearInputs() {
        inputSubject.value = "";
        inputMessage.value = "";
        inputUrl.value = "";
        updateCharCounter();
        clearError();
        resetResultsCard();
    }

    /**
     * Clear active error display
     */
    function clearError() {
        errorBox.classList.add("hidden");
    }

    /**
     * Show error box with title and message
     */
    function showError(title, message) {
        errorTitle.textContent = title;
        errorMessage.textContent = message;
        errorBox.classList.remove("hidden");
        resultPlaceholder.classList.add("hidden");
        resultContent.classList.add("hidden");
    }

    /**
     * Reset results card back to standby placeholder
     */
    function resetResultsCard() {
        resultPlaceholder.classList.remove("hidden");
        resultContent.classList.add("hidden");
        reportTypeBadge.className = "badge badge-idle";
        reportTypeBadge.textContent = "Standby";
    }

    /**
     * Set loading state during active scan
     */
    function setLoading(isLoading) {
        btnAnalyze.disabled = isLoading;
        btnClear.disabled = isLoading;
        scanSpinner.classList.toggle("hidden", !isLoading);
        btnAnalyzeText.textContent = isLoading ? "Analyzing..." : "Analyze for Phishing";
    }

    /**
     * Primary handler for scan submission
     */
    async function handleAnalysis(e) {
        if (e) e.preventDefault();
        clearError();

        let endpoint = "";
        let payload = {};

        if (currentMode === "url") {
            const rawUrl = inputUrl.value.trim();
            if (!rawUrl) {
                showError("Input Required", "Please enter a URL to inspect.");
                return;
            }
            endpoint = "/api/analyze/url";
            payload = { url: rawUrl };
        } else {
            const rawText = inputMessage.value.trim();
            if (!rawText) {
                showError("Input Required", `Please enter ${currentMode.toUpperCase()} message content to analyze.`);
                return;
            }
            endpoint = "/api/analyze/message";
            payload = {
                text: rawText,
                mode: currentMode,
                subject: inputSubject.value.trim(),
            };
        }

        setLoading(true);

        try {
            const response = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            const data = await response.json();

            if (!response.ok) {
                const errMsg = data.message || data.error || "The server rejected the analysis request.";
                showError("Analysis Rejected", errMsg);
                return;
            }

            renderResults(data);
            loadScanHistory(); // Refresh recent scans table
        } catch (err) {
            showError("Network / Server Error", "Could not connect to the phishing detection backend. Ensure the Flask server is running.");
            console.error("Analysis request failed:", err);
        } finally {
            setLoading(false);
        }
    }

    /**
     * Render returned analysis data into UI components
     */
    function renderResults(data) {
        resultPlaceholder.classList.add("hidden");
        errorBox.classList.add("hidden");
        resultContent.classList.remove("hidden");

        const status = data.status || "Unknown";
        const risk = (data.risk_level || "Unknown").toLowerCase();
        const confPct = data.confidence_percentage;
        const analysisType = data.analysis_type || "Analysis";

        // Update Header Badge
        reportTypeBadge.textContent = `${currentMode.toUpperCase()} REPORT`;
        reportTypeBadge.className = `badge badge-${risk}`;

        // Update Verdict Banner
        verdictStatus.textContent = status;
        verdictSubtitle.textContent = data.verdict || "";

        verdictBanner.className = "verdict-banner";
        if (status.includes("Likely Phishing") || status.includes("Suspicious")) {
            verdictBanner.classList.add("status-phishing");
        } else if (status.includes("No Strong Phishing")) {
            verdictBanner.classList.add("status-safe");
        } else {
            verdictBanner.classList.add("status-warning");
        }

        // Risk Pill
        riskPill.textContent = `${risk.toUpperCase()} RISK`;
        riskPill.className = `risk-pill ${risk}`;

        // Metrics Grid
        if (confPct !== null && confPct !== undefined) {
            metricConfidence.textContent = `${confPct}%`;
            meterFill.style.width = `${Math.min(100, Math.max(0, confPct))}%`;
            meterFill.style.backgroundColor = risk === "high" ? "var(--danger-red)" : (risk === "medium" ? "var(--warning-amber)" : "var(--success-green)");
        } else {
            metricConfidence.textContent = "Heuristic";
            meterFill.style.width = risk === "high" ? "90%" : (risk === "medium" ? "50%" : "20%");
            meterFill.style.backgroundColor = "var(--accent-blue)";
        }

        metricEngine.textContent = analysisType;
        if (currentMode === "url") {
            const feats = data.features || {};
            metricWordcount.textContent = `Host: ${feats.hostname || 'Analyzed'}`;
        } else {
            metricWordcount.textContent = `${data.word_count || 0} words evaluated`;
        }

        // Indicators List
        indicatorsList.innerHTML = "";
        const indicators = data.indicators || [];

        if (indicators.length === 0) {
            indicatorsList.innerHTML = `<div class="no-indicators">✓ No recognized threat indicators or red flags triggered.</div>`;
        } else {
            indicators.forEach(item => {
                const div = document.createElement("div");
                const sev = (item.severity || "low").toLowerCase();
                div.className = `indicator-item ${sev}`;

                let icon = "⚠️";
                if (sev === "high") icon = "🚨";
                else if (sev === "medium") icon = "⚡";
                else if (sev === "info") icon = "ℹ️";

                div.innerHTML = `
                    <span class="indicator-icon">${icon}</span>
                    <div class="indicator-body">
                        <span class="indicator-category">${escapeHtml(item.category)}</span>
                        <p class="indicator-detail">${escapeHtml(item.detail)}</p>
                    </div>
                `;
                indicatorsList.appendChild(div);
            });
        }

        // Recommendation
        recommendationText.textContent = data.recommendation || "Always exercise care when dealing with unsolicited communications.";
    }

    /**
     * Check backend system health and loaded models
     */
    async function checkSystemHealth() {
        try {
            const res = await fetch("/api/health");
            if (!res.ok) throw new Error("Health endpoint returned non-200");
            const data = await res.json();

            const msgLoaded = data.components?.message_model_loaded;
            const urlLoaded = data.components?.url_model_loaded;

            const dot = systemStatusPill.querySelector(".status-dot");
            dot.classList.remove("pulsing");
            dot.classList.add("active");

            if (msgLoaded && urlLoaded) {
                systemStatusText.textContent = "AI Engines: Fully Operational";
                systemStatusPill.title = "Both Message and URL Machine Learning models are active.";
            } else if (msgLoaded || urlLoaded) {
                systemStatusText.textContent = "AI Engines: Partial (Heuristic Active)";
            } else {
                systemStatusText.textContent = "Engine: Heuristic Mode";
                systemStatusPill.title = "ML models not found; running rule-based heuristics.";
            }
        } catch (e) {
            const dot = systemStatusPill.querySelector(".status-dot");
            dot.classList.remove("active", "pulsing");
            dot.style.backgroundColor = "var(--danger-red)";
            systemStatusText.textContent = "Backend: Disconnected";
        }
    }

    /**
     * Load recent scans from backend SQLite database
     */
    async function loadScanHistory() {
        try {
            const res = await fetch("/api/history");
            if (!res.ok) return;
            const data = await res.json();
            const history = data.history || [];

            if (history.length === 0) {
                historyTbody.innerHTML = `<tr><td colspan="5" class="empty-table-cell">No recent scans recorded yet.</td></tr>`;
                return;
            }

            historyTbody.innerHTML = "";
            history.forEach(item => {
                const tr = document.createElement("tr");
                const risk = (item.risk_level || "Unknown").toLowerCase();
                const preview = escapeHtml(item.target_preview || "");
                const confDisplay = item.confidence ? `${Math.round(item.confidence * 100)}%` : "-";

                tr.innerHTML = `
                    <td class="font-mono">${escapeHtml(item.timestamp || "")}</td>
                    <td><span class="history-mode-pill">${escapeHtml(item.mode || "")}</span></td>
                    <td title="${preview}">${preview}</td>
                    <td>${escapeHtml(item.status || "")}</td>
                    <td><span class="risk-pill ${risk}" style="padding: 2px 8px; font-size: 0.7rem;">${escapeHtml(item.risk_level || "")}</span></td>
                `;
                historyTbody.appendChild(tr);
            });
        } catch (e) {
            console.warn("Could not load scan history:", e);
        }
    }

    /**
     * Clear all recorded scan history
     */
    async function clearScanHistory() {
        try {
            const res = await fetch("/api/history/clear", { method: "POST" });
            if (res.ok) {
                loadScanHistory();
            }
        } catch (e) {
            console.error("Could not clear history:", e);
        }
    }

    /**
     * HTML Escaping utility to prevent XSS
     */
    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
