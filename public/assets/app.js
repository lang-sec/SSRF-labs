"use strict";

(() => {
    const STORAGE_KEY = "ssrf-field-lab-progress-v2";
    const SOURCE_KEY = "ssrf-field-lab-sources-v1";

    const state = {
        bootstrap: null,
        completed: new Set(),
        responses: new Map(),
        hintCounts: new Map(),
        sources: new Map(),
        activeLevel: null,
        toastTimer: null,
    };

    document.addEventListener("DOMContentLoaded", initialize);

    async function initialize() {
        loadProgress();
        loadSources();
        $("#reset-progress")?.addEventListener("click", resetProgress);
        window.addEventListener("hashchange", handleRoute);

        try {
            state.bootstrap = await requestJson("/api/bootstrap");
        } catch (error) {
            const content = $("#content");
            if (content) {
                content.innerHTML = `<p class="muted">无法连接靶场服务：${escapeHtml(error.message)}</p>`;
            }
            return;
        }

        buildNav();
        updateProgress();
        handleRoute();
    }

    /* ---------------------------------------------------------------------
     * Utilities
     * ------------------------------------------------------------------ */

    function $(selector, root = document) {
        return root.querySelector(selector);
    }

    function $$(selector, root = document) {
        return Array.from(root.querySelectorAll(selector));
    }

    function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>"']/g, (character) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
        }[character]));
    }

    function pad(value) {
        return String(value).padStart(2, "0");
    }

    async function requestJson(url, options = {}) {
        const response = await fetch(url, {
            ...options,
            headers: {
                "Content-Type": "application/json",
                ...(options.headers || {}),
            },
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok && !data.result) {
            throw new Error(data.error || `请求失败：HTTP ${response.status}`);
        }
        return data;
    }

    function showToast(message) {
        const toast = $("#toast");
        if (!toast) {
            return;
        }
        toast.textContent = message;
        toast.classList.add("visible");
        clearTimeout(state.toastTimer);
        state.toastTimer = setTimeout(() => toast.classList.remove("visible"), 2000);
    }

    /* ---------------------------------------------------------------------
     * Progress and navigation
     * ------------------------------------------------------------------ */

    function loadProgress() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            const data = raw ? JSON.parse(raw) : null;
            if (Array.isArray(data?.completed)) {
                state.completed = new Set(data.completed.map((id) => Number(id)).filter(Number.isFinite));
            }
        } catch {
            state.completed = new Set();
        }
    }

    function saveProgress() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                completed: Array.from(state.completed),
                updatedAt: new Date().toISOString(),
            }));
        } catch {
            // Progress is only a convenience.
        }
    }

    function loadSources() {
        try {
            const raw = localStorage.getItem(SOURCE_KEY);
            const data = raw ? JSON.parse(raw) : null;
            if (data && typeof data === "object") {
                for (const [level, source] of Object.entries(data)) {
                    if (source && typeof source.snippet === "string") {
                        state.sources.set(Number(level), source);
                    }
                }
            }
        } catch {
            state.sources = new Map();
        }
    }

    function saveSources() {
        try {
            const data = {};
            for (const [level, source] of state.sources) {
                data[level] = source;
            }
            localStorage.setItem(SOURCE_KEY, JSON.stringify(data));
        } catch {
            // Source caching is only a convenience.
        }
    }

    function updateProgress() {
        if (!state.bootstrap) {
            return;
        }

        const challenges = state.bootstrap.challenges;
        const completed = challenges.filter((challenge) => state.completed.has(challenge.id)).length;

        const label = $("#progress-label");
        const bar = $("#progress-bar");
        if (label) {
            label.textContent = `${completed} / ${challenges.length}`;
        }
        if (bar) {
            bar.style.width = challenges.length > 0 ? `${(completed / challenges.length) * 100}%` : "0%";
        }

        for (const item of $$(".stage-link[data-stage]")) {
            const id = Number(item.dataset.stage);
            item.classList.toggle("completed", state.completed.has(id));
        }
    }

    function buildNav() {
        const nav = $("#stage-nav");
        if (!nav || !state.bootstrap) {
            return;
        }

        nav.innerHTML = state.bootstrap.challenges.map((challenge) => `
            <button class="stage-link" type="button" data-stage="${challenge.id}">
                <span class="stage-number">${pad(challenge.id)}</span>
                <span class="stage-title">${escapeHtml(challenge.title)}</span>
            </button>
        `).join("");

        for (const item of $$(".stage-link", nav)) {
            item.addEventListener("click", () => {
                location.hash = `#${item.dataset.stage}`;
            });
        }
    }

    function updateNavActive(stage) {
        for (const item of $$(".stage-link")) {
            item.classList.toggle("active", item.dataset.stage === String(stage));
        }
    }

    function handleRoute() {
        if (!state.bootstrap) {
            return;
        }

        const raw = location.hash.replace(/^#/, "").trim();
        const challenges = state.bootstrap.challenges;

        if (raw === "") {
            const first = challenges.find((challenge) => !state.completed.has(challenge.id)) || challenges[0];
            if (first) {
                location.hash = `#${first.id}`;
            }
            return;
        }

        const id = Number(raw);
        const challenge = challenges.find((item) => item.id === id);
        if (!challenge) {
            location.hash = "#1";
            return;
        }

        state.activeLevel = id;
        updateNavActive(id);
        renderLevel(challenge);
        window.scrollTo(0, 0);
    }

    /* ---------------------------------------------------------------------
     * Level page
     * ------------------------------------------------------------------ */

    function renderLevel(challenge) {
        const content = $("#content");
        if (!content) {
            return;
        }

        const business = challenge.business || {};
        const saved = state.responses.get(challenge.id);
        const solved = state.completed.has(challenge.id);
        const extraFields = Array.isArray(challenge.extraFields) ? challenge.extraFields : [];

        content.innerHTML = `
            <section class="level" data-level="${challenge.id}">
                <header class="level-header">
                    <div>
                        <span class="level-number">关卡 ${pad(challenge.id)}</span>
                        <h1 class="challenge-title">${escapeHtml(challenge.title)}</h1>
                    </div>
                    <span class="completion-badge ${solved ? "is-solved" : ""}" id="completion-badge">${solved ? "已完成" : "未完成"}</span>
                </header>

                <form id="probe-form" class="probe-form" autocomplete="off">
                    <label for="url-input">服务端请求 URL</label>
                    <div class="input-row">
                        <input
                            class="url-input"
                            id="url-input"
                            name="${escapeHtml(business.param || "url")}"
                            type="text"
                            spellcheck="false"
                            placeholder="http://..."
                            value="${escapeHtml(saved?.input || "")}"
                        >
                        <button class="primary-button" id="send-button" type="submit">发送请求</button>
                    </div>
                    ${renderExtraFields(extraFields, saved)}
                </form>

                <section class="section result-section">
                    <div class="section-head">
                        <h2>结果</h2>
                        <span class="status" id="response-status">未请求</span>
                        <span class="meta" id="response-meta"></span>
                    </div>
                    <div id="solve-area"></div>
                    <pre id="response-body" class="response-body">提交后在此显示服务端响应。</pre>
                </section>

                <section class="section">
                    <div class="section-head">
                        <h2>提示</h2>
                        <span class="meta" id="hint-count">0 / ${Array.isArray(challenge.hints) ? challenge.hints.length : 0}</span>
                    </div>
                    <div id="hint-list" class="hint-list">
                        <p class="muted">需要时逐条查看提示。</p>
                    </div>
                    <button class="secondary-button" id="hint-button" type="button">显示下一条提示</button>
                </section>

                <section class="section">
                    <div class="section-head"><h2>源码</h2></div>
                    <div id="source-content" class="source-content"></div>
                </section>
            </section>
        `;

        bindLevelEvents(challenge);
        renderHints(challenge);
        renderSource(challenge);

        if (saved) {
            renderResponse(challenge, saved);
        }
    }

    function renderExtraFields(fields, saved) {
        if (fields.length === 0) {
            return "";
        }

        return `
            <div class="extra-fields">
                ${fields.map((field) => `
                    <label class="extra-field">
                        <span>${escapeHtml(field.label)}</span>
                        <input
                            type="text"
                            data-extra-key="${escapeHtml(field.key)}"
                            spellcheck="false"
                            placeholder="${escapeHtml(field.placeholder || "")}"
                            value="${escapeHtml(saved?.fields?.[field.key] || "")}"
                        >
                    </label>
                `).join("")}
            </div>
        `;
    }

    function collectExtraFields() {
        const fields = {};
        for (const input of $$("[data-extra-key]")) {
            fields[input.dataset.extraKey] = input.value.trim();
        }
        return fields;
    }

    function bindLevelEvents(challenge) {
        const form = $("#probe-form");
        const input = $("#url-input");

        form?.addEventListener("submit", (event) => {
            event.preventDefault();
            submitProbe(challenge, input?.value || "", collectExtraFields());
        });

        for (const field of $$("#probe-form input")) {
            field.addEventListener("keydown", (event) => {
                if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault();
                    submitProbe(challenge, input?.value || "", collectExtraFields());
                }
            });
        }

        $("#hint-button")?.addEventListener("click", () => {
            const count = state.hintCounts.get(challenge.id) || 0;
            const total = Array.isArray(challenge.hints) ? challenge.hints.length : 0;
            state.hintCounts.set(challenge.id, count >= total ? 0 : count + 1);
            renderHints(challenge);
        });
    }

    function renderHints(challenge) {
        const hints = Array.isArray(challenge.hints) ? challenge.hints : [];
        const count = state.hintCounts.get(challenge.id) || 0;
        const list = $("#hint-list");
        const counter = $("#hint-count");
        const button = $("#hint-button");

        if (!list || !counter || !button) {
            return;
        }

        if (count === 0) {
            list.innerHTML = '<p class="muted">需要时逐条查看提示。</p>';
        } else {
            list.innerHTML = hints.slice(0, count).map((hint) => `
                <div class="hint-item">${escapeHtml(hint)}</div>
            `).join("");
        }

        counter.textContent = `${count} / ${hints.length}`;
        button.textContent = count >= hints.length ? "收起提示" : "显示下一条提示";
    }

    function renderSource(challenge) {
        const container = $("#source-content");
        if (!container) {
            return;
        }

        if (!state.completed.has(challenge.id)) {
            container.innerHTML = '<p class="locked">通关后可查看本关源码。</p>';
            return;
        }

        const source = state.sources.get(challenge.id);
        if (!source) {
            container.innerHTML = '<p class="locked">本关已通关，但当前浏览器没有保存源码。重置进度后重新通关即可查看。</p>';
            return;
        }

        container.innerHTML = `
            <div class="code-label">${escapeHtml(source.codeLabel || "vulnerable.php")}</div>
            <pre class="code-block">${escapeHtml(source.snippet || "")}</pre>
        `;
    }

    /* ---------------------------------------------------------------------
     * Submission and result
     * ------------------------------------------------------------------ */

    async function submitProbe(challenge, rawUrl, fields = {}) {
        const url = rawUrl.trim();
        const input = $("#url-input");
        if (!url) {
            showToast("先填写一个 URL");
            input?.focus();
            return;
        }

        const business = challenge.business || {};
        if (!business.api) {
            showToast("本关缺少业务端点配置");
            return;
        }

        const headers = {};
        if (business.header && business.headerField) {
            const headerValue = (fields[business.headerField] || "").trim();
            if (!headerValue) {
                showToast(`${business.header} 不能为空`);
                return;
            }
            headers[business.header] = headerValue;
        }

        const button = $("#send-button");
        if (button) {
            button.disabled = true;
            button.textContent = "请求中…";
        }

        try {
            const requestPayload = {};
            requestPayload[business.param || "url"] = url;

            const data = await requestJson(business.api, {
                method: business.method || "POST",
                headers,
                body: JSON.stringify(requestPayload),
            });

            const payload = { ...data, input: url, fields };
            state.responses.set(challenge.id, payload);

            if (data.result?.solved && !state.completed.has(challenge.id)) {
                state.completed.add(challenge.id);
                saveProgress();
                updateProgress();
                showToast(`关卡 ${pad(challenge.id)} 完成`);
            }

            if (data.source && typeof data.source.snippet === "string") {
                state.sources.set(challenge.id, data.source);
                saveSources();
            }

            renderResponse(challenge, payload);
            renderSource(challenge);
        } catch (error) {
            const failed = {
                input: url,
                fields,
                result: {
                    ok: false,
                    blocked: false,
                    validation: { decision: "error", message: error.message },
                    response: { status: 0, durationMs: 0, bytes: 0, body: error.message },
                    solved: false,
                },
            };
            state.responses.set(challenge.id, failed);
            renderResponse(challenge, failed);
            renderSource(challenge);
            showToast(error.message);
        } finally {
            if (button) {
                button.disabled = false;
                button.textContent = "发送请求";
            }
        }
    }

    function renderResponse(challenge, payload) {
        const result = payload.result || {};
        const status = $("#response-status");
        const meta = $("#response-meta");
        const body = $("#response-body");
        const solveArea = $("#solve-area");
        const badge = $("#completion-badge");

        if (!status || !meta || !body || !solveArea) {
            return;
        }

        let kind = "error";
        let label = "ERROR";
        if (result.blocked) {
            kind = "blocked";
            label = "BLOCKED";
        } else if (result.ok) {
            kind = "success";
            label = `HTTP ${result.response?.status ?? 0}`;
        }

        status.className = `status ${kind}`;
        status.textContent = label;
        meta.textContent = `${result.response?.durationMs ?? 0} ms · ${result.validation?.decision || "error"}`;
        body.textContent = result.response?.body || "响应正文为空。";

        if (result.solved) {
            const responseBody = result.response?.body || "";
            const flag = responseBody.match(/FLAG\{[^}]+\}/);
            const md5 = responseBody.match(/\b[a-f0-9]{32}\b/i);
            const solveMode = challenge.business?.solveMode || "";

            if (solveMode === "md5") {
                solveArea.innerHTML = `
                    <div class="flag-banner">
                        <span>MD5</span>
                        <code>${md5 ? escapeHtml(md5[0]) : "已通关，检测到有回显 SSRF。"}</code>
                    </div>
                `;
            } else if (solveMode === "dnslog") {
                solveArea.innerHTML = `
                    <div class="flag-banner">
                        <span>DNS</span>
                        <code>${escapeHtml(responseBody || "已通关，盲请求已发出。")}</code>
                    </div>
                `;
            } else if (flag) {
                solveArea.innerHTML = `<div class="flag-banner"><span>FLAG</span><code>${escapeHtml(flag[0])}</code></div>`;
            } else {
                solveArea.innerHTML = '<div class="flag-banner"><span>结果</span><code>已通关，盲请求已确认。</code></div>';
            }
        } else {
            solveArea.innerHTML = "";
        }

        if (badge) {
            const solved = state.completed.has(challenge.id);
            badge.textContent = solved ? "已完成" : "未完成";
            badge.classList.toggle("is-solved", solved);
        }
    }

    function resetProgress() {
        state.completed.clear();
        state.responses.clear();
        state.hintCounts.clear();
        state.sources.clear();
        saveProgress();
        saveSources();
        updateProgress();
        handleRoute();
        showToast("学习进度已重置");
    }
})();
