(() => {
    "use strict";

    const STORAGE_KEY = "ssrf-field-lab-progress-v1";
    const state = {
        bootstrap: null,
        stage: "intro",
        completed: new Set(),
        responses: new Map(),
        hintCounts: new Map(),
        solutions: new Map(),
        logs: [],
        traceOpen: false,
        toastTimer: null,
        logTimer: null,
    };

    const icons = {
        arrow: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 12h14"></path><path d="m14 7 5 5-5 5"></path></svg>',
        send: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m22 2-7 20-4-9-9-4Z"></path><path d="M22 2 11 13"></path></svg>',
        check: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5 12 4 4L19 6"></path></svg>',
        eye: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"></path><circle cx="12" cy="12" r="3"></circle></svg>',
        copy: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>',
        shield: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3Z"></path><path d="m9 12 2 2 4-4"></path></svg>',
        book: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z"></path></svg>',
        code: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m16 18 6-6-6-6"></path><path d="m8 6-6 6 6 6"></path></svg>',
        terminal: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m4 17 6-6-6-6"></path><path d="M12 19h8"></path></svg>',
    };

    const $ = (selector, root = document) => root.querySelector(selector);
    const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

    function escapeHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function stageById(id) {
        if (!state.bootstrap) return null;
        return state.bootstrap.challenges.find((item) => String(item.id) === String(id)) || null;
    }

    function getChallenge(id) {
        return state.bootstrap.challenges.find((item) => item.id === Number(id));
    }

    function loadProgress() {
        try {
            const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
            state.completed = new Set(Array.isArray(saved.completed) ? saved.completed.map(Number) : []);
        } catch {
            state.completed = new Set();
        }
    }

    function saveProgress() {
        localStorage.setItem(STORAGE_KEY, JSON.stringify({
            completed: [...state.completed],
            updatedAt: new Date().toISOString(),
        }));
    }

    function setTraceOpen(open) {
        const dock = $("#trace-dock");
        const body = $("#trace-dock-body");
        const toggle = $("#trace-toggle");
        const shortcut = $("#trace-shortcut");
        if (!dock || !body || !toggle || !shortcut) return;

        state.traceOpen = Boolean(open);
        dock.classList.toggle("open", state.traceOpen);
        body.hidden = !state.traceOpen;
        document.body.classList.toggle("trace-open", state.traceOpen);
        toggle.setAttribute("aria-expanded", String(state.traceOpen));
        shortcut.setAttribute("aria-expanded", String(state.traceOpen));
    }

    function updateTraceSummary() {
        const count = $("#trace-count");
        const summary = $("#trace-summary");
        if (!count || !summary) return;

        count.textContent = String(state.logs.length);
        if (state.logs.length === 0) {
            summary.textContent = "尚无请求，展开查看实时记录";
            return;
        }

        const latest = state.logs[0];
        const result = latest.solved
            ? "命中"
            : (latest.decision === "blocked" ? "拦截" : "放行");
        summary.textContent = `${state.logs.length} 条记录 · 最近 L${latest.level} ${result}`;
    }

    function setContextHint(stage) {
        const hint = $("#context-hint");
        if (!hint) return;

        if (stage === "intro") {
            hint.textContent = "从请求链路开始理解 SSRF";
        } else if (stage === "defense") {
            hint.textContent = "把每个绕过点映射到防线";
        } else {
            hint.textContent = "比较应用层校验与真实连接目标";
        }
    }

    function showToast(message) {
        const toast = $("#toast");
        toast.textContent = message;
        toast.classList.add("visible");
        clearTimeout(state.toastTimer);
        state.toastTimer = setTimeout(() => toast.classList.remove("visible"), 2400);
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
        if (!response.ok) {
            throw new Error(data.error || `请求失败：HTTP ${response.status}`);
        }
        return data;
    }

    function buildNav() {
        const nav = $("#stage-nav");
        nav.replaceChildren();

        const introButton = navButton({
            id: "intro",
            index: "00",
            title: "认识 SSRF",
        });
        nav.append(introButton);

        const groupLabel = document.createElement("div");
        groupLabel.className = "nav-group-label";
        groupLabel.textContent = "绕过练习";
        nav.append(groupLabel);

        for (const challenge of state.bootstrap.challenges) {
            const button = navButton({
                id: challenge.id,
                index: String(challenge.id).padStart(2, "0"),
                title: challenge.title,
            });
            if (state.completed.has(challenge.id)) {
                button.classList.add("completed");
            }
            nav.append(button);
        }

        const defenseLabel = document.createElement("div");
        defenseLabel.className = "nav-group-label";
        defenseLabel.textContent = "进入防御";
        nav.append(defenseLabel);

        nav.append(navButton({
            id: "defense",
            index: String(state.bootstrap.challenges.length + 1).padStart(2, "0"),
            title: "修复与防线",
        }));

        updateProgress();
    }

    function navButton({ id, index, title }) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "stage-link";
        button.dataset.stage = String(id);
        button.innerHTML = `
            <span class="stage-link-index">${escapeHtml(index)}</span>
            <span class="stage-link-title">${escapeHtml(title)}</span>
            <span class="stage-link-state">${icons.check}</span>
        `;
        button.addEventListener("click", () => navigate(id));
        return button;
    }

    function updateProgress() {
        const total = state.bootstrap?.challenges.length || 6;
        const completed = state.completed.size;
        $("#progress-label").textContent = `${completed} / ${total}`;
        $("#progress-bar").style.width = `${(completed / total) * 100}%`;

        $$(".stage-link").forEach((button) => {
            const id = Number(button.dataset.stage);
            const active = String(state.stage) === button.dataset.stage;
            button.classList.toggle("active", active);
            button.classList.toggle("completed", state.completed.has(id));
            if (active) {
                button.setAttribute("aria-current", "page");
            } else {
                button.removeAttribute("aria-current");
            }
        });
        updateTraceSummary();
    }

    function setBreadcrumb(label) {
        $("#breadcrumb-current").textContent = label;
    }

    function navigate(stage) {
        state.stage = stage;
        const normalized = String(stage);
        if (window.location.hash !== `#${normalized}`) {
            history.replaceState(null, "", `#${normalized}`);
        }

        if (stage === "intro") {
            renderIntro();
        } else if (stage === "defense") {
            renderDefense();
        } else {
            const challenge = getChallenge(stage);
            if (challenge) {
                renderChallenge(challenge);
            } else {
                renderIntro();
            }
        }

        setContextHint(stage);
        setTraceOpen(false);
        updateProgress();
        window.scrollTo({ top: 0, behavior: "smooth" });
    }

    function renderIntro() {
        const total = state.bootstrap.challenges.length;
        const curriculum = state.bootstrap.challenges.map((challenge) => `
            <div class="curriculum-item ${state.completed.has(challenge.id) ? "completed" : ""}">
                <span class="curriculum-item-index">${String(challenge.id).padStart(2, "0")}</span>
                <strong>${escapeHtml(challenge.title)}</strong>
                <p>${escapeHtml(challenge.summary)}</p>
                <span class="curriculum-item-status">${state.completed.has(challenge.id) ? "已完成" : challenge.difficulty}</span>
            </div>
        `).join("");

        $("#content").innerHTML = `
            <section class="lesson-home">
                <div class="home-hero">
                    <div class="home-copy">
                        <p class="eyebrow">SSRF 学习靶场</p>
                        <h1 class="home-title">请求从浏览器出发，<span>却从服务器抵达。</span></h1>
                        <p class="home-lead">
                            当业务服务替用户读取 URL，它使用的是自己的网络身份。
                            解析差异、DNS、重定向、协议、渲染器和远程内容都可能把请求带进内网。
                        </p>
                        <div class="home-actions">
                            <button class="primary-button" type="button" id="start-lab">
                                ${icons.arrow}
                                进入第一关
                            </button>
                            <button class="secondary-button" type="button" id="go-defense">
                                ${icons.shield}
                                先看防线
                            </button>
                        </div>
                    </div>

                    <aside class="signal-board" aria-label="SSRF 请求链路示意">
                        <div class="signal-board-head">
                            <span>Routing preview</span>
                            <strong>Boundary: loopback only</strong>
                        </div>
                        <div class="signal-routes">
                            <div class="signal-route">
                                <span class="signal-route-index">01</span>
                                <span class="signal-node">用户输入</span>
                                <span class="signal-link" aria-hidden="true"></span>
                                <span class="signal-node">url=...</span>
                            </div>
                            <div class="signal-route">
                                <span class="signal-route-index">02</span>
                                <span class="signal-node">业务服务</span>
                                <span class="signal-link" aria-hidden="true"></span>
                                <span class="signal-node">curl_get()</span>
                            </div>
                            <div class="signal-route">
                                <span class="signal-route-index">03</span>
                                <span class="signal-node">目标校验</span>
                                <span class="signal-link" aria-hidden="true"></span>
                                <span class="signal-node">filter</span>
                            </div>
                            <div class="signal-route target">
                                <span class="signal-route-index">04</span>
                                <span class="signal-node">真实目标</span>
                                <span class="signal-link" aria-hidden="true"></span>
                                <span class="signal-node">127.0.0.1</span>
                            </div>
                        </div>
                        <div class="signal-board-meta">
                            <div class="signal-stat">
                                <span>练习关口</span>
                                <strong>${total} 个渐进关卡</strong>
                            </div>
                            <div class="signal-stat">
                                <span>当前进度</span>
                                <strong>${state.completed.size} / ${total}</strong>
                            </div>
                        </div>
                    </aside>
                </div>

                <div class="attack-chain-band">
                    <div class="attack-chain-label">
                        <span>一条 URL 的路径</span>
                        <strong>失守发生在哪里</strong>
                    </div>
                    <div class="attack-chain" aria-label="SSRF 从输入到内网目标的路径">
                        <div class="chain-node">
                            <span>输入</span>
                            <strong>不可信 URL</strong>
                            <code>upload / webhook / import</code>
                        </div>
                        <span class="chain-connector" aria-hidden="true"></span>
                        <div class="chain-node">
                            <span>信任</span>
                            <strong>服务端发起请求</strong>
                            <code>server-side network identity</code>
                        </div>
                        <span class="chain-connector" aria-hidden="true"></span>
                        <div class="chain-node">
                            <span>绕过</span>
                            <strong>校验未绑定目标</strong>
                            <code>string / redirect / DNS</code>
                        </div>
                        <span class="chain-connector" aria-hidden="true"></span>
                        <div class="chain-node">
                            <span>结果</span>
                            <strong>触达内部资源</strong>
                            <code>loopback / metadata</code>
                        </div>
                    </div>
                </div>

                <div class="curriculum-section">
                    <div class="section-heading-row">
                        <h2>从直连内网到二级请求滥用</h2>
                        <span>按顺序练习，每关都会展示校验结果与真实目标</span>
                    </div>
                    <div class="curriculum-strip">
                        ${curriculum}
                    </div>
                </div>
            </section>
        `;
        setBreadcrumb("起点");
        $("#start-lab").addEventListener("click", () => navigate(1));
        $("#go-defense").addEventListener("click", () => navigate("defense"));
    }

    function renderChallenge(challenge) {
        const completed = state.completed.has(challenge.id);
        const savedResponse = state.responses.get(challenge.id);
        const targetText = challenge.id === 4
            ? "从公开站点开始"
            : challenge.target;
        const cause = challenge.cause || { summary: "", points: [], keyGap: "" };
        const business = challenge.business || { feature: "", entry: "", workflow: [], impact: "" };

        $("#content").innerHTML = `
            <section class="challenge-view" data-level="${challenge.id}">
                <header class="challenge-hero">
                    <span class="challenge-ghost" aria-hidden="true">${String(challenge.id).padStart(2, "0")}</span>
                    <div class="challenge-heading">
                        <div class="challenge-meta">
                            <span class="meta-chip">关卡 ${String(challenge.id).padStart(2, "0")}</span>
                            <span class="meta-text">${escapeHtml(challenge.difficulty)} · 绕过练习</span>
                        </div>
                        <h1 class="challenge-title">${escapeHtml(challenge.title)}</h1>
                        <p class="challenge-summary">${escapeHtml(challenge.summary)}</p>
                    </div>
                    <div class="completion-badge ${completed ? "completed" : ""}" id="completion-badge">
                        ${completed ? icons.check : ""}
                        ${completed ? "已完成" : "待完成"}
                    </div>
                </header>

                <section class="business-context" aria-labelledby="business-title-${challenge.id}">
                    <div class="business-summary">
                        <span class="business-kicker">真实业务场景</span>
                        <h2 id="business-title-${challenge.id}">${escapeHtml(business.feature)}</h2>
                        <p>${escapeHtml(business.impact)}</p>
                    </div>
                    <div class="business-flow" aria-label="业务流程">
                        ${business.workflow.map((step, index) => `
                            <div class="business-step">
                                <span>${String(index + 1).padStart(2, "0")}</span>
                                <strong>${escapeHtml(step)}</strong>
                            </div>
                        `).join("")}
                    </div>
                    <div class="business-entry">
                        <span>业务入口</span>
                        <code>${escapeHtml(business.entry)}</code>
                    </div>
                </section>

                <div class="brief-grid">
                    <section class="brief-copy">
                        <h2>为什么这里会失守</h2>
                        <p>${escapeHtml(challenge.concept)}</p>
                        <div class="objective-block">
                            <span>目标</span>
                            <strong>${escapeHtml(challenge.goal)}</strong>
                        </div>
                        <div class="filter-block">${escapeHtml(challenge.filter)}</div>
                    </section>
                    <div class="code-window">
                        <div class="code-header">
                            <span><i></i> ${escapeHtml(challenge.codeLabel || "vulnerable.php")}</span>
                            <span>PHP 8.4</span>
                        </div>
                        <pre>${escapeHtml(challenge.snippet)}</pre>
                    </div>
                </div>

                <section class="cause-section" aria-labelledby="cause-title-${challenge.id}">
                    <div class="cause-heading">
                        <div>
                            <span class="cause-kicker">漏洞成因拆解</span>
                            <h2 id="cause-title-${challenge.id}">这一关到底哪里出了问题</h2>
                        </div>
                        <p class="cause-summary">${escapeHtml(cause.summary)}</p>
                    </div>
                    <div class="cause-grid">
                        ${cause.points.map((point) => `
                            <article class="cause-item">
                                <span class="cause-marker" aria-hidden="true"></span>
                                <h3>${escapeHtml(point.title)}</h3>
                                <p>${escapeHtml(point.body)}</p>
                            </article>
                        `).join("")}
                    </div>
                    <div class="cause-gap">
                        <span>关键缺口</span>
                        <strong>${escapeHtml(cause.keyGap)}</strong>
                    </div>
                </section>

                <section class="request-console">
                    <div class="console-heading">
                        <h2>构造服务端请求</h2>
                        <span class="target-chip" title="${escapeHtml(targetText)}">${escapeHtml(challenge.targetLabel)}</span>
                    </div>
                    <form id="probe-form" autocomplete="off">
                        <label class="sr-only" for="url-input">服务端请求 URL</label>
                        <div class="request-row">
                            <span class="method-badge">GET</span>
                            <input
                                class="url-input"
                                id="url-input"
                                name="url"
                                type="text"
                                spellcheck="false"
                                placeholder="${escapeHtml(challenge.target)}"
                                value="${escapeHtml(savedResponse?.input || "")}"
                                aria-describedby="keyboard-note"
                            >
                            <button class="primary-button send-button" id="send-button" type="submit">
                                ${icons.send}
                                <span>发送请求</span>
                            </button>
                        </div>
                        ${renderExtraFields(challenge, savedResponse)}
                        <div class="request-meta-row">
                            <div class="hint-controls">
                                <button class="text-button" id="hint-button" type="button">
                                    ${icons.eye}
                                    <span>给我一条提示</span>
                                </button>
                                <span class="hint-count" id="hint-count">0 / ${challenge.hints.length}</span>
                            </div>
                            <span class="keyboard-note" id="keyboard-note"><kbd>Ctrl</kbd> + <kbd>Enter</kbd> 发送</span>
                        </div>
                    </form>
                </section>

                <div class="route-strip" id="route-strip" aria-label="请求路径">
                    ${routeNode("01", "Browser", "你的浏览器")}
                    <span class="route-link" aria-hidden="true"></span>
                    ${routeNode("02", "Application", "靶场业务服务")}
                    <span class="route-link" aria-hidden="true"></span>
                    ${routeNode("03", "Validation", "目标校验")}
                    <span class="route-link" aria-hidden="true"></span>
                    ${routeNode("04", "Sink", "真实目标")}
                </div>

                <section class="response-panel">
                    <div class="response-header">
                        <div class="response-title">
                            <h2>服务端响应</h2>
                            <span class="response-status" id="response-status">IDLE</span>
                        </div>
                        <span class="response-meta" id="response-meta">尚未发起请求</span>
                    </div>
                    <div class="terminal">
                        <div class="terminal-bar">
                            <span>HTTP RESPONSE / BODY</span>
                            <div class="terminal-bar-actions">
                                <span id="response-bytes">0 B</span>
                                <button class="terminal-copy" id="copy-response" type="button" title="复制响应内容" aria-label="复制响应内容">
                                    ${icons.copy}
                                </button>
                            </div>
                        </div>
                        <pre id="response-body" class="terminal-placeholder">等待请求。响应正文会显示在这里。</pre>
                    </div>
                    <div id="solve-area"></div>
                </section>

                <div class="learning-notes">
                    <section class="notes-section">
                        <h2>逐步提示</h2>
                        <div id="hint-list"><p class="hint-empty">先自己观察原始请求和目标。需要时再逐条打开提示。</p></div>
                    </section>
                    <section class="notes-section">
                        <h2>通关后复盘</h2>
                        <div id="solution-content">
                            <p class="solution-empty">完成本关后，可查看完整绕过步骤和对应防线。</p>
                        </div>
                        <button class="secondary-button" id="solution-button" type="button">
                            ${icons.book}
                            <span>查看解法</span>
                        </button>
                    </section>
                </div>
            </section>
        `;

        setBreadcrumb(`关卡 ${String(challenge.id).padStart(2, "0")} · ${challenge.title}`);
        bindChallengeEvents(challenge);
        renderHints(challenge);

        if (savedResponse) {
            renderResponse(challenge, savedResponse);
        }
    }

    function routeNode(index, label, title) {
        return `
            <div class="route-node">
                <span class="route-node-index">${escapeHtml(index)}</span>
                <div>
                    <small>${escapeHtml(label)}</small>
                    <strong>${escapeHtml(title)}</strong>
                </div>
            </div>
        `;
    }

    function renderExtraFields(challenge, savedResponse) {
        const fields = Array.isArray(challenge.extraFields) ? challenge.extraFields : [];
        if (fields.length === 0) return "";

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
                            value="${escapeHtml(savedResponse?.fields?.[field.key] || "")}"
                        >
                    </label>
                `).join("")}
            </div>
        `;
    }

    function collectExtraFields() {
        const fields = {};
        $$("[data-extra-key]").forEach((input) => {
            fields[input.dataset.extraKey] = input.value.trim();
        });
        return fields;
    }

    function bindChallengeEvents(challenge) {
        const form = $("#probe-form");
        const input = $("#url-input");
        const hintButton = $("#hint-button");
        const solutionButton = $("#solution-button");
        const copyButton = $("#copy-response");

        form.addEventListener("submit", (event) => {
            event.preventDefault();
            submitProbe(challenge, input.value, collectExtraFields());
        });

        $$("#probe-form input").forEach((field) => {
            field.addEventListener("keydown", (event) => {
                if (event.key === "Enter" && event.ctrlKey) {
                    event.preventDefault();
                    submitProbe(challenge, input.value, collectExtraFields());
                }
            });
        });

        hintButton.addEventListener("click", () => {
            const current = state.hintCounts.get(challenge.id) || 0;
            if (current >= challenge.hints.length) {
                state.hintCounts.set(challenge.id, 0);
            } else {
                state.hintCounts.set(challenge.id, current + 1);
            }
            renderHints(challenge);
        });

        copyButton.addEventListener("click", async () => {
            const text = $("#response-body").textContent || "";
            try {
                await navigator.clipboard.writeText(text);
                showToast("响应正文已复制");
            } catch {
                showToast("浏览器未允许复制");
            }
        });

        solutionButton.addEventListener("click", () => loadSolution(challenge));
    }

    function renderHints(challenge) {
        const count = state.hintCounts.get(challenge.id) || 0;
        const list = $("#hint-list");
        const counter = $("#hint-count");
        const button = $("#hint-button span");

        if (!list || !counter || !button) return;

        if (count === 0) {
            list.innerHTML = '<p class="hint-empty">先自己观察原始请求和目标。需要时再逐条打开提示。</p>';
        } else {
            list.innerHTML = challenge.hints.slice(0, count).map((hint, index) => `
                <div class="hint-item">
                    <span>${String(index + 1).padStart(2, "0")}</span>
                    <div>${escapeHtml(hint)}</div>
                </div>
            `).join("");
        }

        counter.textContent = `${count} / ${challenge.hints.length}`;
        button.textContent = count >= challenge.hints.length ? "收起提示" : (count === 0 ? "给我一条提示" : "再给一条提示");
    }

    async function submitProbe(challenge, rawUrl, fields = {}) {
        const url = rawUrl.trim();
        if (!url) {
            showToast("先填写一个 URL");
            $("#url-input").focus();
            return;
        }

        const button = $("#send-button");
        const buttonText = $("#send-button span");
        button.disabled = true;
        buttonText.textContent = "请求中";

        const route = $("#route-strip");
        route.classList.remove("flowing");
        void route.offsetWidth;
        route.classList.add("flowing");

        try {
            const data = await requestJson("/api/probe", {
                method: "POST",
                body: JSON.stringify({ level: challenge.id, url, fields }),
            });
            const payload = { ...data, input: url, fields };
            state.responses.set(challenge.id, payload);

            if (data.result.solved && !state.completed.has(challenge.id)) {
                state.completed.add(challenge.id);
                saveProgress();
                updateProgress();
                showToast(`关卡 ${challenge.id} 完成`);
            }

            renderResponse(challenge, payload);
            await refreshLogs(false);
            setTraceOpen(true);
        } catch (error) {
            const failed = {
                input: url,
                fields,
                result: {
                    ok: false,
                    blocked: false,
                    validation: { decision: "error", message: error.message },
                    transport: { target: url, finalUrl: "", resolvedIp: null },
                    response: { status: 0, durationMs: 0, bytes: 0, body: error.message },
                    solved: false,
                },
            };
            state.responses.set(challenge.id, failed);
            renderResponse(challenge, failed);
            showToast(error.message);
        } finally {
            button.disabled = false;
            buttonText.textContent = "发送请求";
        }
    }

    function renderResponse(challenge, payload) {
        const result = payload.result;
        const status = $("#response-status");
        const meta = $("#response-meta");
        const body = $("#response-body");
        const bytes = $("#response-bytes");
        const solveArea = $("#solve-area");
        const badge = $("#completion-badge");
        const nodes = $$(".route-node");

        if (!status || !meta || !body || !bytes || !solveArea) return;

        let kind = "error";
        let label = "ERROR";
        if (result.blocked) {
            kind = "blocked";
            label = "BLOCKED";
        } else if (result.ok) {
            kind = result.solved ? "success" : "success";
            label = `HTTP ${result.response.status}`;
        }

        status.className = `response-status ${kind}`;
        status.textContent = label;
        meta.textContent = `${result.response.durationMs} ms · ${result.validation.decision}`;
        body.classList.remove("terminal-placeholder");
        body.textContent = result.response.body || "响应正文为空。";
        bytes.textContent = formatBytes(result.response.bytes || 0);

        nodes.forEach((node) => node.classList.remove("active", "solved", "blocked", "error"));
        nodes[0]?.classList.add("active");
        nodes[1]?.classList.add("active");

        if (result.blocked) {
            nodes[2]?.classList.add("blocked");
        } else if (result.ok) {
            nodes[2]?.classList.add("active");
            nodes[3]?.classList.add(result.solved ? "solved" : "active");
        } else {
            nodes[2]?.classList.add("active");
            nodes[3]?.classList.add("error");
        }

        if (result.solved) {
            solveArea.innerHTML = `
                <div class="solve-banner">
                    ${icons.shield}
                    <div>
                        <strong>目标达成，已在响应中命中本关 FLAG</strong>
                        <span>${escapeHtml(result.validation.message)}</span>
                    </div>
                </div>
            `;
        } else {
            solveArea.innerHTML = "";
        }

        if (badge && state.completed.has(challenge.id)) {
            badge.classList.add("completed");
            badge.innerHTML = `${icons.check} 已完成`;
        }
    }

    function formatBytes(value) {
        if (!value) return "0 B";
        if (value < 1024) return `${value} B`;
        return `${(value / 1024).toFixed(1)} KB`;
    }

    async function loadSolution(challenge) {
        const container = $("#solution-content");
        const button = $("#solution-button span");

        if (state.solutions.has(challenge.id)) {
            state.solutions.delete(challenge.id);
            container.innerHTML = '<p class="solution-empty">完成本关后，可查看完整绕过步骤和对应防线。</p>';
            button.textContent = "查看解法";
            return;
        }

        button.textContent = "读取中";
        try {
            const data = await requestJson(`/api/solution?level=${challenge.id}`);
            state.solutions.set(challenge.id, data);
            container.innerHTML = `
                <ol class="solution-list">
                    ${data.steps.map((step, index) => `
                        <li>
                            <span>${String(index + 1).padStart(2, "0")}</span>
                            <div>${escapeHtml(step)}</div>
                        </li>
                    `).join("")}
                </ol>
                <div class="defense-note">${escapeHtml(data.defense)}</div>
            `;
            button.textContent = "收起解法";
        } catch (error) {
            showToast(error.message);
            button.textContent = "查看解法";
        }
    }

    function renderDefense() {
        const defense = state.bootstrap.defense;
        const secureCode = `$url = $_POST['url'] ?? '';
$parts = parse_url($url);

if (($parts['scheme'] ?? '') !== 'https') {
    reject('只允许 HTTPS');
}

$ips = resolveAllAandAAAA($parts['host']);
foreach ($ips as $ip) {
    if (isLoopback($ip) || isPrivate($ip) || isLinkLocal($ip)) {
        reject('目标地址不允许');
    }
}

// 固定已校验的 IP，禁用自动跳转
$body = fetchPinned($url, $ips[0], followRedirects: false);`;

        $("#content").innerHTML = `
            <section class="defense-view">
                <header class="defense-hero">
                    <div>
                        <div class="challenge-meta">
                            <span class="meta-chip">第 ${String(state.bootstrap.challenges.length + 1).padStart(2, "0")} 节</span>
                            <span class="meta-text">修复与防线</span>
                        </div>
                        <h1 class="defense-title">校验必须和真实连接绑定。</h1>
                        <p class="defense-intro">
                            SSRF 修复不是增加一条正则，而是限制“业务服务器最终能连到哪里”。
                            应用层校验、DNS 固定和网络层出站策略需要一起工作。
                        </p>
                    </div>
                    <aside class="defense-principle">
                        <strong>防线顺序</strong>
                        <p>解析目标 → 校验全部 IP → 固定连接 → 复查每一次跳转 → 网络层兜底。</p>
                    </aside>
                </header>

                <div class="defense-grid">
                    ${defense.map((item, index) => `
                        <article class="defense-item">
                            <span>${String(index + 1).padStart(2, "0")}</span>
                            <h3>${escapeHtml(item.title)}</h3>
                            <p>${escapeHtml(item.body)}</p>
                        </article>
                    `).join("")}
                </div>

                <div class="secure-code-grid">
                    <div class="secure-code-copy">
                        <h2>所有关卡共同指向的防线</h2>
                        <p>修复时逐项对照，避免只堵住练习里出现过的 payload。</p>
                        <ul>
                            <li>统一解析 Scheme、Host、Port，不能检查 userinfo 或 URL 关键词。</li>
                            <li>检查全部 A/AAAA 记录，并把批准结果固定给真实连接。</li>
                            <li>每次重定向、渲染资源和 RSS enclosure 都要重新校验。</li>
                            <li>Header、远程内容和二级 URL 与用户输入具有同等级风险。</li>
                            <li>协议与端口使用最小能力白名单，禁用 gopher 和其他非必要协议。</li>
                            <li>盲 SSRF 依赖回调检测、出站代理与网络监控，不能只看响应。</li>
                        </ul>
                    </div>
                    <div class="code-window">
                        <div class="code-header">
                            <span><i></i> secure-fetch.php</span>
                            <span>DEFENSE SKETCH</span>
                        </div>
                        <pre>${escapeHtml(secureCode)}</pre>
                    </div>
                </div>
            </section>
        `;
        setBreadcrumb("修复与防线");
    }

    async function refreshLogs(showError = true) {
        try {
            const data = await requestJson("/api/logs");
            state.logs = data.logs || [];
            renderLogs();
        } catch (error) {
            if (showError) showToast(error.message);
        }
    }

    function renderLogs() {
        const list = $("#log-list");
        if (!list) return;

        if (state.logs.length === 0) {
            list.innerHTML = `
                <div class="log-empty">
                    <span class="log-empty-mark" aria-hidden="true">00</span>
                    <div>
                        <strong>还没有请求</strong>
                        <p>从任意关卡发起一次服务端请求后，这里会记录应用层校验、实际目标和响应状态。</p>
                    </div>
                </div>
            `;
            updateTraceSummary();
            return;
        }

        list.innerHTML = state.logs.map((entry) => {
            const decisionClass = entry.solved ? "solved" : (entry.decision === "blocked" ? "blocked" : "allowed");
            return `
                <article class="log-entry" title="${escapeHtml(entry.message || "")}">
                    <time class="log-time" datetime="${escapeHtml(entry.time || "")}">${formatTime(entry.time)}</time>
                    <span class="log-level">L${escapeHtml(entry.level)}</span>
                    <div class="log-main">
                        <strong>${escapeHtml(entry.levelTitle || `关卡 ${entry.level}`)}</strong>
                        <span class="log-url">${escapeHtml(entry.url || "")}</span>
                    </div>
                    <span class="log-message" title="${escapeHtml(entry.message || "")}">${escapeHtml(entry.message || "")}</span>
                    <div class="log-result">
                        <span class="${decisionClass}">${entry.solved ? "已命中" : (entry.decision === "blocked" ? "已拦截" : "已放行")}</span>
                        <span>${entry.status ? `HTTP ${escapeHtml(entry.status)}` : "无响应"}</span>
                        <span>${escapeHtml(entry.durationMs)} ms</span>
                    </div>
                </article>
            `;
        }).join("");
        updateTraceSummary();
    }

    function formatTime(isoTime) {
        if (!isoTime) return "--:--";
        const date = new Date(isoTime);
        if (Number.isNaN(date.getTime())) return "--:--";
        return new Intl.DateTimeFormat("zh-CN", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
        }).format(date);
    }

    async function clearLogs() {
        try {
            await requestJson("/api/clear-logs", { method: "POST", body: "{}" });
            state.logs = [];
            renderLogs();
            updateTraceSummary();
            showToast("服务端请求记录已清空");
        } catch (error) {
            showToast(error.message);
        }
    }

    function bindGlobalEvents() {
        $("#reset-progress").addEventListener("click", () => {
            if (!window.confirm("清空本机的关卡完成状态？服务端日志不会自动删除。")) return;
            state.completed.clear();
            state.responses.clear();
            state.hintCounts.clear();
            state.solutions.clear();
            saveProgress();
            buildNav();
            navigate(state.stage);
            showToast("本机学习进度已清空");
        });

        $("#refresh-logs").addEventListener("click", () => refreshLogs());
        $("#clear-logs").addEventListener("click", clearLogs);
        $("#trace-toggle").addEventListener("click", () => setTraceOpen(!state.traceOpen));
        $("#trace-shortcut").addEventListener("click", () => setTraceOpen(!state.traceOpen));

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && state.traceOpen) {
                setTraceOpen(false);
                $("#trace-shortcut").focus();
            }
        });

        window.addEventListener("hashchange", () => {
            const hash = window.location.hash.replace(/^#/, "");
            if (!hash || hash === String(state.stage)) return;
            navigate(hash === "defense" ? "defense" : (hash === "intro" ? "intro" : Number(hash)));
        });

        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                clearInterval(state.logTimer);
                state.logTimer = null;
            } else if (!state.logTimer) {
                refreshLogs(false);
                state.logTimer = setInterval(() => refreshLogs(false), 4000);
            }
        });
    }

    async function initialize() {
        loadProgress();
        bindGlobalEvents();

        try {
            state.bootstrap = await requestJson("/api/bootstrap");
            buildNav();
            await refreshLogs(false);
            setTraceOpen(false);

            const hash = window.location.hash.replace(/^#/, "");
            if (hash === "defense") {
                navigate("defense");
            } else if (hash && hash !== "intro") {
                const id = Number(hash);
                navigate(getChallenge(id) ? id : "intro");
            } else {
                navigate("intro");
            }

            state.logTimer = setInterval(() => refreshLogs(false), 4000);
        } catch (error) {
            $("#content").innerHTML = `
                <div class="error-state">
                    <strong>靶场服务没有正确响应</strong>
                    <p>${escapeHtml(error.message)}</p>
                </div>
            `;
        }
    }

    initialize();
})();

