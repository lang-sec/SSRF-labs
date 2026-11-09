"use strict";

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const debuggingPort = 9333;
const profile = path.join(root, ".runtime", `edge-cdp-${Date.now()}`);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForTarget() {
    for (let attempt = 0; attempt < 60; attempt += 1) {
        try {
            const response = await fetch(`http://127.0.0.1:${debuggingPort}/json/list`);
            const targets = await response.json();
            const page = targets.find((target) => target.type === "page");
            if (page?.webSocketDebuggerUrl) {
                return page.webSocketDebuggerUrl;
            }
        } catch {
            // Edge is still starting.
        }
        await delay(150);
    }
    throw new Error("Timed out waiting for Edge DevTools.");
}

function createCdp(wsUrl) {
    const socket = new WebSocket(wsUrl);
    const pending = new Map();
    const events = [];
    let nextId = 1;

    socket.addEventListener("message", (event) => {
        const message = JSON.parse(String(event.data));
        if (message.id && pending.has(message.id)) {
            const { resolve, reject } = pending.get(message.id);
            pending.delete(message.id);
            if (message.error) {
                reject(new Error(message.error.message));
            } else {
                resolve(message.result);
            }
            return;
        }
        events.push(message);
    });

    const opened = new Promise((resolve, reject) => {
        socket.addEventListener("open", resolve, { once: true });
        socket.addEventListener("error", reject, { once: true });
    });

    return {
        socket,
        events,
        opened,
        send(method, params = {}) {
            const id = nextId;
            nextId += 1;
            return new Promise((resolve, reject) => {
                pending.set(id, { resolve, reject });
                socket.send(JSON.stringify({ id, method, params }));
            });
        },
    };
}

async function evaluate(cdp, expression) {
    const result = await cdp.send("Runtime.evaluate", {
        expression,
        returnByValue: true,
    });
    return result.result.value;
}

async function main() {
    const browser = spawn(edge, [
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        `--remote-debugging-port=${debuggingPort}`,
        `--user-data-dir=${profile}`,
        "--no-first-run",
        "--no-default-browser-check",
        "about:blank",
    ], {
        stdio: "ignore",
        windowsHide: true,
    });

    let cdp;
    try {
        const wsUrl = await waitForTarget();
        cdp = createCdp(wsUrl);
        await cdp.opened;
        await cdp.send("Page.enable");
        await cdp.send("Runtime.enable");
        await cdp.send("Log.enable");
        await cdp.send("Emulation.setDeviceMetricsOverride", {
            width: 1280,
            height: 900,
            deviceScaleFactor: 1,
            mobile: false,
        });

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#1" });
        await delay(1200);

        const initial = await evaluate(cdp, `(() => ({
            title: document.querySelector(".challenge-title")?.textContent.trim(),
            navItems: document.querySelectorAll(".stage-link").length,
            progress: document.querySelector("#progress-label")?.textContent.trim(),
            sourceLocked: document.querySelector("#source-content")?.textContent.includes("通关后"),
            hasSourceCode: document.querySelector("#source-content pre") !== null,
            scrollWidth: document.documentElement.scrollWidth,
            viewport: window.innerWidth
        }))()`);

        if (initial.title !== "有回显 SSRF 验证") {
            throw new Error(`Unexpected level heading: ${initial.title}`);
        }
        if (initial.navItems !== 16) {
            throw new Error(`Expected 16 levels, found ${initial.navItems}.`);
        }
        if (initial.progress !== "0 / 16") {
            throw new Error(`Unexpected initial progress: ${initial.progress}`);
        }
        if (!initial.sourceLocked || initial.hasSourceCode) {
            throw new Error("The source code was visible before the level was solved.");
        }
        if (initial.scrollWidth > initial.viewport + 1) {
            throw new Error(`Desktop horizontal overflow: ${initial.scrollWidth} > ${initial.viewport}`);
        }
        console.log("PASS  level page renders with locked source code");

        // 第 1 关的目标是非本地验证端点；本地界面测试用第 2 关验证通关/源码解锁流程。
        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#2" });
        await delay(800);

        await evaluate(cdp, `(() => {
            const input = document.querySelector("#url-input");
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
            setter.call(input, "http://2130706433:8081/admin");
            document.querySelector("#probe-form").requestSubmit();
            return true;
        })()`);
        await delay(1200);

        const solved = await evaluate(cdp, `(() => ({
            body: document.querySelector("#response-body")?.textContent || "",
            badge: document.querySelector("#completion-badge")?.textContent.trim(),
            source: document.querySelector("#source-content pre")?.textContent || "",
            progress: document.querySelector("#progress-label")?.textContent.trim()
        }))()`);

        if (!solved.body.includes("FLAG{SSRF_BLACKLIST_IP_ENCODING}")) {
            throw new Error("The level 2 response did not contain its FLAG.");
        }
        if (!solved.badge.includes("已完成")) {
            throw new Error("The completion badge did not update.");
        }
        if (!solved.source.includes("LogoImportController")) {
            throw new Error("The source code did not unlock after solving.");
        }
        if (solved.progress !== "1 / 16") {
            throw new Error(`Unexpected solved progress: ${solved.progress}`);
        }
        console.log("PASS  level 2 solves and unlocks its source code");

        await evaluate(cdp, `document.querySelector("#hint-button").click()`);
        await delay(120);
        const hints = await evaluate(cdp, `(() => ({
            count: document.querySelectorAll("#hint-list .hint-item").length,
            label: document.querySelector("#hint-count")?.textContent.trim()
        }))()`);

        if (hints.count < 1 || hints.label !== "1 / 3") {
            throw new Error(`Hint reveal failed: ${JSON.stringify(hints)}`);
        }
        console.log("PASS  hints reveal one at a time");

        const desktopShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-desktop.png"), Buffer.from(desktopShot.data, "base64"));

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#11" });
        await delay(800);

        const headerField = await evaluate(cdp, `(() => ({
            exists: document.querySelector("[data-extra-key='headerHost']") !== null,
            label: document.querySelector("[data-extra-key='headerHost']")?.closest(".extra-field")?.textContent.trim(),
            sourceLocked: document.querySelector("#source-content")?.textContent.includes("通关后")
        }))()`);

        if (!headerField.exists || !headerField.label?.includes("X-Forwarded-Host") || !headerField.sourceLocked) {
            throw new Error(`Header field or source lock is wrong: ${JSON.stringify(headerField)}`);
        }

        await evaluate(cdp, `(() => {
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
            setter.call(document.querySelector("#url-input"), "http://127.0.0.1:8080/webhook/test");
            setter.call(document.querySelector("[data-extra-key='headerHost']"), "127.0.0.1:8081");
            document.querySelector("#probe-form").requestSubmit();
            return true;
        })()`);
        await delay(1200);

        const headerResult = await evaluate(cdp, `(() => ({
            body: document.querySelector("#response-body")?.textContent || "",
            badge: document.querySelector("#completion-badge")?.textContent.trim(),
            source: document.querySelector("#source-content")?.textContent || ""
        }))()`);

        if (!headerResult.body.includes("FLAG{SSRF_HEADER_DRIVEN}")) {
            throw new Error("The header-driven request did not return its FLAG.");
        }
        if (!headerResult.badge.includes("已完成") || !headerResult.source.includes("WebhookTestController")) {
            throw new Error("The level 11 source code did not unlock.");
        }
        console.log("PASS  X-Forwarded-Host submission solves level 11 and unlocks source");

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#1" });
        await cdp.send("Emulation.setDeviceMetricsOverride", {
            width: 390,
            height: 844,
            deviceScaleFactor: 1,
            mobile: true,
        });
        await cdp.send("Page.reload", { ignoreCache: true });
        await delay(1200);

        const mobile = await evaluate(cdp, `(() => ({
            title: document.querySelector(".challenge-title")?.textContent.trim(),
            scrollWidth: document.documentElement.scrollWidth,
            viewport: window.innerWidth
        }))()`);

        if (mobile.title !== "有回显 SSRF 验证") {
            throw new Error(`Unexpected mobile heading: ${mobile.title}`);
        }
        if (mobile.scrollWidth > mobile.viewport + 1) {
            throw new Error(`Mobile horizontal overflow: ${mobile.scrollWidth} > ${mobile.viewport}`);
        }
        console.log("PASS  mobile layout has no horizontal overflow");

        const mobileShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-mobile.png"), Buffer.from(mobileShot.data, "base64"));

        const exceptions = cdp.events.filter((event) =>
            event.method === "Runtime.exceptionThrown"
            || (event.method === "Log.entryAdded" && event.params?.entry?.level === "error")
        );
        const relevantErrors = exceptions.filter((event) => {
            const text = JSON.stringify(event.params);
            return !text.includes("QQBrowser") && !text.includes("fallback_task_provider");
        });
        if (relevantErrors.length > 0) {
            throw new Error(`Browser console errors: ${JSON.stringify(relevantErrors)}`);
        }
        console.log("PASS  no page-level console errors");

        console.log("Screenshots: " + path.join(root, ".runtime", "browser-desktop.png"));
        console.log("Screenshots: " + path.join(root, ".runtime", "browser-mobile.png"));
    } finally {
        cdp?.socket.close();
        browser.kill();
    }
}

main().catch((error) => {
    console.error("FAIL ", error.message);
    process.exit(1);
});
