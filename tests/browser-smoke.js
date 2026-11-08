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

async function main() {
    const process = spawn(edge, [
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
            width: 1440,
            height: 1100,
            deviceScaleFactor: 1,
            mobile: false,
        });

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#intro" });
        await delay(1500);

        const desktopIntro = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                heading: document.querySelector(".home-title")?.textContent.replace(/\\s+/g, " ").trim(),
                viewport: window.innerWidth,
                scrollWidth: document.documentElement.scrollWidth,
                startButton: document.querySelector("#start-lab") !== null
            }))()`,
            returnByValue: true,
        });
        const desktopIntroValue = desktopIntro.result.value;
        if (!desktopIntroValue.heading?.includes("请求从浏览器出发")) {
            throw new Error(`Unexpected intro heading: ${desktopIntroValue.heading}`);
        }
        if (!desktopIntroValue.startButton) {
            throw new Error("The intro start button was not rendered.");
        }
        if (desktopIntroValue.scrollWidth > desktopIntroValue.viewport + 1) {
            throw new Error(`Desktop intro overflow: ${desktopIntroValue.scrollWidth} > ${desktopIntroValue.viewport}`);
        }

        const introShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-intro.png"), Buffer.from(introShot.data, "base64"));

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#1" });
        await delay(1500);

        const desktop = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                title: document.title,
                heading: document.querySelector(".challenge-title")?.textContent.trim(),
                viewport: window.innerWidth,
                scrollWidth: document.documentElement.scrollWidth,
                navItems: document.querySelectorAll(".stage-link").length,
                consoleReady: document.querySelector("#probe-form") !== null,
                codeLabel: document.querySelector(".code-header span:first-child")?.textContent.trim(),
                codeText: document.querySelector(".code-window pre")?.textContent || "",
                causePoints: document.querySelectorAll(".cause-item").length,
                causeText: document.querySelector(".cause-section")?.textContent || "",
                businessText: document.querySelector(".business-context")?.textContent || ""
            }))()`,
            returnByValue: true,
        });

        const desktopValue = desktop.result.value;
        if (desktopValue.heading !== "直连内部服务") {
            throw new Error(`Unexpected challenge heading: ${desktopValue.heading}`);
        }
        if (desktopValue.scrollWidth > desktopValue.viewport + 1) {
            throw new Error(`Desktop horizontal overflow: ${desktopValue.scrollWidth} > ${desktopValue.viewport}`);
        }
        if (desktopValue.navItems !== 18) {
            throw new Error(`Unexpected navigation count: ${desktopValue.navItems}`);
        }
        if (
            !desktopValue.codeLabel.includes("ProductImageController.php")
            || !desktopValue.codeText.includes("curl_init")
            || !desktopValue.codeText.includes("学习目标")
        ) {
            throw new Error("The level-specific PHP source code was not rendered.");
        }
        if (desktopValue.causePoints !== 4 || !desktopValue.causeText.includes("不可信输入直接决定请求目标")) {
            throw new Error("The detailed vulnerability cause was not rendered.");
        }
        if (!desktopValue.businessText.includes("商品图片远程导入") || !desktopValue.businessText.includes("/products/import-image")) {
            throw new Error("The real business scenario was not rendered.");
        }

        await cdp.send("Runtime.evaluate", {
            expression: `(() => {
                const input = document.querySelector("#url-input");
                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
                setter.call(input, "http://127.0.0.1:8082/latest/meta-data/iam/security-credentials/lab-role");
                document.querySelector("#probe-form").requestSubmit();
                return true;
            })()`,
            returnByValue: true,
        });
        await delay(1200);

        const interaction = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                status: document.querySelector("#response-status")?.textContent.trim(),
                body: document.querySelector("#response-body")?.textContent || "",
                badge: document.querySelector("#completion-badge")?.textContent.trim(),
                traceOpen: document.querySelector("#trace-dock")?.classList.contains("open"),
                traceEntries: document.querySelectorAll(".log-entry").length
            }))()`,
            returnByValue: true,
        });
        const interactionValue = interaction.result.value;
        if (!interactionValue.body.includes("FLAG{SSRF_DIRECT_METADATA_ACCESS}")) {
            throw new Error("The level 1 browser request did not return its FLAG.");
        }
        if (!interactionValue.badge.includes("已完成")) {
            throw new Error("The completed level was not reflected in the UI.");
        }
        if (!interactionValue.traceOpen || interactionValue.traceEntries < 1) {
            throw new Error("The request trace did not open after submitting a probe.");
        }

        const desktopShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-desktop.png"), Buffer.from(desktopShot.data, "base64"));

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#5" });
        await delay(800);
        const rebindCode = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                codeLabel: document.querySelector(".code-header span:first-child")?.textContent.trim(),
                codeText: document.querySelector(".code-window pre")?.textContent || "",
                target: document.querySelector("#url-input")?.placeholder || "",
                causeText: document.querySelector(".cause-section")?.textContent || ""
            }))()`,
            returnByValue: true,
        });
        const rebindCodeValue = rebindCode.result.value;
        if (!rebindCodeValue.codeLabel.includes("AvatarPreviewController.php")) {
            throw new Error(`Unexpected DNS rebinding code label: ${rebindCodeValue.codeLabel}`);
        }
        if (!rebindCodeValue.codeText.includes("cdn-preview.ssrf.lab") || !rebindCodeValue.target.includes("avatar-7f3a")) {
            throw new Error("The avatar-preview DNS rebinding scenario was not rendered.");
        }
        if (!rebindCodeValue.causeText.includes("两次 DNS 解析")) {
            throw new Error("The DNS rebinding root cause was not rendered.");
        }

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#11" });
        await delay(800);
        const headerField = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                label: document.querySelector("[data-extra-key='headerHost']")?.closest(".extra-field")?.textContent.trim(),
                codeLabel: document.querySelector(".code-header span:first-child")?.textContent.trim()
            }))()`,
            returnByValue: true,
        });
        const headerFieldValue = headerField.result.value;
        if (!headerFieldValue.label?.includes("X-Forwarded-Host") || !headerFieldValue.codeLabel.includes("WebhookController.php")) {
            throw new Error("The header-driven SSRF field was not rendered.");
        }

        await cdp.send("Runtime.evaluate", {
            expression: `(() => {
                const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
                const url = document.querySelector("#url-input");
                const header = document.querySelector("[data-extra-key='headerHost']");
                setValue.call(url, "http://127.0.0.1:8080/webhook/test");
                setValue.call(header, "127.0.0.1:8081");
                document.querySelector("#probe-form").requestSubmit();
                return true;
            })()`,
            returnByValue: true,
        });
        await delay(1200);
        const headerResult = await cdp.send("Runtime.evaluate", {
            expression: `document.querySelector("#response-body")?.textContent || ""`,
            returnByValue: true,
        });
        if (!headerResult.result.value.includes("FLAG{SSRF_HEADER_DRIVEN}")) {
            throw new Error("The browser did not submit the X-Forwarded-Host field correctly.");
        }

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#1" });
        await delay(800);

        await cdp.send("Emulation.setDeviceMetricsOverride", {
            width: 390,
            height: 844,
            deviceScaleFactor: 1,
            mobile: true,
        });
        await cdp.send("Page.reload", { ignoreCache: true });
        await delay(1500);

        const mobile = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                viewport: window.innerWidth,
                scrollWidth: document.documentElement.scrollWidth,
                heading: document.querySelector(".challenge-title")?.textContent.trim(),
                bodyOverflow: document.body.scrollWidth
            }))()`,
            returnByValue: true,
        });
        const mobileValue = mobile.result.value;
        if (mobileValue.heading !== "直连内部服务") {
            throw new Error(`Unexpected mobile challenge heading: ${mobileValue.heading}`);
        }
        if (mobileValue.scrollWidth > mobileValue.viewport + 1) {
            throw new Error(`Mobile horizontal overflow: ${mobileValue.scrollWidth} > ${mobileValue.viewport}`);
        }

        const mobileShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-mobile.png"), Buffer.from(mobileShot.data, "base64"));

        await cdp.send("Runtime.evaluate", {
            expression: `document.querySelector("#trace-shortcut").click()`,
            returnByValue: true,
        });
        await delay(350);
        const mobileTrace = await cdp.send("Runtime.evaluate", {
            expression: `(() => {
                const dock = document.querySelector("#trace-dock");
                return {
                    open: dock.classList.contains("open"),
                    height: Math.round(dock.getBoundingClientRect().height),
                    viewportHeight: window.innerHeight,
                    viewportWidth: window.innerWidth,
                    scrollWidth: document.documentElement.scrollWidth,
                    entries: document.querySelectorAll(".log-entry").length
                };
            })()`,
            returnByValue: true,
        });
        const mobileTraceValue = mobileTrace.result.value;
        if (!mobileTraceValue.open || mobileTraceValue.height < 300 || mobileTraceValue.entries < 1) {
            throw new Error(`Mobile request trace did not open correctly: ${JSON.stringify(mobileTraceValue)}`);
        }
        if (mobileTraceValue.scrollWidth > mobileTraceValue.viewportWidth + 1) {
            throw new Error(`Mobile request trace overflow: ${mobileTraceValue.scrollWidth} > ${mobileTraceValue.viewportWidth}`);
        }
        const mobileTraceShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-mobile-trace.png"), Buffer.from(mobileTraceShot.data, "base64"));

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#intro" });
        await delay(1200);
        const mobileIntro = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                viewport: window.innerWidth,
                scrollWidth: document.documentElement.scrollWidth,
                heading: document.querySelector(".home-title")?.textContent.replace(/\\s+/g, " ").trim()
            }))()`,
            returnByValue: true,
        });
        const mobileIntroValue = mobileIntro.result.value;
        if (!mobileIntroValue.heading?.includes("请求从浏览器出发")) {
            throw new Error(`Unexpected mobile intro heading: ${mobileIntroValue.heading}`);
        }
        if (mobileIntroValue.scrollWidth > mobileIntroValue.viewport + 1) {
            throw new Error(`Mobile intro overflow: ${mobileIntroValue.scrollWidth} > ${mobileIntroValue.viewport}`);
        }

        const mobileIntroShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-mobile-intro.png"), Buffer.from(mobileIntroShot.data, "base64"));

        await cdp.send("Page.navigate", { url: "http://127.0.0.1:8080/#defense" });
        await delay(1200);
        const defense = await cdp.send("Runtime.evaluate", {
            expression: `(() => ({
                heading: document.querySelector(".defense-title")?.textContent.trim(),
                viewport: window.innerWidth,
                scrollWidth: document.documentElement.scrollWidth
            }))()`,
            returnByValue: true,
        });
        const defenseValue = defense.result.value;
        if (!defenseValue.heading?.includes("校验必须和真实连接绑定")) {
            throw new Error(`Unexpected defense heading: ${defenseValue.heading}`);
        }
        if (defenseValue.scrollWidth > defenseValue.viewport + 1) {
            throw new Error(`Mobile defense overflow: ${defenseValue.scrollWidth} > ${defenseValue.viewport}`);
        }
        const defenseShot = await cdp.send("Page.captureScreenshot", {
            format: "png",
            fromSurface: true,
            captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(root, ".runtime", "browser-mobile-defense.png"), Buffer.from(defenseShot.data, "base64"));

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

        console.log("PASS  desktop challenge render and horizontal layout");
        console.log("PASS  level 1 browser interaction and FLAG detection");
        console.log("PASS  detailed vulnerability causes render in each level view");
        console.log("PASS  avatar-preview DNS rebinding code renders in level 5");
        console.log("PASS  header-driven SSRF extra field submits correctly");
        console.log("PASS  request trace dock opens with server records");
        console.log("PASS  mobile challenge render and horizontal layout");
        console.log("PASS  desktop and mobile intro layouts");
        console.log("PASS  mobile request trace layout");
        console.log("PASS  mobile defense layout");
        console.log("PASS  no page-level console errors");
        console.log(`Screenshots: ${path.join(root, ".runtime", "browser-intro.png")}`);
        console.log(`Screenshots: ${path.join(root, ".runtime", "browser-desktop.png")}`);
        console.log(`Screenshots: ${path.join(root, ".runtime", "browser-mobile.png")}`);
        console.log(`Screenshots: ${path.join(root, ".runtime", "browser-mobile-intro.png")}`);
        console.log(`Screenshots: ${path.join(root, ".runtime", "browser-mobile-trace.png")}`);
        console.log(`Screenshots: ${path.join(root, ".runtime", "browser-mobile-defense.png")}`);

        await cdp.send("Browser.close");
    } finally {
        if (cdp?.socket && cdp.socket.readyState === WebSocket.OPEN) {
            try {
                await cdp.send("Browser.close");
            } catch {
                // Browser may already be closed.
            }
            cdp.socket.close();
        }
        process.kill();
    }
}

main().catch((error) => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
});

