
"use strict";

function renderRiskAnalytics(records) {
    const palette = {
        High: "#fb7185",
        Elevated: "#fbbf74",
        Guarded: "#a78bfa",
        Low: "#2dd4bf",
        Unknown: "#64748b"
    };

    function scoreOf(record) {
        const raw = record?.risk_score;
        if (raw === null || raw === undefined ||
            raw === "" || typeof raw === "boolean") return null;

        const score = Number(raw);
        return Number.isFinite(score) && score >= 0 && score <= 100
            ? score : null;
    }

    function levelOf(score) {
        if (score === null) return "Unknown";
        if (score >= 70) return "High";
        if (score >= 40) return "Elevated";
        if (score >= 20) return "Guarded";
        return "Low";
    }

    if (!Array.isArray(records)) return;

    const counts = {
        High: 0,
        Elevated: 0,
        Guarded: 0,
        Low: 0,
        Unknown: 0
    };

    for (const record of records) {
        counts[levelOf(scoreOf(record))]++;
    }

    const mapping = {
        High: "riskHigh",
        Elevated: "riskElevated",
        Guarded: "riskGuarded",
        Low: "riskLow",
        Unknown: "riskUnknown"
    };

    for (const [level, id] of Object.entries(mapping)) {
        const element = document.getElementById(id);
        if (element) element.textContent = counts[level];
    }

    const total = document.getElementById("riskTotal");
    if (total) total.textContent = records.length;

    const donut = document.getElementById("riskDonut");

    if (donut) {
        let start = 0;
        const stops = [];

        for (const [level, count] of Object.entries(counts)) {
            if (!count) continue;

            const end = start + count / records.length * 100;
            stops.push(`${palette[level]} ${start}% ${end}%`);
            start = end;
        }

        donut.style.background = stops.length
            ? `conic-gradient(${stops.join(", ")})`
            : "#293850";

        donut.setAttribute(
            "aria-label",
            "Risk distribution: " +
            Object.entries(counts)
                .map(([level, count]) => `${level} ${count}`)
                .join(", ")
        );
    }

    const container = document.getElementById("riskBars");
    if (!container) return;

    container.replaceChildren();

    if (!records.length) {
        const message = document.createElement("p");
        message.textContent = "No investigation data available.";
        container.appendChild(message);
        return;
    }

    for (const record of records.slice(0, 6)) {
        const score = scoreOf(record);
        const level = levelOf(score);

        const item = document.createElement("div");
        const heading = document.createElement("div");
        const name = document.createElement("span");
        const value = document.createElement("span");
        const track = document.createElement("div");
        const fill = document.createElement("div");

        heading.className = "risk-bar-head";
        name.className = "risk-bar-name";
        value.className = "risk-bar-score";
        track.className = "risk-bar-track";
        fill.className = "risk-bar-fill";

        name.textContent = String(record.indicator ?? "Unknown IOC");
        value.textContent = score === null ? "N/A" : `${score}/100`;

        fill.style.width = `${score ?? 0}%`;
        fill.style.background = palette[level];

        heading.append(name, value);
        track.appendChild(fill);
        item.append(heading, track);
        container.appendChild(item);
    }
}
