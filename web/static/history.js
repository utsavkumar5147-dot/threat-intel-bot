
"use strict";

function historyRiskLevel(raw) {
    if (raw === null || raw === undefined ||
        raw === "" || typeof raw === "boolean") {
        return "Unknown";
    }

    const score = Number(raw);

    if (!Number.isFinite(score) || score < 0 || score > 100) {
        return "Unknown";
    }

    if (score >= 70) return "High";
    if (score >= 40) return "Elevated";
    if (score >= 20) return "Guarded";
    return "Low";
}

function filterHistory() {
    const body = document.getElementById("investigationRows");
    const search = document.getElementById("historySearch");
    const filter = document.getElementById("historyRiskFilter");
    const count = document.getElementById("historyCount");

    if (!body || !search || !filter) return;

    const query = search.value.trim().toLowerCase();
    const selected = filter.value;
    const rows = [...body.querySelectorAll("tr[data-history-row]")];

    let visible = 0;

    for (const row of rows) {
        const matchesText = row.dataset.search.includes(query);
        const matchesRisk =
            selected === "all" || row.dataset.risk === selected;

        row.hidden = !(matchesText && matchesRisk);

        if (!row.hidden) visible++;
    }

    if (count) {
        count.textContent =
            `Showing ${visible} of ${rows.length} investigations`;
    }

    const previous = body.querySelector(".history-no-match");
    if (previous) previous.remove();

    if (rows.length && visible === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");

        tr.className = "history-no-match";
        td.colSpan = 5;
        td.className = "empty";
        td.textContent = "No investigations match your filters.";

        tr.appendChild(td);
        body.appendChild(tr);
    }
}

function enhanceHistory(records) {
    if (!Array.isArray(records)) return;

    const body = document.getElementById("investigationRows");
    if (!body) return;

    const rows = [...body.querySelectorAll("tr")];

    records.forEach((record, index) => {
        const row = rows[index];
        if (!row || row.cells.length < 5) return;

        const level = historyRiskLevel(record.risk_score);
        const status = String(record.status ?? "unknown");
        const statusClass = status.toLowerCase();

        row.dataset.historyRow = "true";
        row.dataset.risk = level;
        row.dataset.search = [
            record.indicator,
            record.ioc_type,
            status
        ].map(value => String(value ?? ""))
         .join(" ").toLowerCase();

        const statusBadge = document.createElement("span");
        statusBadge.className =
            "history-status-badge " +
            (statusClass === "completed"
                ? "status-completed"
                : statusClass === "failed"
                ? "status-failed"
                : "status-pending");
        statusBadge.textContent = status;

        row.cells[2].replaceChildren(statusBadge);

        const riskBadge = document.createElement("span");
        riskBadge.className =
            "history-risk-badge risk-" + level.toLowerCase();

        const score = record.risk_score;
        riskBadge.textContent = level === "Unknown"
            ? "Unknown"
            : `${level} · ${score}`;

        row.cells[3].replaceChildren(riskBadge);
    });

    filterHistory();
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("historySearch")
        ?.addEventListener("input", filterHistory);

    document.getElementById("historyRiskFilter")
        ?.addEventListener("change", filterHistory);
});
