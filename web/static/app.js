"use strict";

const $ = id => document.getElementById(id);

function setText(id, value) {
    const element = $(id);
    if (element) element.textContent = String(value ?? "—");
}

async function getJSON(endpoint) {
    const response = await fetch(endpoint, {
        cache: "no-store"
    });

    if (!response.ok) {
        throw new Error(`${endpoint}: HTTP ${response.status}`);
    }

    return response.json();
}

function renderTable(tableId, records, columns) {
    const table = $(tableId);
    if (!table) return;

    table.replaceChildren();

    if (!records.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = columns.length;
        cell.className = "empty";
        cell.textContent = "No records available";

        row.appendChild(cell);
        table.appendChild(row);
        return;
    }

    for (const record of records) {
        const row = document.createElement("tr");

        for (const column of columns) {
            const cell = document.createElement("td");
            cell.textContent = String(record[column] ?? "—");
            row.appendChild(cell);
        }

        table.appendChild(row);
    }
}

async function refreshDashboard() {
    try {
        const [
            health,
            overview,
            investigations,
            monitored,
            notifications
        ] = await Promise.all([
            getJSON("/api/health"),
            getJSON("/api/overview"),
            getJSON("/api/investigations"),
            getJSON("/api/monitored"),
            getJSON("/api/notifications")
        ]);

        setText(
            "connectionStatus",
            health.status === "ok"
                ? "● Backend connected"
                : "Backend status unknown"
        );

        setText("investigationsCount", overview.investigations);
        setText("monitoredCount", overview.monitored_iocs);
        setText("notificationsCount", overview.notifications);
        setText("activeJobsCount", overview.active_jobs);

        renderTable(
            "investigationRows",
            investigations,
            [
                "indicator",
                "ioc_type",
                "status",
                "risk_score",
                "investigated_at"
            ]
        );

        renderTable(
            "monitoredRows",
            monitored,
            [
                "indicator",
                "status",
                "last_risk_score"
            ]
        );

        renderTable(
            "notificationRows",
            notifications,
            [
                "indicator",
                "severity",
                "message"
            ]
        );

    } catch (error) {
        console.error("Dashboard error:", error);
        setText(
            "connectionStatus",
            "● Backend connection failed: " + error.message
        );
    }
}


async function classifyIOC(event) {
    event.preventDefault();

    const input = $("iocInput");
    const result = $("iocResult");
    const indicator = input.value.trim();

    if (!indicator) {
        result.textContent = "Please enter an IOC.";
        return;
    }

    result.textContent = "Classifying indicator...";

    try {
        const response = await fetch("/api/classify", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({indicator})
        });

        const data = await response.json();

        result.replaceChildren();

        if (!response.ok || !data.valid) {
            result.textContent =
                "Invalid IOC: " +
                (data.error || data.message || "Unknown error");
            return;
        }

        const fields = [
            ["IOC Type", data.type],
            ["Normalized IOC", data.value],
            ["Classification", data.classification],
            [
                "External Lookup Eligible",
                data.external_lookup_allowed ? "Yes" : "No"
            ]
        ];

        for (const [label, value] of fields) {
            const line = document.createElement("p");
            const name = document.createElement("strong");

            name.textContent = label + ": ";
            line.append(name, document.createTextNode(String(value ?? "—")));
            result.appendChild(line);
        }

    } catch (error) {
        result.textContent = "Classification failed: " + error.message;
    }
}


async function investigateIOC() {
    const indicator = $("iocInput").value.trim();
    const consent = $("externalConsent").checked;
    const result = $("investigationResult");
    const button = $("investigateBtn");

    if (!indicator) {
        result.textContent = "Please enter an IOC first.";
        return;
    }

    if (!consent) {
        result.textContent = "Please authorize external lookups first.";
        return;
    }

    button.disabled = true;
    result.textContent = "Submitting investigation...";

    try {
        const response = await fetch("/api/investigate", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                indicator: indicator,
                allow_external: true
            })
        });

        const data = await response.json();

        if (response.ok) {
            result.textContent =
                data.status === "queued"
                ? "Investigation queued successfully."
                : data.status === "duplicate"
                ? "This IOC already has an active investigation."
                : "Investigation status: " + data.status;

            await refreshDashboard();
        } else {
            result.textContent =
                "Investigation rejected: " +
                (data.reason || data.message || data.error || "Unknown error");
        }
    } catch (error) {
        result.textContent = "Submission failed: " + error.message;
    } finally {
        button.disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const form = $("iocForm");
    if (form) form.addEventListener("submit", classifyIOC);
    const investigateButton = $("investigateBtn");
    if (investigateButton) {
        investigateButton.addEventListener("click", investigateIOC);
    }

    refreshDashboard();
    setInterval(refreshDashboard, 30000);
});
