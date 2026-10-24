# Automated Threat Intelligence & IOC Enrichment Bot

A Python-based cybersecurity project for automated Indicator of Compromise (IOC) investigation and enrichment.

## Overview

This project integrates VirusTotal and AbuseIPDB to investigate public IP addresses, calculate risk scores, and display results through a Flask dashboard.

## Features

- IOC classification: IP addresses, domains, URLs, and SHA-256 hashes
- VirusTotal and AbuseIPDB enrichment
- Automated public-IP investigation queue
- Risk scoring and severity classification
- SQLite investigation history
- JSON investigation reports
- Threat intelligence caching
- Background worker with retry scheduling
- Interrupted-job recovery
- IOC monitoring and notification components
- Flask dashboard and REST API
- Explicit consent for external investigations


## SOC Dashboard

The interactive dark-mode dashboard includes:

- Sidebar navigation and live backend status
- Investigation, monitoring, and notification counters
- Threat risk distribution donut chart
- Recent IOC risk-score visualization
- Searchable investigation history
- Risk-level filters and colored status badges

Dashboard statistics use actual investigation records.

## Architecture

Dashboard -> Flask API -> IOC Validation -> Job Queue -> Background Worker

Background Worker -> VirusTotal / AbuseIPDB -> Risk Assessment

Risk Assessment -> SQLite Database / JSON Reports / Monitoring

## Technology Stack

Python, Flask, SQLite, JavaScript, HTML, VirusTotal API, AbuseIPDB API.

## Project Structure

- core/ : Threat intelligence and automation modules
- web/ : Flask dashboard and API
- config/ : Local configuration
- data/ : SQLite database
- reports/ : Generated investigation reports

## Installation

Clone the repository:

    git clone https://github.com/utsavkumar5147-dot/threat-intel-bot.git
    cd threat-intel-bot

Create a virtual environment and install dependencies:

    python3 -m venv .venv
    ./.venv/bin/python -m pip install -r requirements.txt

Configure your local API credentials using
config/api_keys.env.example as a reference.

Never commit real API keys to GitHub.

## Deployment and Security Limitations

- The Flask dashboard is intended for local use at 127.0.0.1.
- The dashboard has no authentication; do not expose it directly to the internet.
- API request bodies are limited to 16 KB.
- Automated external investigations currently support public IPs only.
- External enrichment requires explicit authorization and valid API keys.
- Risk scores are heuristic and do not prove that an IOC is safe.
- External provider availability and rate limits can affect investigations.

## Running the Application

Create a Python virtual environment and install the required dependencies.

Configure your API credentials locally without committing them to Git.

Start the dashboard:

    python web/app.py

Open http://127.0.0.1:5050 in your browser.

Start the background worker in a separate terminal:

    python core/background_worker.py

## Security

- API credentials are excluded from Git.
- External investigations require explicit consent.
- The automated queue currently supports public IP addresses only.
- Private and reserved IPs are blocked from automated external investigation.
- Risk scores are heuristic assessments, not guarantees of safety.

## Verified Tests

- Live VirusTotal and AbuseIPDB enrichment
- SQLite investigation persistence
- Flask dashboard API responses
- IOC classification and validation
- External lookup consent enforcement
- Retry scheduling and maximum retry limits
- Interrupted-job recovery
- Fresh database initialization


## Automated Testing and CI

The project includes 33 automated pytest tests covering:

- IOC classification and input validation
- Investigation queue operations
- Threat risk-scoring calculations

Run all tests locally:

    ./.venv/bin/python -m pytest tests/ -v

GitHub Actions automatically runs the test suite on
pushes and pull requests targeting the main branch.

Additional integration checks cover Flask API responses,
external lookup consent, and investigation submission.

## Future Improvements

- Domain, URL, and hash enrichment
- Additional threat intelligence providers
- Containerized deployment
- Improved monitoring and visualization

## Disclaimer

For defensive cybersecurity education and authorized security investigations only.
