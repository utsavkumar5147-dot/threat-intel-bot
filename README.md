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

## Future Improvements

- Domain, URL, and hash enrichment
- Additional threat intelligence providers
- Automated testing and CI
- Containerized deployment
- Improved monitoring and visualization

## Disclaimer

For defensive cybersecurity education and authorized security investigations only.
