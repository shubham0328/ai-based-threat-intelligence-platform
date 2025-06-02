# ai-based-threat-intelligence-platform
AI Based Threat Intellegence Platform
# AI-Based Threat Intelligence Platform

AI-Based Threat Intelligence Platform is a solution designed to collect, analyze, and display threat data from various sources, helping security teams proactively manage and mitigate potential cyber threats. This repository contains both the backend (FastAPI) and frontend (Angular) components required to run the platform.

---

## Table of Contents

1. [Introduction](#introduction)  
2. [Project Overview](#project-overview)  
3. [System Architecture](#system-architecture)  
4. [Directory Structure](#directory-structure)  
5. [Technology Stack](#technology-stack)  
6. [Backend Details](#backend-details)  
   - [ThreatData Model](#threatdata-model)  
   - [CORS Configuration](#cors-configuration)  
   - [In-Memory Database](#in-memory-database)  
   - [Utility Functions](#utility-functions)  
   - [API Endpoints](#api-endpoints)  
7. [Frontend Details](#frontend-details)  
   - [Angular Configuration](#angular-configuration)  
   - [Main Components](#main-components)  
8. [Installation and Setup](#installation-and-setup)  
   - [Prerequisites](#prerequisites)  
   - [Backend Setup](#backend-setup)  
   - [Frontend Setup](#frontend-setup)  
9. [Running the Application](#running-the-application)  
10. [Future Enhancements](#future-enhancements)  
11. [License](#license)  

---

## 1. Introduction

This document provides comprehensive documentation for the AI Threat Intelligence Platform project. The purpose of this platform is to collect, analyze, and display threat data from various sources, helping security teams proactively manage and mitigate potential cyber threats.

---

## 2. Project Overview

The AI Threat Intelligence Platform consists of:  
- **Backend (FastAPI)**: Handles threat data ingestion, validation, and storage in an in-memory database.  
- **Frontend (Angular)**: Provides a user interface for interacting with threat data, viewing logs, and visualizing results.

Key goals:  
- Ingest threat data via REST API.  
- Validate and score threats based on severity and blacklist.  
- Store threat logs temporarily (in-memory).  
- Allow users to view, filter, and retrieve threat logs via the frontend.

---

## 3. System Architecture

1. **Backend (FastAPI)**  
   - Exposes RESTful endpoints for threat ingestion, retrieval, and health checks.  
   - Uses Pydantic models to enforce data schema and validation.  
   - Applies business logic (e.g., IP blacklist check, severity threshold).  
   - Stores threat logs in a simple in-memory list (`threat_log_db`).

2. **Frontend (Angular)**  
   - Single-page application (Angular 15+) that consumes backend APIs.  
   - Displays threat logs in a responsive dashboard.  
   - Allows filtering by source IP and viewing details.

3. **In-Memory Database**  
   - A Python list that holds threat records during runtime.  
   - No persistence—logs reset whenever the backend service restarts.

4. **CORS Middleware**  
   - Configured to allow cross-origin requests between the Angular frontend (e.g., `http://localhost:4200`) and the FastAPI backend (e.g., `http://localhost:8000`).

---

## 4. Directory Structure

```plaintext
Final_AI_Threat_Intelligence_Platform/
├── backend/
│   ├── main.py
│   └── requirements.txt
└── frontend/
    ├── angular.json
    ├── package.json
    ├── tailwind.config.js
    ├── tsconfig.json
    └── src/
        ├── index.html
        ├── main.ts
        └── app/
            ├── app.component.ts
            ├── app.component.html
            ├── app.component.css
            └── app.module.ts
