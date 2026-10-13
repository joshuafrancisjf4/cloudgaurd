import { useState } from "react";
import "./App.css";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

function App() {
const [repoUrl, setRepoUrl] = useState("");
const [scanStatus, setScanStatus] = useState("waiting");
const [cloneStatus, setCloneStatus] = useState("waiting");
const [scanResult, setScanResult] = useState(null);
const [error, setError] = useState("");

const startDeployment = async () => {
if (!repoUrl.trim()) {
setError("Please enter a GitHub repository URL.");
return;
}

setError("");
setScanResult(null);
setCloneStatus("running");
setScanStatus("running");

try {
  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      repo_url: repoUrl.trim(),
    }),
  });

  // Read the response safely, including error responses.
  const data = await response.json();

  if (!response.ok) {
    setCloneStatus("failed");
    setScanStatus("failed");

    throw new Error(
      data.detail || data.message || "The scan request failed."
    );
  }

  setScanResult(data);

  // Cloning and security scanning are separate pipeline stages.
  const cloneMessage = String(data.clone_status || "").toLowerCase();

  const cloneSucceeded =
    cloneMessage.includes("success") ||
    cloneMessage.includes("cloned");

  setCloneStatus(cloneSucceeded ? "passed" : "failed");

  // Only mark the security scan as passed when the API confirms it.
  const securityStatus = String(
    data.security_status || ""
  ).toUpperCase();

  setScanStatus(
    securityStatus === "PASSED" ? "passed" : "failed"
  );

  // Show a useful message if the backend reports a clone failure.
  if (!cloneSucceeded) {
    setError(
      data.clone_status ||
        "The backend did not confirm that the repository was cloned."
    );
  }
} catch (err) {
  console.error("CloudGuard scan error:", err);

  setError(
    err.message || "Unable to connect to the CloudGuard backend."
  );

  // Do not label a successful clone as failed because of a later error.
  if (cloneStatus !== "passed") {
    setCloneStatus("failed");
  }

  setScanStatus("failed");
}

};

const securitySummary = scanResult?.security_summary || {};

return (
<div className="app">
{/* NAVBAR */}
<header className="navbar">
<div className="brand">
<div className="shield">CG</div>

      <div>
        <h2>CloudGuard</h2>
        <span>Secure Deployment Platform</span>
      </div>
    </div>

    <div className="status">
      <span className="status-dot"></span>
      System Ready
    </div>
  </header>

  <main className="container">
    {/* HERO */}
    <section className="hero">
      <p className="tag">SECURE • BUILD • DEPLOY</p>

      <h1>
        Deploy your code
        <span> securely.</span>
      </h1>

      <p className="description">
        Enter a GitHub repository and CloudGuard will scan
        your application for security issues and assess its
        deployment readiness.
      </p>
    </section>

    {/* REPOSITORY INPUT */}
    <section className="deploy-card">
      <label htmlFor="repoUrl">GitHub Repository</label>

      <div className="repo-input">
        <span>⌘</span>

        <input
          id="repoUrl"
          type="url"
          placeholder="https://github.com/username/repository"
          value={repoUrl}
          onChange={(event) => setRepoUrl(event.target.value)}
          disabled={scanStatus === "running"}
        />

        <button
          type="button"
          onClick={startDeployment}
          disabled={scanStatus === "running"}
        >
          {scanStatus === "running"
            ? "Scanning..."
            : "Start Deployment →"}
        </button>
      </div>

      {error && (
        <div className="error-message" role="alert">
          {error}
        </div>
      )}
    </section>

    {/* PIPELINE */}
    <section className="pipeline">
      <div className="section-heading">
        <div>
          <p>PIPELINE</p>
          <h2>Deployment Progress</h2>
        </div>

        <span>
          {scanStatus === "waiting" &&
            "Waiting for repository"}

          {scanStatus === "running" &&
            "CloudGuard is scanning..."}

          {scanStatus === "passed" &&
            "Security scan passed"}

          {scanStatus === "failed" &&
            (cloneStatus === "passed"
              ? "Repository cloned — security issues found"
              : "Scan request failed — check error details")}
        </span>
      </div>

      <div className="steps">
        <PipelineStep
          number="01"
          title="Clone Repository"
          description="Fetch source code from GitHub"
          status={cloneStatus}
        />

        <PipelineStep
          number="02"
          title="Security Scan"
          description="Scan code, secrets and dependencies"
          status={scanStatus}
        />

        <PipelineStep
          number="03"
          title="Docker Build"
          description="Build the application Docker image"
          status="waiting"
        />

        <PipelineStep
          number="04"
          title="Deploy"
          description="Launch the application container"
          status="waiting"
        />
      </div>
    </section>

    {/* SECURITY SUMMARY */}
    {scanResult && (
      <section className="pipeline">
        <div className="section-heading">
          <div>
            <p>SECURITY</p>
            <h2>Scan Results</h2>
          </div>

          <span>
            {scanResult.security_status ||
              scanResult.status ||
              "Unknown"}
          </span>
        </div>

        <div className="security-summary">
          <p>
            Total findings:{" "}
            {securitySummary.total_findings ?? "Not reported"}
          </p>

          <p>
            Secret findings:{" "}
            {securitySummary.secret_findings ?? "Not reported"}
          </p>

          <p>
            Code findings:{" "}
            {securitySummary.code_findings ?? "Not reported"}
          </p>

          <p>
            Dependency findings:{" "}
            {securitySummary.dependency_findings ??
              "Not reported"}
          </p>

          <p>
            Docker findings:{" "}
            {securitySummary.docker_findings ?? "Not reported"}
          </p>
        </div>

        <h3>Full API Response</h3>

        <pre
          style={{
            whiteSpace: "pre-wrap",
            overflowWrap: "anywhere",
            color: "#94a3b8",
            fontSize: "12px",
            lineHeight: "1.6",
            overflowX: "auto",
          }}
        >
          {JSON.stringify(scanResult, null, 2)}
        </pre>
      </section>
    )}
  </main>
</div>

);
}

function PipelineStep({
number,
title,
description,
status,
}) {
const statusText = {
waiting: "Waiting",
running: "Running...",
passed: "Passed ✓",
failed: "Failed ✕",
};

const statusColor = {
waiting: "#64748b",
running: "#38bdf8",
passed: "#22c55e",
failed: "#ef4444",
};

return (
<div className="pipeline-step">
<div className="step-number">{number}</div>

  <div>
    <h3>{title}</h3>
    <p>{description}</p>
  </div>

  <div
    className="waiting"
    style={{
      color: statusColor[status] || statusColor.waiting,
    }}
  >
    {statusText[status] || "Waiting"}
  </div>
</div>

);
}

export default App;