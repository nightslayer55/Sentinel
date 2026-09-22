// @ts-ignore: CSS modules are handled by the bundler.
import "./index.css";
import { useState } from "react";
import {
  ShieldCheck,
  Link,
  QrCode,
  MessageSquare,
  Search,
} from "lucide-react";

type Mode = "url" | "qr" | "message";

interface EvidenceItem {
  category: string;
  severity: string;
  points: number;
  finding: string;
  explanation: string;
  details?: {
    matched_patterns?: string[];
  };
}

interface AnalysisResult {
  risk_score: number;
  risk_level: string;
  evidence?: EvidenceItem[];
  explanation: string;
}

function App() {
  const [mode, setMode] = useState<Mode>("url");
  const [input, setInput] = useState("");
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [decodedQrUrl, setDecodedQrUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expandedEvidence, setExpandedEvidence] = useState<number | null>(null);

  const analyze = async () => {
    if (mode === "qr" && !qrFile) {
      setError("Please select a QR code image.");
      return;
    }

    if (mode !== "qr" && !input.trim()) {
      setError("Please enter something to analyze.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setDecodedQrUrl("");

    try {
      // QR CODE
      if (mode === "qr") {
        const formData = new FormData();
        formData.append("image", qrFile!);

        const response = await fetch(
          "http://127.0.0.1:5000/api/analyze/qr",
          {
            method: "POST",
            body: formData,
          }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.error || "QR analysis failed.");
        }

        setDecodedQrUrl(data.qr.data);
        setResult(data.analysis);

        return;
      }

      // URL
      if (mode === "url") {
        const response = await fetch(
          "http://127.0.0.1:5000/api/analyze/url",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              url: input,
            }),
          }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.error || "Analysis failed.");
        }

        setResult(data);

        return;
      }

      // MESSAGE
      if (mode === "message") {
        const response = await fetch(
          "http://127.0.0.1:5000/api/analyze/message",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              message: input,
            }),
          }
        );

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.error || "Message analysis failed.");
        }

        if (data.analyses?.length > 0) {
          setResult(data.analyses[0].analysis);
        } else {
          throw new Error("No URL was found in the message.");
        }
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Something went wrong."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <ShieldCheck size={30} />
          <span>SENTINEL</span>
        </div>

        <span className="status">
          <span className="status-dot"></span>
          SYSTEM ONLINE
        </span>
      </header>

      <main className="main">
        <section className="hero">
          <p className="eyebrow">SECURITY ANALYSIS</p>

          <h1>
            Check before
            <br />
            <span>you click.</span>
          </h1>

          <p className="subtitle">
            Sentinel analyzes suspicious links, QR codes, and
            messages and explains the evidence behind its
            assessment.
          </p>
        </section>

        <section className="scanner">
          <div className="modes">
            <button
              className={mode === "url" ? "mode active" : "mode"}
              onClick={() => {
                setMode("url");
                setError("");
              }}
            >
              <Link size={19} />
              URL
            </button>

            <button
              className={mode === "qr" ? "mode active" : "mode"}
              onClick={() => {
                setMode("qr");
                setError("");
              }}
            >
              <QrCode size={19} />
              QR CODE
            </button>

            <button
              className={
                mode === "message" ? "mode active" : "mode"
              }
              onClick={() => {
                setMode("message");
                setError("");
              }}
            >
              <MessageSquare size={19} />
              MESSAGE
            </button>
          </div>

          <div className="input-area">
            {mode === "url" && (
              <input
                type="text"
                placeholder="Paste a URL to analyze..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    analyze();
                  }
                }}
              />
            )}

            {mode === "message" && (
              <textarea
                placeholder="Paste a suspicious message..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
              />
            )}

            {mode === "qr" && (
              <div className="qr-upload">
                <QrCode size={48} />

                <p>
                  {qrFile
                    ? `Selected: ${qrFile.name}`
                    : "Select a QR code image to analyze."}
                </p>

                <input
                  type="file"
                  accept="image/*"
                  onChange={(e) => {
                    const file = e.target.files?.[0];

                    if (file) {
                      setQrFile(file);
                      setError("");
                    }
                  }}
                />
              </div>
            )}

            <button
              className="analyze-button"
              onClick={analyze}
              disabled={loading}
            >
              <Search size={19} />
              {loading ? "ANALYZING..." : "ANALYZE"}
            </button>

            {error && <p className="error">{error}</p>}
          </div>
        </section>

        {result && (
          <section className="result">
            {decodedQrUrl && (
              <div className="decoded-url">
                <p className="eyebrow">DECODED URL</p>
                <code>{decodedQrUrl}</code>
              </div>
            )}

            <div className="result-header">
              <div>
                <p className="eyebrow">ASSESSMENT</p>
                <h2>{result.risk_level}</h2>
              </div>

              <div className="score">
                <strong>{result.risk_score}</strong>
                <span>/100</span>
              </div>
            </div>

            <div className="risk-meter">
              <div className="risk-meter-labels">
                <span>LOW</span>
                <span>MODERATE</span>
                <span>HIGH</span>
                <span>CRITICAL</span>
              </div>

              <div className="risk-bar">
                <div
                  className="risk-marker"
                  style={{
                    left: `${result.risk_score}%`,
                  }}
                />
              </div>

              <div className="risk-score-label">
                {result.risk_score}/100
              </div>
            </div>

            <div className="explanation">
              <h3>Why this result?</h3>
              <p>{result.explanation}</p>
            </div>

            <div className="evidence">
  <h3>Evidence</h3>

  {(result.evidence ?? []).map((item, index) => {
    const type =
      item.points > 0
        ? "risk"
        : item.points < 0
        ? "positive"
        : "info";

    const expanded = expandedEvidence === index;

    return (
      <div
        className={`evidence-item ${type} ${
          expanded ? "expanded" : ""
        }`}
        key={index}
      >
        <div className="evidence-content">
          <button
            className="evidence-toggle"
            onClick={() =>
              setExpandedEvidence(
                expanded ? null : index
              )
            }
          >
            <div>
              <div className="evidence-label">
                {type === "risk" && "⚠ RISK FINDING"}
                {type === "info" && "ⓘ INFORMATION"}
                {type === "positive" && "✓ POSITIVE SIGNAL"}
              </div>

              <strong>{item.finding}</strong>
            </div>

            <span className="expand-icon">
              {expanded ? "−" : "+"}
            </span>
          </button>

          {expanded && (
            <div className="evidence-details">
              {item.details?.matched_patterns &&
                item.details.matched_patterns.length > 0 && (
                  <div className="detail-section">
                    <span className="detail-label">
                      MATCHED INDICATORS
                    </span>

                    <div className="matched-patterns">
                      {item.details.matched_patterns.map(
                        (pattern) => (
                          <span
                            className="pattern-tag"
                            key={pattern}
                          >
                            {pattern}
                          </span>
                        )
                      )}
                    </div>
                  </div>
                )}

              <div className="detail-section">
                <span className="detail-label">
                  EXPLANATION
                </span>

                <p>{item.explanation}</p>
              </div>

              <div className="detail-section">
                <span className="detail-label">
                  RISK CONTRIBUTION
                </span>

                <span className="detail-points">
                  {item.points > 0
                    ? `+${item.points} points`
                    : item.points < 0
                    ? `${item.points} points`
                    : "0 points — informational only"}
                </span>
              </div>
            </div>
          )}
        </div>

        <span className="points">
          {item.points > 0
            ? `+${item.points}`
            : item.points < 0
            ? item.points
            : "0"}
        </span>
      </div>
    );
  })}
</div>
          </section>
        )}
      </main>
      <section className="architecture">
  <div className="architecture-header">
    <p className="eyebrow">UNDER THE HOOD</p>

    <h2>How Sentinel works</h2>

    <p>
      Sentinel separates security analysis from AI explanation.
      The security engine determines the risk, while the AI
      explains the evidence in simple language.
    </p>
  </div>

  <div className="architecture-flow">
    <div className="architecture-step">
      <span className="step-number">01</span>
      <strong>INPUT</strong>
      <p>URL, QR code, or message</p>
    </div>

    <div className="flow-arrow">→</div>

    <div className="architecture-step">
      <span className="step-number">02</span>
      <strong>SECURITY ENGINE</strong>
      <p>
        Structure, connection, hostname, and reputation
        analysis
      </p>
    </div>

    <div className="flow-arrow">→</div>

    <div className="architecture-step">
      <span className="step-number">03</span>
      <strong>EVIDENCE</strong>
      <p>Concrete findings collected from the analysis</p>
    </div>

    <div className="flow-arrow">→</div>

    <div className="architecture-step">
      <span className="step-number">04</span>
      <strong>RISK SCORE</strong>
      <p>Deterministic 0–100 assessment</p>
    </div>

    <div className="flow-arrow">→</div>

    <div className="architecture-step">
      <span className="step-number">05</span>
      <strong>AI EXPLANATION</strong>
      <p>Evidence translated into plain language</p>
    </div>
  </div>

  <div className="architecture-principle">
    <span>DESIGN PRINCIPLE</span>

    <strong>
      AI explains the assessment.
      <br />
      It does not make the assessment.
    </strong>
  </div>
</section>
    </div>
  );
}

export default App;