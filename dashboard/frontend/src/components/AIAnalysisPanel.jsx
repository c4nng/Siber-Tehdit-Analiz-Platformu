import { CheckCircle, HelpCircle, AlertTriangle, Shield, Brain, RefreshCw } from 'lucide-react'
import { Badge, VerdictBadge, ConfidenceBar } from './ui'

export function AIAnalysisPanel({ analysisData, loading, onAnalyze, onReanalyze }) {
  if (loading) {
    return (
      <div className="ai-loading">
        <div className="ai-spinner" />
        <span>Ollama analiz yapıyor...</span>
        <span className="ai-loading-sub">llama3.1:8b</span>
      </div>
    )
  }

  if (analysisData?.error) {
    return (
      <div className="ai-error">
        <AlertTriangle size={14} />{analysisData.error}
      </div>
    )
  }

  if (!analysisData) {
    return (
      <div className="ai-empty">
        <Brain size={24} />
        <p>Henüz analiz yapılmadı</p>
        <button className="btn-analyze" onClick={() => onAnalyze(false)}>
          <Brain size={14} /> AI ile Analiz Et
        </button>
      </div>
    )
  }

  const { analysis, timings, source, model } = analysisData

  return (
    <div className="ai-panel">
      <div className="ai-verdict-card">
        <div className="ai-verdict-top">
          <div className="ai-badges">
            <VerdictBadge verdict={analysis.verdict} />
            {analysis.severity && <Badge variant="ghost">{analysis.severity}</Badge>}
            {analysis.attack_type && <Badge variant="indigo">{analysis.attack_type}</Badge>}
          </div>
          <ConfidenceBar value={analysis.confidence} />
        </div>
        {analysis.summary && <p className="ai-summary">{analysis.summary}</p>}
      </div>

      {analysis.confirmed_findings?.length > 0 && (
        <div className="ai-section">
          <div className="ai-section-title ai-section-title--green"><CheckCircle size={10}/> Tespit Edilenler</div>
          <ul className="ai-list">
            {analysis.confirmed_findings.map((f, i) => (
              <li key={i} className="ai-list-item ai-list-item--green"><span className="ai-dot">·</span>{f}</li>
            ))}
          </ul>
        </div>
      )}

      {analysis.hypotheses?.length > 0 && (
        <div className="ai-section">
          <div className="ai-section-title ai-section-title--yellow"><HelpCircle size={10}/> Hipotezler</div>
          <ul className="ai-list">
            {analysis.hypotheses.map((h, i) => (
              <li key={i} className="ai-list-item ai-list-item--yellow"><span className="ai-dot">·</span>{h}</li>
            ))}
          </ul>
        </div>
      )}

      {analysis.recommended_actions?.length > 0 && (
        <div className="ai-section">
          <div className="ai-section-title ai-section-title--blue"><Shield size={10}/> Önerilen Aksiyonlar</div>
          <ul className="ai-list">
            {analysis.recommended_actions.map((a, i) => (
              <li key={i} className="ai-list-item ai-list-item--blue"><span className="ai-arrow">→</span>{a}</li>
            ))}
          </ul>
        </div>
      )}

      {analysis.gaps?.length > 0 && (
        <div className="ai-section">
          <div className="ai-section-title ai-section-title--gray">Eksik Bilgiler</div>
          <ul className="ai-list">
            {analysis.gaps.map((g, i) => (
              <li key={i} className="ai-list-item ai-list-item--gray"><span className="ai-dot">·</span>{g}</li>
            ))}
          </ul>
        </div>
      )}

      {analysis.input_manipulation_detected && (
        <div className="ai-manipulation-warning">
          <AlertTriangle size={13}/> Girdi manipülasyonu tespit edildi
        </div>
      )}

      <div className="ai-footer">
        <span className="ai-meta">
          {source === 'cache' ? '● Önbellekten'
            : timings ? `${model} · ${(timings.total_duration_ns / 1e9).toFixed(1)}s · ${timings.eval_count} token`
            : model}
        </span>
        <button className="btn-reanalyze" onClick={() => onReanalyze(true)}>
          <RefreshCw size={11}/> Yenile
        </button>
      </div>
    </div>
  )
}
