import { useState, useEffect } from 'react'
import axios from 'axios'
import { X, Eye, Clock, Shield, Server, Network, FileText, AlertTriangle, Brain } from 'lucide-react'
import { API } from '../lib/config'
import { Badge, SeverityBadge, ScoreBar } from './ui'
import { AIAnalysisPanel } from './AIAnalysisPanel'

function DetailRow({ label, value, mono = false }) {
  if (!value) return null
  return (
    <div className="detail-row">
      <span className="detail-label">{label}</span>
      <span className={`detail-value ${mono ? 'detail-value--mono' : ''}`}>{value}</span>
    </div>
  )
}

function Section({ title, icon: Icon, accent = '', children }) {
  return (
    <div className={`detail-section ${accent}`}>
      <div className="detail-section-title"><Icon size={11}/>{title}</div>
      {children}
    </div>
  )
}

export function DetailPanel({ alert, onClose, onRefresh }) {
  const [analysisData, setAnalysisData] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (alert.ai_analysis) {
      try {
        setAnalysisData({ analysis: JSON.parse(alert.ai_analysis), source: 'cache' })
      } catch {
        setAnalysisData({ analysis: { summary: alert.ai_analysis }, source: 'cache' })
      }
    } else {
      setAnalysisData(null)
    }
  }, [alert])

  const runAnalysis = async (force = false) => {
    setLoading(true)
    try {
      const r = await axios.post(`${API}/api/analyze`, { event_id: alert.event_id, force })
      setAnalysisData(r.data)
      if (r.data.saved) onRefresh?.()
    } catch (e) {
      setAnalysisData({ error: e?.response?.data?.error || 'Ollama bağlantı hatası.' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel-overlay">
      <div className="panel-backdrop" onClick={onClose} />
      <div className="panel">
        <div className="panel-header">
          <div className="panel-header-left">
            <div className="panel-header-icon"><Eye size={15}/></div>
            <div>
              <div className="panel-title">Alert Detayı</div>
              <div className="panel-subtitle"><Clock size={9}/>{alert.ts} · #{alert.event_id}</div>
            </div>
          </div>
          <button className="panel-close" onClick={onClose}><X size={15}/></button>
        </div>

        <div className="panel-body">
          <Section title="Temel Bilgiler" icon={Shield}>
            <DetailRow label="Alert"      value={alert.rule_desc} />
            <DetailRow label="Rule ID"    value={`#${alert.rule_id}`} mono />
            <div className="detail-row">
              <span className="detail-label">Severity</span>
              <SeverityBadge level={alert.severity} />
            </div>
            <DetailRow label="Tetiklenme" value={alert.fired_times > 0 ? `${alert.fired_times} kez` : null} />
            <DetailRow label="Konum"      value={alert.location} />
            <DetailRow label="Decoder"    value={alert.decoder} mono />
            {alert.rule_groups && (
              <div className="detail-row">
                <span className="detail-label">Gruplar</span>
                <div className="detail-tags">
                  {alert.rule_groups.split(', ').map((g, i) => <Badge key={i} variant="indigo">{g}</Badge>)}
                </div>
              </div>
            )}
            {alert.compliance && (
              <div className="detail-row">
                <span className="detail-label">Compliance</span>
                <div className="detail-tags">
                  {alert.compliance.split(', ').map((c, i) => <Badge key={i} variant="green">{c}</Badge>)}
                </div>
              </div>
            )}
          </Section>

          <Section title="Agent" icon={Server}>
            <DetailRow label="Ad" value={alert.agent_name} />
            <DetailRow label="IP" value={alert.agent_ip} mono />
          </Section>

          {(alert.src_ip || alert.domain || alert.md5) && (
            <Section title="Network / Dosya" icon={Network}>
              <DetailRow label="Kaynak IP" value={alert.src_ip} mono />
              <DetailRow label="Domain"    value={alert.domain} mono />
              <DetailRow label="MD5"       value={alert.md5} mono />
            </Section>
          )}

          {alert.full_log && (
            <Section title="Ham Log" icon={FileText}>
              <div className="log-box">{alert.full_log}</div>
            </Section>
          )}

          {alert.ioc_matched === 1 && (
            <Section title="Threat Intelligence" icon={AlertTriangle} accent="detail-section--threat">
              <div className="threat-banner">
                <AlertTriangle size={13}/> IOC Eşleşmesi Tespit Edildi
                {alert.ioc_description && <span className="threat-desc">{alert.ioc_description}</span>}
              </div>
              <DetailRow label="IOC Tipi"       value={alert.ioc_type} />
              <DetailRow label="IOC Değeri"     value={alert.ioc_value} mono />
              {alert.opencti_score > 0 && (
                <div className="detail-row">
                  <span className="detail-label">Risk Skoru</span>
                  <ScoreBar value={alert.opencti_score} />
                </div>
              )}
              <DetailRow label="Threat Actor"   value={alert.threat_actor} />
              <DetailRow label="MITRE"          value={alert.mitre_technique} />
              <DetailRow label="TLP"            value={alert.tlp_level} />
              <DetailRow label="CVE"            value={alert.cve} mono />
            </Section>
          )}

          <Section title="AI Güvenlik Analizi" icon={Brain}>
            <AIAnalysisPanel
              analysisData={analysisData}
              loading={loading}
              onAnalyze={runAnalysis}
              onReanalyze={runAnalysis}
            />
          </Section>
        </div>
      </div>
    </div>
  )
}
