import { useState } from 'react'
import { RefreshCw, Filter, Shield, AlertTriangle, CheckCircle } from 'lucide-react'
import { Badge, SeverityBadge, VerdictBadge } from './ui'

function AlertRow({ alert, onClick }) {
  const aiParsed = (() => {
    if (!alert.ai_analysis) return null
    try { return JSON.parse(alert.ai_analysis) } catch { return null }
  })()

  return (
    <tr className={`alert-row ${alert.ioc_matched === 1 ? 'alert-row--ioc' : ''}`} onClick={onClick}>
      <td className="cell cell--time">{alert.ts}</td>
      <td className="cell">
        <div className="agent-cell">
          <span className="agent-name">{alert.agent_name}</span>
          {alert.agent_ip && <span className="agent-ip">{alert.agent_ip}</span>}
        </div>
      </td>
      <td className="cell">
        <div className="alert-desc-cell">
          <span className="alert-desc" title={alert.rule_desc}>{alert.rule_desc}</span>
          {alert.rule_groups && <span className="alert-groups">{alert.rule_groups}</span>}
        </div>
      </td>
      <td className="cell"><SeverityBadge level={alert.severity} /></td>
      <td className="cell cell--mono">{alert.src_ip || '—'}</td>
      <td className="cell">
        {alert.ioc_matched === 1 ? (
          <div className="ioc-cell">
            <Badge variant="red"><AlertTriangle size={9}/> {alert.ioc_type}</Badge>
            {alert.ioc_description && <span className="ioc-desc" title={alert.ioc_description}>{alert.ioc_description}</span>}
          </div>
        ) : <span className="cell--empty">—</span>}
      </td>
      <td className="cell">
        {alert.compliance ? <Badge variant="green">{alert.compliance.split(', ')[0]}</Badge> : <span className="cell--empty">—</span>}
      </td>
      <td className="cell">
        {aiParsed ? <VerdictBadge verdict={aiParsed.verdict} />
          : alert.ai_analysis ? <Badge variant="purple"><CheckCircle size={9}/> Var</Badge>
          : <span className="cell--empty">—</span>}
      </td>
      <td className="cell cell--chevron">›</td>
    </tr>
  )
}

export function AlertTable({ alerts, onSelect, onRefresh }) {
  const [iocOnly, setIocOnly] = useState(false)
  const [agentFilter, setAgentFilter] = useState('')

  const filtered = alerts.filter(a => {
    if (iocOnly && a.ioc_matched !== 1) return false
    if (agentFilter && !a.agent_name.toLowerCase().includes(agentFilter.toLowerCase())) return false
    return true
  })

  return (
    <div className="table-container">
      <div className="table-header">
        <div className="table-title">
          <span>Güvenlik Alertleri</span>
          <span className="table-count">{filtered.length}</span>
        </div>
        <div className="table-controls">
          <div className="search-box">
            <Filter size={11} />
            <input type="text" placeholder="Agent filtrele..." onChange={e => setAgentFilter(e.target.value)} />
          </div>
          <label className="ioc-toggle">
            <input type="checkbox" onChange={e => setIocOnly(e.target.checked)} />
            <span>Sadece IOC</span>
          </label>
          <button className="refresh-btn" onClick={onRefresh}>
            <RefreshCw size={12} /> Yenile
          </button>
        </div>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {['Zaman','Agent','Alert','Severity','Kaynak IP','IOC','Compliance','AI Verdict',''].map((h, i) => (
                <th key={i}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((a, i) => <AlertRow key={i} alert={a} onClick={() => onSelect(a)} />)}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="table-empty">
            <Shield size={28} />
            <span>Gösterilecek alert yok</span>
          </div>
        )}
      </div>
    </div>
  )
}
