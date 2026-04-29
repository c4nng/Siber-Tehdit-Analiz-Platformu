export function Badge({ children, variant = 'default', className = '' }) {
  const variants = {
    default: 'badge-default', red: 'badge-red', orange: 'badge-orange',
    yellow: 'badge-yellow', blue: 'badge-blue', green: 'badge-green',
    purple: 'badge-purple', indigo: 'badge-indigo', ghost: 'badge-ghost',
  }
  return (
    <span className={`badge ${variants[variant] || variants.default} ${className}`}>
      {children}
    </span>
  )
}

export function SeverityBadge({ level }) {
  const s = Number(level)
  if (s >= 12) return <Badge variant="red">● {s} Kritik</Badge>
  if (s >= 8)  return <Badge variant="orange">● {s} Yüksek</Badge>
  if (s >= 5)  return <Badge variant="yellow">● {s} Orta</Badge>
  return <Badge variant="blue">● {s} Düşük</Badge>
}

export function VerdictBadge({ verdict }) {
  if (!verdict) return null
  const map = {
    malicious:       { v: 'red',    label: '✕ Zararlı'       },
    suspicious:      { v: 'orange', label: '⚠ Şüpheli'       },
    benign:          { v: 'green',  label: '✓ Temiz'          },
    needs_more_data: { v: 'ghost',  label: '? Yetersiz Veri'  },
  }
  const m = map[verdict] || { v: 'ghost', label: verdict }
  return <Badge variant={m.v}>{m.label}</Badge>
}

export function ConfidenceBar({ value }) {
  const color = value >= 70 ? '#ef4444' : value >= 40 ? '#f97316' : '#3b82f6'
  return (
    <div className="confidence-bar">
      <div className="confidence-track">
        <div className="confidence-fill" style={{ width: `${value}%`, background: color }} />
      </div>
      <span className="confidence-label">{value}%</span>
    </div>
  )
}

export function ScoreBar({ value }) {
  const color = value > 70 ? '#ef4444' : value > 40 ? '#f97316' : '#eab308'
  return (
    <div className="score-bar">
      <div className="score-track">
        <div className="score-fill" style={{ width: `${value}%`, background: color }} />
      </div>
      <span className="score-label">{value}/100</span>
    </div>
  )
}
