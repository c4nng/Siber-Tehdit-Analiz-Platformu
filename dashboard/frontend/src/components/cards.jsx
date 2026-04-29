import { fmtBytes } from '../lib/config'
import { TrendingUp, AlertTriangle, Zap, Users, Brain, Cpu, Server, HardDrive, Wifi } from 'lucide-react'

export function StatCard({ title, value, icon: Icon, accent }) {
  return (
    <div className="stat-card">
      <div className="stat-header">
        <span className="stat-title">{title}</span>
        <div className="stat-icon" style={{ color: accent }}><Icon size={15} /></div>
      </div>
      <div className="stat-value" style={{ color: accent }}>{value ?? 0}</div>
    </div>
  )
}

export function MetricCard({ title, value, unit, icon: Icon, accent, percent }) {
  return (
    <div className="metric-card">
      <div className="metric-header">
        <span className="metric-title">{title}</span>
        <div className="metric-icon" style={{ color: accent }}><Icon size={14} /></div>
      </div>
      <div className="metric-value">{value}<span className="metric-unit">{unit}</span></div>
      {percent !== undefined && (
        <div className="metric-track">
          <div className="metric-fill" style={{
            width: `${Math.min(percent, 100)}%`,
            background: percent > 80 ? '#ef4444' : percent > 60 ? '#f97316' : accent
          }} />
        </div>
      )}
    </div>
  )
}

export function StatsRow({ stats }) {
  return (
    <div className="stats-row">
      <StatCard title="Toplam Alert"   value={stats.total}       icon={TrendingUp}    accent="#94a3b8" />
      <StatCard title="IOC Eşleşmesi" value={stats.ioc_matched} icon={AlertTriangle} accent="#ef4444" />
      <StatCard title="Kritik"         value={stats.critical}    icon={Zap}           accent="#f97316" />
      <StatCard title="Agentlar"       value={stats.agents}      icon={Users}         accent="#3b82f6" />
      <StatCard title="AI Analiz"      value={stats.ai_analyzed} icon={Brain}         accent="#a855f7" />
    </div>
  )
}

export function MetricsRow({ metrics }) {
  return (
    <div className="metrics-row">
      <MetricCard title="CPU"       value={metrics.cpu_percent?.toFixed(1) ?? 0}  unit="%" icon={Cpu}       accent="#3b82f6" percent={metrics.cpu_percent} />
      <MetricCard title="RAM"       value={metrics.mem_percent?.toFixed(1) ?? 0}  unit="%" icon={Server}    accent="#a855f7" percent={metrics.mem_percent} />
      <MetricCard title="Disk"      value={fmtBytes(metrics.disk_used)}            unit=""  icon={HardDrive} accent="#22c55e" percent={metrics.disk_percent} />
      <MetricCard title="Network ↓" value={fmtBytes(metrics.net_recv)}             unit=""  icon={Wifi}      accent="#f59e0b" />
    </div>
  )
}
