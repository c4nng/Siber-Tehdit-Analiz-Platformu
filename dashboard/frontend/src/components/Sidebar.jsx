import { Shield, Activity, Database, Brain } from 'lucide-react'

export function Sidebar({ wsStatus }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo"><Shield size={16} /></div>
      <nav className="sidebar-nav">
        <button className="sidebar-btn sidebar-btn--active" title="Alertler"><Activity size={15} /></button>
        <button className="sidebar-btn" title="Veritabanı"><Database size={15} /></button>
        <button className="sidebar-btn" title="AI Analiz"><Brain size={15} /></button>
      </nav>
      <div className="sidebar-status">
        <div className={`ws-dot ${wsStatus === 'live' ? 'ws-dot--live' : ''}`} />
      </div>
    </aside>
  )
}
