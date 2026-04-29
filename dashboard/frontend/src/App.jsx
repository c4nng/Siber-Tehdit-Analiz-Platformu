import { useState } from 'react'
import { Radio } from 'lucide-react'
import { Sidebar } from './components/Sidebar'
import { StatsRow, MetricsRow } from './components/cards'
import { AlertTable } from './components/AlertTable'
import { DetailPanel } from './components/DetailPanel'
import { useWebSocket, useMetrics, useStats, useAlerts } from './hooks/useData'

export default function App() {
  const [selected, setSelected] = useState(null)
  const wsStatus          = useWebSocket()
  const metrics           = useMetrics()
  const stats             = useStats()
  const [alerts, refresh] = useAlerts(false, '')

  return (
    <div className="app">
      <main className="main">
        <div className="topbar">
          <div className="topbar-left">
            <h1 className="page-title">Siber Tehdit Zenginleştirme ve Analiz Platformu</h1>
            <p className="page-sub">Wazuh · OpenCTI · ClickHouse · Ollama</p>
          </div>
          <div className={`live-badge ${wsStatus === 'live' ? 'live-badge--on' : ''}`}>
            <Radio size={10} />
            {wsStatus === 'live' ? 'Canlı' : 'Bağlanıyor'}
          </div>
        </div>
        <StatsRow stats={stats} />
        <MetricsRow metrics={metrics} />
        <AlertTable alerts={alerts} onSelect={setSelected} onRefresh={refresh} />
      </main>
      {selected && (
        <DetailPanel alert={selected} onClose={() => { setSelected(null); refresh() }} onRefresh={refresh} />
      )}
    </div>
  )
}
