import { useState, useEffect, useRef, useCallback } from 'react'
import axios from 'axios'
import { API, WS } from '../lib/config'

export function useWebSocket() {
  const [status, setStatus] = useState('connecting')
  const wsRef = useRef(null)
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(WS)
      wsRef.current = ws
      ws.onopen  = () => setStatus('live')
      ws.onclose = () => { setStatus('disconnected'); setTimeout(connect, 3000) }
      ws.onerror = () => setStatus('error')
    }
    connect()
    return () => wsRef.current?.close()
  }, [])
  return status
}

export function useMetrics() {
  const [metrics, setMetrics] = useState({})
  useEffect(() => {
    const fetch = () =>
      axios.get(`${API}/api/metrics`).then(r => {
        const d = r.data
        setMetrics({
          cpu_percent:  d.cpu?.percent ?? 0,
          mem_percent:  d.memory?.percent ?? 0,
          disk_used:    d.disk?.used ?? 0,
          disk_percent: d.disk?.percent ?? 0,
          net_recv:     d.network?.bytes_recv ?? 0,
        })
      })
    fetch()
    const t = setInterval(fetch, 5000)
    return () => clearInterval(t)
  }, [])
  return metrics
}

export function useStats() {
  const [stats, setStats] = useState({})
  useEffect(() => {
    const fetch = () => axios.get(`${API}/api/alerts/stats`).then(r => setStats(r.data))
    fetch()
    const t = setInterval(fetch, 10000)
    return () => clearInterval(t)
  }, [])
  return stats
}

export function useAlerts(iocOnly, agentFilter) {
  const [alerts, setAlerts] = useState([])
  const fetch = useCallback(() => {
    const params = { limit: 100 }
    if (iocOnly) params.ioc_only = true
    if (agentFilter) params.agent = agentFilter
    axios.get(`${API}/api/alerts`, { params }).then(r => setAlerts(r.data || []))
  }, [iocOnly, agentFilter])
  useEffect(() => { fetch() }, [fetch])
  return [alerts, fetch]
}
