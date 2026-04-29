export const API = 'http://172.23.10.12:8090'
export const WS  = 'ws://172.23.10.12:8090/ws'

export function getSeverityLevel(s) {
  if (s >= 12) return 'critical'
  if (s >= 8)  return 'high'
  if (s >= 5)  return 'medium'
  return 'low'
}

export function fmtBytes(b) {
  if (!b) return '0 B'
  if (b > 1e9) return (b / 1e9).toFixed(1) + ' GB'
  if (b > 1e6) return (b / 1e6).toFixed(1) + ' MB'
  return (b / 1e3).toFixed(1) + ' KB'
}
