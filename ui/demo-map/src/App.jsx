import { useState, useMemo } from 'react'
import { generateMockSession, TICK_COUNT } from './mockData'
import MapCanvas from './MapCanvas'
import Timeline from './Timeline'

export default function App() {
  const session = useMemo(() => generateMockSession(), [])
  const [tick, setTick] = useState(0)
  const [playing, setPlaying] = useState(false)

  const currentPlayers = session.ticks[tick].players

  return (
    <div style={{ fontFamily: 'sans-serif', background: '#1b1e23', color: '#eee', minHeight: '100vh', padding: '1.5rem' }}>
      <h1 style={{ fontSize: '1.2rem', marginBottom: '0.25rem' }}>Intact-CS-Map — разбор демки</h1>
      <p style={{ color: '#888', fontSize: '0.85rem', marginBottom: '1rem' }}>
        {session.mapName} · UI-каркас на моках, без реального parser/WebSocket-синка
      </p>

      <MapCanvas players={currentPlayers} />

      <Timeline
        tick={tick}
        tickCount={TICK_COUNT}
        playing={playing}
        onTickChange={setTick}
        onTogglePlay={() => setPlaying((p) => !p)}
      />
    </div>
  )
}
