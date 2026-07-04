import { useEffect, useRef } from 'react'

// Timeline — управление текущим тиком: слайдер + play/pause.
// tick меняется наружу через onTickChange, компонент не хранит собственное
// состояние тика — это ответственность родителя (App), чтобы MapCanvas
// и Timeline оставались синхронизированы через единый источник истины.
export default function Timeline({ tick, tickCount, playing, onTickChange, onTogglePlay }) {
  const rafRef = useRef(null)
  const lastTsRef = useRef(null)

  useEffect(() => {
    if (!playing) {
      lastTsRef.current = null
      return
    }

    function step(ts) {
      if (lastTsRef.current == null) lastTsRef.current = ts
      const elapsed = ts - lastTsRef.current
      // ~30 тиков в секунду для наглядности проигрывания на моках
      if (elapsed > 1000 / 30) {
        lastTsRef.current = ts
        onTickChange((prev) => (prev + 1 >= tickCount ? 0 : prev + 1))
      }
      rafRef.current = requestAnimationFrame(step)
    }
    rafRef.current = requestAnimationFrame(step)
    return () => cancelAnimationFrame(rafRef.current)
  }, [playing, tickCount, onTickChange])

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '1rem' }}>
      <button onClick={onTogglePlay}>{playing ? '⏸ Пауза' : '▶ Играть'}</button>
      <input
        type="range"
        min={0}
        max={tickCount - 1}
        value={tick}
        onChange={(e) => onTickChange(Number(e.target.value))}
        style={{ flex: 1 }}
      />
      <span style={{ minWidth: '4.5rem', textAlign: 'right', color: '#aaa', fontSize: '0.85rem' }}>
        тик {tick}/{tickCount - 1}
      </span>
    </div>
  )
}
