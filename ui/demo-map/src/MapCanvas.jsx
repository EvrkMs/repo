import { useState, useRef } from 'react'
import { Stage, Layer, Rect, Circle, Text, Line } from 'react-konva'
import { TEAM_COLORS } from './mockData'

const CANVAS_SIZE = 640

// MapCanvas рендерит текущий кадр (players на заданном тике) поверх карты-заглушки
// и позволяет рисовать поверх мышью — это заготовка под будущий WebSocket-синк:
// массив strokes уже сейчас имеет форму, которую можно без переделок отправлять/
// принимать по WS (список точек на линию, цвет).
export default function MapCanvas({ players }) {
  const [strokes, setStrokes] = useState([]) // [{ points: [x1,y1,x2,y2,...], color }]
  const isDrawing = useRef(false)

  function handleMouseDown(e) {
    isDrawing.current = true
    const pos = e.target.getStage().getPointerPosition()
    setStrokes((prev) => [...prev, { points: [pos.x, pos.y], color: '#ff4d4f' }])
  }

  function handleMouseMove(e) {
    if (!isDrawing.current) return
    const stage = e.target.getStage()
    const pos = stage.getPointerPosition()
    setStrokes((prev) => {
      const last = prev[prev.length - 1]
      const updated = { ...last, points: [...last.points, pos.x, pos.y] }
      return [...prev.slice(0, -1), updated]
    })
  }

  function handleMouseUp() {
    isDrawing.current = false
  }

  function clearDrawings() {
    setStrokes([])
  }

  return (
    <div>
      <Stage
        width={CANVAS_SIZE}
        height={CANVAS_SIZE}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        style={{ border: '1px solid #333', background: '#2a2e35', cursor: 'crosshair' }}
      >
        <Layer>
          {/* Карта-заглушка — заменится на реальное radar-изображение, когда
              появится internal/parser с реальными координатами */}
          <Rect x={0} y={0} width={CANVAS_SIZE} height={CANVAS_SIZE} fill="#3a3f47" />
          <Text
            text="de_dust2 (заглушка)"
            x={12}
            y={12}
            fontSize={14}
            fill="#888"
          />
        </Layer>

        <Layer>
          {players.map((p) => (
            <PlayerDot key={p.id} player={p} />
          ))}
        </Layer>

        <Layer>
          {strokes.map((s, i) => (
            <Line
              key={i}
              points={s.points}
              stroke={s.color}
              strokeWidth={3}
              lineCap="round"
              lineJoin="round"
              tension={0.3}
            />
          ))}
        </Layer>
      </Stage>

      <button onClick={clearDrawings} style={{ marginTop: '0.5rem' }}>
        Очистить рисунок
      </button>
    </div>
  )
}

function PlayerDot({ player }) {
  const x = player.x * CANVAS_SIZE
  const y = player.y * CANVAS_SIZE
  return (
    <>
      <Circle x={x} y={y} radius={7} fill={TEAM_COLORS[player.team]} stroke="#111" strokeWidth={1} />
      <Text text={player.name} x={x + 10} y={y - 6} fontSize={11} fill="#ccc" />
    </>
  )
}
