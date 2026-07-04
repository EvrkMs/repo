// Синтетические данные для UI-каркаса. Формат намеренно похож на то, что
// в будущем будет отдавать internal/parser (demoinfocs-golang) — массив тиков,
// на каждом тике позиции всех игроков в системе координат карты (0..1 нормализовано).
// Когда парсер будет готов, эта функция заменится на fetch реальных данных сессии,
// компоненты MapCanvas/Timeline менять не придётся — они работают с этой же формой данных.

const TEAMS = {
  CT: '#5b9bd5',
  T: '#e0a458',
}

function makePlayer(id, team, name, pathFn) {
  return { id, team, name, pathFn }
}

// Простые параметрические траектории — не игровая логика, просто чтобы было
// на что смотреть в UI (движение по дуге/зигзагу/кругу).
const PLAYER_DEFS = [
  makePlayer('ct1', 'CT', 'CT_Alpha', (t) => [0.2 + 0.3 * t, 0.25]),
  makePlayer('ct2', 'CT', 'CT_Bravo', (t) => [0.25, 0.2 + 0.5 * t]),
  makePlayer('ct3', 'CT', 'CT_Charlie', (t) => [0.3 + 0.2 * Math.sin(t * Math.PI), 0.35]),
  makePlayer('ct4', 'CT', 'CT_Delta', (t) => [0.35, 0.3 + 0.3 * t]),
  makePlayer('ct5', 'CT', 'CT_Echo', (t) => [0.2 + 0.15 * t, 0.45 + 0.1 * Math.sin(t * 4)]),
  makePlayer('t1', 'T', 'T_Alpha', (t) => [0.8 - 0.3 * t, 0.75]),
  makePlayer('t2', 'T', 'T_Bravo', (t) => [0.75, 0.8 - 0.5 * t]),
  makePlayer('t3', 'T', 'T_Charlie', (t) => [0.7 - 0.2 * Math.sin(t * Math.PI), 0.65]),
  makePlayer('t4', 'T', 'T_Delta', (t) => [0.65, 0.7 - 0.3 * t]),
  makePlayer('t5', 'T', 'T_Echo', (t) => [0.8 - 0.15 * t, 0.55 - 0.1 * Math.sin(t * 4)]),
]

export const TICK_COUNT = 200

// generateMockSession() -> { mapName, ticks: [{ tick, players: [{id, team, name, x, y}] }] }
export function generateMockSession() {
  const ticks = []
  for (let tick = 0; tick < TICK_COUNT; tick++) {
    const t = tick / (TICK_COUNT - 1)
    const players = PLAYER_DEFS.map((p) => {
      const [x, y] = p.pathFn(t)
      return { id: p.id, team: p.team, name: p.name, x, y }
    })
    ticks.push({ tick, players })
  }
  return { mapName: 'de_dust2 (заглушка — реальный radar появится вместе с parser)', ticks }
}

export const TEAM_COLORS = TEAMS
