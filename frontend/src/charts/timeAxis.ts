// Подписи времени по оси X.
//
// Раньше график показывал только два времени - начало и конец, прижатые к краям.
// По такому графику нельзя ответить на главный вопрос: "а когда был вот этот пик?"
// Приходилось наводить курсор и читать тултип, то есть график сам по себе ничего
// не говорил.
//
// Метки ставим не "равными долями" (получилось бы 10:07, 10:19, 10:31 - читать
// такое так же тяжело), а по КРУГЛЫМ моментам: :00, :15, каждый час, полночь.
// Тогда глаз цепляется за знакомые значения и переводит расстояние во время сам.

const MIN = 60_000
const HOUR = 60 * MIN
const DAY = 24 * HOUR

// шаги, которые человек читает без счета в уме
const STEPS = [
  MIN, 2 * MIN, 5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN,
  HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR,
  DAY, 2 * DAY, 7 * DAY, 14 * DAY, 30 * DAY, 90 * DAY,
]

export type Tick = { t: number; label: string }

// Локальная полночь для дневных шагов: выравнивание по UTC уводило бы метки
// на 3 часа (МСК) и "сутки" начинались бы в 03:00.
function alignDown(t: number, step: number): number {
  if (step < DAY) {
    const off = new Date(t).getTimezoneOffset() * MIN
    return Math.floor((t - off) / step) * step + off
  }
  const d = new Date(t)
  d.setHours(0, 0, 0, 0)
  const days = Math.round(step / DAY)
  if (days <= 1) return d.getTime()
  return d.getTime() - (Math.floor(d.getTime() / DAY) % days) * DAY
}

function two(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

/**
 * Метки времени для оси X.
 * target - сколько подписей хочется видеть (реально выйдет близко к этому).
 */
export function timeTicks(tMin: number, tMax: number, target = 6): Tick[] {
  const span = tMax - tMin
  if (!(span > 0)) return []
  const step = STEPS.find((s) => span / s <= target) ?? STEPS[STEPS.length - 1]
  const out: Tick[] = []
  for (let t = alignDown(tMin, step) + step; t <= tMax; t += step) {
    const d = new Date(t)
    const midnight = d.getHours() === 0 && d.getMinutes() === 0
    // в длинном окне у полуночи показываем дату - иначе непонятно, какой это день
    const label =
      step >= DAY || midnight
        ? `${two(d.getDate())}.${two(d.getMonth() + 1)}`
        : `${two(d.getHours())}:${two(d.getMinutes())}`
    out.push({ t, label })
  }
  return out
}
