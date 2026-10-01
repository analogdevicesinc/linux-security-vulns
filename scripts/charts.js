"use strict";

import * as d3 from 'd3'

export const SERIES_COLORS = [
  '#e45756', '#f58518', '#c9a70a', '#54a24b',
  '#4c78a8', '#9467bd', '#d6619f', '#17a2b8',
]

const fmt = d3.format(',')
const DURATION = 450
let uid = 0

/* ---------------------------------------------------------------- helpers */

function createCard (host, { title, subtitle }) {
  const root = d3.select(host).append('figure').attr('class', 'stats-chart')
  const caption = root.append('figcaption')
  caption.append('div').attr('class', 'stats-chart-title').text(title)
  caption.append('div').attr('class', 'stats-chart-subtitle').text(subtitle ?? '')
  const toolbar = root.append('div').attr('class', 'stats-chart-toolbar')
  const plot = root.append('div').attr('class', 'stats-chart-plot')
  const tooltip = plot.append('div').attr('class', 'stats-chart-tooltip').attr('aria-hidden', 'true')
  return { root, toolbar, plot, tooltip }
}

function toggleButton (parent, { label, pressed = true, title, swatch, onClick }) {
  const button = parent.append('button')
    .attr('type', 'button')
    .attr('class', 'stats-chart-toggle')
    .attr('aria-pressed', String(pressed))
    .attr('title', title ?? null)
  if (swatch) swatch(button.append('span').attr('class', 'stats-chart-swatch'))
  button.append('span').text(label)
  button.on('click', event => onClick(event))
  return button
}

/** Redraw on container width changes; returns a disconnect function. */
function observeWidth (node, draw) {
  let width = 0, frame = 0
  const observer = new ResizeObserver(entries => {
    const next = Math.floor(entries[0].contentRect.width)
    if (!next || next === width) return
    width = next
    cancelAnimationFrame(frame)
    frame = requestAnimationFrame(() => draw(width))
  })
  observer.observe(node)
  return () => { observer.disconnect(); cancelAnimationFrame(frame) }
}

function moveTooltip (tooltip, plotNode, event) {
  const [px, py] = d3.pointer(event, plotNode)
  const node = tooltip.node()
  const width = node.offsetWidth, height = node.offsetHeight
  let left = px + 18
  if (left + width > plotNode.clientWidth) left = px - width - 18
  const top = Math.max(0, Math.min(py - height / 2, plotNode.clientHeight - height))
  tooltip.style('left', `${Math.max(0, left)}px`).style('top', `${top}px`)
}

function truncate (textNode, maxWidth) {
  const full = textNode.textContent
  if (textNode.getComputedTextLength() <= maxWidth) return
  let lo = 0, hi = full.length
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2)
    textNode.textContent = full.slice(0, mid) + '…'
    if (textNode.getComputedTextLength() <= maxWidth) lo = mid
    else hi = mid - 1
  }
  textNode.textContent = full.slice(0, lo) + '…'
  d3.select(textNode).append('title').text(full)
}

/* ------------------------------------------------- CVEs across releases */

/**
 * Line chart of unfixed CVEs per stable patch release, one line per series
 * and kind (e.g. absolute and per defconfig).
 *
 * lines: [{ base, label, kind, color, values: [{ x, y, release }] }]
 * kinds: [{ key, label, dash }]
 */
export function releaseChart (host, { lines, kinds }) {
  const card = createCard(host, {
    title: 'Unfixed CVEs across stable releases',
    subtitle: 'Per patch release for the Linux kernel tree and filtered by affected files in a defconfig.',
  })
  const kindOf = Object.fromEntries(kinds.map(k => [k.key, k]))
  const bases = [...new Map(lines.map(l => [l.base, l])).values()]
  const xMax = d3.max(lines, l => d3.max(l.values, v => v.x)) ?? 1
  lines.forEach(l => { l.byX = new Map(l.values.map(v => [v.x, v])) })

  const state = {
    kinds: new Set(kinds.map(k => k.key)),
    hidden: new Set(),
    domain: null,
    focus: null,
  }
  const visible = l => state.kinds.has(l.kind) && !state.hidden.has(l.base)

  /* toolbar */
  const kindGroup = card.toolbar.append('div').attr('class', 'stats-chart-group')
  const kindButtons = kinds.map(kind => toggleButton(kindGroup, {
    label: kind.label,
    title: `Show or hide all ${kind.label} lines`,
    swatch: s => s.append('svg').attr('class', 'no-background').attr('width', 22).attr('height', 10)
      .append('line').attr('x1', 1).attr('x2', 21).attr('y1', 5).attr('y2', 5)
      .attr('stroke', 'currentColor').attr('stroke-width', 2).attr('stroke-dasharray', kind.dash),
    onClick: () => {
      state.kinds.has(kind.key) ? state.kinds.delete(kind.key) : state.kinds.add(kind.key)
      update()
    },
  }))
  const baseGroup = card.toolbar.append('div').attr('class', 'stats-chart-group')
  const baseButtons = bases.map(base => toggleButton(baseGroup, {
    label: base.label,
    swatch: s => s.classed('stats-chart-dot', true).style('background', base.color),
    onClick: () => {
      state.hidden.has(base.base) ? state.hidden.delete(base.base) : state.hidden.add(base.base)
      update()
    },
  }).on('dblclick', () => {
    state.hidden = new Set(bases.map(b => b.base).filter(b => b !== base.base))
    update()
  }).on('pointerenter', () => focus(base.base))
    .on('pointerleave', () => focus(null)))
  const reset = card.toolbar.append('button')
    .attr('type', 'button').attr('class', 'stats-chart-action')
    .text('Reset zoom').style('display', 'none')
    .on('click', () => setDomain(null))

  /* plot */
  let chart = null
  function draw (width) {
    card.plot.selectAll('svg').remove()
    const height = Math.round(Math.max(300, Math.min(460, width * 0.55)))
    const m = { top: 12, right: 16, bottom: 46, left: 56 }
    const iw = width - m.left - m.right, ih = height - m.top - m.bottom
    const clipId = `stats-clip-${++uid}`

    const svg = card.plot.insert('svg', '.stats-chart-tooltip')
      .attr('class', 'no-background')
      .attr('width', width).attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('role', 'img')
      .attr('aria-label', 'Line chart of unfixed CVEs per stable patch release')
    svg.append('defs').append('clipPath').attr('id', clipId)
      .append('rect').attr('y', -4).attr('width', iw).attr('height', ih + 8)
    const g = svg.append('g').attr('transform', `translate(${m.left},${m.top})`)

    const x = d3.scaleLinear().range([0, iw])
    const y = d3.scaleLinear().range([ih, 0])
    const grid = g.append('g').attr('class', 'stats-chart-grid')
    const xAxis = g.append('g').attr('class', 'stats-chart-axis').attr('transform', `translate(0,${ih})`)
    const yAxis = g.append('g').attr('class', 'stats-chart-axis')
    g.append('text').attr('class', 'stats-chart-axis-label')
      .attr('x', iw / 2).attr('y', ih + 38).attr('text-anchor', 'middle')
      .text('Stable patch release (N in x.y.N)')
    g.append('text').attr('class', 'stats-chart-axis-label')
      .attr('transform', 'rotate(-90)').attr('x', -ih / 2).attr('y', -42)
      .attr('text-anchor', 'middle').text('Unfixed CVEs')

    const area = g.append('g').attr('clip-path', `url(#${clipId})`)
    const line = d3.line().x(d => chart.x(d.x)).y(d => chart.y(d.y)).curve(d3.curveMonotoneX)
    const paths = area.selectAll('path').data(lines).join('path')
      .attr('class', 'stats-chart-line')
      .attr('stroke', d => d.color)
      .attr('stroke-dasharray', d => kindOf[d.kind]?.dash ?? null)
    const rule = area.append('line').attr('class', 'stats-chart-rule')
      .attr('y1', 0).attr('y2', ih).style('display', 'none')
    const dots = area.append('g')
    const empty = g.append('text').attr('class', 'stats-chart-empty')
      .attr('x', iw / 2).attr('y', ih / 2).attr('text-anchor', 'middle')
      .text('No series selected')

    const brush = d3.brushX().extent([[0, 0], [iw, ih]]).on('end', event => {
      if (!event.sourceEvent || !event.selection) return
      const [a, b] = event.selection.map(px => Math.round(x.invert(px)))
      brushG.call(brush.move, null)
      if (b - a >= 2) setDomain([a, b])
    })
    const brushG = g.append('g').attr('class', 'stats-chart-brush').call(brush)
      .on('dblclick', () => setDomain(null))
      .on('pointermove.hover', hover)
      .on('pointerleave.hover', hideHover)

    chart = { svg, x, y, iw, ih, grid, xAxis, yAxis, paths, line, rule, dots, empty, brushG }
    update(false)
  }

  function update (animate = true) {
    kindButtons.forEach((b, i) => b.attr('aria-pressed', String(state.kinds.has(kinds[i].key))))
    baseButtons.forEach((b, i) => b.attr('aria-pressed', String(!state.hidden.has(bases[i].base))))
    reset.style('display', state.domain ? null : 'none')
    if (!chart) return

    const [x0, x1] = state.domain ?? [0, xMax]
    const shown = lines.filter(visible)
    const yMax = d3.max(shown, l => d3.max(l.values, v => v.x >= x0 && v.x <= x1 ? v.y : undefined))
    chart.x.domain([x0, x1])
    const yTicks = Math.max(3, Math.round(chart.ih / 55))
    chart.y.domain([0, Math.max(1, yMax ?? 1)]).nice()
    const yAxisOf = scale => d3.axisLeft(scale).ticks(yTicks).tickSizeOuter(0)

    const t = chart.svg.transition().duration(animate ? DURATION : 0).ease(d3.easeCubicOut)
    chart.xAxis.transition(t).call(d3.axisBottom(chart.x)
      .ticks(Math.max(2, Math.round(chart.iw / 70))).tickFormat(d3.format('d')).tickSizeOuter(0))
    chart.yAxis.transition(t).call(yAxisOf(chart.y).tickFormat(d3.format('~s')))
    chart.grid.transition(t).call(yAxisOf(chart.y).tickSize(-chart.iw).tickFormat(''))
    chart.paths.transition(t)
      .attr('d', d => chart.line(d.values))
      .style('opacity', d => lineOpacity(d))
    chart.empty.style('display', shown.length ? 'none' : null)
    hideHover()
  }

  function lineOpacity (d) {
    if (!visible(d)) return 0
    return state.focus && state.focus !== d.base ? 0.12 : 1
  }

  function focus (base) {
    state.focus = base
    chart?.paths.transition().duration(150).style('opacity', d => lineOpacity(d))
  }

  function setDomain (domain) {
    state.domain = domain
    update()
  }

  let hoverX = null
  function hover (event) {
    const [mx] = d3.pointer(event, chart.brushG.node())
    const xv = Math.round(chart.x.invert(mx))
    const points = lines.filter(visible)
      .map(l => ({ line: l, point: l.byX.get(xv) }))
      .filter(p => p.point)
    if (!points.length) return hideHover()

    const px = chart.x(xv)
    chart.rule.style('display', null).attr('x1', px).attr('x2', px)
    chart.dots.selectAll('circle').data(points).join('circle')
      .attr('class', 'stats-chart-dot-marker').attr('r', 4)
      .attr('cx', px).attr('cy', d => chart.y(d.point.y))
      .attr('fill', d => d.line.color)

    if (hoverX !== xv) {
      hoverX = xv
      renderHoverTooltip(xv, points)
    }
    card.tooltip.classed('visible', true)
    moveTooltip(card.tooltip, card.plot.node(), event)
  }

  function renderHoverTooltip (xv, points) {
    const tip = card.tooltip
    tip.selectAll('*').remove()
    tip.append('div').attr('class', 'stats-chart-tooltip-title').text(`Patch release .${xv}`)
    const shownKinds = kinds.filter(k => state.kinds.has(k.key))
    const table = tip.append('table')
    const head = table.append('thead').append('tr')
    head.append('th').text('Release')
    shownKinds.forEach(k => head.append('th').text(k.label))
    const byBase = d3.group(points, p => p.line.base)
    for (const base of bases.filter(b => byBase.has(b.base)).reverse()) {
      const entries = byBase.get(base.base)
      const row = table.append('tr')
      const name = row.append('td')
      name.append('span').attr('class', 'stats-chart-dot').style('background', base.color)
      name.append('span').text(entries[0].point.release)
      for (const kind of shownKinds) {
        const entry = entries.find(e => e.line.kind === kind.key)
        row.append('td').attr('class', 'num').text(entry ? fmt(entry.point.y) : '—')
      }
    }
  }

  function hideHover () {
    hoverX = null
    if (!chart) return
    chart.rule.style('display', 'none')
    chart.dots.selectAll('circle').remove()
    card.tooltip.classed('visible', false)
  }

  update(false)
  const disconnect = observeWidth(card.plot.node(), draw)
  return { destroy: () => { disconnect(); card.root.remove() } }
}

/* ------------------------------------------- CVEs per image and branch */

/**
 * Horizontal bars, one per image, grouped by git ref.
 *
 * groups: [{ ref, label, sha, rows: [{ ref, defconfig, total }] }]
 */
export function imageChart (host, { groups, uniqueCves, onSelect }) {
  const images = d3.sum(groups, g => g.rows.length)
  const card = createCard(host, {
    title: 'CVEs per image and branch',
    subtitle: `${fmt(uniqueCves)} unique CVEs across ${images} images.`,
  })
  card.toolbar.remove()

  function draw (width) {
    card.plot.selectAll('svg').remove()
    const rowH = 24, groupH = 30, groupGap = 10
    const m = { top: 26, right: 56, bottom: 8, left: Math.round(Math.min(340, Math.max(150, width * 0.4))) }
    const iw = width - m.left - m.right

    let cursor = 0
    const layout = groups.map(group => {
      const y = cursor
      cursor += groupH
      const rows = group.rows.map(row => {
        const ry = cursor
        cursor += rowH
        return { row, y: ry - y }
      })
      cursor += groupGap
      return { group, y, rows }
    })
    const height = m.top + cursor + m.bottom

    const svg = card.plot.insert('svg', '.stats-chart-tooltip')
      .attr('class', 'no-background')
      .attr('width', width).attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('role', 'img')
      .attr('aria-label', 'Bar chart of CVEs per image and branch')
    const g = svg.append('g').attr('transform', `translate(${m.left},${m.top})`)
    const x = d3.scaleLinear()
      .domain([0, Math.max(1, d3.max(groups.flatMap(g => g.rows), r => r.total) ?? 1)]).nice()
      .range([0, iw])
    const ticks = Math.max(2, Math.round(iw / 90))
    g.append('g').attr('class', 'stats-chart-grid')
      .call(d3.axisTop(x).ticks(ticks).tickSize(-cursor).tickFormat(''))
    g.append('g').attr('class', 'stats-chart-axis')
      .call(d3.axisTop(x).ticks(ticks).tickFormat(d3.format('~s')).tickSizeOuter(0))

    const groupG = g.selectAll('g.stats-chart-bar-group').data(layout).join('g')
      .attr('class', 'stats-chart-bar-group')
      .attr('transform', d => `translate(0,${d.y})`)
    const groupLabel = groupG.append('text').attr('class', 'stats-chart-group-label')
      .attr('x', -m.left + 2).attr('y', groupH - 10)
    groupLabel.append('tspan').text(d => d.group.label)
    groupLabel.append('tspan').attr('class', 'stats-chart-muted').attr('dx', 8)
      .text(d => d.group.sha ? d.group.sha.substring(0, 12) : '')

    const rowG = groupG.selectAll('g.stats-chart-row').data(d => d.rows).join('g')
      .attr('class', 'stats-chart-row')
      .attr('transform', d => `translate(0,${d.y})`)
      .attr('tabindex', 0)
      .attr('role', 'button')
      .attr('aria-label', d => `${d.row.defconfig}: ${d.row.total} CVEs`)
      .on('click', (_, d) => onSelect?.(d.row))
      .on('keydown', (event, d) => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect?.(d.row) }
      })
      .on('pointerenter', (event, d) => showRow(event, d.row))
      .on('pointermove', event => moveTooltip(card.tooltip, card.plot.node(), event))
      .on('pointerleave', () => card.tooltip.classed('visible', false))

    rowG.append('rect').attr('class', 'stats-chart-row-bg')
      .attr('x', -m.left).attr('width', width).attr('height', rowH)
    rowG.append('text').attr('class', 'stats-chart-row-label')
      .attr('x', -10).attr('y', rowH / 2).attr('dy', '0.35em').attr('text-anchor', 'end')
      .text(d => d.row.defconfig)
      .each(function () { truncate(this, m.left - 22) })
    const barH = rowH - 8
    rowG.append('rect').attr('class', 'stats-chart-bar')
      .attr('y', (rowH - barH) / 2).attr('height', barH)
      .attr('width', 0)
      .transition().duration(DURATION).ease(d3.easeCubicOut)
      .attr('width', d => x(d.row.total))
    rowG.append('text').attr('class', 'stats-chart-row-total')
      .attr('x', d => x(d.row.total) + 6).attr('y', rowH / 2).attr('dy', '0.35em')
      .text(d => fmt(d.row.total))
  }

  function showRow (event, row) {
    const tip = card.tooltip
    tip.selectAll('*').remove()
    tip.append('div').attr('class', 'stats-chart-tooltip-title').text(row.defconfig)
    tip.append('div').attr('class', 'stats-chart-muted').text(row.ref.replace('refs/heads/', ''))
    tip.append('div').text(`${fmt(row.total)} CVEs`)
    card.tooltip.classed('visible', true)
    moveTooltip(card.tooltip, card.plot.node(), event)
  }

  const disconnect = observeWidth(card.plot.node(), draw)
  return { destroy: () => { disconnect(); card.root.remove() } }
}
