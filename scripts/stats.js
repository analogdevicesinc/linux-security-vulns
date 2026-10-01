"use strict";

import { WaitEvent } from '@shared/scripts/event.js'
import { DOM } from '@shared/scripts/dom.js'
import { releaseChart, imageChart, SERIES_COLORS } from './charts.js'

const RELEASE_KINDS = [
  { key: 'absolute',  label: 'all',         dash: null },
  { key: 'defconfig', label: 'sc598-som-ezlite_defconfig', dash: '5 3' },
]

function versionKey (r) {
  return r.split(/[.\-]/).filter(s => /^\d+$/.test(s)).map(Number)
}

function versionCmp (a, b) {
  const ka = versionKey(a), kb = versionKey(b)
  for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
    const d = (ka[i] || 0) - (kb[i] || 0)
    if (d !== 0) return d
  }
  return 0
}

function cvssScore (vector) {
  if (!vector) return null
  try {
    const p = Object.fromEntries(vector.split('/').slice(1).map(s => s.split(':')))
    const AV = {N:0.85,A:0.62,L:0.55,P:0.2}[p.AV]
    const AC = {L:0.77,H:0.44}[p.AC]
    const PR = (p.S==='C' ? {N:0.85,L:0.68,H:0.50} : {N:0.85,L:0.62,H:0.27})[p.PR]
    const UI = {N:0.85,R:0.62}[p.UI]
    const C = {H:0.56,L:0.22,N:0}[p.C], I = {H:0.56,L:0.22,N:0}[p.I], A = {H:0.56,L:0.22,N:0}[p.A]
    const ISS = 1-(1-C)*(1-I)*(1-A)
    const imp = p.S==='U' ? 6.42*ISS : 7.52*(ISS-0.029)-3.25*Math.pow(ISS-0.02,15)
    if (imp <= 0) return 0
    const base = p.S==='U' ? Math.min(imp+8.22*AV*AC*PR*UI,10) : Math.min(1.08*(imp+8.22*AV*AC*PR*UI),10)
    return Math.ceil(base*10)/10
  } catch { return null }
}

class Stats {
  constructor (app) {
    this.$ = {}
    this.parent = app

    this.construct()

    this.parent = app
  }
  chart_slot_ (name) {
    const stats = DOM.get('#security-stats', this.$.body)
    if (!stats) return null
    let slots = stats.querySelector(':scope > .stats-charts')
    if (!slots) {
      slots = DOM.new('div', { className: 'stats-charts' })
      for (const slot of ['releases', 'images'])
        slots.append(DOM.new('div', { className: `stats-chart-slot slot-${slot}` }))
      stats.prepend(slots)
    }
    return slots.querySelector(`.slot-${name}`)
  }
  mount_chart_ (name, create) {
    this.charts_ ??= {}
    this.charts_[name]?.destroy()
    delete this.charts_[name]
    const slot = this.chart_slot_(name)
    if (!slot) return
    slot.replaceChildren()
    this.charts_[name] = create(slot)
  }
  render_charts_ (results, scoreMap) {
    const refs = results.filter(r => r.status === 'fulfilled').map(r => r.value.data)
    if (!refs.length) return

    const severityOf = cve => {
      const s = scoreMap.get(cve)
      if (s == null) return 'unrated'
      return s >= 7 ? 'high' : s >= 4 ? 'medium' : 'low'
    }
    const groups = refs.map(ref => ({
      ref: ref.ref,
      label: ref.ref.replace('refs/heads/', ''),
      sha: ref.sha,
      rows: Object.entries(ref.result).map(([defconfig, entry]) => {
        const counts = { high: 0, medium: 0, low: 0, unrated: 0 }
        entry.cves.forEach(cve => counts[severityOf(cve)]++)
        const scored = entry.cves.map(cve => scoreMap.get(cve)).filter(s => s != null)
        return { ref: ref.ref, defconfig, total: entry.cves.length, counts, avg: d3.mean(scored) ?? null }
      }).sort((a, b) => b.total - a.total),
    })).filter(group => group.rows.length)

    const unique = new Set(refs.flatMap(ref => Object.values(ref.result).flatMap(e => e.cves)))
    const totals = { high: 0, medium: 0, low: 0, unrated: 0 }
    unique.forEach(cve => totals[severityOf(cve)]++)

    this.mount_chart_('images', slot => imageChart(slot, {
      groups,
      totals,
      uniqueCves: unique.size,
      scored: scoreMap.size > 0,
      onSelect: row => {
        const input = document.getElementById(`${row.ref}-${row.defconfig}`)
        if (!input) return
        input.checked = true
        input.closest('.collapsible')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      },
    }))
  }
  render_tags_chart_ (tags, perDefconfig) {
    // tags.json: { "<release>": count, ..., "_series": { "<x.y>": "stable"|"longterm" } }
    const seriesInfo = { ...(tags._series ?? {}) }
    const releases = Object.keys(tags).filter(tag => tag !== '_series' && Number.isFinite(tags[tag]))
    if (!Object.keys(seriesInfo).length)
      releases.forEach(tag => { const m = tag.match(/^(\d+\.\d+)/); if (m) seriesInfo[m[1]] = '' })
    const bases = Object.keys(seriesInfo).sort(versionCmp)
    const baseOf = tag => bases.find(base => tag === base || tag.startsWith(base + '.'))
    const patchOf = (tag, base) => tag === base ? 0 : Number(tag.slice(base.length + 1))

    const collect = (entries, kind) => {
      const byBase = d3.group(entries.filter(([tag, value]) => baseOf(tag) && Number.isFinite(value)),
                              ([tag]) => baseOf(tag))
      return [...byBase].map(([base, points]) => ({ base, kind, points }))
    }
    const configEntries = (perDefconfig?.tags ?? []).map((tag, i) => [tag, perDefconfig.values[i]])
    const raw = [
      ...collect(releases.map(tag => [tag, tags[tag]]), 'absolute'),
      ...collect(configEntries, 'defconfig'),
    ]

    const lines = raw.map(({ base, kind, points }) => {
      const index = bases.indexOf(base)
      return {
        base,
        kind,
        label: seriesInfo[base] === 'stable' ? `${base} (stable)` : base,
        color: SERIES_COLORS[index % SERIES_COLORS.length],
        values: points
          .map(([release, y]) => ({ release, y, x: patchOf(release, base) }))
          .filter(v => Number.isFinite(v.x))
          .sort((a, b) => a.x - b.x),
      }
    }).filter(line => line.values.length)
      .sort((a, b) => versionCmp(a.base, b.base))
    if (!lines.length) return

    const kinds = RELEASE_KINDS.filter(kind => lines.some(line => line.kind === kind.key))
    this.mount_chart_('releases', slot => releaseChart(slot, { lines, kinds }))
  }
  render_tags_chart (tags, perDefconfig) { this.render_tags_chart_(tags, perDefconfig) }
  render_charts (results, scoreMap) { this.render_charts_(results, scoreMap) }
  render_vulns (results, scoreMap) {
    let stats = DOM.get('#security-stats', this.$.body)
    if (!stats)
      return

    stats.querySelectorAll('.stats-ref-entry').forEach(entry => entry.remove())
    for (const result of results) {
      if (result.status !== 'fulfilled')
        continue

      let ref_entry = DOM.new('div', { className: 'stats-ref-entry' })
      const modified = new Date(result.value.data.modified).toUTCString()
      const sha_url = this.parent.state.metadata.source_hostname
                        .replace('{repository}', 'linux')
                        .replace('{branch}', result.value.data.sha)
                        .replace('{pathname}', '')
      let sha_entry = DOM.new('span')
      sha_entry.append(...[
        DOM.new('span', { textContent: 'sha:' }),
        DOM.new('a', {
          className: 'icon git',
          href: sha_url,
          textContent: result.value.data.sha.substring(0, 12)
        })
      ])
      ref_entry.append(...[
        DOM.new('h3', {
          className: 'title',
          textContent: `ref: ${result.value.data.ref}`
        }),
        sha_entry,
        DOM.new('div', {
          textContent: `Last scan: ${modified}`
        })
      ])

      for (const [key, value] of Object.entries(result.value.data.result)) {

        let entry = DOM.new('div', {
          className: 'collapsible',
        })

        let label = DOM.new('label', {
          htmlFor: `${result.value.data.ref}-${key}`,
        })
        let label_header = DOM.new('div')
        label_header.append(...[
          DOM.new('div', {
            textContent: key
          }),
          DOM.new('p', {
            textContent: `${value.cves.length} vulnerabilities`
          })
        ])
        label.append(...[
          label_header,
          DOM.new('div', { className: 'icon' })
        ])
        entry.append(...[
          DOM.new('input', {
            className: 'collapsible_input',
            id: `${result.value.data.ref}-${key}`,
            name: `${result.value.data.ref}-${key}`,
            type: 'checkbox',
          }),
          label
        ])
        let collapsible_content = DOM.new('div', {
          className: 'collapsible_content'
        })
        let cves_grid = DOM.new('div', {
          className: 'grid'
        })
        let artifact_download = DOM.new('p')
        artifact_download.append(...[
          DOM.new('span', { textContent: 'Download:' }),
          DOM.new('a', {
            className: 'icon download',
            href: `https://dl.cloudsmith.io/public/adi/linux/raw/versions/${result.value.data.sha}/${key}`,
            target: '_blank',
            textContent: `${result.value.data.sha}/${key}`
          })
        ])
        collapsible_content.append(...[
          artifact_download,
          cves_grid
        ])

        let cves = []
        for (const cve of value.cves) {
          cves.push(DOM.new('a', {
            className: 'entry',
            href: `https://nvd.nist.gov/vuln/detail/${cve}`,
            target: '_blank',
            textContent: cve
          }))
        }
        cves_grid.append(...cves)
        entry.append(collapsible_content)
        ref_entry.append(entry)
      }
      ref_entry.append(DOM.new('hr'))
      stats.append(ref_entry)
    }

    this.render_charts(results, scoreMap)
  }
  collect_vuls (obj, base_url, generation) {
    if (!DOM.get('#security-stats', this.$.body))
      return

    const requests = obj.map(file =>
      fetch(new Request(new URL(file, base_url)))
        .then(response => {
          if (!response.ok) throw new Error()
          return response.json()
        })
        .then(data => ({ file, data }))
    )

    const scores_p = fetch(new Request(new URL('scores.json', base_url)))
      .then(r => r.ok ? r.json() : null)
      .catch(() => null)

    Promise.all([Promise.allSettled(requests), scores_p])
      .then(([results, scores]) => {
        const scoreMap = new Map()
        if (scores)
          scores.cve.forEach((cve, i) => {
            const s = cvssScore(scores.cvss_score[i])
            if (s !== null) scoreMap.set(cve, s)
          })
        if (generation === this.generation_) this.render_vulns(results, scoreMap)
      })
      .catch(err => console.error(err))
  }
  construct_vulns () {
    if (!this.active) return
    const metadata = this.parent.state.metadata
    const repository = this.parent.state.repository
    let base_url = metadata.source_hostname_raw.replace('{repository}', repository)
                              .replace('{branch}', 'data')
                              .replace('{pathname}', '')

    const generation = this.generation_ = (this.generation_ ?? 0) + 1
    fetch(new Request(new URL('refs.json', base_url)))
      .then(response => {
        if (!response.ok) throw new Error()
        return response.json()
      })
      .then(obj => { if (generation === this.generation_) this.collect_vuls(obj, base_url, generation) })
      .catch(() => {})

    const loadJson = file => fetch(new Request(new URL(file, base_url)))
      .then(response => {
        if (!response.ok) throw new Error(`Failed to load ${file}`)
        return response.json()
      })
    Promise.all([loadJson('tags.json'), loadJson('ezlite_defconfig-per-tag.json').catch(() => null)])
      .then(([tags, perDefconfig]) => {
        if (generation === this.generation_) this.render_tags_chart(tags, perDefconfig)
      })
      .catch(err => console.error(err))
  }
  construct () {
    this.$.body = DOM.get('.body')
    this.active = this.parent.state.repository === 'linux-security-vulns';

    (async () => {
      await WaitEvent(this.parent, 'fetch', "app:fetch:constructed")
      this.parent.fetch.then(
        this.construct_vulns.bind(this)
      )
    })();
    window.addEventListener('app:hot_reload:doc_unload', () => {
      this.active = false
      this.generation_ = (this.generation_ ?? 0) + 1
      for (const chart of Object.values(this.charts_ ?? {})) chart.destroy()
      this.charts_ = {}
    })
    window.addEventListener('app:hot_reload:doc_loaded', () => {
      this.active = this.parent.state.repository === 'linux-security-vulns'
    })
    window.addEventListener('app:hot_reload:page_loaded', () => {
      if (this.active) this.construct_vulns()
    })
  }
}

const VulnsPage = () => {
  let on_visible = () => {
    new Stats(app)
  }

  if (document.visibilityState === 'visible')
    on_visible()
  else
    window.addEventListener('focus', on_visible, { once: true })
}

(async () => {
  await WaitEvent(window, 'app', "app:created")
  VulnsPage()
})()
