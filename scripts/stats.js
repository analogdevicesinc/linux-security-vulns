"use strict";

import { WaitEvent } from '@shared/scripts/event.js'
import { DOM } from '@shared/scripts/dom.js'

function scoreColor (score, count, maxCount, alpha = 0.65) {
  if (score === null) return `rgba(132,139,149,${alpha})`
  const t = (score / 10) * (count / maxCount)
  const r = Math.round(254 + t * (100 - 254))
  const g = Math.round(238 + t * (  6 - 238))
  const b = Math.round(239 + t * ( 14 - 239))
  return `rgba(${r},${g},${b},${alpha})`
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
  render_charts_ (results, scoreMap) {
    const refs = results
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value.data)

    const refLabels = refs.map(r => r.ref)
    const defconfigs = [...new Set(refs.flatMap(r => Object.keys(r.result)))]


    const maxCount = Math.max(...refs.flatMap(ref => Object.values(ref.result).map(e => e.cves.length)))
    const scorePoints = [], scoreColors = [], scoreBorders = []
    refs.forEach((ref, ri) => {
      defconfigs.forEach((defconfig, di) => {
        const entry = ref.result[defconfig]
        if (!entry) return
        const count = entry.cves.length
        const scored = entry.cves.map(cve => scoreMap.get(cve)).filter(s => s != null)
        const avg = scored.length ? scored.reduce((a, b) => a + b, 0) / scored.length : null
        scorePoints.push({ x: ri, y: di, r: Math.max(4, Math.sqrt(count) * 2.5), avgScore: avg })
        scoreColors.push(scoreColor(avg, count, maxCount))
        scoreBorders.push(scoreColor(avg, count, maxCount, 1))
      })
    })

    const stats = DOM.get('#security-stats', this.$.body)

    const wrap1 = DOM.new('div', { style: 'position: relative; height: 1200px' })
    const ctx1 = DOM.new('canvas', { id: 'chart-count' })
    wrap1.append(ctx1)
    new Chart(ctx1, {
      type: 'bubble',
      data: { datasets: [{ data: scorePoints, backgroundColor: scoreColors, borderColor: scoreBorders }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          title: { display: true, text: 'CVE count and score per defconfig and git ref' },
          tooltip: { callbacks: { label: (item) => {
            const count = Math.round((item.raw.r / 2.5) ** 2)
            const score = item.raw.avgScore !== null ? ` — avg CVSS ${item.raw.avgScore.toFixed(2)}` : ''
            return `${count} CVEs${score}`
          }}}
        },
        scales: {
          x: {
            ticks: { callback: (v) => (refLabels[v] ?? '').replace('refs/heads/', '') },
            min: -1, max: refs.length
          },
          y: {
            ticks: { stepSize: 1, maxRotation: 45, minRotation: 45, callback: (v) => defconfigs[v] ?? '' },
            min: -1, max: defconfigs.length
          }
        }
      }
    })

    // Severity distribution
    const allCves = new Set(refs.flatMap(ref => Object.values(ref.result).flatMap(e => e.cves)))
    const buckets = { High: 0, Medium: 0, Low: 0, Unrated: 0 }
    allCves.forEach(cve => {
      const s = scoreMap.get(cve)
      if      (s == null) buckets.Unrated++
      else if (s >= 7.0)  buckets.High++
      else if (s >= 4.0)  buckets.Medium++
      else                buckets.Low++
    })

    const wrap2 = DOM.new('div', { style: 'position: relative; max-width: 600px; max-height: 600px; margin: 0 auto;' })
    const ctx2 = DOM.new('canvas', { id: 'chart-pie' })
    wrap2.append(ctx2)
    new Chart(ctx2, {
      type: 'pie',
      data: {
        labels: Object.keys(buckets),
        datasets: [{
          data: Object.values(buckets),
          backgroundColor: ['rgba(100,6,14,0.8)', 'rgba(220,190,0,0.8)', 'rgba(50,180,50,0.8)', 'rgba(132,139,149,0.8)']
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: 'CVE severity distribution' },
          legend: { position: 'right' },
          tooltip: { callbacks: { label: (item) => ` ${item.label}: ${item.raw} (${(item.raw / allCves.size * 100).toFixed(1)}%)` } }
        }
      }
    })

    stats.prepend(wrap2)
    stats.prepend(wrap1)
  }
  render_charts (results, scoreMap) {
    if (typeof Chart === "undefined")
      import('https://cdn.jsdelivr.net/npm/chart.js').then(() => {
        this.render_charts_(results, scoreMap)
      })
    else
      this.render_charts_(results, scoreMap)
  }
  render_vulns (results, scoreMap) {
    let stats = DOM.get('#security-stats', this.$.body)
    if (!stats)
      return

    for (const result of results) {
      if (result.status !== 'fulfilled')
        continue

      let ref_entry = DOM.new('p')
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
  collect_vuls (obj, base_url) {
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
        this.render_vulns(results, scoreMap)
      })
      .catch(err => console.error(err))
  }
  construct_vulns () {
    const metadata = this.parent.state.metadata
    const repository = this.parent.state.repository
    let base_url = metadata.source_hostname_raw.replace('{repository}', repository)
                              .replace('{branch}', 'data')
                              .replace('{pathname}', '')

    const response = fetch(
      new Request(new URL('refs.json', base_url))
    )
      .then(response => response)
      .then(response => {
        if (!response.ok)
          throw new Error();
        return response.json()
      })
      .then(obj => this.collect_vuls(obj, base_url))
      .catch(err => {})
  }
  construct () {
    this.$.body = DOM.get('.body');

    (async () => {
      await WaitEvent(this.parent, 'fetch', "app:fetch:constructed")
      this.parent.fetch.then(
        this.construct_vulns.bind(this)
      )
    })();
    window.addEventListener("app:hot_reload:page_loaded", () => {
      this.construct_vulns()
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
