"use strict";

import { WaitEvent } from '@shared/scripts/event.js'
import { DOM } from '@shared/scripts/dom.js'

const SERIES_COLORS = [
  'rgba(220, 60, 60,0.8)',
  'rgba(230,140, 30,0.8)',
  'rgba(200,190, 30,0.8)',
  'rgba( 50,180, 80,0.8)',
  'rgba( 40,140,220,0.8)',
  'rgba(130, 70,200,0.8)',
  'rgba(180, 60,180,0.8)',
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

class Stats {
  constructor (app) {
    this.$ = {}
    this.parent = app

    this.construct()

    this.parent = app
  }
  render_abs_cves_chart_ (graph) {
    const stats = DOM.get('#security-stats', this.$.body)
    if (!stats || !Array.isArray(graph.tags) || !Array.isArray(graph.values)) return

    const series = {}
    graph.tags.forEach((tag, index) => {
      const match = tag.match(/^(\d+\.\d+)\.(\d+)$/)
      const value = graph.values[index]
      if (!match || !Number.isFinite(value)) return
      ;(series[match[1]] ??= []).push({ y: value, label: tag })
    })

    const datasets = Object.entries(series)
      .sort((a, b) => versionCmp(a[0], b[0]))
      .map(([base, points], index) => {
        const data = points.sort((a, b) => versionCmp(a.label, b.label))
          .map(point => ({ ...point, x: Number(point.label.split('.').at(-1)) }))
        const color = SERIES_COLORS[index % SERIES_COLORS.length]
        return {
          label: base,
          data,
          borderColor: color,
          backgroundColor: color,
          showLine: true,
          tension: 0.2,
          pointRadius: 0,
          pointHoverRadius: 5,
        }
      })

    if (datasets.length === 0) return
    const wrap = DOM.new('div', { style: 'position: relative; height: 500px; margin-bottom: 2em;' })
    const ctx = DOM.new('canvas', { id: 'chart-absolute-cves' })
    wrap.append(ctx)
    new Chart(ctx, {
      type: 'scatter',
      data: { datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: "CVEs findings for image 'ezlite_defconfig' across releases" },
          tooltip: { callbacks: { label: (item) => `${item.raw.label}: ${item.raw.y} CVEs` } },
        },
        scales: {
          x: { title: { display: true, text: 'Stable patch release' }, beginAtZero: true },
          y: { title: { display: true, text: 'Affected CVEs' }, beginAtZero: true },
        },
      },
    })
    stats.prepend(wrap)
  }
  render_abs_cves_chart (graph) {
    if (typeof Chart === 'undefined')
      import('https://cdn.jsdelivr.net/npm/chart.js').then(() => this.render_abs_cves_chart_(graph))
    else
      this.render_abs_cves_chart_(graph)
  }
  render_tags_chart_ (tags) {
    const stats = DOM.get('#security-stats', this.$.body)
    if (!stats) return

    const seriesInfo = tags._series || {}
    const tagNames = Object.keys(tags).filter(tag => tag !== '_series')
    if (Object.keys(seriesInfo).length === 0) {
      for (const tag of tagNames) {
        const match = tag.match(/^(\d+\.\d+)/)
        if (match) seriesInfo[match[1]] = ''
      }
    }

    const series = {}
    for (const tag of tagNames) {
      const base = Object.keys(seriesInfo).find(
        series => tag === series || tag.startsWith(series + '.')
      )
      if (!base) continue
      ;(series[base] ??= []).push(tag)
    }

    const datasets = []
    const sortedSeries = Object.entries(series).sort((a, b) => versionCmp(a[0], b[0]))
    for (const [index, [base, rels]] of sortedSeries.entries()) {
      rels.sort(versionCmp)
      const stable = seriesInfo[base] === 'stable'
      const color = SERIES_COLORS[index % SERIES_COLORS.length]
      datasets.push({
        label: stable ? `${base} (stable)` : base,
        data: rels.map(r => ({ x: Number(r.split('.').at(-1)), y: tags[r], label: r })),
        backgroundColor: color,
        borderColor: color.replace(/[\d.]+\)$/, '1)'),
        showLine: true,
        tension: 0.2,
        pointRadius: 0,
        pointHoverRadius: 5,
      })
    }

    const wrap = DOM.new('div', { style: 'position: relative; height: 500px; margin-bottom: 2em;' })
    const ctx = DOM.new('canvas', { id: 'chart-tags' })
    wrap.append(ctx)
    new Chart(ctx, {
      type: 'scatter',
      data: { datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: 'Absolute CVEs findings across releases' },
          tooltip: { callbacks: { label: (item) => `${item.raw.label}: ${item.raw.y} CVEs` } },
        },
        scales: {
          x: { title: { display: true, text: 'Stable patch release' }, beginAtZero: true },
          y: {
            title: { display: true, text: 'Unfixed CVEs' },
            beginAtZero: true,
          },
        },
      },
    })

    stats.prepend(wrap)
  }
  render_tags_chart (tags) {
    if (typeof Chart === 'undefined')
      import('https://cdn.jsdelivr.net/npm/chart.js').then(() => this.render_tags_chart_(tags))
    else
      this.render_tags_chart_(tags)
  }
  render_vulns (results) {
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

    Promise.allSettled(requests)
      .then(results => this.render_vulns(results))
      .catch(err => console.error(err))
  }
  construct_vulns () {
    const metadata = this.parent.state.metadata
    const repository = this.parent.state.repository
    let base_url = metadata.source_hostname_raw.replace('{repository}', repository)
                              .replace('{branch}', 'data')
                              .replace('{pathname}', '')

    fetch(new Request(new URL('refs.json', base_url)))
      .then(response => {
        if (!response.ok) throw new Error()
        return response.json()
      })
      .then(obj => this.collect_vuls(obj, base_url))
      .catch(() => {})

    fetch(new Request(new URL('tags.json', base_url)))
      .then(response => {
        if (!response.ok) throw new Error()
        return response.json()
      })
      .then(tags => this.render_tags_chart(tags))
      .catch(() => {})

    fetch('https://raw.githubusercontent.com/analogdevicesinc/linux-security-vulns/refs/heads/data/ezlite_defconfig-per-tag.json')
      .then(response => {
        if (!response.ok) throw new Error()
        return response.json()
      })
      .then(graph => this.render_abs_cves_chart(graph))
      .catch(() => {})
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
