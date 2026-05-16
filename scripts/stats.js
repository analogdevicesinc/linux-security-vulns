"use strict";

import { WaitEvent } from '@shared/scripts/event.js'
import { DOM } from '@shared/scripts/dom.js'

class Stats {
  constructor (app) {
    this.$ = {}
    this.parent = app

    this.construct()

    this.parent = app
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
    const requests = obj.map(file => {
      const url = new URL(file, base_url)

      return fetch(new Request(url))
        .then(response => {
          if (!response.ok)
            throw new Error()
          return response.json()
        })
        .then(data => ({
          file,
          data
        }))
    })

    Promise.allSettled(requests)
      .then(results => {
        this.render_vulns(results)
      })
      .catch(err => {
        console.error(err)
      })
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

    window.addEventListener("app:hot_reload:page_loaded", () => {
      this.construct_vulns()
    })
  }
  construct () {
    this.$.body = DOM.get('.body');

    (async () => {
      await WaitEvent(this.parent, 'fetch', "app:fetch:constructed")
      this.parent.fetch.then(
        this.construct_vulns.bind(this)
      )
    })();
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
