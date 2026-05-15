import alias from '@rollup/plugin-alias'
import terser from '@rollup/plugin-terser'
import path from 'path'

const doctools_path = process.env.DOCTOOLS_PATH
let shared = path.resolve(`${doctools_path}/adi_doctools/theme/harmonic`)

export default [
  {
    input: `./scripts/stats.js`,
    output: {
      file: `./docs/sources/custom.umd.js`,
      format: "umd",
      name: "StatsPage",
      sourcemap: true,
    },
    plugins: [
      alias({
        entries: [
          { find: '@shared', replacement: shared }
        ]
      }),
      terser()
    ],
  }
]

