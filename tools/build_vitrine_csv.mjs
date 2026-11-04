// Rebuild the standalone vt-csv bundle from the pinned upstream checkout.
// Usage: node tools/build_vitrine_csv.mjs /path/to/vitrine
import {createRequire} from "node:module";
import {readFile} from "node:fs/promises";
import {resolve} from "node:path";

if (!process.argv[2]) throw new Error("Usage: node tools/build_vitrine_csv.mjs /path/to/vitrine");
const source = resolve(process.argv[2]);
const require = createRequire(resolve(source, "package.json"));
const {build} = require("esbuild");
const rawCss = {
  name: "raw-css",
  setup(builder) {
    builder.onResolve({filter: /\.css\?raw$/}, args => ({
      path: resolve(args.resolveDir, args.path.replace(/\?raw$/, "")),
      namespace: "raw-css"
    }));
    builder.onLoad({filter: /.*/, namespace: "raw-css"}, async args => ({
      contents: await readFile(args.path, "utf8"), loader: "text"
    }));
  }
};
await build({
  absWorkingDir: source,
  entryPoints: ["src/entries/vt-csv.js"],
  outfile: resolve("app/static/vendor/vitrine/esm/vt-csv.js"),
  bundle: true,
  format: "esm",
  minify: true,
  sourcemap: false,
  target: ["es2022", "chrome120", "firefox121", "safari17"],
  legalComments: "eof",
  plugins: [rawCss],
  define: {__VITRINE_VERSION__: '"0.0.0"'},
  banner: {js: `/*! Vitrine | MIT | https://github.com/ecrou-exact/vitrine
 * Source: 7c379edba7ffb89abcae01b0806f20ed43dbc627. Standalone vt-csv bundle.
 * Includes highlight.js (BSD-3-Clause), DOMPurify (Apache-2.0 OR MPL-2.0),
 * and Lucide icons (ISC). See LICENSE and THIRD_PARTY_NOTICES.md. */`},
  logLevel: "info"
});
