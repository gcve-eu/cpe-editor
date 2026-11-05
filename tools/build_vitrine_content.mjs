// Build content components from the same pinned checkout as vt-table.
// Usage: node tools/build_vitrine_content.mjs /path/to/vitrine
import {createRequire} from "node:module";
import {readFile, rm} from "node:fs/promises";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";
if (!process.argv[2]) throw new Error("Pass the pinned Vitrine checkout");
const source = resolve(process.argv[2]);
const require = createRequire(resolve(source, "package.json"));
const {build} = require("esbuild");
const output = resolve("app/static/vendor/vitrine/content");
const rawCss = {name: "raw-css", setup(builder) {
  builder.onResolve({filter: /\.css\?raw$/}, args => ({path: resolve(args.resolveDir, args.path.replace(/\?raw$/, "")), namespace: "raw-css"}));
  builder.onLoad({filter: /.*/, namespace: "raw-css"}, async args => ({contents: await readFile(args.path, "utf8"), loader: "text"}));
}};
const trustedTypesSafe = {name: "trusted-types-safe", setup(builder) {
  builder.onLoad({filter: /node_modules[\\/](?:echarts|zrender)[\\/].*\.js$/}, async args => ({
    contents: (await readFile(args.path, "utf8")).replace(/\.innerHTML\s*=\s*(?:''|""|null)\s*;/g, ".textContent = '';"), loader: "js"
  }));
}};
const common = {absWorkingDir: source, bundle: true, format: "esm", minify: true, sourcemap: false,
  target: ["es2022", "chrome120", "firefox121", "safari17"], legalComments: "eof",
  define: {__VITRINE_VERSION__: '"0.0.0"'}, logLevel: "info"};
await rm(output, {recursive: true, force: true});
await build({...common, entryPoints: Object.fromEntries(["code", "json", "markdown", "diff", "chart"].map(name => [`vt-${name}`, `src/entries/vt-${name}.js`])),
  outdir: `${output}/esm`, splitting: true, chunkNames: "chunks/[name]-[hash]", plugins: [rawCss],
  banner: {js: "/*! Vitrine | MIT | Source e7db1ebd587b27f41988a0da9785310eaa6f2f08 | See app/static/vendor/vitrine/LICENSE and THIRD_PARTY_NOTICES.md */"}});
await build({...common, entryPoints: ["src/vendor/echarts.js"], outfile: `${output}/vendor/echarts.js`, plugins: [trustedTypesSafe],
  banner: {js: "/*! Apache ECharts and zrender | Apache-2.0 | See ../../THIRD_PARTY_NOTICES.md */"}});
const {listLanguages, BUNDLED_LANGUAGES} = await import(pathToFileURL(resolve(source, "scripts/languages.js")));
const languages = listLanguages().filter(({name}) => !BUNDLED_LANGUAGES.includes(name));
await build({...common, entryPoints: Object.fromEntries(languages.map(({name}) => [name, require.resolve(`highlight.js/lib/languages/${name}`)])),
  outdir: `${output}/languages`, logLevel: "silent",
  banner: {js: "/*! highlight.js | BSD-3-Clause | See ../../THIRD_PARTY_NOTICES.md */"}});
