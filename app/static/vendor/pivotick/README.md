# Pivotick assets

Locally hosted browser bundle and stylesheet from
[Pivotick/Pivotick v3.0.0](https://github.com/Pivotick/Pivotick/releases/tag/v3.0.0)
(MIT). Files are copied unmodified from the official `pivotick-dist.zip` release:

```sh
curl -fLO https://github.com/Pivotick/Pivotick/releases/download/v3.0.0/pivotick-dist.zip
unzip pivotick-dist.zip pivotick.iife.js pivotick.css
```

SHA-256 checksums:

```
78ccefad8485a9fa6a87d3ef109a234aa1c4c3c3300cc56c63a6bede25d18617  pivotick-dist.zip
e3472a1ad9dbc047b4e379d657276311fd7726180550133c25b68423b288c59d  pivotick.iife.js
402afa28d1525ab64fa1c46638a2cc39a7e4680a1fc724d77dc428d6298e2244  pivotick.css
```

No Node build or external CDN is needed to run CPE Editor. Assets are loaded
only when the graph panel is expanded. The integration uses viewer mode and the
bundle's embedded simulation worker, so no separate worker file or editing
interface is needed. If browser policy prevents worker creation, Pivotick falls
back to the main thread. Warmup, cooldown, and alpha decay are configured to keep
that fallback short, including the additional cooling stage.
The browser constructor is `new Pivotick(container, data, options)`.

The v3 viewer uses the height set on `.graph-canvas`. Node labels follow v3's
default visibility threshold (hidden below 9 rendered pixels). The integration
does not use the cluster APIs removed in v3; pan, zoom, record inspection, and
the embedded worker retain the same API.

`entity-graph.js` contains a v3 tooltip adapter: it moves this graph's pinned
tooltips into the canvas, constrains dragging and resizing there, and converts
their connector endpoints back to page coordinates. It uses the tooltip
module's pin map and connector methods; recheck these when upgrading Pivotick.
The vendored release files remain unmodified.

See LICENSE for Pivotick's license and THIRD_PARTY_NOTICES.md for bundled
dependency licenses.
