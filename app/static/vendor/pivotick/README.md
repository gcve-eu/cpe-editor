# Pivotick assets

Locally hosted browser bundle and stylesheet from
[Pivotick/Pivotick v2.0.1](https://github.com/Pivotick/Pivotick/releases/tag/v2.0.1)
(MIT). Files are copied unmodified from the official `pivotick-dist.zip` release:

```sh
curl -fLO https://github.com/Pivotick/Pivotick/releases/download/v2.0.1/pivotick-dist.zip
unzip pivotick-dist.zip pivotick.iife.js pivotick.css
```

SHA-256 checksums:

```
325f4a5b6be4550026d98a5cf74cac0dd20c12f5e604519612e5260d5b74b3f7  pivotick-dist.zip
8f3d6bcb59dfa0e9026efe515a6258774bd43c4b70b6b6b30a5f7df8ad54daa8  pivotick.iife.js
c41ddf02a13e5a560dae84dfc57608fb49010d1397d716314c2272376db888a9  pivotick.css
```

No Node build or external CDN is needed to run CPE Editor. Assets are loaded
only when the graph panel is expanded. The integration uses viewer mode and the
bundle's embedded simulation worker, so no separate worker file or editing
interface is needed. If browser policy prevents worker creation, Pivotick falls
back to the main thread. Warmup, cooldown, and alpha decay are configured to keep
that fallback short, including v2.0.1's additional cooling stage.
The browser constructor is `new Pivotick(container, data, options)`.

See LICENSE for Pivotick's license and THIRD_PARTY_NOTICES.md for bundled
dependency licenses.
