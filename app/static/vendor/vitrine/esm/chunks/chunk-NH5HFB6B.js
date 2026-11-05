/*! Vitrine v0.0.0 | MIT License | https://github.com/ecrou-exact/vitrine
 * Includes: highlight.js 11.12.0 (BSD-3-Clause), marked 18.1.0 (MIT), DOMPurify 3.4.16 (Apache-2.0 OR MPL-2.0), Lucide 1.52.0 (ISC; icons derived from Feather: MIT).
 * Full license texts: THIRD_PARTY_NOTICES.md */
import{d as o,o as t}from"./chunk-MFWTUL36.js";var l=null;function p(){if(l)return l;let a=t().vendorUrl||o(),r={ready:!1,parse:null,parseAll:null,promise:Promise.resolve()};return r.promise=import(new URL("yaml.js",a||location.href).href).then(e=>{r.parse=e.parseYaml,r.parseAll=e.parseYamlAll,r.ready=!0},e=>{throw l=null,e}),l=r,r}export{p as a};
