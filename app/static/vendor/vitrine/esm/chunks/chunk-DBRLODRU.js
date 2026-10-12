/*! Vitrine v0.0.0 | MIT License | https://github.com/ecrou-exact/vitrine
 * Includes: highlight.js 11.12.0 (BSD-3-Clause), marked 18.1.0 (MIT), DOMPurify 3.4.16 (Apache-2.0 OR MPL-2.0), Lucide 1.52.0 (ISC; icons derived from Feather: MIT).
 * Full license texts: THIRD_PARTY_NOTICES.md */
import{a as D,o as X}from"./chunk-VMG7NFEI.js";import{B as R,H as j,K as V,L as J,O as z,Q as Y,S as P,U as G,d as U,f as H,h as I,m as C,o as a,q as T,y as B,z as N}from"./chunk-NRXOEWTQ.js";var F=`/*
 * API reference: introduction, tag buttons, and endpoints that open to show their
 * parameters, bodies, responses, schema trees and examples.
 */
.api-body {
  padding: var(--_space-5);
  background: var(--_surface);
}

/* ---------- Introduction ---------- */

.api-intro {
  display: grid;
  gap: var(--_space-3);
  padding-bottom: var(--_space-5);
  border-bottom: 1px solid var(--_border);
}

.api-title {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--_space-3);
}

.api-title h2 {
  margin: 0;
  font: 700 1.5rem/1.2 var(--_font-ui);
  letter-spacing: -0.02em;
}

.api-version,
.api-spec {
  padding: 2px 8px;
  border-radius: var(--_radius-full);
  font: 600 11px/1.6 var(--_font-mono);
}

.api-version {
  background: var(--_accent-soft);
  color: var(--_accent-fg);
}

.api-spec {
  border: 1px solid var(--_border);
  color: var(--_fg-muted);
}

.plain {
  margin: 0;
  color: var(--_fg-muted);
  white-space: pre-wrap;
}

.api-facts {
  display: grid;
  gap: var(--_space-2);
  margin: var(--_space-2) 0 0;
}

.api-facts > div {
  display: grid;
  grid-template-columns: 9rem minmax(0, 1fr);
  gap: var(--_space-3);
}

.api-facts dt {
  color: var(--_fg-muted);
  font-weight: 600;
}

.api-facts dd {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 14px;
  margin: 0;
}

.server,
.auth {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.server code,
.auth code {
  font-size: var(--_font-size-small);
}

.server.current code {
  color: var(--_accent-fg);
}

.server-note {
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
}

.auth .icon {
  width: 14px;
  height: 14px;
  color: var(--_warning);
}

@container (max-width: 560px) {
  .api-facts > div {
    grid-template-columns: minmax(0, 1fr);
    gap: 2px;
  }
}

/* ---------- Tag buttons ---------- */

.tag-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: var(--_space-4) 0 0;
}

.tag-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 30px;
  padding: 0 12px;
  border: 1px solid var(--_border);
  border-radius: var(--_radius-full);
  background: var(--_surface);
  color: var(--_fg);
  font: 500 var(--_font-size-ui) / 1 var(--_font-ui);
  cursor: pointer;
}

.tag-chip:hover {
  border-color: var(--_border-strong);
}

.tag-chip[aria-pressed='true'] {
  border-color: color-mix(in srgb, var(--_accent) 50%, var(--_border));
  background: var(--_accent-soft);
  color: var(--_accent-fg);
  font-weight: 600;
}

.chip-count {
  color: var(--_fg-muted);
  font: 500 11px/1 var(--_font-mono);
}

/* ---------- Groups and endpoints ---------- */

.api-tag {
  padding-top: var(--_space-5);
}

.tag-name {
  margin: 0 0 var(--_space-2);
  font: 700 1.125rem/1.3 var(--_font-ui);
  text-transform: none;
}

.tag-description {
  margin-bottom: var(--_space-3);
}

.op {
  --_tone: var(--_fg-muted);
  margin-top: var(--_space-2);
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--_tone) 30%, var(--_border));
  border-radius: var(--_radius);
  background: color-mix(in srgb, var(--_tone) 4%, var(--_surface));
}

.op.method-get,
.op.method-head,
.op.method-options {
  --_tone: var(--_info);
}

.op.method-post {
  --_tone: var(--_success);
}

.op.method-put,
.op.method-patch {
  --_tone: var(--_warning);
}

.op.method-delete {
  --_tone: var(--_danger);
}

.op-head {
  display: flex;
  align-items: center;
  gap: var(--_space-3);
  width: 100%;
  min-height: 46px;
  padding: 8px var(--_space-3);
  border: 0;
  background: none;
  color: var(--_fg);
  font: inherit;
  text-align: left;
  cursor: pointer;
}

.op-head:hover {
  background: color-mix(in srgb, var(--_tone) 7%, transparent);
}

.op-head:focus-visible {
  outline: 2px solid var(--_accent);
  outline-offset: -2px;
}

.op-method {
  flex: none;
  min-width: 64px;
  padding: 3px 8px;
  border-radius: var(--_radius-sm);
  background: color-mix(in srgb, var(--_tone) 16%, transparent);
  color: color-mix(in srgb, var(--_tone) 62%, var(--_fg));
  font: 700 12px/1.4 var(--_font-mono);
  text-align: center;
}

.op-path {
  flex: none;
  max-width: 45%;
  overflow: hidden;
  font: 600 var(--_font-size) / 1.4 var(--_font-mono);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.path-param {
  color: var(--_accent-fg);
}

.op-summary {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  color: var(--_fg-muted);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.op.deprecated .op-path {
  text-decoration: line-through;
}

.op-flag,
.flag {
  padding: 1px 6px;
  border-radius: var(--_radius-full);
  background: color-mix(in srgb, var(--_warning) 16%, transparent);
  color: color-mix(in srgb, var(--_warning) 62%, var(--_fg));
  font: 600 11px/1.5 var(--_font-ui);
}

.op-lock .icon,
.op-chevron .icon {
  width: 16px;
  height: 16px;
  color: var(--_fg-muted);
}

.op-chevron .icon {
  transition: transform var(--_duration) var(--_easing);
}

.op-head[aria-expanded='true'] .op-chevron .icon {
  transform: rotate(180deg);
}

@container (max-width: 620px) {
  .op-head {
    flex-wrap: wrap;
  }

  .op-path {
    max-width: none;
    flex: 1 1 auto;
  }

  .op-summary {
    flex-basis: 100%;
    white-space: normal;
  }
}

/* ---------- Details ---------- */

.op-details {
  display: grid;
  gap: var(--_space-4);
  padding: var(--_space-4);
  border-top: 1px solid color-mix(in srgb, var(--_tone) 25%, var(--_border));
  background: var(--_surface);
}

.op-section h4 {
  margin: 0 0 var(--_space-2);
  color: var(--_fg-muted);
  font: 700 12px/1.3 var(--_font-ui);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.params {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--_font-size-ui);
}

.params th,
.params td {
  padding: 7px var(--_space-2);
  border-bottom: 1px solid var(--_border);
  text-align: left;
  vertical-align: top;
}

.params thead th {
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  font-weight: 600;
}

.params tbody th {
  font-weight: 500;
  white-space: nowrap;
}

.params tr.deprecated th code {
  text-decoration: line-through;
}

.required {
  margin-left: 6px;
  color: var(--_danger);
  font: 600 11px/1 var(--_font-ui);
}

.type {
  color: var(--_syntax-type);
  font-size: var(--_font-size-small);
}

.type.recursive {
  color: var(--_fg-muted);
}

.media {
  display: grid;
  gap: var(--_space-2);
  margin-top: var(--_space-2);
}

.media-type code {
  padding: 2px 6px;
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
  font-size: var(--_font-size-small);
}

.schema-name {
  font: 600 var(--_font-size-ui) / 1.4 var(--_font-mono);
}

/* ---------- Schema trees ---------- */

.props {
  margin: 0;
  padding: 0 0 0 var(--_space-3);
  border-left: 1px solid var(--_border);
  list-style: none;
}

.prop {
  padding: 4px 0;
}

.prop-row {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 8px;
}

.prop-name {
  font-weight: 600;
}

.prop details > summary {
  cursor: pointer;
  list-style-position: outside;
}

.prop details > summary::marker {
  color: var(--_fg-muted);
}

.prop-description,
.constraints {
  margin: 2px 0 0;
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
}

.constraints {
  font-family: var(--_font-mono);
}

.variants {
  display: grid;
  gap: var(--_space-2);
  margin-top: var(--_space-2);
  padding-left: var(--_space-3);
  border-left: 2px dashed var(--_border);
}

/* ---------- Responses ---------- */

.responses {
  display: grid;
  gap: 6px;
}

.response {
  border: 1px solid var(--_border);
  border-radius: var(--_radius-sm);
}

.response > summary {
  display: flex;
  align-items: center;
  gap: var(--_space-3);
  padding: 8px var(--_space-3);
  cursor: pointer;
}

.response[open] > summary {
  border-bottom: 1px solid var(--_border);
}

.response > .media,
.response > .none {
  padding: 0 var(--_space-3) var(--_space-3);
}

.status-code {
  --_tone: var(--_fg-muted);
  min-width: 48px;
  padding: 2px 8px;
  border-radius: var(--_radius-sm);
  background: color-mix(in srgb, var(--_tone) 16%, transparent);
  color: color-mix(in srgb, var(--_tone) 62%, var(--_fg));
  font: 700 12px/1.4 var(--_font-mono);
  text-align: center;
}

.status-code.status-2xx {
  --_tone: var(--_success);
}

.status-code.status-3xx {
  --_tone: var(--_info);
}

.status-code.status-4xx {
  --_tone: var(--_warning);
}

.status-code.status-5xx {
  --_tone: var(--_danger);
}

.response-description {
  color: var(--_fg-muted);
}

.none {
  margin: var(--_space-2) 0 0;
  color: var(--_fg-muted);
  font-style: italic;
}

/* ---------- Edit mode ---------- */

.api-edit > .editor-body {
  max-height: min(40vh, 360px);
  border-bottom: 1px solid var(--_border);
}

/* Markdown descriptions read as text, without the frame of a standalone element. */
vt-markdown.prose::part(container),
vt-markdown.tag-description::part(container) {
  border: 0;
  background: transparent;
}

vt-markdown.prose::part(body),
vt-markdown.tag-description::part(body) {
  padding: 0;
}
`;var ne=["get","put","post","delete","options","head","patch","trace"];var k=class extends Error{};function v(n){return!!n&&typeof n=="object"&&!Array.isArray(n)}function f(n){return typeof n=="string"?n:""}function ae(n,e){if(!e.startsWith("#"))return;let t=n;for(let r of e.slice(1).split("/").slice(1)){let s=decodeURIComponent(r).replace(/~1/g,"/").replace(/~0/g,"~");if(!t||typeof t!="object"||!Object.prototype.hasOwnProperty.call(t,s))return;t=t[s]}return t}function b(n,e){let t=e;for(let r=0;r<20&&v(t)&&typeof t.$ref=="string";r+=1)t=ae(n,t.$ref);return v(t)&&typeof t.$ref!="string"?t:null}function M(n){return v(n)&&typeof n.$ref=="string"?decodeURIComponent(n.$ref.split("/").pop()??""):""}function K(n,e){return v(e)?Object.entries(e).slice(0,20).map(([t,r])=>{let s=b(n,r)??{},o=v(s.examples)?Object.values(s.examples):[],c=o.length?b(n,o[0])?.value:void 0;return{type:t,schema:s.schema??null,example:s.example!==void 0?s.example:c}}):[]}function W(n){if(!v(n))throw new k("The document is not an object.");let e=f(n.swagger).startsWith("2"),t=f(n.openapi)||f(n.swagger);if(!t)throw new k('Missing "openapi" (or "swagger") version field.');if(!e&&!/^3\./.test(t))throw new k(`Unsupported OpenAPI version ${t}.`);let r=v(n.info)?n.info:{},s=[];if(e){let i=f(n.host);i&&(s=[{url:`${Array.isArray(n.schemes)&&n.schemes.includes("https")?"https":n.schemes?.[0]??"https"}://${i}${f(n.basePath)}`,description:""}])}else Array.isArray(n.servers)&&(s=n.servers.filter(v).slice(0,20).map(i=>({url:ie(i),description:f(i.description)})));let o=[],c=!1,p=v(n.paths)?n.paths:{};for(let[i,u]of Object.entries(p)){let d=b(n,u);if(!d)continue;let g=Array.isArray(d.parameters)?d.parameters:[];for(let _ of ne){let S=d[_];if(v(S)){if(o.length>=2e3){c=!0;break}o.push(oe(n,i,_,S,g,e))}}}let l=Array.isArray(n.tags)?n.tags.filter(v).map(i=>({name:f(i.name),description:f(i.description)})):[],m=new Set(o.flatMap(i=>i.tags)),h=[...l.filter(i=>m.has(i.name)),...[...m].filter(i=>!l.some(u=>u.name===i)).map(i=>({name:i,description:""}))],x=e?n.securityDefinitions:n.components?.securitySchemes,y=v(x)?Object.entries(x).map(([i,u])=>{let d=b(n,u)??{},g=f(d.type),_=g==="http"?`HTTP ${f(d.scheme)}${d.bearerFormat?` (${f(d.bearerFormat)})`:""}`:g==="apiKey"?`API key in ${f(d.in)} "${f(d.name)}"`:g==="oauth2"?"OAuth 2.0":g==="openIdConnect"?"OpenID Connect":g;return{name:i,type:_,description:f(d.description)}}):[];return{root:n,version:t,title:f(r.title)||"API",apiVersion:f(r.version),description:f(r.description),servers:s,tags:h,operations:o,securitySchemes:y,truncated:c}}function ie(n){let e=v(n.variables)?n.variables:{};return f(n.url).replace(/\{([^}]+)\}/g,(t,r)=>{let s=e[r];return v(s)&&s.default!==void 0?String(s.default):t})}function oe(n,e,t,r,s,o){let c=new Map,p=null,l=[];for(let y of[...s,...Array.isArray(r.parameters)?r.parameters:[]]){let i=b(n,y);if(!i)continue;if(o&&i.in==="body"){p=i;continue}if(o&&i.in==="formData"){l.push(i);continue}let u=i.schema??(o?{type:i.type,format:i.format,enum:i.enum,items:i.items,default:i.default}:null);c.set(`${i.in}:${i.name}`,{name:f(i.name),in:f(i.in),required:i.in==="path"||!!i.required,deprecated:!!i.deprecated,description:f(i.description),schema:u,example:i.example??(v(i.examples)?b(n,Object.values(i.examples)[0])?.value:void 0)})}let m=null;if(!o&&r.requestBody){let y=b(n,r.requestBody)??{};m={description:f(y.description),required:!!y.required,content:K(n,y.content)}}else if(p){let y=Array.isArray(r.consumes)?r.consumes:Array.isArray(n.consumes)?n.consumes:["application/json"];m={description:f(p.description),required:!!p.required,content:y.slice(0,5).map(i=>({type:String(i),schema:p?.schema??null,example:void 0}))}}else if(l.length){let y=Object.fromEntries(l.map(i=>[f(i.name),{type:i.type,format:i.format,description:i.description}]));m={description:"",required:l.some(i=>i.required),content:[{type:"application/x-www-form-urlencoded",schema:{type:"object",properties:y,required:l.filter(i=>i.required).map(i=>i.name)},example:void 0}]}}let h=[];if(v(r.responses)){let y=Array.isArray(r.produces)?r.produces:Array.isArray(n.produces)?n.produces:["application/json"];for(let[i,u]of Object.entries(r.responses).slice(0,40)){let d=b(n,u)??{},g=o?d.schema?y.slice(0,3).map(_=>({type:String(_),schema:d.schema,example:d.examples?.[_]})):[]:K(n,d.content);h.push({status:i,description:f(d.description),content:g})}}let x=Array.isArray(r.security)?r.security:Array.isArray(n.security)?n.security:[];return{key:`${t} ${e}`,method:t.toUpperCase(),path:e,operationId:f(r.operationId),summary:f(r.summary),description:f(r.description),tags:Array.isArray(r.tags)&&r.tags.length?r.tags.map(String):["default"],deprecated:!!r.deprecated,parameters:[...c.values()],requestBody:m,responses:h,security:[...new Set(x.filter(v).flatMap(y=>Object.keys(y)))]}}function q(n,e){if(!Array.isArray(e.allOf))return e;let t={...e,allOf:void 0,properties:{...e.properties??{}},required:[...e.required??[]]};for(let r of e.allOf.slice(0,20)){let s=b(n,r);if(!s)continue;let o=q(n,s);Object.assign(t.properties,o.properties??{}),t.required.push(...o.required??[]),!t.type&&o.type&&(t.type=o.type),!t.description&&o.description&&(t.description=o.description)}return t}function A(n,e){let t=M(e),r=b(n,e);if(!r)return t||"any";if(t)return t;if(Array.isArray(r.enum)&&r.enum.length<=6&&r.enum.length)return r.enum.map(p=>JSON.stringify(p)).join(" | ");for(let p of["oneOf","anyOf"])if(Array.isArray(r[p]))return`${p==="oneOf"?"one of":"any of"}: ${r[p].slice(0,6).map(l=>A(n,l)).join(", ")}`;let s=Array.isArray(r.type)?r.type.filter(p=>p!=="null"):[r.type],o=r.nullable===!0||Array.isArray(r.type)&&r.type.includes("null"),c=s.filter(Boolean).join(" | ");return s.includes("array")||!c&&r.items?c=`array of ${A(n,r.items)}`:c||(c=r.properties||r.allOf?"object":"any"),r.format&&(c+=` (${r.format})`),o?`${c} | null`:c}function w(n,e,t=0,r=new Set){let s=b(n,e);if(!s||t>8||r.has(s))return null;if(s.example!==void 0)return s.example;if(Array.isArray(s.examples)&&s.examples.length)return s.examples[0];if(s.default!==void 0)return s.default;if(s.const!==void 0)return s.const;if(Array.isArray(s.enum)&&s.enum.length)return s.enum[0];let o=new Set(r).add(s);if(Array.isArray(s.allOf))return w(n,q(n,s),t,r);for(let p of["oneOf","anyOf"])if(Array.isArray(s[p])&&s[p].length)return w(n,s[p][0],t+1,o);let c=Array.isArray(s.type)?s.type.find(p=>p!=="null"):s.type;if(c==="array"||s.items){let p=w(n,s.items,t+1,o);return p===null?[]:[p]}if(c==="object"||s.properties){let p={};for(let[l,m]of Object.entries(s.properties??{}).slice(0,40))p[l]=w(n,m,t+1,o);return p}switch(c){case"integer":return s.minimum??0;case"number":return s.minimum??0;case"boolean":return!0;case"string":return pe(s);default:return null}}function pe(n){switch(n.format){case"date-time":return"2026-01-31T09:30:00Z";case"date":return"2026-01-31";case"time":return"09:30:00";case"email":return"ada@example.com";case"uuid":return"3fa85f64-5717-4562-b3fc-2c963f66afa6";case"uri":case"url":return"https://example.com";case"hostname":return"example.com";case"ipv4":return"192.0.2.1";case"ipv6":return"2001:db8::1";case"byte":return"U3dhZ2dlcg==";case"password":return"********";default:return"string"}}var E=null;function Z(){if(E)return E;let n=C().vendorUrl||U(),e={ready:!1,parse:null,promise:Promise.resolve()};return e.promise=import(new URL("yaml.js",n||location.href).href).then(t=>{e.parse=t.parseYaml,e.ready=!0},t=>{throw E=null,t}),E=e,e}var ee=class extends G{static type="openapi";static componentAttributes=Object.freeze(["tags","expand","server","examples","markdown"]);static presets={simple:{examples:!0,markdown:!0},full:{header:!0,dot:!0,copy:!0,search:!0,download:!0,fullscreen:!0,examples:!0,markdown:!0}};static styles=[H,D,F];constructor(){super(),this.parsed=null,this.opened=new Set,this.tagChoice=null,this.query="",this.matchCount=0,this.panelId=T("panel"),this.listHost=null,this.editor=null,this.previewTimer=void 0}disconnectedCallback(){clearTimeout(this.previewTimer),this.editor?.destroy(),super.disconnectedCallback()}contentChanged(){this.parsed=null,this.opened.clear()}parse(){let e=this.text??"";if(this.parsed?.text===e&&!this.parsed.pending)return this.parsed;let t=e.trim(),r;try{if(!t)return this.parsed={text:e,model:null,error:null,pending:!1},this.parsed;if(/^[[{]/.test(t))r=JSON.parse(t);else{let s=Z();if(!s.ready||!s.parse)return s.promise.then(()=>this.requestRender(),o=>{this.parsed={text:e,model:null,error:new k(this.t("openapiYamlFailed",{message:String(o?.message??o)})),pending:!1},this.requestRender()}),this.parsed={text:e,model:null,error:null,pending:!0},this.parsed;r=s.parse(t)}this.parsed={text:e,model:W(r),error:null,pending:!1}}catch(s){this.parsed={text:e,model:null,error:s instanceof Error?s:new k(String(s)),pending:!1}}return this.parsed}get spec(){let e=this.parse().model;return e?structuredClone(e.root):null}get shownTags(){if(this.tagChoice!==null)return this.tagChoice?new Set([this.tagChoice]):null;let e=this.getAttribute("tags");return e?.trim()?new Set(e.split(/[\s,]+/)):null}visible(e){let t=this.shownTags;if(t&&!e.tags.some(s=>t.has(s)))return!1;if(!this.query)return!0;let r=this.query.toLowerCase();return[e.method,e.path,e.summary,e.operationId,e.description,...e.tags].some(s=>s.toLowerCase().includes(r))}renderContent(e){let t=this.t,{model:r,error:s,pending:o}=this.parse(),c=a("div",{class:"panel",attrs:{id:this.panelId}}),p=[],l=a("div",{class:"body api-body",part:"body"});if(o?l.append(Y(t)):s?l.append(P(t("openapiInvalid",{message:s.message}))):r?(l.append(this.intro(r)),r.truncated&&l.append(P(t("openapiTruncated"))),r.tags.length>1&&l.append(this.tagBar(r)),this.listHost=a("div",{class:"api-groups"}),l.append(this.listHost),this.renderGroups()):l.append(a("div",{class:"empty",part:"empty",text:t("empty")})),this.editing){let i=this.createEditor();c.classList.add("api-edit"),c.append(a("div",{class:"body editor-body",part:"body source"},i.element),l),p=this.historyButtons(i)}else c.append(l);let m={run:i=>(this.query=i.slice(0,J).trim(),this.renderGroups(),{total:this.matchCount,capped:this.matchCount>=V}),go:i=>{let u=this.listHost?.querySelectorAll(".op")??[];u[i]?.scrollIntoView({block:"nearest"}),(u[i]?.querySelector(".op-head")??null)?.focus({preventScroll:!0})},clear:()=>{this.query="",this.renderGroups()}},h=/^\s*[[{]/.test(this.text??""),x=[this.searchButton(m),...p,r&&!this.editing?z({icon:"expand-all",label:t("expandAll"),key:"expand-all",onClick:()=>this.openAll(!0)}):null,r&&!this.editing?z({icon:"collapse-all",label:t("collapseAll"),key:"collapse-all",onClick:()=>this.openAll(!1)}):null,this.editToggleButton(),this.fullscreenButton(),this.feature("download")?this.downloadButton(()=>this.text??"",this.downloadName(h?"openapi.json":"openapi.yaml"),h?"application/json":"application/yaml"):null,this.feature("copy")?this.copyButton(()=>this.text??"",t("copy")):null],y=r?r.apiVersion?`v${r.apiVersion}`:`OpenAPI ${r.version}`:"";e.append(...this.chrome({badge:y,actions:x}),c),this.editor?.align()}get heading(){return super.heading||this.parse().model?.title||""}intro(e){let t=this.t,r=a("div",{class:"api-intro",part:"intro"}),s=a("div",{class:"api-title"},a("h2",{text:e.title}));e.apiVersion&&s.append(a("span",{class:"api-version",text:e.apiVersion})),s.append(a("span",{class:"api-spec",text:`${e.version.startsWith("2")?"Swagger":"OpenAPI"} ${e.version}`})),r.append(s),e.description&&r.append(this.prose(e.description));let o=a("dl",{class:"api-facts"});if(e.servers.length){let c=Math.min(e.servers.length-1,I(this.getAttribute("server"),{min:0,max:50,fallback:0}));o.append(a("div",{},a("dt",{text:t("openapiServers")}),a("dd",{},...e.servers.map((p,l)=>a("span",{class:`server${l===c?" current":""}`},a("code",{text:p.url}),p.description?a("span",{class:"server-note",text:p.description}):null)))))}return e.securitySchemes.length&&o.append(a("div",{},a("dt",{text:t("openapiAuth")}),a("dd",{},...e.securitySchemes.map(c=>a("span",{class:"auth",attrs:{title:c.description||null}},j("lock"),a("code",{text:c.name}),a("span",{class:"server-note",text:c.type})))))),o.append(a("div",{},a("dt",{text:t("openapiEndpoints")}),a("dd",{text:R(e.operations.length,this.locale)}))),r.append(o),r}tagBar(e){let t=a("div",{class:"tag-bar",attrs:{role:"group","aria-label":this.t("openapiTags")}}),r=this.tagChoice??"",s=(o,c,p)=>a("button",{class:"tag-chip",attrs:{type:"button","aria-pressed":String(r===o),"data-focus-key":`tag-${o}`},on:{click:()=>{this.tagChoice=o,this.render()}}},c,a("span",{class:"chip-count",text:R(p,this.locale)}));t.append(s("",this.t("openapiAllTags"),e.operations.length));for(let o of e.tags)t.append(s(o.name,o.name,e.operations.filter(c=>c.tags.includes(o.name)).length));return t}renderGroups(){let e=this.listHost,t=this.parse().model;if(!e||!t)return;this.matchCount=0;let r=t.tags.length?t.tags:[{name:"default",description:""}],s=[],o=new Set;for(let c of r){let p=t.operations.filter(m=>m.tags.includes(c.name)&&this.visible(m));if(!p.length)continue;let l=a("section",{class:"api-tag",part:"tag",attrs:{"aria-label":c.name}},a("h3",{class:"tag-name",text:c.name}));c.description&&l.append(this.prose(c.description,"tag-description"));for(let m of p)o.has(m.key)||(o.add(m.key),this.matchCount+=1),l.append(this.operation(m,t));s.push(l)}e.replaceChildren(...s.length?s:[a("div",{class:"empty",part:"empty",text:this.t("openapiNoMatch")})])}openAll(e){let t=this.parse().model;if(t){if(e)for(let r of t.operations)this.opened.add(r.key);else this.opened.clear();this.renderGroups()}}operation(e,t){let r=this.opened.has(e.key)||this.feature("expand"),s=T("op"),o=a("div",{class:`op method-${e.method.toLowerCase()}${e.deprecated?" deprecated":""}`,part:"operation",attrs:{"data-key":e.key}}),c=a("button",{class:"op-head",attrs:{type:"button","aria-expanded":String(r),"aria-controls":s},on:{click:()=>{let p=c.getAttribute("aria-expanded")!=="true";p?this.opened.add(e.key):this.opened.delete(e.key),c.setAttribute("aria-expanded",String(p));let l=o.querySelector(":scope > .op-details");p&&!l?o.append(this.details(e,t,s)):l?.toggleAttribute("hidden",!p),p&&N(this,B.SELECT,{method:e.method,path:e.path,operationId:e.operationId})}}},a("span",{class:"op-method",part:"method",text:e.method}),this.pathNode(e.path),a("span",{class:"op-summary",text:e.summary||e.operationId}),e.deprecated?a("span",{class:"op-flag",text:this.t("openapiDeprecated")}):null,e.security.length?a("span",{class:"op-lock",attrs:{title:e.security.join(", ")}},j("lock")):null,a("span",{class:"op-chevron",attrs:{"aria-hidden":"true"}},j("chevron-down")));return o.append(c),r&&o.append(this.details(e,t,s)),o}pathNode(e){let t=a("code",{class:"op-path",part:"path"}),r=e;for(;r;){let s=r.indexOf("{"),o=s>=0?r.indexOf("}",s):-1;if(s<0||o<0){t.append(r);break}s>0&&t.append(r.slice(0,s)),t.append(a("span",{class:"path-param",text:r.slice(s,o+1)})),r=r.slice(o+1)}return t}details(e,t,r){let s=this.t,o=t.root,c=a("div",{class:"op-details",attrs:{id:r}});if(e.description&&c.append(this.prose(e.description)),e.parameters.length){let p=a("table",{class:"params",attrs:{"aria-label":s("openapiParameters")}},a("thead",{},a("tr",{},a("th",{attrs:{scope:"col"},text:s("openapiName")}),a("th",{attrs:{scope:"col"},text:s("openapiIn")}),a("th",{attrs:{scope:"col"},text:s("openapiType")}),a("th",{attrs:{scope:"col"},text:s("openapiDescription")}))),a("tbody",{},...e.parameters.map(l=>a("tr",{class:l.deprecated?"deprecated":""},a("th",{attrs:{scope:"row"}},a("code",{text:l.name}),l.required?a("span",{class:"required",text:s("openapiRequired")}):null),a("td",{text:l.in}),a("td",{},a("code",{class:"type",text:l.schema?A(o,l.schema):"string"})),a("td",{text:l.description})))));c.append(this.section(s("openapiParameters"),p))}if(e.requestBody){let p=a("div",{class:"media-list"});e.requestBody.description&&p.append(this.prose(e.requestBody.description));for(let l of e.requestBody.content)p.append(this.media(l,o));c.append(this.section(`${s("openapiRequestBody")}${e.requestBody.required?` (${s("openapiRequired")})`:""}`,p))}if(e.responses.length){let p=a("div",{class:"responses"});for(let l of e.responses){let m=/^\d/.test(l.status)?`${l.status[0]}xx`:"default",h=a("details",{class:`response status-${m}`});h.append(a("summary",{},a("span",{class:`status-code status-${m}`,text:l.status}),a("span",{class:"response-description",text:ce(l.description)})));for(let x of l.content)h.append(this.media(x,o));l.content.length||h.append(a("p",{class:"none",text:s("httpNoBody")})),p.append(h)}c.append(this.section(s("openapiResponses"),p))}if(this.feature("examples")&&customElements.get("vt-http")){let p=document.createElement("vt-http");p.setAttribute("variant","full"),p.setAttribute("label",s("openapiExample")),p.setAttribute("layout","columns"),this.getAttribute("theme")&&p.setAttribute("theme",this.getAttribute("theme")),p.exchange=this.exampleExchange(e,t),c.append(this.section(s("openapiExample"),p))}return c}section(e,t){return a("div",{class:"op-section"},a("h4",{text:e}),t)}media(e,t){let r=a("div",{class:"media"},a("div",{class:"media-type"},a("code",{text:e.type})));if(e.schema){let o=M(e.schema);o&&r.append(a("div",{class:"schema-name",text:o})),r.append(this.schema(t,e.schema,0,new Set))}let s=e.example!==void 0?e.example:e.schema?w(t,e.schema):void 0;if(s!=null&&/json/i.test(e.type)){let o=document.createElement("vt-code");o.setAttribute("language","json"),o.setAttribute("copy",""),o.setAttribute("label",this.t("openapiExampleValue")),o.setAttribute("header",""),o.setAttribute("badge","false"),o.content=JSON.stringify(s,null,2),r.append(a("div",{class:"media-example"},o))}return r}schema(e,t,r,s){let o=b(e,t),c=a("div",{class:"schema",part:"schema"});if(!o)return c.append(a("span",{class:"type",text:A(e,t)})),c;if(s.has(o)||r>12)return c.append(a("span",{class:"type recursive",text:`${A(e,t)} \u21BA`})),c;let p=new Set(s).add(o),l=q(e,o),m=l.type==="array"||l.items?b(e,l.items):null,h=m?q(e,m):l,x=h.properties&&typeof h.properties=="object"?Object.entries(h.properties):[];if(!x.length){c.append(a("code",{class:"type",text:A(e,t)}));let u=te(l);u&&c.append(a("span",{class:"constraints",text:u}));for(let d of["oneOf","anyOf"])if(Array.isArray(l[d])){let g=a("div",{class:"variants"});for(let _ of l[d].slice(0,8))g.append(this.schema(e,_,r+1,p));c.append(g)}return c}m&&r===0&&c.append(a("code",{class:"type",text:A(e,t)}));let y=new Set(Array.isArray(h.required)?h.required:[]),i=a("ul",{class:"props"});for(let[u,d]of x.slice(0,200)){let g=b(e,d)??{},_=q(e,g),S=_.items?b(e,_.items):null,re=!!(_.properties||S?.properties||S?.allOf),L=a("div",{class:"prop-row"},a("code",{class:"prop-name",text:u}),a("code",{class:"type",text:A(e,d)}),y.has(u)?a("span",{class:"required",text:this.t("openapiRequired")}):null,g.readOnly?a("span",{class:"flag",text:"read-only"}):null,g.writeOnly?a("span",{class:"flag",text:"write-only"}):null,g.deprecated?a("span",{class:"flag",text:this.t("openapiDeprecated")}):null),$=a("li",{class:"prop"});if(re&&r<12){let O=a("details",{attrs:{open:r<1?"":null}},a("summary",{},L));g.description&&O.append(a("p",{class:"prop-description",text:g.description})),O.append(this.schema(e,d,r+1,p)),$.append(O)}else{$.append(L),g.description&&$.append(a("p",{class:"prop-description",text:g.description}));let O=te(g);O&&$.append(a("p",{class:"constraints",text:O}))}i.append($)}return c.append(i),c}exampleExchange(e,t){let r=t.root,s=Math.min(Math.max(0,t.servers.length-1),I(this.getAttribute("server"),{min:0,max:50,fallback:0})),o=(t.servers[s]?.url||"https://api.example.com").replace(/\/$/,""),c=e.path,p=[],l={};for(let i of e.parameters){let u=i.example??(i.schema?w(r,i.schema):"value"),d=typeof u=="string"?u:JSON.stringify(u);i.in==="path"?c=c.split(`{${i.name}}`).join(encodeURIComponent(d)):i.in==="query"&&i.required?p.push(`${encodeURIComponent(i.name)}=${encodeURIComponent(d)}`):i.in==="header"&&i.required&&(l[i.name]=d)}for(let i of e.security){let u=t.securitySchemes.find(d=>d.name===i);if(u){if(/bearer/i.test(u.type)||/OAuth|OpenID/.test(u.type))l.Authorization="Bearer YOUR_TOKEN";else if(/basic/i.test(u.type))l.Authorization="Basic YOUR_CREDENTIALS";else{let d=/API key in header "([^"]+)"/.exec(u.type);d&&(l[d[1]]="YOUR_API_KEY")}break}}let m,h=e.requestBody?.content.find(i=>/json/i.test(i.type))??e.requestBody?.content[0];if(h){l["Content-Type"]=h.type;let i=h.example!==void 0?h.example:h.schema?w(r,h.schema):void 0;i!==void 0&&(m=typeof i=="string"?i:JSON.stringify(i,null,2))}let x=e.responses.find(i=>/^2/.test(i.status))??e.responses[0],y=null;if(x){let i=/^\d{3}$/.test(x.status)?Number(x.status):200,u=x.content.find(g=>/json/i.test(g.type))??x.content[0],d=u?u.example!==void 0?u.example:u.schema?w(r,u.schema):void 0:void 0;y={status:i,headers:u?{"Content-Type":u.type}:{},body:d===void 0?"":typeof d=="string"?d:JSON.stringify(d,null,2)}}return{request:{method:e.method,url:`${o}${c}${p.length?`?${p.join("&")}`:""}`,headers:l,body:m},response:y}}prose(e,t="prose"){if(this.feature("markdown")&&customElements.get("vt-markdown")){let r=document.createElement("vt-markdown");return r.className=t,r.setAttribute("images","block"),r.content=e,r}return a("p",{class:`${t} plain`,text:e})}createEditor(){this.editor?.destroy();let e=/^\s*[[{]/.test(this.text??"");return this.editor=new X({text:this.text??"",language:e?"json":"yaml",lineNumbers:!0,wrap:!1,highlightLimit:C().highlightLimit,label:this.heading||this.t("editor"),placeholder:this.getAttribute("placeholder")??void 0,onInput:t=>this.edited(t),onChange:t=>N(this,B.CHANGE,{value:t}),history:this.editHistory??void 0}),this.editor}contentEdited(){clearTimeout(this.previewTimer),this.previewTimer=setTimeout(()=>{this.parsed=null,this.render()},400)}};function te(n){let e=[],t=(r,s)=>{s!=null&&e.push(`${r} ${typeof s=="string"?s:JSON.stringify(s)}`)};return t("min",n.minimum),t("max",n.maximum),t("min length",n.minLength),t("max length",n.maxLength),t("min items",n.minItems),t("max items",n.maxItems),t("pattern",n.pattern),Array.isArray(n.enum)&&n.enum.length>6&&t("one of",n.enum.slice(0,12).join(", ")),n.default!==void 0&&t("default",JSON.stringify(n.default)),n.example!==void 0&&t("example",JSON.stringify(n.example)),e.join(", ")}function ce(n){let e=n.split(`
`)[0].trim();return e.length>160?`${e.slice(0,159)}\u2026`:e}export{ee as a};
