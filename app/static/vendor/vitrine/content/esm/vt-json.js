/*! Vitrine | MIT | Source e7db1ebd587b27f41988a0da9785310eaa6f2f08 | See app/static/vendor/vitrine/LICENSE and THIRD_PARTY_NOTICES.md */
import{A as S,B as V,C as A,D as b,F as N,G as q,I as P,J as j,L as U,V as $,W as M,X as W,Y as H,a as L,b as R,c as J,d as T,e as I,h as x,i as dt,j as c,k as z,q as w,r as v,s as pt,t as k,u as ft,v as mt,w as gt,x as yt,z as xt}from"./chunks/chunk-KRU63GZ6.js";var F=`/*
 * JSON tree. Colors reuse the syntax roles so code and JSON look the same.
 * Spec: docs/DESIGN_SYSTEM.md \xA72.4 and \xA76 (tree-toggle).
 */
.tree-body {
  padding: var(--_space-2) 0;
}

.tree,
.group {
  margin: 0;
  padding: 0;
  list-style: none;
}

.tree {
  min-width: 100%;
  color: var(--_code-fg);
  font-family: var(--_font-mono);
  font-size: var(--_font-size);
  line-height: var(--_line-height);
}

.item {
  outline: none;
}

.row {
  display: flex;
  align-items: baseline;
  gap: 0;
  min-height: calc(var(--_font-size) * var(--_line-height));
  padding: 1px var(--_space-4) 1px calc(var(--_space-3) + var(--_level, 0) * 1.25em);
  cursor: default;
}

.row > * {
  flex: none;
  white-space: pre;
}

.row > .key {
  flex: 0 0 auto;
  max-width: min(50%, 48ch);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.row:hover {
  background: color-mix(in srgb, var(--_accent-soft) 60%, transparent);
}

.item[aria-selected='true'] > .row {
  background: var(--_accent-soft);
}

.item:focus-visible > .row {
  outline: 2px solid var(--_accent);
  outline-offset: -2px;
  border-radius: 2px;
}

.toggle {
  display: inline-grid;
  flex: none;
  place-items: center;
  align-self: center;
  width: 16px;
  height: 16px;
  margin-right: 4px;
  color: var(--_fg-muted);
  cursor: pointer;
}

.toggle .icon {
  width: 14px;
  height: 14px;
  transition: transform var(--_duration) var(--_easing);
}

.item[aria-expanded='true'] > .row > .toggle .icon {
  transform: rotate(90deg);
}

.toggle.leaf {
  cursor: default;
}

.vt:not([data-syntax-theme]) .key {
  color: var(--_syntax-attr);
}

.vt:not([data-syntax-theme]) .index {
  color: var(--_syntax-meta);
}

.vt:not([data-syntax-theme]) .punct {
  color: var(--_syntax-meta);
}

.row > .value.string,
.row > .value-wrap {
  flex: 0 1 auto;
  min-width: 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.vt:not([data-syntax-theme]) .value.string {
  color: var(--_syntax-string);
}

.vt:not([data-syntax-theme]) .value.number {
  color: var(--_syntax-number);
}

.vt:not([data-syntax-theme]) .value.literal {
  color: var(--_syntax-keyword);
}

/* Dates and times of formats that have them (TOML). */
.vt:not([data-syntax-theme]) .value.date {
  color: var(--_syntax-type);
}

.count {
  margin-left: var(--_space-2);
  color: var(--_fg-muted);
  font-family: var(--_font-ui);
  font-size: var(--_font-size-small);
}

.type {
  margin-left: var(--_space-2);
  padding: 0 5px;
  border: 1px solid var(--_border);
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
  color: var(--_fg-muted);
  font-family: var(--_font-ui);
  font-size: var(--_font-size-small);
  line-height: 1.5;
}

.inline-more,
.more-label {
  font-family: var(--_font-ui);
  font-size: var(--_font-size-small);
}

.inline-more {
  margin-left: var(--_space-2);
  padding: 0 6px;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-sm);
  background: var(--_surface);
  color: var(--_accent-fg);
  cursor: pointer;
}

.more-item > .row {
  cursor: pointer;
}

.more-label {
  color: var(--_accent-fg);
  text-decoration: underline;
  text-underline-offset: 3px;
}

/* ---------- Path bar ---------- */

.pathbar {
  display: flex;
  align-items: center;
  gap: var(--_space-2);
  min-height: 36px;
  padding: 0 var(--_space-2) 0 var(--_space-3);
  border-top: 1px solid var(--_border);
  background: var(--_surface);
}

.path-text {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  color: var(--_fg-muted);
  font-family: var(--_font-mono);
  font-size: var(--_font-size-small);
  white-space: nowrap;
  text-overflow: ellipsis;
}

/* With a syntax theme, badges and counts take the colors of the code area. */
.vt[data-syntax-theme] .count {
  color: color-mix(in srgb, var(--_code-fg) 80%, var(--_code-bg-solid));
}

.vt[data-syntax-theme] .type {
  border-color: color-mix(in srgb, var(--_code-fg) 30%, transparent);
  background: transparent;
  color: color-mix(in srgb, var(--_code-fg) 80%, var(--_code-bg-solid));
}
`;var m=class extends Error{constructor(t,e,s=!1){super(t),this.offset=e,this.tooDeep=s}},K=/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y,G={'"':'"',"\\":"\\","/":"/",b:"\b",f:"\f",n:`
`,r:"\r",t:"	"};function Y(l,{maxDepth:t}){try{let{value:e,count:s}=new O(l,t).parse();return{ok:!0,value:e,count:s}}catch(e){if(!(e instanceof m))throw e;let{line:s,column:r}=et(l,e.offset);return{ok:!1,error:{message:e.message,offset:e.offset,line:s,column:r,tooDeep:e.tooDeep}}}}function et(l,t){let e=1,s=0,r=Math.min(t,l.length);for(let i=l.indexOf(`
`);i!==-1&&i<r;i=l.indexOf(`
`,i+1))e+=1,s=i+1;return{line:e,column:r-s+1}}var O=class{constructor(t,e){this.text=t,this.maxDepth=e,this.i=t.charCodeAt(0)===65279?1:0,this.count=0}parse(){let t=this.text,e=[],s=null,r="",i="value";for(;;){this.skipWhitespace();let o=t[this.i],n=e[e.length-1];if(i==="value"){if(o===void 0)throw new m("Unexpected end of input",this.i);let h=n??null,f=h?.type==="object"?r:h?h.items.length:null;if(o==="{"||o==="["){if(e.length>=this.maxDepth)throw new m(`Nesting deeper than ${this.maxDepth} levels`,this.i,!0);let u=o==="{"?{type:"object",entries:[],id:this.count++,parent:h,key:f}:{type:"array",items:[],id:this.count++,parent:h,key:f};this.i+=1,h?X(h,u,r):s=u,e.push(u),this.skipWhitespace(),t[this.i]===(o==="{"?"}":"]")?(this.i+=1,e.pop(),i="after"):i=o==="{"?"key":"value";continue}let p=this.readPrimitive(h,f);h?X(h,p,r):s=p,i="after";continue}if(i==="key"){if(o!=='"')throw new m(o===void 0?"Unexpected end of input":"Expected a property name in double quotes",this.i);if(r=this.readString(),this.skipWhitespace(),t[this.i]!==":")throw new m('Expected ":" after the property name',this.i);this.i+=1,i="value";continue}if(!n){if(o!==void 0)throw new m("Unexpected content after the JSON value",this.i);return{value:s,count:this.count}}let a=n.type==="object"?"}":"]";if(o===","){if(this.i+=1,this.skipWhitespace(),t[this.i]===a)throw new m("Trailing comma",this.i-1);i=n.type==="object"?"key":"value"}else if(o===a)this.i+=1,e.pop();else throw new m(o===void 0?"Unexpected end of input":`Expected "," or "${a}"`,this.i)}}skipWhitespace(){let t=this.text,e=t.charCodeAt(this.i);for(;e===32||e===10||e===13||e===9;)this.i+=1,e=t.charCodeAt(this.i)}readPrimitive(t,e){let s=this.text,r=s[this.i],i=this.count++;if(r==='"')return{type:"string",value:this.readString(),id:i,parent:t,key:e};if(r==="-"||r>="0"&&r<="9"){K.lastIndex=this.i;let n=K.exec(s);if(!n)throw new m("Invalid number",this.i);return this.i+=n[0].length,{type:"number",raw:n[0],id:i,parent:t,key:e}}for(let[n,a]of[["true",{type:"boolean",value:!0}],["false",{type:"boolean",value:!1}],["null",{type:"null"}]])if(s.startsWith(n,this.i))return this.i+=n.length,{...a,id:i,parent:t,key:e};let o=/[\x20-\x7e]/.test(r)?`"${r}"`:`U+${r.codePointAt(0)?.toString(16).toUpperCase().padStart(4,"0")}`;throw new m(`Unexpected character ${o}`,this.i)}readString(){let t=this.text,e=this.i;this.i+=1;let s="",r=this.i;for(;;){let i=t.charCodeAt(this.i);if(Number.isNaN(i))throw new m("Unterminated string",e);if(i===34)break;if(i<32)throw new m("Control character in string (escape it)",this.i);if(i===92){s+=t.slice(r,this.i);let o=t[this.i+1];if(o==="u"){let n=t.slice(this.i+2,this.i+6);if(!/^[0-9a-fA-F]{4}$/.test(n))throw new m("Invalid \\u escape",this.i);s+=String.fromCharCode(parseInt(n,16)),this.i+=6}else if(o!==void 0&&Object.prototype.hasOwnProperty.call(G,o))s+=G[o],this.i+=2;else throw new m("Invalid escape sequence",this.i);r=this.i;continue}this.i+=1}return s+=t.slice(r,this.i),this.i+=1,s}};function X(l,t,e){l.type==="object"?l.entries.push({key:e,value:t}):l.items.push(t)}function B(l,{indent:t,sortKeys:e}){let s=[],r=" ".repeat(t),i=t?`
`:"",o=t?": ":":",n=[[l,0]];for(;n.length;){let[a,h]=n.pop();if(typeof a=="string"){s.push(a);continue}let f=i+r.repeat(h+1),p=i+r.repeat(h);if(a.type==="object"){let u=e?D(a):a.entries;if(!u.length){s.push("{}");continue}let d=[["{",h]];u.forEach((g,Z)=>{d.push([`${Z?",":""}${f}${JSON.stringify(g.key)}${o}`,h],[g.value,h+1])}),d.push([`${p}}`,h]);for(let g=d.length-1;g>=0;g-=1)n.push(d[g])}else if(a.type==="array"){if(!a.items.length){s.push("[]");continue}let u=[["[",h]];a.items.forEach((d,g)=>u.push([`${g?",":""}${f}`,h],[d,h+1])),u.push([`${p}]`,h]);for(let d=u.length-1;d>=0;d-=1)n.push(u[d])}else s.push(st(a))}return s.join("")}function D(l){return[...l.entries].sort((t,e)=>t.key<e.key?-1:t.key>e.key?1:0)}function st(l){switch(l.type){case"string":return JSON.stringify(l.value);case"number":return l.raw;case"boolean":return String(l.value);case"null":return"null";default:return""}}var it=/^[A-Za-z_$][\w$]*$/;function _(l){let t=[],e=l;for(;e&&e.parent;){let s=e.key;typeof s=="number"?t.push(`[${s}]`):it.test(String(s))?t.push(`.${s}`):t.push(`[${JSON.stringify(s)}]`),e=e.parent}return`$${t.reverse().join("")}`}var y=100,rt=5e3,nt=2e4,Q=500,ot=120,E=class{constructor(t,e){this.root=t,this.options=e,this.expanded=new Map,this.defaultDepth=e.depth,this.shown=new Map,this.fullStrings=new Set,this.selected=t,this.matches=[],this.current=-1,this.query="",this.info=new WeakMap,this.items=new Map,this.rendered=0,this.element=c("ul",{class:"tree",part:"tree",attrs:{role:"tree","aria-label":e.label}}),this.element.addEventListener("keydown",s=>this.onKeyDown(s)),this.element.addEventListener("click",s=>this.onClick(s))}children(t){return t.type==="object"?(this.options.sortKeys?D(t):t.entries).map(s=>({node:s.value,label:s.key})):t.type==="array"?t.items.map((e,s)=>({node:e,label:s})):[]}isExpanded(t,e){return t.type!=="object"&&t.type!=="array"?!1:this.expanded.get(t.id)??e<=this.defaultDepth}render(){this.items.clear(),this.rendered=0;let t=this.renderItem({node:this.root,label:null},1,1,1);this.element.replaceChildren(t),(this.items.get(this.selected.id)??t).setAttribute("tabindex","0")}renderItem(t,e,s,r){let{node:i,label:o}=t;this.rendered+=1;let n=i.type==="object"||i.type==="array",a=this.isExpanded(i,e),h=c("li",{class:`item ${i.type}`,part:"tree-item",attrs:{role:"treeitem","aria-level":e,"aria-setsize":r,"aria-posinset":s,"aria-expanded":n?String(a):null,"aria-selected":String(i===this.selected),tabindex:"-1"}});return this.info.set(h,{node:i,label:o,level:e,pos:s,size:r}),this.items.set(i.id,h),h.append(this.renderRow(i,o,e,n,a)),n&&a&&h.append(this.renderGroup(i,e)),h}renderRow(t,e,s,r,i){let{locale:o}=this.options,n=c("div",{class:"row",part:"row"});n.style.setProperty("--_level",String(s-1));let a=c("span",{class:r?"toggle":"toggle leaf",part:"tree-toggle",attrs:{"aria-hidden":"true"}});if(r&&a.append(S("chevron-right")),n.append(a),e!==null){let h=typeof e=="number",f=h?String(e):ht(lt(e),ot);n.append(c("span",{class:h?"index hljs-number":"key hljs-attr",part:h?"index":"key",text:f}),c("span",{class:"punct hljs-punctuation",text:": "}))}if(r){let h=t,f=h.type==="object"?h.entries.length:h.items.length,[p,u]=t.type==="object"?["{","}"]:["[","]"];n.append(c("span",{class:"punct hljs-punctuation",text:i||f===0?`${p}${f?"":u}`:`${p}\u2026${u}`}));let d=t.type==="object"?f===1?"key":"keys":f===1?"item":"items";n.append(c("span",{class:"count",part:"count",text:this.options.t(d,{count:k(f,o)})}))}else n.append(this.renderValue(t));return this.options.showTypes&&n.append(c("span",{class:"type",part:"type-badge",text:t.kind??t.type})),this.decorate(n,t),n}renderValue(t){if(t.type==="string"){let i=this.fullStrings.has(t.id)||t.value.length<=Q,o=i?JSON.stringify(t.value):`${JSON.stringify(t.value.slice(0,Q)).slice(0,-1)}\u2026"`,n=c("span",{class:"value string hljs-string",part:"value",text:o});if(!i){let a=c("button",{class:"inline-more",text:this.options.t("showFullString",{count:k(t.value.length,this.options.locale)}),attrs:{type:"button",tabindex:"-1","data-action":"full-string"}});return c("span",{class:"value-wrap"},n,a)}return n}let e=t.type==="number"?t.raw:t.type==="boolean"?String(t.value):"null",r=(t.kind?/^(date|time)/.test(t.kind):!1)?"date":t.type==="number"?"number":"literal";return c("span",{class:`value ${r} ${r==="number"?"hljs-number":r==="date"?"hljs-symbol":"hljs-literal"}`,part:"value",text:e})}renderGroup(t,e){let s=c("ul",{class:"group",attrs:{role:"group"}}),r=this.children(t),i=Math.min(r.length,this.shown.get(t.id)??y);for(let n=0;n<i&&!(this.rendered>=nt);n+=1)s.append(this.renderItem(r[n],e+1,n+1,r.length));let o=r.length-Math.min(i,s.children.length);if(o>0){let n=Math.min(y,o),a=c("li",{class:"item more-item",part:"more-item",attrs:{role:"treeitem","aria-level":e+1,tabindex:"-1","data-action":"more"}},c("div",{class:"row",part:"row"},c("span",{class:"toggle leaf"}),c("span",{class:"more-label",text:this.options.t("showMoreItems",{count:k(n,this.options.locale)})})));a.firstElementChild.style.setProperty("--_level",String(e)),this.info.set(a,{node:t,label:null,level:e+1,pos:0,size:0}),s.append(a)}return s}decorate(t,e){if(!this.query)return;let s=this.matches[this.current];for(let r of this.matches){if(r.node!==e)continue;let i=t.querySelector(r.field==="key"?".key":".value");if(!i)continue;let o=new b(i);if(o.run(this.query),s===r)for(let n of o.matches)for(let a of n)a.classList.add("current")}}toggle(t,e){let s=this.info.get(t);if(!s||s.node.type!=="object"&&s.node.type!=="array")return;let r=e??!this.isExpanded(s.node,s.level);this.expanded.set(s.node.id,r),this.replaceItem(t,s)}replaceItem(t,e){this.rendered=0;let s=this.renderItem({node:e.node,label:e.label},e.level,e.pos,e.size);return t.replaceWith(s),this.focusItem(s),s}showMore(t){let e=this.info.get(t);if(!e)return;let s=e.node;this.shown.set(s.id,(this.shown.get(s.id)??y)+y);let r=t.closest('ul[role="group"]')?.parentElement??null,i=r?this.info.get(r):null;if(!r||!i)return;let o=(this.shown.get(s.id)??y)-y,a=this.replaceItem(r,i).querySelector(`:scope > ul > li:nth-child(${o+1})`);a instanceof HTMLElement&&this.focusItem(a)}expandAll(){this.expanded.clear(),this.defaultDepth=0;let t=rt,e=[this.root],s=!0;for(;e.length;){let r=[];for(let i of e){if(i.type!=="object"&&i.type!=="array")continue;let o=this.children(i);if(t<=0){s=!1;break}this.expanded.set(i.id,!0);let n=o.slice(0,this.shown.get(i.id)??y);t-=n.length;for(let a of n)r.push(a.node)}if(!s)break;e=r}return this.render(),s}collapseAll(){this.expanded.clear(),this.defaultDepth=1,this.shown.clear(),this.render()}search(t){this.query=t,this.matches=[],this.current=-1;let e=!1;if(t){let s=t.toLowerCase(),r=[{node:this.root,label:null}];for(;r.length;){let{node:i,label:o}=r.pop();if(typeof o=="string"&&o.toLowerCase().includes(s)&&this.matches.push({node:i,field:"key"}),i.type!=="object"&&i.type!=="array"&&at(i).toLowerCase().includes(s)&&this.matches.push({node:i,field:"value"}),this.matches.length>=A){e=!0,this.matches.length=A;break}let n=this.children(i);for(let a=n.length-1;a>=0;a-=1)r.push(n[a])}}return this.render(),{total:this.matches.length,capped:e}}goToMatch(t){let e=this.matches[t];if(!e)return;this.current=t,this.reveal(e.node),this.selected=e.node,this.render(),this.items.get(e.node.id)?.querySelector("mark.current")?.scrollIntoView({block:"nearest",inline:"nearest"}),this.options.onSelect(e.node)}reveal(t){let e=t;for(;e.parent;){let s=e.parent;this.expanded.set(s.id,!0);let r=this.children(s).findIndex(o=>o.node===e),i=Math.ceil((r+1)/y)*y;i>(this.shown.get(s.id)??y)&&this.shown.set(s.id,i),e=s}}visibleItems(){return Array.from(this.element.querySelectorAll('[role="treeitem"]'))}focusItem(t){for(let s of this.element.querySelectorAll('[tabindex="0"]'))s.setAttribute("tabindex","-1");t.setAttribute("tabindex","0"),t.focus({preventScroll:!0}),t.scrollIntoView({block:"nearest",inline:"nearest"});let e=this.info.get(t);e&&t.dataset.action!=="more"&&(this.element.querySelector('[aria-selected="true"]')?.setAttribute("aria-selected","false"),t.setAttribute("aria-selected","true"),this.selected=e.node,this.options.onSelect(e.node))}onKeyDown(t){let e=t.target.closest?.('[role="treeitem"]');if(!e)return;let s=this.visibleItems(),r=s.indexOf(e),i=this.info.get(e),o=i&&e.dataset.action!=="more"&&(i.node.type==="object"||i.node.type==="array"),n=e.getAttribute("aria-expanded")==="true",a=!0;switch(t.key){case"ArrowDown":s[r+1]&&this.focusItem(s[r+1]);break;case"ArrowUp":s[r-1]&&this.focusItem(s[r-1]);break;case"Home":s[0]&&this.focusItem(s[0]);break;case"End":s.length&&this.focusItem(s[s.length-1]);break;case"ArrowRight":o&&!n?this.toggle(e,!0):o&&s[r+1]&&this.focusItem(s[r+1]);break;case"ArrowLeft":{if(o&&n)this.toggle(e,!1);else{let h=e.parentElement?.closest('[role="treeitem"]');h instanceof HTMLElement&&this.focusItem(h)}break}case"Enter":case" ":this.activate(e);break;default:a=!1}a&&(t.preventDefault(),t.stopPropagation())}activate(t){t.dataset.action==="more"?this.showMore(t):t.querySelector(':scope > .row [data-action="full-string"]')?this.showFullString(t):this.toggle(t)}showFullString(t){let e=this.info.get(t);e&&(this.fullStrings.add(e.node.id),this.replaceItem(t,e))}onClick(t){let e=t.target,s=e.closest?.('[role="treeitem"]');s&&(e.closest('[data-action="full-string"]')?this.showFullString(s):s.dataset.action==="more"?this.showMore(s):e.closest(".toggle:not(.leaf)")?this.toggle(s):this.focusItem(s))}};function at(l){return l.type==="string"?l.value:l.type==="number"?l.raw:l.type==="boolean"?String(l.value):"null"}function lt(l){return l===""||/[\u0000-\u001f\u007f]/.test(l)?JSON.stringify(l):l}function ht(l,t){return l.length>t?`${l.slice(0,t)}\u2026`:l}var ct=["tree","raw"],C=class extends U{static type="json";static componentAttributes=Object.freeze(["view","tabs","depth","indent","sort-keys","show-types","expand-controls","path","line-numbers","on-invalid"]);static presets={simple:{},full:{header:!0,dot:!0,copy:!0,search:!0,download:!0,tabs:!0,"show-types":!0,"expand-controls":!0,path:!0,"line-numbers":!0,fullscreen:!0}};static styles=[L,R,F];static upgradeProperties=["content","data"];static source=Object.freeze({language:"json",file:"data.json",mime:"application/json",badge:"JSON"});get source(){return this.constructor.source}constructor(){super(),this.viewState=null,this.panelId=z("panel"),this.parsed=null,this.treeCache=null,this.rawCache=null,this.invalidReported=!1,this.pathText=null,this.editor=null,this.status=null,this.errorLine=0,this.validateTimer=void 0}get data(){return this.parse()?.ok?JSON.parse(this.text??"null"):void 0}set data(t){let e;try{e=JSON.stringify(t,null,2)}catch(s){this._content="",this.setError(new Error(this.t("unserializable"),{cause:s}));return}this.content=e===void 0?"":e}attributeChangedCallback(t,e,s){t==="view"&&(this.viewState=null),super.attributeChangedCallback(t,e,s)}contentChanged(){this.parsed=null,this.treeCache=null,this.rawCache=null,this.invalidReported=!1}parse(){if(this.text===null)return null;let t=x().maxDepth;return(!this.parsed||this.parsed.text!==this.text||this.parsed.maxDepth!==t)&&(this.parsed={text:this.text,maxDepth:t,result:Y(this.text,{maxDepth:t})}),this.parsed.result}get view(){let t=this.editing||this.variant!=="full"?"raw":"tree";return this.viewState??I(this.getAttribute("view"),ct,t)}get format(){return{indent:T(this.getAttribute("indent"),{min:0,max:8,fallback:2}),sortKeys:this.feature("sort-keys")}}prettyText(t){let e=JSON.stringify(this.format);return(!this.rawCache||this.rawCache.key!==e)&&(this.rawCache={key:e,text:B(t,this.format)}),this.rawCache.text}renderContent(t){let e=this.parse();if(!e)return;if(this.editing&&this.view==="raw"){this.renderEditor(t,e);return}if(!e.ok){this.renderInvalid(t,e.error);return}let s=e.value,r=this.view,i,o,n=null;if(r==="tree"){n=this.treeFor(s),n.render(),o=[c("div",{class:"body tree-body",part:"body"},n.element)],this.feature("path")&&o.push(this.pathBar(n));let u=n;i={run:d=>u.search(d),go:d=>u.goToMatch(d),clear:()=>u.search("")}}else{let p=this.rawText(s),u=$(p,{language:this.source.language,lineNumbers:this.feature("line-numbers"),startLine:1,highlightRanges:[],diff:!1,highlightLimit:x().highlightLimit}),d=new b(u.code);i={run:g=>d.run(g),go:g=>M(d.go(g)),clear:()=>d.clear()},o=[c("div",{class:"body",part:"body",attrs:{tabindex:"0",role:"region","aria-label":this.heading||this.source.badge}},u.element)],u.highlightSkipped&&o.unshift(j(this.t("highlightSkipped")))}let a=[this.searchButton(i),n&&this.feature("expand-controls")?this.expandButtons(n):null,this.editToggleButton(),this.fullscreenButton(),this.feature("download")?this.downloadButton(()=>this.rawText(s),this.downloadName(this.source.file),this.source.mime):null,...this.extraActions(s),this.feature("copy")?this.copyButton(()=>this.rawText(s),this.t("copy")):null].flat(),h=this.viewTabs(r),f=c("div",{class:"panel",attrs:{id:this.panelId,role:h?"tabpanel":null}},...o);t.append(...this.chrome({badge:h?"":this.source.badge,tabs:h,actions:a}),f)}rawText(t){return this.prettyText(t)}extraActions(t){return[]}viewTabs(t){return this.feature("tabs")?q({tabs:[{id:"tree",label:this.t("tree"),icon:"list"},{id:"raw",label:this.t("raw"),icon:"code"}],selected:t,label:this.t("tabs"),panelId:this.panelId,onSelect:e=>this.selectView(e)}):null}renderEditor(t,e){let s=this.t,r=e.ok?null:e.error;this.editor?.destroy();let i=new W({text:this.text??"",language:this.source.language,lineNumbers:this.feature("line-numbers"),wrap:!1,highlightRanges:r?[[r.line,r.line]]:[],highlightLimit:x().highlightLimit,label:this.heading||`${this.source.badge} ${s("editor").toLowerCase()}`,placeholder:this.getAttribute("placeholder")??void 0,onInput:p=>this.edited(p),onChange:p=>v(this,w.CHANGE,{value:p}),history:this.editHistory??void 0});this.editor=i,this.errorLine=r?.line??0,this.status=c("div",{class:"edit-status",part:"status",attrs:{role:"status"}}),this.showStatus(e);let o=null,n={run:p=>(o=new b(i.layer.querySelector("pre.code")),o.run(p)),go:p=>M(o?.go(p)??null),clear:()=>o?.clear()},a=this.viewTabs("raw"),h=[this.searchButton(n),...this.historyButtons(i),this.editToggleButton(),this.fullscreenButton(),this.feature("download")?this.downloadButton(()=>this.text??"",this.downloadName(this.source.file),this.source.mime):null,this.feature("copy")?this.copyButton(()=>this.text??"",s("copy")):null],f=c("div",{class:"panel",attrs:{id:this.panelId,role:a?"tabpanel":null}},c("div",{class:"body editor-body",part:"body"},i.element),J(this.getAttribute("status"))===!1?null:this.status);t.append(...this.chrome({badge:a?"":this.source.badge,tabs:a,actions:h}),f),i.align()}validMessage(){return this.t("validJson")}syntaxMessage(t){return t.tooDeep?this.t("tooDeep",{limit:x().maxDepth}):this.t("invalidJson",{line:t.line,column:t.column,message:t.message})}rawNotice(t){return this.t("invalidJsonRaw",{line:t.line,column:t.column})}showStatus(t){if(!this.status)return;let e=t.ok?this.validMessage():this.syntaxMessage(t.error);this.status.className=`edit-status ${t.ok?"ok":"bad"}`,this.status.replaceChildren(S(t.ok?"check":"alert"),c("span",{text:e}))}contentEdited(){this.treeCache=null,this.rawCache=null,this.invalidReported=!1,clearTimeout(this.validateTimer),this.validateTimer=setTimeout(()=>{let t=this.parse();if(!t)return;this.showStatus(t);let e=t.ok?0:t.error.line;e!==this.errorLine&&(this.errorLine=e,this.editor?.setHighlightRanges(e?[[e,e]]:[])),this.searchOpen&&this.searchQuery&&this.searchBar?.run()},150)}treeFor(t){let e={t:this.t,locale:this.locale,depth:T(this.getAttribute("depth"),{min:0,max:1e3,fallback:2}),sortKeys:this.feature("sort-keys"),showTypes:this.feature("show-types"),label:this.heading||"JSON",onSelect:r=>this.updatePath(r)},s=JSON.stringify({...e,t:void 0,onSelect:void 0});return!this.treeCache||this.treeCache.key!==s?this.treeCache={key:s,tree:new E(t,e)}:this.treeCache.tree.options=e,this.treeCache.tree}expandButtons(t){return[N({icon:"expand-all",label:this.t("expandAll"),key:"expand-all",onClick:()=>{t.expandAll()||this.announce(this.t("truncated"))}}),N({icon:"collapse-all",label:this.t("collapseAll"),key:"collapse-all",onClick:()=>t.collapseAll()})]}pathBar(t){this.pathText=c("code",{class:"path-text",text:_(t.selected)});let e=this.copyTextButton(()=>_(t.selected),this.t("copyPath"),"copy-path"),s=this.copyTextButton(()=>ut(t.selected,this.format),this.t("copyValue"),"copy-value");return c("div",{class:"pathbar",part:"path"},this.pathText,c("div",{class:"toolbar"},e,s))}updatePath(t){this.pathText&&(this.pathText.textContent=_(t))}renderInvalid(t,e){let s=this.t,r=I(this.getAttribute("on-invalid"),["error","raw"],"error"),i=this.syntaxMessage(e),o=$(this.text??"",{language:"plaintext",lineNumbers:!0,startLine:1,highlightRanges:[[e.line,e.line]],diff:!1,highlightLimit:0}),n=c("div",{class:"body",part:"body",attrs:{tabindex:"0",role:"region","aria-label":this.heading||this.source.badge}},o.element);t.append(...this.chrome({badge:this.source.badge,actions:[this.editToggleButton(),this.fullscreenButton(),this.feature("copy")?this.copyButton(()=>this.text??""):null]}),r==="raw"?j(this.rawNotice(e)):P(s("errorTitle"),i),n),requestAnimationFrame(()=>{let a=V(n,e.line);a instanceof HTMLElement&&(n.scrollTop=Math.max(0,a.offsetTop-n.clientHeight/2))}),this._readyPending=!1,this.invalidReported||(this.invalidReported=!0,v(this,w.ERROR,{message:i,cause:e}))}selectView(t){t!==this.view&&(this.viewState=t,this.render(),this.root.querySelector(`[data-tab="${t}"]`)?.focus(),v(this,w.TAB_CHANGE,{tab:t}))}};function ut(l,t){return l.type==="string"?l.value:B(l,t)}H(new URL("../",import.meta.url));customElements.get("vt-json")||customElements.define("vt-json",C);export{ft as BUILT_IN_THEMES,w as EVENTS,C as VtJson,dt as configure,x as getConfig,yt as getTheme,xt as listSyntaxThemes,gt as listThemes,pt as registerLocale,mt as registerTheme};
