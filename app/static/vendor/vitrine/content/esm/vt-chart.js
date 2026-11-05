/*! Vitrine | MIT | Source e7db1ebd587b27f41988a0da9785310eaa6f2f08 | See app/static/vendor/vitrine/LICENSE and THIRD_PARTY_NOTICES.md */
import{G as R,H as V,J as A,L as B,X as U,Y as P,a as z,b as L,d as j,e as k,h as w,i as lt,j as d,k as F,q as _,r as S,s as ct,t as T,u as ht,v as dt,w as ut,x as pt,y as D,z as ft}from"./chunks/chunk-KRU63GZ6.js";var q=`/*
 * Charts: a legend of toggle buttons above the plot (drawn by Apache ECharts in the theme
 * colors), and the data table view.
 */
.vt {
  --_chart-1: var(--vt-chart-1, var(--_accent));
  --_chart-2: var(--vt-chart-2, var(--_info));
  --_chart-3: var(--vt-chart-3, var(--_warning));
  --_chart-4: var(--vt-chart-4, var(--_syntax-keyword));
  --_chart-5: var(--vt-chart-5, var(--_danger));
  --_chart-6: var(--vt-chart-6, var(--_syntax-string));
  --_chart-7: var(--vt-chart-7, var(--_syntax-number));
  --_chart-8: var(--vt-chart-8, var(--_fg-muted));
}

.chart-body {
  padding: var(--_space-3) var(--_space-3) var(--_space-2);
  background: var(--_surface);
}

.plot {
  position: relative;
  width: 100%;
  min-height: 120px;
  border-radius: var(--_radius-sm);
}

.plot:focus-visible {
  outline: 2px solid var(--_accent);
  outline-offset: 2px;
}

.plot > .loading {
  height: 100%;
}

/* ---------- Legend ---------- */

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 0 var(--_space-1) var(--_space-3);
}

.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 28px;
  padding: 0 10px;
  border: 1px solid var(--_border);
  border-radius: var(--_radius-full);
  background: var(--_surface);
  color: var(--_fg);
  font: 500 var(--_font-size-small) / 1 var(--_font-ui);
  cursor: pointer;
  transition:
    opacity var(--_duration-fast) var(--_easing),
    border-color var(--_duration-fast) var(--_easing);
}

.legend-item:hover {
  border-color: var(--_border-strong);
}

.legend-item[aria-pressed='false'] {
  opacity: 0.45;
}

.legend-item[aria-pressed='false'] .swatch {
  background: transparent;
  box-shadow: inset 0 0 0 2px var(--_c);
}

.swatch {
  width: 10px;
  height: 10px;
  border-radius: 3px;
  background: var(--_c);
}

.s-0 {
  --_c: var(--_chart-1);
}
.s-1 {
  --_c: var(--_chart-2);
}
.s-2 {
  --_c: var(--_chart-3);
}
.s-3 {
  --_c: var(--_chart-4);
}
.s-4 {
  --_c: var(--_chart-5);
}
.s-5 {
  --_c: var(--_chart-6);
}
.s-6 {
  --_c: var(--_chart-7);
}
.s-7 {
  --_c: var(--_chart-8);
}

/* ---------- Table view ---------- */

.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--_font-size-ui);
  font-variant-numeric: tabular-nums;
}

.data-table th,
.data-table td {
  padding: 7px var(--_space-3);
  border-bottom: 1px solid var(--_border);
  text-align: right;
  white-space: nowrap;
}

.data-table th:first-child {
  text-align: left;
}

.data-table thead th {
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  font-weight: 600;
}

.data-table tbody th {
  font-weight: 500;
}

/* ---------- Edit mode ---------- */

.chart-edit > .editor-body {
  max-height: min(36vh, 300px);
  border-bottom: 1px solid var(--_border);
}
`;var C=null;function W(){if(C)return C;let a=w().vendorUrl||D(),t={ready:!1,echarts:null,promise:Promise.resolve()};return t.promise=import(new URL("echarts.js",a||location.href).href).then(e=>(t.echarts=e.echarts,t.ready=!0,e.echarts),e=>{throw C=null,e}),C=t,t}var et=Object.freeze([",",";","	","|"]);function rt(a){let t=a.slice(0,2e4).split(/\r?\n/).slice(0,20).filter(i=>i.trim()),e=",",s=0;for(let i of et){let r=t.map(c=>st(c,i));if(!r.length||r[0]===0)continue;let n=r.filter(c=>c===r[0]).length/r.length*10+Math.min(r[0],10);n>s&&(e=i,s=n)}return e}function st(a,t){let e=0,s=!1;for(let i of a)i==='"'?s=!s:i===t&&!s&&(e+=1);return e}function H(a,t={}){let e=a.charCodeAt(0)===65279?a.slice(1):a,s=t.delimiter??rt(e),i=[],r=[],o="",n=!1,c=0,l=1,f=0,p=!1,h=0,v=e.length,x=()=>{r.length<1e3?r.push(o):p=!0,o=""},u=()=>{x(),f=Math.max(f,r.length),i.push(r),r=[]};for(;h<v;){let g=e[h];if(n){if(g==='"'){if(e[h+1]==='"'){o+='"',h+=2;continue}n=!1,h+=1;continue}let $=e.indexOf('"',h),I=$===-1?v:$,O=e.slice(h,I);l+=it(O),o+=O,h=I;continue}g==='"'&&o===""?(n=!0,c=l,h+=1):g===s?(x(),h+=1):g===`
`||g==="\r"?(u(),h+=g==="\r"&&e[h+1]===`
`?2:1,l+=1):(o+=g,h+=1)}return(o!==""||r.length)&&u(),{rows:i,delimiter:s,columns:f,truncatedColumns:p,error:n?{message:"Unclosed quoted field",line:c}:null}}function it(a){let t=0;for(let e=a.indexOf(`
`);e!==-1;e=a.indexOf(`
`,e+1))t+=1;return t}var y=5e3,J=12,m=class extends Error{};function N(a){if(typeof a=="number")return Number.isFinite(a)?a:null;if(typeof a!="string")return null;let t=a.trim().replace(/[\s,_](?=\d{3}\b)/g,"").replace(/%$/,"");if(!t||!/^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i.test(t))return null;let e=Number(t);return Number.isFinite(e)?e:null}function at(a){return a?.trim()?a.split(/[\s,]+/).map(t=>t.trim()).filter(Boolean):null}function X(a,t,e){let s=t.length>y,i=s?t.slice(0,y):t,r=e.x?a.indexOf(e.x):-1;if(e.x&&r<0)throw new m(`No column named "${e.x}".`);let o=at(e.y??null),n;if(o)n=o.map(c=>{let l=a.indexOf(c);if(l<0)throw new m(`No column named "${c}".`);return l});else{let c=a.map((l,f)=>{let p=i.map(h=>h[f]).filter(h=>h!==""&&h!=null);return p.length>0&&p.filter(h=>N(h)!==null).length>=p.length*.8});r<0&&(r=c.findIndex(l=>!l)),r<0&&(r=0),n=a.map((l,f)=>f).filter(l=>l!==r&&c[l])}if(r<0&&(r=a.findIndex((c,l)=>!n.includes(l)),r<0&&(r=-1)),!n.length)throw new m("No numeric column to plot.");return{labels:i.map((c,l)=>String(c[r]??l+1)),series:n.slice(0,J).map(c=>({name:a[c]||`Series ${c+1}`,values:i.map(l=>N(l[c]))})),truncated:s}}function G(a){return Array.isArray(a)?a.slice(0,y).map(t=>N(t)):[]}function K(a,t={}){let e=a.trim();if(!e)return{labels:[],series:[],truncated:!1};if(/^[[{]/.test(e)){let i;try{i=JSON.parse(e)}catch(r){throw new m(r instanceof Error?r.message:"Invalid JSON.")}if(Array.isArray(i)&&i.every(r=>typeof r!="object"||r===null)){let r=G(i);return{labels:r.map((o,n)=>String(n+1)),series:[{name:"Value",values:r}],truncated:i.length>y}}if(Array.isArray(i)){let r=i.filter(n=>n&&typeof n=="object"&&!Array.isArray(n)),o=[...new Set(r.flatMap(n=>Object.keys(n)))];return X(o,r.map(n=>o.map(c=>n[c])),t)}if(i&&typeof i=="object"){let r=Array.isArray(i.labels)?i.labels.slice(0,y).map(String):[],o=Array.isArray(i.datasets)?i.datasets:Array.isArray(i.series)?i.series:null;if(!o)throw new m('Expected "labels" with "series" or "datasets".');let n=o.slice(0,J).map((l,f)=>({name:String(l?.name??l?.label??`Series ${f+1}`),values:G(Array.isArray(l)?l:l?.data)})),c=Math.max(r.length,...n.map(l=>l.values.length));for(;r.length<c;)r.push(String(r.length+1));return{labels:r,series:n,truncated:c>y}}throw new m("Unsupported JSON shape.")}let{rows:s}=H(e);if(s.length<2)throw new m("Expected a header row and at least one data row.");return X(s[0].map(i=>i.trim()),s.slice(1),t)}function Q(a){let t=i=>/[",\n]/.test(i)?`"${i.replace(/"/g,'""')}"`:i,e=["label",...a.series.map(i=>i.name)].map(t).join(","),s=a.labels.map((i,r)=>[t(i),...a.series.map(o=>o.values[r]===null||o.values[r]===void 0?"":String(o.values[r]))].join(","));return[e,...s].join(`
`)}var nt=["line","area","bar","pie"],ot=["chart","table"],M=8,E=class extends B{static type="chart";static componentAttributes=Object.freeze(["type","stacked","smooth","horizontal","zoom","x","y","height","legend","grid","points","unit","compact","min","max","tabs","view"]);static presets={simple:{grid:!0},full:{header:!0,dot:!0,copy:!0,download:!0,fullscreen:!0,tabs:!0,grid:!0}};static styles=[z,L,q];constructor(){super(),this.parsed=null,this.hiddenSeries=new Set,this.viewState=null,this.panelId=F("panel"),this.plot=null,this.instance=null,this.resize=null,this.active=-1,this.animateIn=!0,this.editor=null,this.previewTimer=void 0}disconnectedCallback(){this.dispose(),clearTimeout(this.previewTimer),this.editor?.destroy(),super.disconnectedCallback()}dispose(){this.resize?.disconnect(),this.resize=null,this.instance?.dispose(),this.instance=null}contentChanged(){this.parsed=null,this.hiddenSeries.clear(),this.animateIn=!0}attributeChangedCallback(t,e,s){(t==="x"||t==="y")&&(this.parsed=null),t==="view"&&(this.viewState=null),super.attributeChangedCallback(t,e,s)}parse(){let t=this.text??"",e=this.getAttribute("x"),s=this.getAttribute("y"),i=`${e}\0${s}\0${t}`;if(this.parsed?.key!==i)try{this.parsed={key:i,data:K(t,{x:e,y:s}),error:null}}catch(r){this.parsed={key:i,data:null,error:r instanceof Error?r:new m(String(r))}}return this.parsed}get data(){let t=this.parse().data;return t?{labels:[...t.labels],series:t.series.map(e=>({name:e.name,values:[...e.values]})),truncated:t.truncated}:{labels:[],series:[],truncated:!1}}get chartType(){return k(this.getAttribute("type"),nt,"line")}get view(){return this.viewState??k(this.getAttribute("view"),ot,"chart")}format(t){if(t==null||Number.isNaN(t))return"\u2013";let e=this.feature("compact"),s=new Intl.NumberFormat(this.locale,{notation:e?"compact":"standard",maximumFractionDigits:e?1:2}).format(t),i=(this.getAttribute("unit")??"").slice(0,12);return i?`${s}${/^[%‰]$/.test(i)?"":"\u202F"}${i}`:s}renderContent(t){let e=this.t,{data:s,error:i}=this.parse(),r=d("div",{class:"panel",attrs:{id:this.panelId}}),o=[];this.dispose(),this.plot=null;let n;if(i?n=d("div",{class:"body chart-body",part:"body"},A(e("chartError",{message:i.message}))):!s||!s.labels.length?n=d("div",{class:"body chart-body",part:"body"},d("div",{class:"empty",part:"empty",text:e("empty")})):this.view==="table"&&!this.editing?n=d("div",{class:"body chart-body",part:"body"},this.table(s)):n=d("div",{class:"body chart-body",part:"body"},...this.chart(s)),this.editing){let p=this.createEditor();r.classList.add("chart-edit"),r.append(d("div",{class:"body editor-body",part:"body source"},p.element),n),o=this.historyButtons(p)}else r.append(n);s?.truncated&&r.prepend(A(e("chartTruncated")));let c=this.feature("tabs")&&!this.editing&&s&&!i?R({tabs:[{id:"chart",label:e("chartView"),icon:"chart"},{id:"table",label:e("table"),icon:"table"}],selected:this.view,label:e("tabs"),panelId:this.panelId,onSelect:p=>{this.viewState=p,this.animateIn=p==="chart",this.render(),S(this,_.TAB_CHANGE,{tab:p})}}):null;c&&r.setAttribute("role","tabpanel");let l=()=>s?Q(s):this.text??"",f=[...o,this.editToggleButton(),this.fullscreenButton(),this.feature("download")?this.downloadButton(l,this.downloadName("chart.csv"),"text/csv"):null,this.feature("copy")?this.copyButton(l,e("copyData")):null];t.append(...this.chrome({badge:c?"":e("chartView"),tabs:c,actions:f}),r),this.editor?.align(),this.plot&&this.draw()}chart(t){let e=this.t,s=j(this.getAttribute("height"),{min:120,max:800,fallback:300}),r=!(this.chartType==="pie")&&Z(this,"legend",t.series.length>1),o=[];if(r){let n=d("div",{class:"legend",part:"legend",attrs:{role:"group","aria-label":e("legend")}});t.series.forEach((c,l)=>{n.append(d("button",{class:`legend-item s-${l%M}`,part:"legend-item",attrs:{type:"button","aria-pressed":String(!this.hiddenSeries.has(l)),"data-focus-key":`series-${l}`,title:e("seriesToggle",{name:c.name})},on:{click:()=>this.toggleSeries(l)}},d("span",{class:"swatch",attrs:{"aria-hidden":"true"}}),c.name))}),o.push(n)}return this.plot=d("div",{class:"plot",part:"plot",attrs:{tabindex:"0",role:"img","aria-roledescription":e("chartView"),"aria-label":this.summary(t)},on:{keydown:n=>this.onKeyDown(n),blur:()=>this.hideTip()}}),this.plot.style.height=`${s}px`,o.push(this.plot),o}toggleSeries(t){let e=this.parse().data;if(!e)return;this.hiddenSeries.has(t)?this.hiddenSeries.delete(t):this.hiddenSeries.size<e.series.length-1&&this.hiddenSeries.add(t),this.root.querySelector(`[data-focus-key="series-${t}"]`)?.setAttribute("aria-pressed",String(!this.hiddenSeries.has(t))),this.instance&&this.instance.setOption(this.option(e),{notMerge:!0})}summary(t){let e=this.t,s=t.series.map(i=>{let r=i.values.filter(o=>o!==null);return e("chartRange",{name:i.name,min:this.format(r.length?Math.min(...r):null),max:this.format(r.length?Math.max(...r):null)})});return`${this.heading?`${this.heading}. `:""}${e("chartSummary",{type:e(`chart_${this.chartType}`),series:T(t.series.length,this.locale),points:T(t.labels.length,this.locale)})} ${s.join("; ")}.`}draw(){let t=this.plot;if(!t)return;let e=W();if(!e.ready){t.replaceChildren(V(this.t)),e.promise.then(()=>{this.plot===t&&this.draw()},r=>{this.plot===t&&t.replaceChildren(A(this.t("chartLoadFailed",{message:String(r?.message??r)})))});return}let s=this.parse().data;if(!s)return;t.replaceChildren();let i=e.echarts;this.instance=i.init(t,null,{renderer:"canvas",locale:this.locale.startsWith("fr")?"FR":"EN"}),this.instance.setOption(this.option(s)),this.animateIn=!1,this.instance.on("click",r=>{this.active=r.dataIndex??-1,this.select()}),this.resize=new ResizeObserver(()=>this.instance?.resize()),this.resize.observe(t)}palette(){let t=d("span",{attrs:{"aria-hidden":"true"}});t.style.display="none",this.frame.append(t);let e=r=>(t.style.color=`var(${r})`,getComputedStyle(t).color),i={series:Array.from({length:M},(r,o)=>e(`--_chart-${o+1}`)),fg:e("--_fg"),muted:e("--_fg-muted"),border:e("--_border"),surface:e("--_surface-raised"),font:getComputedStyle(this.frame).fontFamily,mono:getComputedStyle(t).getPropertyValue("--_font-mono")||"monospace"};return t.remove(),i}option(t){let e=this.chartType,s=this.palette(),i=matchMedia("(prefers-reduced-motion: reduce)").matches,r=t.series.map((u,b)=>!this.hiddenSeries.has(b)),o=t.series.map((u,b)=>({series:u,index:b})).filter(({index:u})=>r[u]),n={renderMode:"richText",confine:!0,backgroundColor:s.surface,borderColor:s.border,borderWidth:1,padding:[8,10],textStyle:{color:s.fg,fontFamily:s.font,fontSize:12},valueFormatter:u=>this.format(u)},c={animation:!i,animationDuration:this.animateIn?900:400,animationEasing:"cubicOut",animationDurationUpdate:450,textStyle:{fontFamily:s.font,color:s.muted},aria:{enabled:!0,label:{description:this.summary(t)}}};if(e==="pie"){let u=o[0]?.series??t.series[0];return{...c,color:s.series,tooltip:{...n,trigger:"item"},series:[{name:u.name,type:"pie",radius:["46%","74%"],center:["50%","52%"],avoidLabelOverlap:!0,itemStyle:{borderColor:s.surface,borderWidth:2,borderRadius:4},label:{color:s.fg,formatter:"{b}"},labelLine:{lineStyle:{color:s.border}},emphasis:{scaleSize:6},data:t.labels.map((b,g)=>({name:b,value:u.values[g]??0}))}]}}let l=e==="bar"&&this.feature("horizontal"),f=this.feature("stacked")&&e!=="line",p=Z(this,"points",t.labels.length<=60),h=this.feature("zoom"),v={type:"category",data:t.labels,boundaryGap:e==="bar",axisLine:{lineStyle:{color:s.border}},axisTick:{show:!1},axisLabel:{color:s.muted,hideOverlap:!0}},x={type:"value",min:Y(this,"min")??void 0,max:Y(this,"max")??void 0,scale:e==="line",splitLine:{show:this.feature("grid"),lineStyle:{color:s.border,type:"dashed"}},axisLabel:{color:s.muted,formatter:u=>this.format(u)}};return{...c,color:o.map(({index:u})=>s.series[u%M]),grid:{left:12,right:20,top:20,bottom:h?52:12,containLabel:!0},tooltip:{...n,trigger:"axis",axisPointer:{type:e==="bar"?"shadow":"line",lineStyle:{color:s.muted,type:"dashed"},shadowStyle:{color:"rgba(127, 127, 127, 0.08)"}}},xAxis:l?x:v,yAxis:l?{...v,inverse:!0}:x,dataZoom:h?[{type:"inside",[l?"yAxisIndex":"xAxisIndex"]:0},{type:"slider",height:18,bottom:10,borderColor:s.border,fillerColor:"rgba(20, 184, 166, 0.12)",handleStyle:{color:s.series[0]},textStyle:{color:s.muted},dataBackground:{lineStyle:{color:s.border},areaStyle:{color:s.border}}}]:[],series:o.map(({series:u})=>({name:u.name,type:e==="bar"?"bar":"line",data:u.values.map(b=>b===null?"-":b),stack:f?"total":void 0,smooth:e!=="bar"&&this.feature("smooth")?.35:!1,showSymbol:p,symbolSize:6,connectNulls:!1,lineStyle:{width:2.2},areaStyle:e==="area"?{opacity:f?.55:.16}:void 0,barMaxWidth:38,itemStyle:e==="bar"?{borderRadius:l?[0,4,4,0]:[4,4,0,0]}:void 0,emphasis:{focus:"series"},universalTransition:!0}))}}onKeyDown(t){let e=this.parse().data,s=e?.labels.length??0;if(!e||!s||!this.instance)return;let i=this.active,r=null;if(t.key==="ArrowRight"||t.key==="ArrowDown")r=Math.min(s-1,i+1);else if(t.key==="ArrowLeft"||t.key==="ArrowUp")r=Math.max(0,i-1);else if(t.key==="Home")r=0;else if(t.key==="End")r=s-1;else if(t.key==="Escape"){this.hideTip();return}else if((t.key==="Enter"||t.key===" ")&&i>=0){t.preventDefault(),this.select();return}r!==null&&(t.preventDefault(),this.active=r,this.instance.dispatchAction({type:"showTip",seriesIndex:0,dataIndex:r}),this.announce(`${e.labels[r]}: ${e.series.filter((o,n)=>!this.hiddenSeries.has(n)).map(o=>`${o.name} ${this.format(o.values[r]??null)}`).join(", ")}`))}hideTip(){this.active=-1,this.instance?.dispatchAction({type:"hideTip"})}select(){let t=this.parse().data;!t||this.active<0||S(this,_.SELECT,{index:this.active,label:t.labels[this.active],values:Object.fromEntries(t.series.map(e=>[e.name,e.values[this.active]??null]))})}table(t){return d("table",{class:"data-table",part:"table",attrs:{"aria-label":this.heading||this.t("chartView")}},d("thead",{},d("tr",{},d("th",{attrs:{scope:"col"},text:this.getAttribute("x")||""}),...t.series.map(e=>d("th",{attrs:{scope:"col"},text:e.name})))),d("tbody",{},...t.labels.map((e,s)=>d("tr",{},d("th",{attrs:{scope:"row"},text:e}),...t.series.map(i=>d("td",{text:this.format(i.values[s]??null)}))))))}createEditor(){return this.editor?.destroy(),this.editor=new U({text:this.text??"",language:/^\s*[[{]/.test(this.text??"")?"json":"plaintext",lineNumbers:!1,wrap:!1,highlightLimit:w().highlightLimit,label:this.heading||this.t("editor"),placeholder:this.getAttribute("placeholder")??void 0,onInput:t=>this.edited(t),onChange:t=>S(this,_.CHANGE,{value:t}),history:this.editHistory??void 0}),this.editor}contentEdited(){clearTimeout(this.previewTimer),this.previewTimer=setTimeout(()=>{this.parsed=null;let t=this.parse().data;t&&this.instance?this.instance.setOption(this.option(t),{notMerge:!0}):this.render()},250)}};function Z(a,t,e){return a.getAttribute(t)===null?e:a.feature(t)}function Y(a,t){let e=a.getAttribute(t);if(e===null||e.trim()==="")return null;let s=Number(e);return Number.isFinite(s)?s:null}P(new URL("../",import.meta.url));customElements.get("vt-chart")||customElements.define("vt-chart",E);export{ht as BUILT_IN_THEMES,_ as EVENTS,E as VtChart,lt as configure,w as getConfig,pt as getTheme,ft as listSyntaxThemes,ut as listThemes,ct as registerLocale,dt as registerTheme};
