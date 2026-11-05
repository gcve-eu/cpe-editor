/*! Vitrine | MIT | Source e7db1ebd587b27f41988a0da9785310eaa6f2f08 | See app/static/vendor/vitrine/LICENSE and THIRD_PARTY_NOTICES.md */
import{A as ye,D as te,E as ve,F as U,G as Se,I as _e,L as $e,N as Re,O as Te,P as Ae,Q as ze,S as Pe,V as Le,W as Ce,X as Ee,Y as Be,a as fe,b as ke,c as be,e as I,f as me,h as D,i as wr,j as m,k as xe,l as we,q as H,r as Q,s as yr,u as vr,v as Sr,w as _r,x as $r,z as Rr}from"./chunks/chunk-KRU63GZ6.js";var Ie=`/*
 * Rendered Markdown. The content inherits the host page font (it is the host's content);
 * only the chrome uses the UI font. Spec: docs/DESIGN_SYSTEM.md \xA73.3.
 */
.vt.md {
  font-family: var(--vt-font-body, inherit);
  font-size: var(--vt-font-size-body, inherit);
}

.vt {
  container-type: inline-size;
}

.panel {
  min-width: 0;
}

.panel.split {
  /* Panes scroll on their own so they can be kept in sync; max-height sets their size. */
  --_split-height: var(--_max-height, min(70vh, 640px));
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
}

.panel.split > .body {
  height: var(--_split-height);
  max-height: none;
}

.panel.split > .body + .body {
  border-left: 1px solid var(--_border);
}

.panel.split:is([data-preview='top'], [data-preview='bottom']) {
  grid-template-columns: minmax(0, 1fr);
}

.panel.split:is([data-preview='top'], [data-preview='bottom']) > .body {
  height: calc(var(--_split-height) / 2);
}

.panel.split:is([data-preview='top'], [data-preview='bottom']) > .body + .body {
  border-top: 1px solid var(--_border);
  border-left: 0;
}

@container (max-width: 640px) {
  .panel.split {
    grid-template-columns: minmax(0, 1fr);
  }

  .panel.split > .body {
    height: calc(var(--_split-height) / 2);
  }

  .panel.split > .body + .body {
    border-top: 1px solid var(--_border);
    border-left: 0;
  }
}

.md-body {
  padding: var(--_space-5);
  background: var(--_surface);
}

/* ---------- Table of contents ---------- */

.toc {
  margin: 0 0 var(--_space-5);
  padding: var(--_space-2) var(--_space-3);
  border: 1px solid var(--_border);
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
}

.toc summary {
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  cursor: pointer;
}

.toc-list {
  margin: var(--_space-2) 0 var(--_space-1);
  padding: 0;
  list-style: none;
}

.toc-list li {
  padding: 2px 0;
}

.toc-list a {
  color: var(--_accent-fg);
  text-decoration: none;
}

.toc-list a:hover {
  text-decoration: underline;
  text-underline-offset: 3px;
}

.toc-level-1 {
  padding-left: var(--_space-4) !important;
}

.toc-level-2 {
  padding-left: var(--_space-6) !important;
}

.toc-level-3 {
  padding-left: 48px !important;
}

/* ---------- Typography ---------- */

.markdown {
  color: var(--_fg);
  line-height: 1.65;
  overflow-wrap: break-word;
}

.markdown > :first-child,
.markdown > [data-vt-line]:first-child + * {
  margin-top: 0;
}

.markdown > :last-child {
  margin-bottom: 0;
}

.markdown :is(h1, h2, h3, h4, h5, h6) {
  position: relative;
  margin: 1.6em 0 0.6em;
  color: var(--_fg);
  font-weight: 650;
  line-height: 1.25;
  scroll-margin-top: var(--_space-4);
}

.markdown h1 {
  font-size: 1.75em;
  letter-spacing: -0.02em;
}

.markdown h2 {
  padding-bottom: 0.3em;
  border-bottom: 1px solid var(--_border);
  font-size: 1.4em;
  letter-spacing: -0.01em;
}

.markdown h3 {
  font-size: 1.2em;
}

.markdown h4 {
  font-size: 1.05em;
}

.markdown :is(h5, h6) {
  color: var(--_fg-muted);
  font-size: 0.95em;
}

.markdown :is(h1, h2, h3, h4, h5, h6):focus {
  outline: none;
}

.anchor {
  display: inline-grid;
  place-items: center;
  width: 1.4em;
  height: 1.4em;
  margin-left: 0.25em;
  border-radius: var(--_radius-sm);
  color: var(--_fg-muted);
  vertical-align: middle;
  opacity: 0;
  transition: opacity var(--_duration-fast) var(--_easing);
}

.anchor .icon {
  width: 0.8em;
  height: 0.8em;
}

:is(h1, h2, h3, h4, h5, h6):hover .anchor,
.anchor:focus-visible {
  opacity: 1;
}

.anchor:hover {
  background: var(--_accent-soft);
  color: var(--_accent-fg);
}

@media (hover: none) {
  .anchor {
    opacity: 0.6;
  }
}

.markdown :is(p, ul, ol, dl, blockquote, .table-wrap, .code-block, details, figure) {
  margin: 0 0 1em;
}

.markdown a {
  color: var(--_accent-fg);
  text-decoration: underline;
  text-underline-offset: 3px;
  text-decoration-thickness: 1px;
}

.markdown a:hover {
  text-decoration-thickness: 2px;
}

.markdown :is(ul, ol) {
  padding-left: 1.6em;
}

.markdown li + li {
  margin-top: 0.25em;
}

.markdown li > :is(ul, ol) {
  margin: 0.25em 0 0;
}

.markdown li:has(> input[type='checkbox']) {
  list-style: none;
}

.markdown li > input[type='checkbox'] {
  margin: 0 0.5em 0 -1.4em;
  vertical-align: -0.1em;
  accent-color: var(--_accent);
}

.markdown blockquote {
  padding: 0 0 0 1em;
  border-left: 3px solid var(--_border-strong);
  color: var(--_fg-muted);
}

.markdown hr {
  height: 0;
  margin: 2em 0;
  border: 0;
  border-top: 1px solid var(--_border);
}

.markdown img {
  max-width: 100%;
  height: auto;
  border-radius: var(--_radius-sm);
}

.vt-blocked-image {
  display: inline-flex;
  align-items: center;
  gap: var(--_space-1);
  padding: 2px 8px;
  border: 1px dashed var(--_border-strong);
  border-radius: var(--_radius-sm);
  color: var(--_fg-muted);
  font-size: 0.875em;
}

.vt-blocked-image:empty::before {
  content: '\\25A1';
}

.markdown :is(code, kbd, samp) {
  font-family: var(--_font-mono);
  font-size: 0.875em;
}

.markdown :not(pre) > code {
  padding: 0.12em 0.35em;
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
}

.markdown kbd {
  padding: 0.1em 0.4em;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-sm);
  background: var(--_surface-raised);
  box-shadow: inset 0 -1px 0 var(--_border-strong);
}

.markdown mark {
  background: var(--_highlight);
  color: inherit;
}

/* ---------- Code blocks ---------- */

.code-block {
  position: relative;
}

.code-block pre {
  margin: 0;
  padding: var(--_space-3) var(--_space-4);
  overflow: auto;
  border: 1px solid var(--_border);
  border-radius: var(--_radius-sm);
  background: var(--_code-bg);
  color: var(--_code-fg);
  font-family: var(--_font-mono);
  font-size: var(--_font-size);
  line-height: var(--_line-height);
  tab-size: var(--_tab-size);
}

.code-block pre code {
  font-size: inherit;
}

.code-block > .btn {
  position: absolute;
  top: var(--_space-1);
  right: var(--_space-1);
  border: 1px solid var(--_border);
  background: var(--_surface);
  opacity: 0;
}

.code-block:hover > .btn,
.code-block > .btn:focus-visible,
.code-block > .btn.done {
  opacity: 1;
}

@media (hover: none) {
  .code-block > .btn {
    opacity: 1;
  }
}

/* ---------- Tables ---------- */

.table-wrap {
  max-width: 100%;
  overflow-x: auto;
  border: 1px solid var(--_border);
  border-radius: var(--_radius-sm);
}

.markdown table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.925em;
  font-variant-numeric: tabular-nums;
}

.markdown :is(th, td) {
  padding: var(--_space-2) var(--_space-3);
  border-bottom: 1px solid var(--_border);
  text-align: start;
  vertical-align: top;
}

.markdown tr:last-child td {
  border-bottom: 0;
}

.markdown th {
  background: var(--_surface-sunken);
  color: var(--_fg-muted);
  font-size: 0.8em;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}

.markdown :is(th, td)[align='center'] {
  text-align: center;
}

.markdown :is(th, td)[align='right'] {
  text-align: end;
}

.markdown details {
  padding: var(--_space-2) var(--_space-3);
  border: 1px solid var(--_border);
  border-radius: var(--_radius-sm);
}

.markdown summary {
  cursor: pointer;
  font-weight: 600;
}
`;function ie(){return{async:!1,breaks:!1,extensions:null,gfm:!0,hooks:null,pedantic:!1,renderer:null,silent:!1,tokenizer:null,walkTokens:null}}var A=ie();function Fe(n){A=n}var R={exec:()=>null};function P(n){let e=[];return t=>{let s=Math.max(0,Math.min(3,t-1)),r=e[s];return r||(r=n(s),e[s]=r),r}}function d(n,e=""){let t=typeof n=="string"?n:n.source,s={replace:(r,i)=>{let a=typeof i=="string"?i:i.source;return a=a.replace(x.caret,"$1"),t=t.replace(r,a),s},getRegex:()=>new RegExp(t,e)};return s}var at=((n="")=>{try{return!!new RegExp("(?<=1)(?<!1)"+n)}catch{return!1}})(),x={codeRemoveIndent:/^(?: {0,3}\t| {1,4})/gm,outputLinkReplace:/\\([\[\]])/g,indentCodeCompensation:/^(\s+)(?:```)/,beginningSpace:/^\s+/,endingHash:/#$/,startingSpaceChar:/^ /,endingSpaceChar:/ $/,endingSpaceTabChar:/[ \t]$/,nonSpaceChar:/[^ ]/,newLineCharGlobal:/\n/g,tabCharGlobal:/\t/g,leadingSpaceTab:/^[ \t]+/,multipleSpaceGlobal:/\s+/g,blankLine:/^[ \t]*$/,doubleBlankLine:/\n[ \t]*\n[ \t]*$/,blockquoteStart:/^ {0,3}>/,blockquoteSetextReplace:/\n {0,3}((?:=+|-+) *)(?=\n|$)/g,blockquoteSetextReplace2:/^ {0,3}>[ \t]?/gm,listReplaceNesting:/^ {1,4}(?=( {4})*[^ ])/g,listIsTask:/^\[[ xX]\] +\S/,listReplaceTask:/^\[[ xX]\] +/,listTaskCheckbox:/\[[ xX]\]/,anyLine:/\n.*\n/,hrefBrackets:/^<(.*)>$/,tableDelimiter:/[:|]/,tableAlignChars:/^\||\| *$/g,tableRowBlankLine:/\n[ \t]*$/,tableAlignRight:/^ *-+: *$/,tableAlignCenter:/^ *:-+: *$/,tableAlignLeft:/^ *:-+ *$/,startATag:/^<a /i,endATag:/^<\/a>/i,startPreScriptTag:/^<(pre|code|kbd|script)(\s|>)/i,endPreScriptTag:/^<\/(pre|code|kbd|script)(\s|>)/i,startAngleBracket:/^</,endAngleBracket:/>$/,pedanticHrefTitle:/^([^'"]*[^\s])\s+(['"])(.*)\2/,unicodeAlphaNumeric:/[\p{L}\p{N}]/u,numericCharacterReference:/&#(?:(\d{1,7})|[Xx]([A-Fa-f0-9]{1,6}));/g,escapeTest:/[&<>"']/,escapeReplace:/[&<>"']/g,escapeTestNoEncode:/[<>"']|&(?!(#\d{1,7}|#[Xx][a-fA-F0-9]{1,6}|\w+);)/,escapeReplaceNoEncode:/[<>"']|&(?!(#\d{1,7}|#[Xx][a-fA-F0-9]{1,6}|\w+);)/g,caret:/(^|[^\[])\^/g,percentDecode:/%25/g,findPipe:/\|/g,splitPipe:/ \|/,slashPipe:/\\\|/g,carriageReturn:/\r\n|\r/g,spaceLine:/^ +$/gm,notSpaceStart:/^\S*/,endingNewline:/\n$/,listItemRegex:n=>new RegExp(`^( {0,3}${n})((?:[	 ][^\\n]*)?(?:\\n|$))`),nextBulletRegex:P(n=>new RegExp(`^ {0,${n}}(?:[*+-]|\\d{1,9}[.)])((?:[ 	][^\\n]*)?(?:\\n|$))`)),hrRegex:P(n=>new RegExp(`^ {0,${n}}((?:-[ 	]*){3,}|(?:_[ 	]*){3,}|(?:\\*[ 	]*){3,})(?:\\n+|$)`)),fencesBeginRegex:P(n=>new RegExp(`^ {0,${n}}(?:\`\`\`|~~~)`)),headingBeginRegex:P(n=>new RegExp(`^ {0,${n}}#`)),htmlBeginRegex:P(n=>new RegExp(`^ {0,${n}}(?:</?(?:${Z})(?: +|$|/?>)|<(?:script|pre|style|textarea|!--))`,"i")),blockquoteBeginRegex:P(n=>new RegExp(`^ {0,${n}}>`))},ot=/^(?:[ \t]*(?:\n|$))+/,ct=/^((?: {4}| {0,3}\t)[^\n]+(?:\n(?:[ \t]*(?:\n|$))*)?)+/,ht=/^ {0,3}(`{3,}(?=[^`\n]*(?:\n|$))|~{3,})([^\n]*)(?:\n|$)(?:|([\s\S]*?)(?:\n|$))(?: {0,3}\1[~`]* *(?=\n|$)|$)/,O=/^ {0,3}((?:-[\t ]*){3,}|(?:_[ \t]*){3,}|(?:\*[ \t]*){3,})(?:\n+|$)/,pt=/^ {0,3}(#{1,6})(?=\s|$)(.*)(?:\n+|$)/,le=/ {0,3}(?:[*+-]|\d{1,9}[.)])/,We=/^(?!bull |blockCode|fences|blockquote|heading|html|table)((?:.|\n(?!\s*?\n|bull |fences|blockquote|heading|hr|html|table))+?)\n {0,3}(=+|-+) *(?:\n+|$)/,Ve=d(We).replace(/bull/g,le).replace(/blockCode/g,/(?: {4}| {0,3}\t)/).replace(/fences/g,/ {0,3}(?:`{3,}|~{3,})/).replace(/blockquote/g,/ {0,3}>/).replace(/heading/g,/ {0,3}#{1,6}(?:\s|$)/).replace(/hr/g,/ {0,3}(?:(?:-[\t ]*){3,}|(?:_[ \t]*){3,}|(?:\*[ \t]*){3,})(?:\n+|$)/).replace(/html/g,/ {0,3}<[^\n>]+>\n/).replace(/\|table/g,"").getRegex(),ut=d(We).replace(/bull/g,le).replace(/blockCode/g,/(?: {4}| {0,3}\t)/).replace(/fences/g,/ {0,3}(?:`{3,}|~{3,})/).replace(/blockquote/g,/ {0,3}>/).replace(/heading/g,/ {0,3}#{1,6}(?:\s|$)/).replace(/hr/g,/ {0,3}(?:(?:-[\t ]*){3,}|(?:_[ \t]*){3,}|(?:\*[ \t]*){3,})(?:\n+|$)/).replace(/html/g,/ {0,3}<[^\n>]+>\n/).replace(/table/g,/ {0,3}\|?(?:[:\- ]*\|)+[\:\- ]*\n/).getRegex(),ae=/^([^\n]+(?:\n(?!hr|heading|lheading|blockquote|fences|list|html|table|[ \t]+\n)[^\n]+)*)/,dt=/^[^\n]+/,oe=/(?!\s*\])(?:\\[\s\S]|[^\[\]\\])+/,gt=d(/^ {0,3}\[(label)\]: *(?:\n[ \t]*)?([^<\s][^\s]*|<.*?>)(?:(?: +(?:\n[ \t]*)?| *\n[ \t]*)(title))? *(?:\n+|$)/).replace("label",oe).replace("title",/(?:"(?:\\"?|[^"\\])*"|'[^'\n]*(?:\n[^'\n]+)*\n?'|\([^()]*\))/).getRegex(),ft=d(/^(bull)([ \t][^\n]*?)?(?:\n|$)/).replace(/bull/g,le).getRegex(),Z="address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|meta|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul",ce=/<!--(?:-?>|[\s\S]*?(?:-->|$))/,kt=d("^ {0,3}(?:<(script|pre|style|textarea)[\\s>][\\s\\S]*?(?:</\\1>[^\\n]*\\n*|$)|comment[^\\n]*(\\n+|$)|<\\?[\\s\\S]*?(?:\\?>[^\\n]*\\n*|$)|<![A-Z][\\s\\S]*?(?:>[^\\n]*\\n*|$)|<!\\[CDATA\\[[\\s\\S]*?(?:\\]\\]>[^\\n]*\\n*|$)|</?(tag)(?: +|\\n|/?>)[\\s\\S]*?(?:(?:\\n[ 	]*)+\\n|$)|<(?!script|pre|style|textarea)([a-z][a-z0-9-]*)(?:attribute)*? */?>(?=[ \\t]*(?:\\n|$))[\\s\\S]*?(?:(?:\\n[ 	]*)+\\n|$)|</(?!script|pre|style|textarea)[a-z][a-z0-9-]*\\s*>(?=[ \\t]*(?:\\n|$))[\\s\\S]*?(?:(?:\\n[ 	]*)+\\n|$))","i").replace("comment",ce).replace("tag",Z).replace("attribute",/ +[a-zA-Z:_][\w.:-]*(?: *= *"[^"\n]*"| *= *'[^'\n]*'| *= *[^\s"'=<>`]+)?/).getRegex(),Xe=n=>d(ae).replace("hr",O).replace("heading"," {0,3}#{1,6}(?:\\s|$)").replace("|lheading","").replace("|table","").replace("blockquote"," {0,3}>").replace("fences"," {0,3}(?:`{3,}(?=[^`\\n]*(?:\\n|$))|~~~)[^\\n]*(?:\\n|$)").replace("list",n).replace("html","</?(?:tag)(?: +|\\n|/?>)|<(?:script|pre|style|textarea|!--)").replace("tag",Z).getRegex(),bt=Xe(/ {0,3}(?:[*+-]|1[.)])[ \t]+[^ \t\n]/),mt=Xe(/ {0,3}(?:[*+-]|\d{1,9}[.)])(?:[ \t]|\n|$)/),xt=d(/^( {0,3}> ?(paragraph|[^\n]*)(?:\n|$))+/).replace("paragraph",mt).getRegex(),he={blockquote:xt,code:ct,def:gt,fences:ht,heading:pt,hr:O,html:kt,lheading:Ve,list:ft,newline:ot,paragraph:bt,table:R,text:dt},qe=d("^ *([^\\n ].*)\\n {0,3}((?:\\| *)?:?-+:? *(?:\\| *:?-+:? *)*(?:\\| *)?)(?:\\n((?:(?! *\\n|hr|heading|blockquote|code|fences|list|html).*(?:\\n|$))*)\\n*|$)").replace("hr",O).replace("heading"," {0,3}#{1,6}(?:\\s|$)").replace("blockquote"," {0,3}>").replace("code","(?: {4}| {0,3}	)[^\\n]").replace("fences"," {0,3}(?:`{3,}(?=[^`\\n]*(?:\\n|$))|~~~)[^\\n]*(?:\\n|$)").replace("list"," {0,3}(?:[*+-]|1[.)])[ \\t]").replace("html","</?(?:tag)(?: +|\\n|/?>)|<(?:script|pre|style|textarea|!--)").replace("tag",Z).getRegex(),wt={...he,lheading:ut,table:qe,paragraph:d(ae).replace("hr",O).replace("heading"," {0,3}#{1,6}(?:\\s|$)").replace("|lheading","").replace("table",qe).replace("blockquote"," {0,3}>").replace("fences"," {0,3}(?:`{3,}(?=[^`\\n]*(?:\\n|$))|~~~)[^\\n]*(?:\\n|$)").replace("list"," {0,3}(?:[*+-]|1[.)])[ \\t]+[^ \\t\\n]").replace("html","</?(?:tag)(?: +|\\n|/?>)|<(?:script|pre|style|textarea|!--)").replace("tag",Z).getRegex()},yt={...he,html:d(`^ *(?:comment *(?:\\n|\\s*$)|<(tag)[\\s\\S]+?</\\1> *(?:\\n{2,}|\\s*$)|<tag(?:"[^"]*"|'[^']*'|\\s[^'"/>\\s]*)*?/?> *(?:\\n{2,}|\\s*$))`).replace("comment",ce).replace(/tag/g,"(?!(?:a|em|strong|small|s|cite|q|dfn|abbr|data|time|code|var|samp|kbd|sub|sup|i|b|u|mark|ruby|rt|rp|bdi|bdo|span|br|wbr|ins|del|img)\\b)\\w+(?!:|[^\\w\\s@]*@)\\b").getRegex(),def:/^ *\[([^\]]+)\]: *<?([^\s>]+)>?(?: +(["(][^\n]+[")]))? *(?:\n+|$)/,heading:/^(#{1,6})(.*)(?:\n+|$)/,fences:R,lheading:/^(.+?)\n {0,3}(=+|-+) *(?:\n+|$)/,paragraph:d(ae).replace("hr",O).replace("heading",` *#{1,6} *[^
]`).replace("lheading",Ve).replace("|table","").replace("blockquote"," {0,3}>").replace("|fences","").replace("|list","").replace("|html","").replace("|tag","").getRegex()},vt=/^\\([!"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])/,St=/^(`+)([^`]|[^`][\s\S]*?[^`])\1(?!`)/,Ke=/^( {2,}|\\)\n(?!\s*$)[ \t]*/,_t=/^(`+|[^`])(?:(?= {2,}\n)|[\s\S]*?(?:(?=[\\<!\[`*_]|\b_|$)|[^ ](?= {2,}\n)))/,_=/[\p{P}\p{S}]/u,L=/[\s\p{P}\p{S}]/u,N=/[^\s\p{P}\p{S}]/u,$t=d(/^((?![*_])punctSpace)/,"u").replace(/punctSpace/g,L).getRegex(),Rt=/[\p{Pi}\p{Ps}"']/u,Ye=/(?!~)[\p{P}\p{S}]/u,Tt=/(?!~)[\s\p{P}\p{S}]/u,At=/(?:[^\s\p{P}\p{S}]|~)/u,zt=d(/link|precode-code|html/,"g").replace("link",/\[(?:[^\[\]`]|(?<a>`+)[^`]+\k<a>(?!`))*?\]\((?:\\[\s\S]|[^\\\(\)]|\((?:\\[\s\S]|[^\\\(\)])*\))*\)/).replace("precode-",at?"(?<!`)()":"(^^|[^`])").replace("code",/(?<b>`+)[^`]+\k<b>(?!`)/).replace("html",/<(?! )[^<>]*?>/).getRegex(),Je=/^(?:\*+(?:((?!\*)punct)|([^\s*]))?)|^_+(?:((?!_)punct)|([^\s_]))?/,Pt=d(Je,"u").replace(/punct/g,_).getRegex(),Lt=d(Je,"u").replace(/punct/g,Ye).getRegex(),Ct=/^(?:\*+(?:((?!\*)(?!openQuote)punct)|([^\s*]))?)|^_+(?:((?!_)(?!openQuote)punct)|([^\s_]))?/,Et=d(Ct,"u").replace(/openQuote/g,Rt).replace(/punct/g,_).getRegex(),et="^[^_*]*?__[^_*]*?\\*[^_*]*?(?=__)|[^*]+(?=[^*])|(?!\\*)punct(\\*+)(?=[\\s]|$)|notPunctSpace(\\*+)(?!\\*)(?=punctSpace|$)|(?!\\*)punctSpace(\\*+)(?=notPunctSpace)|[\\s](\\*+)(?!\\*)(?=punct)|(?!\\*)punct(\\*+)(?!\\*)(?=punct)|notPunctSpace(\\*+)(?=notPunctSpace)",Bt=d(et,"gu").replace(/notPunctSpace/g,N).replace(/punctSpace/g,L).replace(/punct/g,_).getRegex(),It=d(et,"gu").replace(/notPunctSpace/g,At).replace(/punctSpace/g,Tt).replace(/punct/g,Ye).getRegex(),qt="^[^_*]*?__[^_*]*?\\*[^_*]*?(?=__)|[^*]+(?=[^*])|(?!\\*)punct(\\*+)(?=[\\s]|$)|notPunctSpace(\\*+)(?!\\*)(?=punctSpace|$)|(?!\\*)[\\s](\\*+)(?=notPunctSpace)|[\\s](\\*+)(?!\\*)(?=punct)|(?!\\*)punct(\\*+)(?!\\*)(?=punct)|(?:(?!\\*)punct|notPunctSpace)(\\*+)(?!\\*)(?=notPunctSpace)",Mt=d(qt,"gu").replace(/notPunctSpace/g,N).replace(/punctSpace/g,L).replace(/punct/g,_).getRegex(),Ot=d("^[^_*]*?\\*\\*[^_*]*?_[^_*]*?(?=\\*\\*)|[^_]+(?=[^_])|(?!_)punct(_+)(?=[\\s]|$)|notPunctSpace(_+)(?!_)(?=punctSpace|$)|(?!_)punctSpace(_+)(?=notPunctSpace)|[\\s](_+)(?!_)(?=punct)|(?!_)punct(_+)(?!_)(?=punct)","gu").replace(/notPunctSpace/g,N).replace(/punctSpace/g,L).replace(/punct/g,_).getRegex(),Zt="^[^_*]*?\\*\\*[^_*]*?_[^_*]*?(?=\\*\\*)|[^_]+(?=[^_])|(?!_)punct(_+)(?=[\\s]|$)|notPunctSpace(_+)(?!_)(?=punctSpace|$)|(?!_)[\\s](_+)(?=notPunctSpace)|[\\s](_+)(?!_)(?=punct)|(?!_)punct(_+)(?!_)(?=punct)|(?:(?!_)punct|notPunctSpace)(_+)(?!_)(?=notPunctSpace)",Nt=d(Zt,"gu").replace(/notPunctSpace/g,N).replace(/punctSpace/g,L).replace(/punct/g,_).getRegex(),Dt=d(/^~~?(?:((?!~)punct)|[^\s~])/,"u").replace(/punct/g,_).getRegex(),Ht="^[^~]+(?=[^~])|(?!~)punct(~~?)(?=[\\s]|$)|notPunctSpace(~~?)(?!~)(?=punctSpace|$)|(?!~)punctSpace(~~?)(?=notPunctSpace)|[\\s](~~?)(?!~)(?=punct)|(?!~)punct(~~?)(?!~)(?=punct)|notPunctSpace(~~?)(?=notPunctSpace)",Qt=d(Ht,"gu").replace(/notPunctSpace/g,N).replace(/punctSpace/g,L).replace(/punct/g,_).getRegex(),Ut=d(/\\(punct)/,"gu").replace(/punct/g,_).getRegex(),jt=d(/^<(scheme:[^\s\x00-\x1f<>]*|email)>/).replace("scheme",/[a-zA-Z][a-zA-Z0-9+.-]{1,31}/).replace("email",/[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+(@)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?![-_])/).getRegex(),Gt=d(ce).replace("(?:-->|$)","-->").getRegex(),Ft=d("^comment|^</[a-zA-Z][a-zA-Z0-9-]*\\s*>|^<[a-zA-Z][a-zA-Z0-9-]*(?:attribute)*?\\s*/?>|^<\\?[\\s\\S]*?\\?>|^<![a-zA-Z]+\\s[\\s\\S]*?>|^<!\\[CDATA\\[[\\s\\S]*?\\]\\]>").replace("comment",Gt).replace("attribute",/\s+[a-zA-Z:_][\w.:-]*(?:\s*=\s*"[^"]*"|\s*=\s*'[^']*'|\s*=\s*[^\s"'=<>`]+)?/).getRegex(),tt=/\[(?:\\[\s\S]|[^\[\]\\])*\]/,G=d(/(?:\[(?:brackets|\\[\s\S]|[^\[\]\\])*\]|\\[\s\S]|`+(?!`)[^`]*?`+(?!`)|``+(?=\])|[^\[\]\\`])*?/).replace("brackets",tt).getRegex(),Wt=d(/^!?\[(label)\]\([ \t\n]*(href)(?:(?:[ \t]+(?:\n[ \t]*)?|\n[ \t]*)(title))?[ \t\n]*\)/).replace("label",G).replace("href",/<(?:\\.|[^\n<>\\])+>|[^ \t\n\x00-\x1f]+|(?=\))/).replace("title",/"(?:\\"?|[^"\\])*"|'(?:\\'?|[^'\\])*'|\((?:\\\)?|[^)\\])*\)/).getRegex(),Vt=d(/^!?\[(label)\]\[(ref)\]/).replace("label",G).replace("ref",oe).getRegex(),Xt=d(/^!?\[(ref)\](?:\[\])?/).replace("ref",oe).getRegex(),Me=/(?!\s*\])(?:\\[\s\S]|[^\[\]\\]){1,999}/,Kt=d(/(?:[^\[\]\\`]*(?:\[(?:brackets|\\[\s\S]|[^\[\]\\])*\]|\\[\s\S]|`+(?!`)[^`]*?`+(?!`)|``+(?=\]))){0,999}?[^\[\]\\`]*?/).replace("brackets",tt).getRegex(),Yt=d("reflink|nolink(?!\\()","g").replace("reflink",d(/^!?\[(label)\]\[(ref)\]/).replace("label",Kt).replace("ref",Me).getRegex()).replace("nolink",d(/^!?\[(ref)\](?:\[\])?/).replace("ref",Me).getRegex()).getRegex(),Oe=/[hH][tT][tT][pP][sS]?|[fF][tT][pP]/,Jt=/[A-Za-z0-9._+-]+@[a-zA-Z0-9-_]+(?:\.[a-zA-Z0-9-_]*[a-zA-Z0-9])+(?![\w-])/,er=d(/(?:mailto:email|xmpp:email(?:\/[A-Za-z0-9@.]+)?)/).replace(/email/g,Jt).getRegex(),pe={_backpedal:R,anyPunctuation:Ut,autolink:jt,blockSkip:zt,br:Ke,code:St,del:R,delLDelim:R,delRDelim:R,emStrongLDelim:Pt,emStrongRDelimAst:Bt,emStrongRDelimUnd:Ot,escape:vt,link:Wt,nolink:Xt,punctuation:$t,reflink:Vt,reflinkSearch:Yt,tag:Ft,text:_t,url:R},tr={...pe,emStrongLDelim:Et,emStrongRDelimAst:Mt,emStrongRDelimUnd:Nt,link:d(/^!?\[(label)\]\((.*?)\)/).replace("label",G).getRegex(),reflink:d(/^!?\[(label)\]\s*\[([^\]]*)\]/).replace("label",G).getRegex()},re={...pe,emStrongRDelimAst:It,emStrongLDelim:Lt,delLDelim:Dt,delRDelim:Qt,url:d(/^emailProtocol|^((?:protocol):\/\/|www\.)(?:[a-zA-Z0-9\-]+\.?)+[^\s<]*|^email/).replace("emailProtocol",er).replace("protocol",Oe).replace("email",/[A-Za-z0-9._+-]+(@)[a-zA-Z0-9-_]+(?:\.[a-zA-Z0-9-_]*[a-zA-Z0-9])+(?![\w-])/).getRegex(),_backpedal:/(?:[^?!.,:;*_'"~()&]+|\([^)]*\)|&(?![a-zA-Z0-9]+;$)|[?!.,:;*_'"~)]+(?!$))+/,del:/^(~~?)(?=[^\s~])((?:\\[\s\S]|[^\\])*?(?:\\[\s\S]|[^\s~\\]))\1(?=[^~]|$)/,text:d(/^(?:[^a-zA-Z0-9](?=emailProtocol)|(`+|~+|[^`~])(?:(?=[`~])|(?= {2,}\n)|(?=[a-zA-Z0-9.!#$%&'*+\/=?_`{\|}~-]+@)|[\s\S]*?(?:(?=[\\<!\[`*~_]|\b_|protocol:\/\/|www\.|$)|[^ ](?= {2,}\n)|[^a-zA-Z0-9](?=emailProtocol)|[^a-zA-Z0-9.!#$%&'*+\/=?_`{\|}~-](?=[a-zA-Z0-9.!#$%&'*+\/=?_`{\|}~-]+@))))/).replace("protocol",Oe).replace(/emailProtocol/g,/(?:mailto|xmpp):/).getRegex()},rr={...re,br:d(Ke).replace("{2,}","*").getRegex(),text:d(re.text).replace("\\b_","\\b_| {2,}\\n").replace(/\{2,\}/g,"*").getRegex()},j={normal:he,gfm:wt,pedantic:yt},q={normal:pe,gfm:re,breaks:rr,pedantic:tr},nr={"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"},Ze=n=>nr[n];function y(n,e){if(e){if(x.escapeTest.test(n))return n.replace(x.escapeReplace,Ze)}else if(x.escapeTestNoEncode.test(n))return n.replace(x.escapeReplaceNoEncode,Ze);return n}function sr(n){return n.replace(x.numericCharacterReference,(e,t,s)=>{let r=t===void 0?Number.parseInt(s,16):Number.parseInt(t,10);return r===0||r>1114111||r>=55296&&r<=57343?"\uFFFD":String.fromCodePoint(r)})}function Ne(n){try{n=encodeURI(n).replace(x.percentDecode,"%")}catch{return null}return n}function De(n,e){let t=n.replace(x.findPipe,(i,a,l)=>{let c=!1,o=a;for(;--o>=0&&l[o]==="\\";)c=!c;return c?"|":" |"}),s=t.split(x.splitPipe),r=0;if(s[0].trim()||s.shift(),s.length>0&&!s.at(-1)?.trim()&&s.pop(),e)if(s.length>e)s.splice(e);else for(;s.length<e;)s.push("");for(;r<s.length;r++)s[r]=s[r].trim().replace(x.slashPipe,"|");return s}function $(n,e,t){let s=n.length;if(s===0)return"";let r=0;for(;r<s;){let i=n.charAt(s-r-1);if(i===e&&!t)r++;else if(i!==e&&t)r++;else break}return n.slice(0,s-r)}function He(n){let e=n.split(`
`),t=e.length-1;for(;t>=0&&x.blankLine.test(e[t]);)t--;return e.length-t<=2?n:e.slice(0,t+1).join(`
`)}function F(n){return n.trim().toLowerCase().toUpperCase().toLowerCase()}function Qe(n,e){if(n.indexOf(e[0])===-1&&n.indexOf(e[1])===-1)return-1;let t=0;for(let s=0;s<n.length;s++)if(n[s]==="\\")s++;else if(n[s]===e[0])t++;else if(n[s]===e[1]&&(t--,t<0))return s;return t>0?-2:-1}function Ue(n,e=0){let t=e,s="";for(let r of n)if(r==="	"){let i=4-t%4;s+=" ".repeat(i),t+=i}else s+=r,t++;return s}function je(n,e,t,s,r){let i=e.href,a=e.title||null,l=n[1].replace(r.other.outputLinkReplace,"$1"),c=n[0].charAt(0)==="!";s.state.inLink=!0;let o=s.state.linkEmitted,h=s.state.inRawBlock;s.state.linkEmitted=!1;let p=s.inlineTokens(l),k=s.state.linkEmitted;if(s.state.linkEmitted=o,s.state.inLink=!1,!c){if(k){s.state.inRawBlock=h;return}s.state.linkEmitted=!0}return{type:c?"image":"link",raw:t,href:i,title:a,text:l,tokens:p}}function ir(n,e,t){let s=n.match(t.other.indentCodeCompensation);if(s===null)return e;let r=s[1];return e.split(`
`).map(i=>{let a=i.match(t.other.beginningSpace);if(a===null)return i;let[l]=a;return i.slice(Math.min(l.length,r.length))}).join(`
`)}function Ge(n,e,t,s){if(!e.includes("<"))return!1;for(let r=0;r<e.length;r++){if(e[r]==="\\"){r++;continue}if(e[r]==="`"){let l=s.inline.code.exec(e.slice(r));if(l){r+=l[0].length-1;continue}}if(e[r]!=="<")continue;let i=n.slice(t+r),a=s.inline.tag.exec(i)||s.inline.autolink.exec(i);if(a){if(a[0].length>e.length-r)return!0;r+=a[0].length-1}}return!1}var W=class{options;rules;lexer;constructor(n){this.options=n||A}space(n){let e=this.rules.block.newline.exec(n);if(e&&e[0].length>0)return{type:"space",raw:e[0]}}code(n){let e=this.rules.block.code.exec(n);if(e){let t=this.options.pedantic?e[0]:He(e[0]),s=t.replace(this.rules.other.codeRemoveIndent,"");return{type:"code",raw:t,codeBlockStyle:"indented",text:s}}}fences(n){let e=this.rules.block.fences.exec(n);if(e){let t=e[0],s=ir(t,e[3]||"",this.rules);return{type:"code",raw:t,lang:e[2]?e[2].trim().replace(this.rules.inline.anyPunctuation,"$1"):e[2],text:s}}}heading(n){let e=this.rules.block.heading.exec(n);if(e){let t=e[2].trim();if(this.rules.other.endingHash.test(t)){let s=$(t,"#");(this.options.pedantic||!s||this.rules.other.endingSpaceTabChar.test(s))&&(t=s.trim())}return{type:"heading",raw:$(e[0],`
`),depth:e[1].length,text:t,tokens:this.lexer.inline(t)}}}hr(n){let e=this.rules.block.hr.exec(n);if(e)return{type:"hr",raw:$(e[0],`
`)}}blockquote(n){let e=this.rules.block.blockquote.exec(n);if(e){let t=$(e[0],`
`).split(`
`),s="",r="",i=[];for(;t.length>0;){let a=!1,l=[],c;for(c=0;c<t.length;c++)if(this.rules.other.blockquoteStart.test(t[c]))l.push(t[c]),a=!0;else if(!a)l.push(t[c]);else break;t=t.slice(c);let o=l.join(`
`),h=o.replace(this.rules.other.blockquoteSetextReplace,`
    $1`).replace(this.rules.other.blockquoteSetextReplace2,"");s=s?`${s}
${o}`:o,r=r?`${r}
${h}`:h;let p=this.lexer.state.top;if(this.lexer.state.top=!0,this.lexer.blockTokens(h,i,!0),this.lexer.state.top=p,t.length===0)break;let k=i.at(-1);if(k?.type==="code")break;if(k?.type==="blockquote"){let f=k,u=t.join(`
`),w=f.raw+`
`+u.replace(this.rules.other.blockquoteSetextReplace2,""),b=this.blockquote(w);i[i.length-1]=b;let z=w.substring(b.raw.length).replace(/^\n/,""),C=z?z.split(`
`).length:0,E=C?t.slice(0,-C):t;E.length>0&&(s=`${s}
${E.join(`
`)}`),r=r.substring(0,r.length-f.text.length)+b.text;break}else if(k?.type==="list"){let f=k,u=f.raw+`
`+t.join(`
`),w=this.list(u);i[i.length-1]=w,s=s.substring(0,s.length-k.raw.length)+w.raw,r=r.substring(0,r.length-f.raw.length)+w.raw,t=u.substring(i.at(-1).raw.length).split(`
`);continue}}return{type:"blockquote",raw:s,tokens:i,text:r}}}list(n){let e=this.rules.block.list.exec(n);if(e){let t=e[1].trim(),s=t.length>1,r={type:"list",raw:"",ordered:s,start:s?+t.slice(0,-1):"",loose:!1,items:[]};t=s?`\\d{1,9}\\${t.slice(-1)}`:`\\${t}`,this.options.pedantic&&(t=s?t:"[*+-]");let i=this.rules.other.listItemRegex(t),a=!1;for(;n;){let c=!1,o="",h="";if(!(e=i.exec(n))||this.rules.block.hr.test(n))break;o=e[0],n=n.substring(o.length);let p=e[2].split(`
`,1)[0],k=e[1].length,f=this.options.pedantic?Ue(p,k):p.replace(this.rules.other.leadingSpaceTab,z=>Ue(z,k)),u=n.split(`
`,1)[0],w=!f.trim(),b=0;if(this.options.pedantic?(b=2,h=f.trimStart()):w?b=k+1:(b=f.search(this.rules.other.nonSpaceChar),b=b>4?1:b,h=f.slice(b),b+=k),w&&this.rules.other.blankLine.test(u)&&(o+=u+`
`,n=n.substring(u.length+1),c=!0),!c){let z=this.rules.other.nextBulletRegex(b),C=this.rules.other.hrRegex(b),E=this.rules.other.fencesBeginRegex(b),ge=this.rules.other.headingBeginRegex(b),nt=this.rules.other.htmlBeginRegex(b),st=this.rules.other.blockquoteBeginRegex(b);for(;n;){let ee=n.split(`
`,1)[0],B;if(u=ee,this.options.pedantic?(u=u.replace(this.rules.other.listReplaceNesting,"  "),B=u):B=u.replace(this.rules.other.leadingSpaceTab,it=>it.replace(this.rules.other.tabCharGlobal,"    ")),E.test(u)||ge.test(u)||nt.test(u)||st.test(u)||z.test(u)||C.test(u))break;if(B.search(this.rules.other.nonSpaceChar)>=b||!u.trim())h+=`
`+B.slice(b);else{if(w||f.replace(this.rules.other.tabCharGlobal,"    ").search(this.rules.other.nonSpaceChar)>=4||E.test(f)||ge.test(f)||C.test(f))break;h+=`
`+u}w=!u.trim(),o+=ee+`
`,n=n.substring(ee.length+1),f=B.slice(b)}}r.loose||(a?r.loose=!0:this.rules.other.doubleBlankLine.test(o)&&(a=!0)),r.items.push({type:"list_item",raw:o,task:!!this.options.gfm&&this.rules.other.listIsTask.test(h),loose:!1,text:h,tokens:[]}),r.raw+=o}let l=r.items.at(-1);if(l)l.raw=l.raw.trimEnd(),l.text=l.text.trimEnd();else return;r.raw=r.raw.trimEnd();for(let c of r.items)if(this.lexer.state.top=!1,c.tokens=this.lexer.blockTokens(c.text,[]),!r.loose){let o=c.tokens.filter(p=>p.type==="space"),h=o.length>0&&o.some(p=>this.rules.other.anyLine.test(p.raw));r.loose=h}for(let c of r.items){let o=c.tokens[0];if(c.task&&(o?.type==="text"||o?.type==="paragraph")){c.text=c.text.replace(this.rules.other.listReplaceTask,""),o.raw=o.raw.replace(this.rules.other.listReplaceTask,""),o.text=o.text.replace(this.rules.other.listReplaceTask,"");for(let p=this.lexer.inlineQueue.length-1;p>=0;p--)if(this.rules.other.listIsTask.test(this.lexer.inlineQueue[p].src)){this.lexer.inlineQueue[p].src=this.lexer.inlineQueue[p].src.replace(this.rules.other.listReplaceTask,"");break}let h=this.rules.other.listTaskCheckbox.exec(c.raw);if(h){let p={type:"checkbox",raw:h[0]+" ",checked:h[0]!=="[ ]"};c.checked=p.checked,r.loose?c.tokens[0]&&["paragraph","text"].includes(c.tokens[0].type)&&"tokens"in c.tokens[0]&&c.tokens[0].tokens?(c.tokens[0].raw=p.raw+c.tokens[0].raw,c.tokens[0].text=p.raw+c.tokens[0].text,c.tokens[0].tokens.unshift(p)):c.tokens.unshift({type:"paragraph",raw:p.raw,text:p.raw,tokens:[p]}):c.tokens.unshift(p)}}else c.task&&(c.task=!1)}if(r.loose)for(let c of r.items){c.loose=!0;for(let o of c.tokens)o.type==="text"&&(o.type="paragraph")}return r}}html(n){let e=this.rules.block.html.exec(n);if(e){let t=He(e[0]);return{type:"html",block:!0,raw:t,pre:e[1]==="pre"||e[1]==="script"||e[1]==="style",text:t}}}def(n){let e=this.rules.block.def.exec(n);if(e){if(!this.rules.other.startAngleBracket.test(e[2])&&Qe(e[2],"()")!==-1)return;let t=F(e[1]).replace(this.rules.other.multipleSpaceGlobal," "),s=e[2]?e[2].replace(this.rules.other.hrefBrackets,"$1").replace(this.rules.inline.anyPunctuation,"$1"):"",r=e[3]?e[3].substring(1,e[3].length-1).replace(this.rules.inline.anyPunctuation,"$1"):e[3];return{type:"def",tag:t,raw:$(e[0],`
`),href:s,title:r}}}table(n){let e=this.rules.block.table.exec(n);if(!e||!this.rules.other.tableDelimiter.test(e[2]))return;let t=De(e[1]),s=e[2].replace(this.rules.other.tableAlignChars,"").split("|"),r=e[3]?.trim()?e[3].replace(this.rules.other.tableRowBlankLine,"").split(`
`):[],i={type:"table",raw:$(e[0],`
`),header:[],align:[],rows:[]};if(t.length===s.length){for(let a of s)this.rules.other.tableAlignRight.test(a)?i.align.push("right"):this.rules.other.tableAlignCenter.test(a)?i.align.push("center"):this.rules.other.tableAlignLeft.test(a)?i.align.push("left"):i.align.push(null);for(let a=0;a<t.length;a++)i.header.push({text:t[a],tokens:this.lexer.inline(t[a]),header:!0,align:i.align[a]});for(let a of r)i.rows.push(De(a,i.header.length).map((l,c)=>({text:l,tokens:this.lexer.inline(l),header:!1,align:i.align[c]})));return i}}lheading(n){let e=this.rules.block.lheading.exec(n);if(e){let t=e[1].trim();return{type:"heading",raw:$(e[0],`
`),depth:e[2].charAt(0)==="="?1:2,text:t,tokens:this.lexer.inline(t)}}}paragraph(n){let e=this.rules.block.paragraph.exec(n);if(e){let t=e[1].charAt(e[1].length-1)===`
`?e[1].slice(0,-1):e[1];return{type:"paragraph",raw:e[0],text:t,tokens:this.lexer.inline(t)}}}text(n){let e=this.rules.block.text.exec(n);if(e)return{type:"text",raw:e[0],text:e[0],tokens:this.lexer.inline(e[0])}}escape(n){let e=this.rules.inline.escape.exec(n);if(e)return{type:"escape",raw:e[0],text:e[1]}}tag(n){let e=this.rules.inline.tag.exec(n);if(e)return!this.lexer.state.inLink&&this.rules.other.startATag.test(e[0])?this.lexer.state.inLink=!0:this.lexer.state.inLink&&this.rules.other.endATag.test(e[0])&&(this.lexer.state.inLink=!1),!this.lexer.state.inRawBlock&&this.rules.other.startPreScriptTag.test(e[0])?this.lexer.state.inRawBlock=!0:this.lexer.state.inRawBlock&&this.rules.other.endPreScriptTag.test(e[0])&&(this.lexer.state.inRawBlock=!1),{type:"html",raw:e[0],inLink:this.lexer.state.inLink,inRawBlock:this.lexer.state.inRawBlock,block:!1,text:e[0]}}link(n){if(this.lexer.state.linkParenPossible===!1)return;let e=this.rules.inline.link.exec(n);if(e){let t=e[0].charAt(0)==="!"?2:1;if(!this.options.pedantic&&Ge(n,e[1],t,this.rules))return;let s=e[2].trim();if(!this.options.pedantic&&this.rules.other.startAngleBracket.test(s)){if(!this.rules.other.endAngleBracket.test(s))return;let a=$(s.slice(0,-1),"\\");if((s.length-a.length)%2===0)return}else{let a=Qe(e[2],"()");if(a===-2)return;if(a>-1){let l=(e[0].indexOf("!")===0?5:4)+e[1].length+a;e[2]=e[2].substring(0,a),e[0]=e[0].substring(0,l).trim(),e[3]=""}}let r=e[2],i="";if(this.options.pedantic){let a=this.rules.other.pedanticHrefTitle.exec(r);a&&(r=a[1],i=a[3])}else i=e[3]?e[3].slice(1,-1):"";return r=r.trim(),this.rules.other.startAngleBracket.test(r)&&(this.options.pedantic&&!this.rules.other.endAngleBracket.test(s)?r=r.slice(1):r=r.slice(1,-1)),je(e,{href:r&&r.replace(this.rules.inline.anyPunctuation,"$1"),title:i&&i.replace(this.rules.inline.anyPunctuation,"$1")},e[0],this.lexer,this.rules)}}reflink(n,e){let t;if((t=this.rules.inline.reflink.exec(n))||(t=this.rules.inline.nolink.exec(n))){let s=t[0].charAt(0)==="!"?2:1;if(!this.options.pedantic&&Ge(n,t[1],s,this.rules))return;let r=(t[2]||t[1]).replace(this.rules.other.multipleSpaceGlobal," "),i=e[F(r)];if(!i){let a=t[0].charAt(0);return{type:"text",raw:a,text:a}}return je(t,i,t[0],this.lexer,this.rules)}}emStrong(n,e,t=""){let s=this.rules.inline.emStrongLDelim.exec(n);if(!(!s||!s[1]&&!s[2]&&!s[3]&&!s[4]||s[4]&&t.match(this.rules.other.unicodeAlphaNumeric))&&(!(s[1]||s[3])||!t||this.rules.inline.punctuation.exec(t))){let r=[...s[0]].length-1,i,a,l=r,c=0,o=s[0][0],h=t===o,p=o==="*"?this.rules.inline.emStrongRDelimAst:this.rules.inline.emStrongRDelimUnd;for(p.lastIndex=0,e=e.slice(-1*n.length+r);(s=p.exec(e))!==null;){if(i=s[1]||s[2]||s[3]||s[4]||s[5]||s[6],!i)continue;if(a=[...i].length,s[3]||s[4]){l+=a;continue}else if(s[5]||s[6]){if(r%3&&!((r+a)%3)){c+=a;continue}if(h)break}if(l-=a,l>0)continue;a=Math.min(a,a+l+c);let k=[...s[0]][0].length,f=n.slice(0,r+s.index+k+a);if(Math.min(r,a)%2){let w=f.slice(1,-1);return{type:"em",raw:f,text:w,tokens:this.lexer.inlineTokens(w)}}let u=f.slice(2,-2);return{type:"strong",raw:f,text:u,tokens:this.lexer.inlineTokens(u)}}}}codespan(n){let e=this.rules.inline.code.exec(n);if(e){let t=e[2].replace(this.rules.other.newLineCharGlobal," "),s=this.rules.other.nonSpaceChar.test(t),r=this.rules.other.startingSpaceChar.test(t)&&this.rules.other.endingSpaceChar.test(t);return s&&r&&(t=t.substring(1,t.length-1)),{type:"codespan",raw:e[0],text:t}}}br(n){let e=this.rules.inline.br.exec(n);if(e)return{type:"br",raw:e[0]}}del(n,e,t=""){let s=this.rules.inline.delLDelim.exec(n);if(s&&(!s[1]||!t||this.rules.inline.punctuation.exec(t))){let r=[...s[0]].length-1,i,a,l=r,c=this.rules.inline.delRDelim;for(c.lastIndex=0,e=e.slice(-1*n.length+r);(s=c.exec(e))!==null;){if(i=s[1]||s[2]||s[3]||s[4]||s[5]||s[6],!i||(a=[...i].length,a!==r))continue;if(s[3]||s[4]){l+=a;continue}if(l-=a,l>0)continue;a=Math.min(a,a+l);let o=[...s[0]][0].length,h=n.slice(0,r+s.index+o+a),p=h.slice(r,-r);return{type:"del",raw:h,text:p,tokens:this.lexer.inlineTokens(p)}}}}autolink(n){let e=this.rules.inline.autolink.exec(n);if(e){let t,s;return e[2]==="@"?(t=e[1],s="mailto:"+t):(t=e[1],s=t),{type:"link",raw:e[0],text:t,href:s,autolink:!0,tokens:[{type:"text",raw:t,text:t}]}}}url(n){let e;if(e=this.rules.inline.url.exec(n)){let t,s;if(e[2]==="@")t=e[0],s="mailto:"+t;else{let r;do r=e[0],e[0]=this.rules.inline._backpedal.exec(e[0])?.[0]??"";while(r!==e[0]);t=e[0],e[1]==="www."?s="http://"+e[0]:s=e[0]}return{type:"link",raw:e[0],text:t,href:s,autolink:!0,tokens:[{type:"text",raw:t,text:t}]}}}inlineText(n){let e=this.rules.inline.text.exec(n);if(e){let t=this.lexer.state.inRawBlock;return{type:"text",raw:e[0],text:t?e[0]:sr(e[0]),escaped:t}}}},v=class ne{tokens;options;state;inlineQueue;tokenizer;constructor(e){this.tokens=[],this.tokens.links=Object.create(null),this.options=e||A,this.options.tokenizer=this.options.tokenizer||new W,this.tokenizer=this.options.tokenizer,this.tokenizer.options=this.options,this.tokenizer.lexer=this,this.inlineQueue=[],this.state={inLink:!1,inRawBlock:!1,linkEmitted:!1,linkParenPossible:!0,top:!0};let t={other:x,block:j.normal,inline:q.normal};this.options.pedantic?(t.block=j.pedantic,t.inline=q.pedantic):this.options.gfm&&(t.block=j.gfm,this.options.breaks?t.inline=q.breaks:t.inline=q.gfm),this.tokenizer.rules=t}static get rules(){return{block:j,inline:q}}static lex(e,t){return new ne(t).lex(e)}static lexInline(e,t){return new ne(t).inlineTokens(e)}lex(e){e=e.replace(x.carriageReturn,`
`),this.blockTokens(e,this.tokens);for(let t=0;t<this.inlineQueue.length;t++){let s=this.inlineQueue[t];this.inlineTokens(s.src,s.tokens)}return this.inlineQueue=[],this.tokens}blockTokens(e,t=[],s=!1){this.tokenizer.lexer=this,this.options.pedantic&&(e=e.replace(x.tabCharGlobal,"    ").replace(x.spaceLine,""));let r=1/0;for(;e;){if(e.length<r)r=e.length;else{this.infiniteLoopError(e.charCodeAt(0));break}let i;if(this.options.extensions?.block?.some(l=>(i=l.call({lexer:this},e,t))?(e=e.substring(i.raw.length),t.push(i),!0):!1))continue;if(i=this.tokenizer.space(e)){e=e.substring(i.raw.length);let l=t.at(-1);i.raw.length===1&&l!==void 0?l.raw+=`
`:t.push(i);continue}if(i=this.tokenizer.code(e)){e=e.substring(i.raw.length);let l=t.at(-1);l?.type==="paragraph"||l?.type==="text"?(l.raw+=(l.raw.endsWith(`
`)?"":`
`)+i.raw,l.text+=`
`+i.text,this.inlineQueue.at(-1).src=l.text):t.push(i);continue}if(i=this.tokenizer.fences(e)){e=e.substring(i.raw.length),t.push(i);continue}if(i=this.tokenizer.heading(e)){e=e.substring(i.raw.length),t.push(i);continue}if(i=this.tokenizer.hr(e)){e=e.substring(i.raw.length),t.push(i);continue}if(i=this.tokenizer.blockquote(e)){e=e.substring(i.raw.length),t.push(i);continue}if(i=this.tokenizer.list(e)){e=e.substring(i.raw.length),t.push(i);continue}if(i=this.tokenizer.html(e)){e=e.substring(i.raw.length),t.push(i);continue}if(i=this.tokenizer.def(e)){e=e.substring(i.raw.length);let l=t.at(-1);l?.type==="paragraph"||l?.type==="text"?(l.raw+=(l.raw.endsWith(`
`)?"":`
`)+i.raw,l.text+=`
`+i.raw,this.inlineQueue.at(-1).src=l.text):this.tokens.links[i.tag]||(this.tokens.links[i.tag]={href:i.href,title:i.title},t.push(i));continue}if(i=this.tokenizer.table(e)){e=e.substring(i.raw.length),t.push(i);continue}if(i=this.tokenizer.lheading(e)){e=e.substring(i.raw.length),t.push(i);continue}let a=e;if(this.options.extensions?.startBlock){let l=1/0,c=e.slice(1),o;this.options.extensions.startBlock.forEach(h=>{o=h.call({lexer:this},c),typeof o=="number"&&o>=0&&(l=Math.min(l,o))}),l<1/0&&l>=0&&(a=e.substring(0,l+1))}if(this.state.top&&(i=this.tokenizer.paragraph(a))){let l=t.at(-1);s&&l?.type==="paragraph"?(l.raw+=(l.raw.endsWith(`
`)?"":`
`)+i.raw,l.text+=`
`+i.text,this.inlineQueue.pop(),this.inlineQueue.at(-1).src=l.text):t.push(i),s=a.length!==e.length,e=e.substring(i.raw.length);continue}if(i=this.tokenizer.text(e)){e=e.substring(i.raw.length);let l=t.at(-1);l?.type==="text"?(l.raw+=(l.raw.endsWith(`
`)?"":`
`)+i.raw,l.text+=`
`+i.text,this.inlineQueue.pop(),this.inlineQueue.at(-1).src=l.text):t.push(i);continue}if(e){this.infiniteLoopError(e.charCodeAt(0));break}}return this.state.top=!0,t}inline(e,t=[]){return this.inlineQueue.push({src:e,tokens:t}),t}linkInText(e){if(!e.includes("["))return!1;let t=this.tokenizer.rules.inline.link;for(let s of e.matchAll(this.tokenizer.rules.inline.blockSkip))if(t.test(s[0])&&e.charAt(s.index-1)!=="!")return!0;for(let s of e.matchAll(this.tokenizer.rules.inline.reflinkSearch)){let r=s[0],i=r.lastIndexOf("[");if(!(r.charAt(0)==="!"||!Object.hasOwn(this.tokens.links,F(r.slice(i+1,-1))))&&!(i>1&&this.linkInText(r.slice(1,i-1))))return!0}return!1}inlineTokens(e,t=[]){this.tokenizer.lexer=this;let s=this.state.linkParenPossible;this.state.linkParenPossible=s&&e.includes(")");try{return this.#e(e,t)}finally{this.state.linkParenPossible=s}}#e(e,t){let s=e;if(this.tokens.links&&e.includes("[")){let l=this.tokenizer.rules.inline.reflinkSearch,c=o=>{let h=o.lastIndexOf("[");if(!Object.hasOwn(this.tokens.links,F(o.slice(h+1,-1))))return o;if(h>1&&o.charAt(0)!=="!"){let p=o.slice(1,h-1);if(this.linkInText(p))return"["+p.replace(l,c)+"]["+"a".repeat(o.length-h-2)+"]"}return"["+"a".repeat(o.length-2)+"]"};s=s.replace(l,c)}s=s.replace(this.tokenizer.rules.inline.anyPunctuation,l=>"+".repeat(l.length)),s=s.replace(this.tokenizer.rules.inline.blockSkip,(l,c,o)=>{let h=o?o.length:0;return l.slice(0,h)+"["+"a".repeat(l.length-h-2)+"]"}),s=this.options.hooks?.emStrongMask?.call({lexer:this},s)??s;let r=!1,i="",a=1/0;for(;e;){if(e.length<a)a=e.length;else{this.infiniteLoopError(e.charCodeAt(0));break}r||(i=""),r=!1;let l;if(this.options.extensions?.inline?.some(o=>(l=o.call({lexer:this},e,t))?(e=e.substring(l.raw.length),t.push(l),!0):!1))continue;if(l=this.tokenizer.escape(e)){e=e.substring(l.raw.length),t.push(l);continue}if(l=this.tokenizer.tag(e)){e=e.substring(l.raw.length),t.push(l);continue}if(l=this.tokenizer.link(e)){e=e.substring(l.raw.length),t.push(l);continue}if(l=this.tokenizer.reflink(e,this.tokens.links)){e=e.substring(l.raw.length);let o=t.at(-1);l.type==="text"&&o?.type==="text"?(o.raw+=l.raw,o.text+=l.text):t.push(l);continue}if(l=this.tokenizer.emStrong(e,s,i)){e=e.substring(l.raw.length),t.push(l);continue}if(l=this.tokenizer.codespan(e)){e=e.substring(l.raw.length),t.push(l);continue}if(l=this.tokenizer.br(e)){e=e.substring(l.raw.length),t.push(l);continue}if(l=this.tokenizer.del(e,s,i)){e=e.substring(l.raw.length),t.push(l);continue}if(l=this.tokenizer.autolink(e)){e=e.substring(l.raw.length),t.push(l);continue}if(!this.state.inLink&&(l=this.tokenizer.url(e))){e=e.substring(l.raw.length),t.push(l);continue}let c=e;if(this.options.extensions?.startInline){let o=1/0,h=e.slice(1),p;this.options.extensions.startInline.forEach(k=>{p=k.call({lexer:this},h),typeof p=="number"&&p>=0&&(o=Math.min(o,p))}),o<1/0&&o>=0&&(c=e.substring(0,o+1))}if(l=this.tokenizer.inlineText(c)){e=e.substring(l.raw.length),l.raw.slice(-1)!=="_"&&(i=l.raw.slice(-1)),r=!0;let o=t.at(-1);o?.type==="text"?(o.raw+=l.raw,o.text+=l.text):t.push(l);continue}if(e){this.infiniteLoopError(e.charCodeAt(0));break}}return t}infiniteLoopError(e){let t="Infinite loop on byte: "+e;if(this.options.silent)console.error(t);else throw new Error(t)}},V=class{options;parser;constructor(n){this.options=n||A}space(n){return""}code({text:n,lang:e,escaped:t}){let s=(e||"").match(x.notSpaceStart)?.[0],r=n?n.replace(x.endingNewline,"")+`
`:"";return s?'<pre><code class="language-'+y(s)+'">'+(t?r:y(r,!0))+`</code></pre>
`:"<pre><code>"+(t?r:y(r,!0))+`</code></pre>
`}blockquote({tokens:n}){return`<blockquote>
${this.parser.parse(n)}</blockquote>
`}html({text:n}){return n}def(n){return""}heading({tokens:n,depth:e}){return`<h${e}>${this.parser.parseInline(n)}</h${e}>
`}hr(n){return`<hr>
`}list(n){let e=n.ordered,t=n.start,s="";for(let a=0;a<n.items.length;a++){let l=n.items[a];s+=this.listitem(l)}let r=e?"ol":"ul",i=e&&t!==1?' start="'+t+'"':"";return"<"+r+i+`>
`+s+"</"+r+`>
`}listitem(n){return`<li>${this.parser.parse(n.tokens)}</li>
`}checkbox({checked:n}){return"<input "+(n?'checked="" ':"")+'disabled="" type="checkbox"> '}paragraph({tokens:n}){return`<p>${this.parser.parseInline(n)}</p>
`}table(n){let e="",t="";for(let r=0;r<n.header.length;r++)t+=this.tablecell(n.header[r]);e+=this.tablerow({text:t});let s="";for(let r=0;r<n.rows.length;r++){let i=n.rows[r];t="";for(let a=0;a<i.length;a++)t+=this.tablecell(i[a]);s+=this.tablerow({text:t})}return s&&(s=`<tbody>${s}</tbody>`),`<table>
<thead>
`+e+`</thead>
`+s+`</table>
`}tablerow({text:n}){return`<tr>
${n}</tr>
`}tablecell(n){let e=this.parser.parseInline(n.tokens),t=n.header?"th":"td";return(n.align?`<${t} align="${n.align}">`:`<${t}>`)+e+`</${t}>
`}strong({tokens:n}){return`<strong>${this.parser.parseInline(n)}</strong>`}em({tokens:n}){return`<em>${this.parser.parseInline(n)}</em>`}codespan({text:n}){return`<code>${y(n,!0)}</code>`}br(n){return"<br>"}del({tokens:n}){return`<del>${this.parser.parseInline(n)}</del>`}link({href:n,title:e,text:t,tokens:s,autolink:r}){let i=r?y(t,!0):this.parser.parseInline(s),a=Ne(n);if(a===null)return i;n=y(a,r);let l='<a href="'+n+'"';return e&&(l+=' title="'+y(e)+'"'),l+=">"+i+"</a>",l}image({href:n,title:e,text:t,tokens:s}){s&&(t=this.parser.parseInline(s,this.parser.textRenderer));let r=Ne(n);if(r===null)return y(t);n=r;let i=`<img src="${y(n)}" alt="${y(t)}"`;return e&&(i+=` title="${y(e)}"`),i+=">",i}text(n){return"tokens"in n&&n.tokens?this.parser.parseInline(n.tokens):"escaped"in n&&n.escaped?n.text:y(n.text)}},ue=class{strong({text:n}){return n}em({text:n}){return n}codespan({text:n}){return n}del({text:n}){return n}html({text:n}){return n}text({text:n}){return n}link({text:n}){return""+n}image({text:n}){return""+n}br(){return""}checkbox({raw:n}){return n}},S=class se{options;renderer;textRenderer;constructor(e){this.options=e||A,this.options.renderer=this.options.renderer||new V,this.renderer=this.options.renderer,this.renderer.options=this.options,this.renderer.parser=this,this.textRenderer=new ue}static parse(e,t){return new se(t).parse(e)}static parseInline(e,t){return new se(t).parseInline(e)}parse(e){this.renderer.parser=this;let t="";for(let s=0;s<e.length;s++){let r=e[s];if(this.options.extensions?.renderers?.[r.type]){let a=r,l=this.options.extensions.renderers[a.type].call({parser:this},a);if(l!==!1||!["space","hr","heading","code","table","blockquote","list","checkbox","html","def","paragraph","text"].includes(a.type)){t+=l||"";continue}}let i=r;switch(i.type){case"space":{t+=this.renderer.space(i);break}case"hr":{t+=this.renderer.hr(i);break}case"heading":{t+=this.renderer.heading(i);break}case"code":{t+=this.renderer.code(i);break}case"table":{t+=this.renderer.table(i);break}case"blockquote":{t+=this.renderer.blockquote(i);break}case"list":{t+=this.renderer.list(i);break}case"checkbox":{t+=this.renderer.checkbox(i);break}case"html":{t+=this.renderer.html(i);break}case"def":{t+=this.renderer.def(i);break}case"paragraph":{t+=this.renderer.paragraph(i);break}case"text":{t+=this.renderer.text(i);break}default:{let a='Token with "'+i.type+'" type was not found.';if(this.options.silent)return console.error(a),"";throw new Error(a)}}}return t}parseInline(e,t=this.renderer){this.renderer.parser=this;let s="";for(let r=0;r<e.length;r++){let i=e[r];if(this.options.extensions?.renderers?.[i.type]){let l=this.options.extensions.renderers[i.type].call({parser:this},i);if(l!==!1||!["escape","html","link","image","checkbox","strong","em","codespan","br","del","text"].includes(i.type)){s+=l||"";continue}}let a=i;switch(a.type){case"escape":{s+=t.text(a);break}case"html":{s+=t.html(a);break}case"link":{s+=t.link(a);break}case"image":{s+=t.image(a);break}case"checkbox":{s+=t.checkbox(a);break}case"strong":{s+=t.strong(a);break}case"em":{s+=t.em(a);break}case"codespan":{s+=t.codespan(a);break}case"br":{s+=t.br(a);break}case"del":{s+=t.del(a);break}case"text":{s+=t.text(a);break}default:{let l='Token with "'+a.type+'" type was not found.';if(this.options.silent)return console.error(l),"";throw new Error(l)}}}return s}},M=class{options;block;constructor(n){this.options=n||A}static passThroughHooks=new Set(["preprocess","postprocess","processAllTokens","emStrongMask"]);static passThroughHooksRespectAsync=new Set(["preprocess","postprocess","processAllTokens"]);preprocess(n){return n}postprocess(n){return n}processAllTokens(n){return n}emStrongMask(n){return n}provideLexer(n=this.block){return n?v.lex:v.lexInline}provideParser(n=this.block){return n?S.parse:S.parseInline}},X=class{defaults=ie();options=this.setOptions;parse=this.parseMarkdown(!0);parseInline=this.parseMarkdown(!1);Parser=S;Renderer=V;TextRenderer=ue;Lexer=v;Tokenizer=W;Hooks=M;constructor(...n){this.use(...n)}walkTokens(n,e){let t=[];for(let s of n)switch(t=t.concat(e.call(this,s)),s.type){case"table":{let r=s;for(let i of r.header)t=t.concat(this.walkTokens(i.tokens,e));for(let i of r.rows)for(let a of i)t=t.concat(this.walkTokens(a.tokens,e));break}case"list":{let r=s;t=t.concat(this.walkTokens(r.items,e));break}default:{let r=s;this.defaults.extensions?.childTokens?.[r.type]?this.defaults.extensions.childTokens[r.type].forEach(i=>{let a=r[i].flat(1/0);t=t.concat(this.walkTokens(a,e))}):r.tokens&&(t=t.concat(this.walkTokens(r.tokens,e)))}}return t}use(...n){let e=this.defaults.extensions||{renderers:{},childTokens:{}};return n.forEach(t=>{let s={...t};if(s.async=this.defaults.async||s.async||!1,t.extensions&&(t.extensions.forEach(r=>{if(!r.name)throw new Error("extension name required");if("renderer"in r){let i=e.renderers[r.name];i?e.renderers[r.name]=function(...a){let l=r.renderer.apply(this,a);return l===!1&&(l=i.apply(this,a)),l}:e.renderers[r.name]=r.renderer}if("tokenizer"in r){if(!r.level||r.level!=="block"&&r.level!=="inline")throw new Error("extension level must be 'block' or 'inline'");let i=e[r.level];i?i.unshift(r.tokenizer):e[r.level]=[r.tokenizer],r.start&&(r.level==="block"?e.startBlock?e.startBlock.push(r.start):e.startBlock=[r.start]:r.level==="inline"&&(e.startInline?e.startInline.push(r.start):e.startInline=[r.start]))}"childTokens"in r&&r.childTokens&&(e.childTokens[r.name]=r.childTokens)}),s.extensions=e),t.renderer){let r=this.defaults.renderer||new V(this.defaults);for(let i in t.renderer){if(!(i in r))throw new Error(`renderer '${i}' does not exist`);if(["options","parser"].includes(i))continue;let a=i,l=t.renderer[a],c=r[a];r[a]=(...o)=>{let h=l.apply(r,o);return h===!1&&(h=c.apply(r,o)),h||""}}s.renderer=r}if(t.tokenizer){let r=this.defaults.tokenizer||new W(this.defaults);for(let i in t.tokenizer){if(!(i in r))throw new Error(`tokenizer '${i}' does not exist`);if(["options","rules","lexer"].includes(i))continue;let a=i,l=t.tokenizer[a],c=r[a];r[a]=(...o)=>{let h=l.apply(r,o);return h===!1&&(h=c.apply(r,o)),h}}s.tokenizer=r}if(t.hooks){let r=this.defaults.hooks||new M;for(let i in t.hooks){if(!(i in r))throw new Error(`hook '${i}' does not exist`);if(["options","block"].includes(i))continue;let a=i,l=t.hooks[a],c=r[a];M.passThroughHooks.has(i)?r[a]=o=>{if(this.defaults.async&&M.passThroughHooksRespectAsync.has(i))return(async()=>{let p=await l.call(r,o);return c.call(r,p)})();let h=l.call(r,o);return c.call(r,h)}:r[a]=(...o)=>{if(this.defaults.async)return(async()=>{let p=await l.apply(r,o);return p===!1&&(p=await c.apply(r,o)),p})();let h=l.apply(r,o);return h===!1&&(h=c.apply(r,o)),h}}s.hooks=r}if(t.walkTokens){let r=this.defaults.walkTokens,i=t.walkTokens;s.walkTokens=function(a){let l=[];return l.push(i.call(this,a)),r&&(l=l.concat(r.call(this,a))),l}}this.defaults={...this.defaults,...s}}),this}setOptions(n){return this.defaults={...this.defaults,...n},this}lexer(n,e){return v.lex(n,e??this.defaults)}parser(n,e){return S.parse(n,e??this.defaults)}parseMarkdown(n){return(e,t)=>{let s={...t},r={...this.defaults,...s},i=this.onError(!!r.silent,!!r.async);if(this.defaults.async===!0&&s.async===!1)return i(new Error("marked(): The async option was set to true by an extension. Remove async: false from the parse options object to return a Promise."));if(typeof e>"u"||e===null)return i(new Error("marked(): input parameter is undefined or null"));if(typeof e!="string")return i(new Error("marked(): input parameter is of type "+Object.prototype.toString.call(e)+", string expected"));if(r.hooks&&(r.hooks.options=r,r.hooks.block=n),r.async)return(async()=>{let a=r.hooks?await r.hooks.preprocess(e):e,l=await(r.hooks?await r.hooks.provideLexer(n):n?v.lex:v.lexInline)(a,r),c=r.hooks?await r.hooks.processAllTokens(l):l;r.walkTokens&&await Promise.all(this.walkTokens(c,r.walkTokens));let o=await(r.hooks?await r.hooks.provideParser(n):n?S.parse:S.parseInline)(c,r);return r.hooks?await r.hooks.postprocess(o):o})().catch(i);try{r.hooks&&(e=r.hooks.preprocess(e));let a=(r.hooks?r.hooks.provideLexer(n):n?v.lex:v.lexInline)(e,r);r.hooks&&(a=r.hooks.processAllTokens(a)),r.walkTokens&&this.walkTokens(a,r.walkTokens);let l=(r.hooks?r.hooks.provideParser(n):n?S.parse:S.parseInline)(a,r);return r.hooks&&(l=r.hooks.postprocess(l)),l}catch(a){return i(a)}}}onError(n,e){return t=>{if(t.message+=`
Please report this to https://github.com/markedjs/marked.`,n){let s="<p>An error occurred:</p><pre>"+y(t.message+"",!0)+"</pre>";return e?Promise.resolve(s):s}if(e)return Promise.reject(t);throw t}}},T=new X;function g(n,e){return T.parse(n,e)}g.options=g.setOptions=function(n){return T.setOptions(n),g.defaults=T.defaults,Fe(g.defaults),g};g.getDefaults=ie;g.defaults=A;function lr(...n){return T.use(...n),g.defaults=T.defaults,Fe(g.defaults),g}g.use=lr;g.walkTokens=function(n,e){return T.walkTokens(n,e)};g.parseInline=T.parseInline;g.Parser=S;g.parser=S.parse;g.Renderer=V;g.TextRenderer=ue;g.Lexer=v;g.lexer=v.lex;g.Tokenizer=W;g.Hooks=M;g.parse=g;var Ar=g.options,zr=g.setOptions,Pr=g.walkTokens,Lr=g.parseInline;var Cr=S.parse,Er=v.lex;var ar=300;function or(n){return n.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}var cr=new X({gfm:!0,breaks:!1,async:!1,renderer:{html(n){let e=or(n.text);return n.block?`<p>${e}</p>`:e}}}),hr=new X({gfm:!0,breaks:!1,async:!1});function rt(n,e){let t=e.allowHtml?hr:cr,s=ur(),r=pr(t,n,s),i=Re(r,{images:e.images,externalLinks:e.externalLinks,baseUrl:e.baseUrl,lineMarkers:s}),a=dr(i,e),l=fr(i,e);for(let c of Array.from(i.querySelectorAll('li > input[type="checkbox"]'))){let o=(c.parentElement?.textContent??"").replace(/\s+/g," ").trim().slice(0,200);o&&c.setAttribute("aria-label",o)}for(let c of Array.from(i.querySelectorAll("table"))){let o=c.querySelector("caption")?.textContent?.trim(),h=m("div",{class:"table-wrap",attrs:{tabindex:"0",role:"region","aria-label":o||e.tableLabel}});c.replaceWith(h),h.append(c)}return{fragment:i,headings:a,codeBlocks:l}}function pr(n,e,t){let s=n.lexer(e),r=1,i="";for(let a of s)a.type!=="space"&&a.type!=="def"&&(i+=`<span data-vt-line="${r}:${t}"></span>`),i+=n.parser(Object.assign([a],{links:s.links})),r+=(a.raw.match(/\n/g)??[]).length;return i}function ur(){let n=new Uint8Array(12);return crypto.getRandomValues(n),Array.from(n,e=>e.toString(16).padStart(2,"0")).join("")}function dr(n,e){let t=[],s=new Map;for(let r of Array.from(n.querySelectorAll("h1, h2, h3, h4, h5, h6"))){let i=(r.textContent??"").trim(),a=gr(i,s);if(r.id=a,r.setAttribute("tabindex","-1"),t.length<ar&&t.push({level:Number(r.localName[1]),text:i.slice(0,200),id:a}),e.anchors){let l=m("a",{class:"anchor",part:"anchor",attrs:{href:`#${a}`,"aria-label":`${e.anchorLabel}: ${i.slice(0,100)}`}});l.append(ye("link")),r.append(l)}}return t}function gr(n,e){let t=n.trim().toLowerCase().replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu,"").replace(/ /g,"-").slice(0,100)||"section",s=t;for(let r=e.get(t)??0;e.has(s);r+=1)s=`${t}-${r+1}`,e.set(t,r+1);return e.set(s,e.get(s)??0),s}function fr(n,e){let t=[];for(let s of Array.from(n.querySelectorAll("pre > code"))){let r=s.parentElement,i=/language-([\w#+.-]+)/.exec(s.className)?.[1]??"",a=Te(i),l=(s.textContent??"").replace(/\n$/,"");a&&a!=="plaintext"&&l.length<=e.highlightLimit&&(Ae(a)?s.replaceChildren(Pe(l,a)):ze(a).then(o=>o&&e.onLanguageLoaded())),r.setAttribute("tabindex","0");let c=m("div",{class:"code-block",part:"code-block",attrs:{"data-language":a??""}});r.replaceWith(c),c.append(r),t.push(c)}return t}var K=class{constructor(e,t){this.source=e,this.preview=t,this.anchors=null,this.lockedUntil=new Map,this.onSourceScroll=()=>this.follow(this.source,this.preview),this.onPreviewScroll=()=>this.follow(this.preview,this.source),this.resize=new ResizeObserver(()=>{this.anchors=null})}start(){this.source.addEventListener("scroll",this.onSourceScroll,{passive:!0}),this.preview.addEventListener("scroll",this.onPreviewScroll,{passive:!0});for(let e of[this.source,this.preview])this.resize.observe(e),e.firstElementChild&&this.resize.observe(e.firstElementChild);return this}stop(){this.source.removeEventListener("scroll",this.onSourceScroll),this.preview.removeEventListener("scroll",this.onPreviewScroll),this.resize.disconnect()}follow(e,t){if(performance.now()<(this.lockedUntil.get(e)??0))return;let s=this.anchors??(this.anchors=this.measure());if(s.length<2)return;let r=e===this.source?"source":"preview",i=r==="source"?"preview":"source",a=e.scrollTop,l=0;for(;l<s.length-2&&s[l+1][r]<=a;)l+=1;let c=s[l],o=s[l+1],h=o[r]-c[r],p=h>0?Math.min(1,Math.max(0,(a-c[r])/h)):0,k=Math.round(c[i]+p*(o[i]-c[i]));Math.abs(t.scrollTop-k)<1||(this.lockedUntil.set(t,performance.now()+150),t.scrollTop=k)}measure(){let e=this.source.querySelectorAll(".line"),t=e[0];if(!t)return[];let s=this.source.querySelector(".chunk")!==null,r=de(this.source,t),i=t.getBoundingClientRect().height||1,a=h=>{if(s)return r+(h-1)*i;let p=e[h-1];return p?de(this.source,p):r+(h-1)*i},l=Math.max(0,this.source.scrollHeight-this.source.clientHeight),c=Math.max(0,this.preview.scrollHeight-this.preview.clientHeight),o=[{source:0,preview:0}];for(let h of this.preview.querySelectorAll("[data-vt-line]")){let p=Number(h.getAttribute("data-vt-line")),k=h.nextElementSibling??h,f={source:a(p),preview:de(this.preview,k)},u=o[o.length-1];f.source>u.source&&f.preview>u.preview&&o.push(f)}for(;o.length>1;){let h=o[o.length-1];if(h.source<l&&h.preview<c)break;o.pop()}return o.push({source:l,preview:c}),o}};function de(n,e){return e.getBoundingClientRect().top-n.getBoundingClientRect().top+n.scrollTop}var Y=["preview","source","split"],kr={preview:"eye",source:"code",split:"columns"},br=["right","left","bottom","top"],mr={right:"left",left:"right",bottom:"top",top:"bottom"},xr={right:"bottom",bottom:"right",left:"top",top:"left"},J=class extends $e{static type="markdown";static componentAttributes=Object.freeze(["tabs","default-tab","toc","anchors","allow-html","external-links","images","line-numbers","split-preview","sync-scroll","split-controls"]);static presets={simple:{"line-numbers":!0,"sync-scroll":!0},full:{header:!0,dot:!0,copy:!0,search:!0,download:!0,toc:!0,anchors:!0,"line-numbers":!0,"sync-scroll":!0,"split-controls":!0,fullscreen:!0}};static styles=[fe,ke,Ie];constructor(){super(),this.tab=null,this.panelId=xe("panel"),this.cache=null,this.position=null,this.sync=null,this.scrollSync=null,this.editor=null,this.previewTimer=void 0}disconnectedCallback(){clearTimeout(this.previewTimer),this.editor?.destroy(),this.scrollSync?.stop(),this.scrollSync=null,super.disconnectedCallback()}get previewPosition(){return this.position??I(this.getAttribute("split-preview"),br,"right")}get syncScroll(){return this.sync??this.feature("sync-scroll")}attributeChangedCallback(e,t,s){(e==="default-tab"||e==="tabs")&&(this.tab=null),e==="split-preview"&&(this.position=null),e==="sync-scroll"&&(this.sync=null),super.attributeChangedCallback(e,t,s)}contentChanged(){this.cache=null}get visibleTabs(){return this.hasAttribute("tabs")?me(this.getAttribute("tabs"),Y)??[]:this.variant==="full"?[...Y]:[]}get activeTab(){let e=this.visibleTabs,t=e.length?e:[...Y],s=this.editing&&t.includes("split")?"split":"preview",r=t.includes(s)?s:t[0],i=this.tab??I(this.getAttribute("default-tab"),Y,r);return t.includes(i)?i:r}rendered(){let e={allowHtml:be(this.getAttribute("allow-html"))===!0,images:I(this.getAttribute("images"),["allow","block","same-origin"],"allow"),externalLinks:I(this.getAttribute("external-links"),["new-tab","same"],"new-tab"),baseUrl:this.baseUrl(),anchors:this.feature("anchors"),anchorLabel:this.t("anchor"),tableLabel:this.t("table"),highlightLimit:D().highlightLimit,onLanguageLoaded:()=>{this.cache=null,this.requestRender()}},t=JSON.stringify({...e,onLanguageLoaded:void 0});if(!this.cache||this.cache.key!==t)try{this.cache={key:t,result:rt(this.text??"",e),error:null}}catch(a){this.cache={key:t,result:null,error:a instanceof RangeError?new we("tooComplex",{},a):a}}if(this.cache.error||!this.cache.result)throw this.cache.error;let{fragment:s,headings:r}=this.cache.result,i=s.cloneNode(!0);return{fragment:i,headings:r,codeBlocks:Array.from(i.querySelectorAll(".code-block"))}}baseUrl(){let e=this.getAttribute("src");if(!(!e||this._content!==void 0))try{return new URL(e,document.baseURI).href}catch{return}}renderContent(e){let t=this.t,s=this.activeTab;e.classList.add("md"),this.scrollSync?.stop(),this.scrollSync=null;let r=null,i=null,a=[];try{(s==="preview"||s==="split")&&(r=this.previewPane(),a.push(new te(r.querySelector(".markdown"),{skip:".anchor"})))}catch(u){this.setError(u);return}if((s==="source"||s==="split")&&this.editing)i=this.editorPane();else if(s==="source"||s==="split"){let u=Le(this.text??"",{language:"markdown",lineNumbers:this.feature("line-numbers"),startLine:1,highlightRanges:[],diff:!1,highlightLimit:D().highlightLimit});i=m("div",{class:"body",part:"body source",attrs:{tabindex:"0",role:"region","aria-label":t("source")}},u.element),a.push(new te(u.code))}let l=ve(a,Ce),c=this.visibleTabs,o=c.length>1?Se({tabs:c.map(u=>({id:u,label:t(u),icon:kr[u]})),selected:s,label:t("tabs"),panelId:this.panelId,onSelect:u=>this.selectTab(u)}):null,h=[this.searchButton(l),...s==="split"&&this.feature("split-controls")?this.splitButtons():[],...this.editor&&this.editing?this.historyButtons(this.editor):[],this.editToggleButton(),this.fullscreenButton(),this.feature("download")?this.downloadButton(()=>this.text??"",this.downloadName("document.md"),"text/markdown"):null,this.feature("copy")?this.copyButton(()=>this.text??"",t("copySource")):null],p=this.previewPosition,k=m("div",{class:s==="split"?"panel split":"panel",attrs:{id:this.panelId,role:o?"tabpanel":null,"data-preview":s==="split"?p:null}}),f=p==="left"||p==="top";for(let u of f?[r,i]:[i,r])u&&k.append(u);e.append(...this.chrome({tabs:o,actions:h}),k),this.editor?.align(),this.startSync()}startSync(){this.scrollSync?.stop(),this.scrollSync=null;let e=this.root.querySelector('.split > [part~="source"]'),t=this.root.querySelector('.split > [part~="preview"]');e&&t&&this.syncScroll&&(this.scrollSync=new K(e,t).start())}editorPane(){return this.editor?.destroy(),this.editor=new Ee({text:this.text??"",language:"markdown",lineNumbers:this.feature("line-numbers"),wrap:!0,highlightLimit:D().highlightLimit,label:this.heading||this.t("editor"),placeholder:this.getAttribute("placeholder")??void 0,onInput:e=>this.edited(e),onChange:e=>Q(this,H.CHANGE,{value:e}),history:this.editHistory??void 0}),m("div",{class:"body editor-body",part:"body source"},this.editor.element)}contentEdited(){this.cache=null,clearTimeout(this.previewTimer),this.previewTimer=setTimeout(()=>this.refreshPreview(),120)}refreshPreview(){let e=this.root.querySelector('[part~="preview"]');if(!e)return;let t;try{t=this.previewPane()}catch(s){let{title:r,detail:i}=this.describeError(s);t=m("div",{class:"body md-body",part:"body preview"},_e(r,i))}e.replaceWith(t),t.scrollTop=e.scrollTop,this.startSync(),this.scrollSync?.follow(this.scrollSync.source,this.scrollSync.preview),this.searchOpen&&this.searchQuery&&this.searchBar?.run()}splitButtons(){let e=this.t,t=this.previewPosition,s=t==="top"||t==="bottom";return[U({icon:"swap",label:e("swapPanes"),key:"swap-panes",part:"swap-button",onClick:()=>this.changeLayout(mr[t],this.syncScroll)}),U({icon:"rows",label:e("stackPanes"),key:"stack-panes",part:"stack-button",pressed:s,onClick:()=>this.changeLayout(xr[t],this.syncScroll)}),U({icon:"sync-scroll",label:e("syncScroll"),key:"sync-scroll",part:"sync-button",pressed:this.syncScroll,onClick:()=>this.changeLayout(t,!this.syncScroll)})]}changeLayout(e,t){this.position=e,this.sync=t,this.render(),Q(this,H.LAYOUT_CHANGE,{preview:e,sync:t})}previewPane(){let{fragment:e,headings:t,codeBlocks:s}=this.rendered(),r=m("div",{class:"markdown",part:"markdown"});if(r.append(e),this.feature("copy"))for(let a of s){let l=a.querySelector("pre");a.append(this.copyButton(()=>(l?.textContent??"").replace(/\n$/,""),this.t("copyCode"),`copy-block-${s.indexOf(a)}`))}let i=m("div",{class:"body md-body",part:"body preview",attrs:{tabindex:"0",role:"region","aria-label":this.heading||this.t("preview")}});return this.feature("toc")&&t.length>1&&i.append(this.tableOfContents(t)),i.append(r),i.addEventListener("click",a=>this.onLinkClick(a)),i}tableOfContents(e){let t=Math.min(...e.map(r=>r.level)),s=m("ol",{class:"toc-list"});for(let r of e){let i=m("li",{class:`toc-level-${Math.min(r.level-t,3)}`});i.append(m("a",{attrs:{href:`#${r.id}`},text:r.text||"\u2014"})),s.append(i)}return m("nav",{class:"toc",part:"toc",attrs:{"aria-label":this.t("toc")}},m("details",{attrs:{open:!0}},m("summary",{text:this.t("toc")}),s))}onLinkClick(e){if(e.defaultPrevented||e.button!==0||e.metaKey||e.ctrlKey||e.shiftKey)return;let t=e.target.closest?.('a[href^="#"]');if(!t)return;let s=decodeURIComponent((t.getAttribute("href")??"").slice(1)),r=s?this.root.getElementById(s):null;r&&(e.preventDefault(),r.scrollIntoView({block:"start",behavior:matchMedia("(prefers-reduced-motion: reduce)").matches?"auto":"smooth"}),r.focus({preventScroll:!0}))}selectTab(e){e!==this.activeTab&&(this.tab=e,this.render(),this.root.querySelector(`[data-tab="${e}"]`)?.focus(),Q(this,H.TAB_CHANGE,{tab:e}))}};Be(new URL("../",import.meta.url));customElements.get("vt-markdown")||customElements.define("vt-markdown",J);export{vr as BUILT_IN_THEMES,H as EVENTS,J as VtMarkdown,wr as configure,D as getConfig,$r as getTheme,Rr as listSyntaxThemes,_r as listThemes,yr as registerLocale,Sr as registerTheme};
