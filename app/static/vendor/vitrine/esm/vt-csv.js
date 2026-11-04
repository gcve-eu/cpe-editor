/*! Vitrine | MIT | https://github.com/ecrou-exact/vitrine
 * Source: 7c379edba7ffb89abcae01b0806f20ed43dbc627. Standalone vt-csv bundle.
 * Includes highlight.js (BSD-3-Clause), DOMPurify (Apache-2.0 OR MPL-2.0),
 * and Lucide icons (ISC). See LICENSE and THIRD_PARTY_NOTICES.md. */
var ja=Object.create;var wr=Object.defineProperty;var Ga=Object.getOwnPropertyDescriptor;var Wa=Object.getOwnPropertyNames;var qa=Object.getPrototypeOf,Va=Object.prototype.hasOwnProperty;var Ka=(t,e)=>()=>{try{return e||t((e={exports:{}}).exports,e),e.exports}catch(n){throw e=0,n}};var Ya=(t,e,n,r)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of Wa(e))!Va.call(t,s)&&s!==n&&wr(t,s,{get:()=>e[s],enumerable:!(r=Ga(e,s))||r.enumerable});return t};var Xa=(t,e,n)=>(n=t!=null?ja(qa(t)):{},Ya(e||!t||!t.__esModule?wr(n,"default",{value:t,enumerable:!0}):n,t));var Ps=Ka((Ul,Ds)=>{function Ts(t){return t instanceof Map?t.clear=t.delete=t.set=function(){throw new Error("map is read-only")}:t instanceof Set&&(t.add=t.clear=t.delete=function(){throw new Error("set is read-only")}),Object.freeze(t),Object.getOwnPropertyNames(t).forEach(e=>{let n=t[e],r=typeof n;(r==="object"||r==="function")&&!Object.isFrozen(n)&&Ts(n)}),t}var Xt=class{constructor(e){e.data===void 0&&(e.data={}),this.data=e.data,this.isMatchIgnored=!1}ignoreMatch(){this.isMatchIgnored=!0}};function ws(t){return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;")}function Pe(t,...e){let n=Object.create(null);for(let r in t)n[r]=t[r];return e.forEach(function(r){for(let s in r)n[s]=r[s]}),n}var Bi="</span>",bs=t=>!!t.scope,Hi=(t,{prefix:e})=>{if(t.startsWith("language:"))return t.replace("language:","language-");if(t.includes(".")){let n=t.split(".");return[`${e}${n.shift()}`,...n.map((r,s)=>`${r}${"_".repeat(s+1)}`)].join(" ")}return`${e}${t}`},Hn=class{constructor(e,n){this.buffer="",this.classPrefix=n.classPrefix,e.walk(this)}addText(e){this.buffer+=ws(e)}openNode(e){if(!bs(e))return;let n=Hi(e.scope,{prefix:this.classPrefix});this.span(n)}closeNode(e){bs(e)&&(this.buffer+=Bi)}value(){return this.buffer}span(e){this.buffer+=`<span class="${e}">`}},ys=(t={})=>{let e={children:[]};return Object.assign(e,t),e},Fn=class t{constructor(){this.rootNode=ys(),this.stack=[this.rootNode]}get top(){return this.stack[this.stack.length-1]}get root(){return this.rootNode}add(e){this.top.children.push(e)}openNode(e){let n=ys({scope:e});this.add(n),this.stack.push(n)}closeNode(){if(this.stack.length>1)return this.stack.pop()}closeAllNodes(){for(;this.closeNode(););}toJSON(){return JSON.stringify(this.rootNode,null,4)}walk(e){return this.constructor._walk(e,this.rootNode)}static _walk(e,n){return typeof n=="string"?e.addText(n):n.children&&(e.openNode(n),n.children.forEach(r=>this._walk(e,r)),e.closeNode(n)),e}static _collapse(e){typeof e!="string"&&e.children&&(e.children.every(n=>typeof n=="string")?e.children=[e.children.join("")]:e.children.forEach(n=>{t._collapse(n)}))}},$n=class extends Fn{constructor(e){super(),this.options=e}addText(e){e!==""&&this.add(e)}startScope(e){this.openNode(e)}endScope(){this.closeNode()}__addSublanguage(e,n){let r=e.root;n&&(r.scope=`language:${n}`),this.add(r)}toHTML(){return new Hn(this,this.options).value()}finalize(){return this.closeAllNodes(),!0}};function yt(t){return t?typeof t=="string"?t:t.source:null}function Ss(t){return qe("(?=",t,")")}function Fi(t){return qe("(?:",t,")*")}function $i(t){return qe("(?:",t,")?")}function qe(...t){return t.map(n=>yt(n)).join("")}function ji(t){let e=t[t.length-1];return typeof e=="object"&&e.constructor===Object?(t.splice(t.length-1,1),e):{}}function Qt(...t){return"("+(ji(t).capture?"":"?:")+t.map(r=>yt(r)).join("|")+")"}function As(t){return new RegExp(t.toString()+"|").exec("").length-1}function Gi(t,e){let n=t&&t.exec(e);return n&&n.index===0}var Wi=new RegExp(Qt(/\[(?:[^\\\]]|\\.)*\]/,/\(\?<(?![=!])[^>]+>/,/\(\?'[^']+'/,/\(\??/,/\\([1-9][0-9]*)/,/\\./));function Gn(t,{joinWith:e}){let n=0;return t.map(r=>{n+=1;let s=n,i=yt(r),o="";for(;i.length>0;){let c=Wi.exec(i);if(!c){o+=i;break}o+=i.substring(0,c.index),i=i.substring(c.index+c[0].length),c[0][0]==="\\"&&c[1]?o+="\\"+String(Number(c[1])+s):(o+=c[0],(c[0]==="("||/^\(\?[<']/.test(c[0]))&&n++)}return o}).map(r=>`(${r})`).join(e)}var qi=/\b\B/,Ns="[a-zA-Z]\\w*",Wn="[a-zA-Z_]\\w*",ks="\\b\\d+(\\.\\d+)?",Rs="(-?)(\\b0[xX][a-fA-F0-9]+|(\\b\\d+(\\.\\d*)?|\\.\\d+)([eE][-+]?\\d+)?)",Cs="\\b(0b[01]+)",Vi="!|!=|!==|%|%=|&|&&|&=|\\*|\\*=|\\+|\\+=|,|-|-=|/=|/|:|;|<<|<<=|<=|<|===|==|=|>>>=|>>=|>=|>>>|>>|>|\\?|\\[|\\{|\\(|\\^|\\^=|\\||\\|=|\\|\\||~",Ki=(t={})=>{let e=/^#![ ]*\//;return t.binary&&(t.begin=qe(e,/.*\b/,t.binary,/\b.*/)),Pe({scope:"meta",begin:e,end:/$/,relevance:0,"on:begin":(n,r)=>{n.index!==0&&r.ignoreMatch()}},t)},vt={begin:"\\\\[\\s\\S]",relevance:0},Yi={scope:"string",begin:"'",end:"'",illegal:"\\n",contains:[vt]},Xi={scope:"string",begin:'"',end:'"',illegal:"\\n",contains:[vt]},Zi={begin:/\b(a|an|the|are|I'm|isn't|don't|doesn't|won't|but|just|should|pretty|simply|enough|gonna|going|wtf|so|such|will|you|your|they|like|more)\b/},Jt=function(t,e,n={}){let r=Pe({scope:"comment",begin:t,end:e,contains:[]},n);r.contains.push({scope:"doctag",begin:"[ ]*(?=(TODO|FIXME|NOTE|BUG|OPTIMIZE|HACK|XXX):)",end:/(TODO|FIXME|NOTE|BUG|OPTIMIZE|HACK|XXX):/,excludeBegin:!0,relevance:0});let s=Qt("I","a","is","so","us","to","at","if","in","it","on",/[A-Za-z]+['](d|ve|re|ll|t|s|n)/,/[A-Za-z]+[-][a-z]+/,/[A-Za-z][a-z]{2,}/);return r.contains.push({begin:qe(/[ ]+/,"(",s,/[.]?[:]?([.][ ]|[ ])/,"){3}")}),r},Qi=Jt("//","$"),Ji=Jt("/\\*","\\*/"),eo=Jt("#","$"),to={scope:"number",begin:ks,relevance:0},no={scope:"number",begin:Rs,relevance:0},ro={scope:"number",begin:Cs,relevance:0},so={scope:"regexp",begin:/\/(?=[^/\n]*\/)/,end:/\/[gimuy]*/,contains:[vt,{begin:/\[/,end:/\]/,relevance:0,contains:[vt]}]},ao={scope:"title",begin:Ns,relevance:0},io={scope:"title",begin:Wn,relevance:0},oo={begin:"\\.\\s*"+Wn,relevance:0},co=function(t){return Object.assign(t,{"on:begin":(e,n)=>{n.data._beginMatch=e[1]},"on:end":(e,n)=>{n.data._beginMatch!==e[1]&&n.ignoreMatch()}})},Yt=Object.freeze({__proto__:null,APOS_STRING_MODE:Yi,BACKSLASH_ESCAPE:vt,BINARY_NUMBER_MODE:ro,BINARY_NUMBER_RE:Cs,COMMENT:Jt,C_BLOCK_COMMENT_MODE:Ji,C_LINE_COMMENT_MODE:Qi,C_NUMBER_MODE:no,C_NUMBER_RE:Rs,END_SAME_AS_BEGIN:co,HASH_COMMENT_MODE:eo,IDENT_RE:Ns,MATCH_NOTHING_RE:qi,METHOD_GUARD:oo,NUMBER_MODE:to,NUMBER_RE:ks,PHRASAL_WORDS_MODE:Zi,QUOTE_STRING_MODE:Xi,REGEXP_MODE:so,RE_STARTERS_RE:Vi,SHEBANG:Ki,TITLE_MODE:ao,UNDERSCORE_IDENT_RE:Wn,UNDERSCORE_TITLE_MODE:io});function lo(t,e){t.input[t.index-1]==="."&&e.ignoreMatch()}function uo(t,e){t.className!==void 0&&(t.scope=t.className,delete t.className)}function ho(t,e){e&&t.beginKeywords&&(t.begin="\\b("+t.beginKeywords.split(" ").join("|")+")(?!\\.)(?=\\b|\\s)",t.__beforeBegin=lo,t.keywords=t.keywords||t.beginKeywords,delete t.beginKeywords,t.relevance===void 0&&(t.relevance=0))}function fo(t,e){Array.isArray(t.illegal)&&(t.illegal=Qt(...t.illegal))}function po(t,e){if(t.match){if(t.begin||t.end)throw new Error("begin & end are not supported with match");t.begin=t.match,delete t.match}}function go(t,e){t.relevance===void 0&&(t.relevance=1)}var mo=(t,e)=>{if(!t.beforeMatch)return;if(t.starts)throw new Error("beforeMatch cannot be used with starts");let n=Object.assign({},t);Object.keys(t).forEach(r=>{delete t[r]}),t.keywords=n.keywords,t.begin=qe(n.beforeMatch,Ss(n.begin)),t.starts={relevance:0,contains:[Object.assign(n,{endsParent:!0})]},t.relevance=0,delete n.beforeMatch},bo=["of","and","for","in","not","or","if","then","parent","list","value"],yo="keyword";function Ls(t,e,n=yo){let r=Object.create(null);return typeof t=="string"?s(n,t.split(" ")):Array.isArray(t)?s(n,t):Object.keys(t).forEach(function(i){Object.assign(r,Ls(t[i],e,i))}),r;function s(i,o){e&&(o=o.map(c=>c.toLowerCase())),o.forEach(function(c){let u=c.split("|");r[u[0]]=[i,vo(u[0],u[1])]})}}function vo(t,e){return e?Number(e):_o(t)?0:1}function _o(t){return bo.includes(t.toLowerCase())}var vs={},We=t=>{console.error(t)},_s=(t,...e)=>{console.log(`WARN: ${t}`,...e)},ot=(t,e)=>{vs[`${t}/${e}`]||(console.log(`Deprecated as of ${t}. ${e}`),vs[`${t}/${e}`]=!0)},Zt=new Error;function Os(t,e,{key:n}){let r=0,s=t[n],i={},o={};for(let c=1;c<=e.length;c++)o[c+r]=s[c],i[c+r]=!0,r+=As(e[c-1]);t[n]=o,t[n]._emit=i,t[n]._multi=!0}function xo(t){if(Array.isArray(t.begin)){if(t.skip||t.excludeBegin||t.returnBegin)throw We("skip, excludeBegin, returnBegin not compatible with beginScope: {}"),Zt;if(typeof t.beginScope!="object"||t.beginScope===null)throw We("beginScope must be object"),Zt;Os(t,t.begin,{key:"beginScope"}),t.begin=Gn(t.begin,{joinWith:""})}}function Eo(t){if(Array.isArray(t.end)){if(t.skip||t.excludeEnd||t.returnEnd)throw We("skip, excludeEnd, returnEnd not compatible with endScope: {}"),Zt;if(typeof t.endScope!="object"||t.endScope===null)throw We("endScope must be object"),Zt;Os(t,t.end,{key:"endScope"}),t.end=Gn(t.end,{joinWith:""})}}function To(t){t.scope&&typeof t.scope=="object"&&t.scope!==null&&(t.beginScope=t.scope,delete t.scope)}function wo(t){To(t),typeof t.beginScope=="string"&&(t.beginScope={_wrap:t.beginScope}),typeof t.endScope=="string"&&(t.endScope={_wrap:t.endScope}),xo(t),Eo(t)}function So(t){function e(o,c){return new RegExp(yt(o),"m"+(t.case_insensitive?"i":"")+(t.unicodeRegex?"u":"")+(c?"g":""))}class n{constructor(){this.matchIndexes={},this.regexes=[],this.matchAt=1,this.position=0}addRule(c,u){u.position=this.position++,this.matchIndexes[this.matchAt]=u,this.regexes.push([u,c]),this.matchAt+=As(c)+1}compile(){this.regexes.length===0&&(this.exec=()=>null);let c=this.regexes.map(u=>u[1]);this.matcherRe=e(Gn(c,{joinWith:"|"}),!0),this.lastIndex=0}exec(c){this.matcherRe.lastIndex=this.lastIndex;let u=this.matcherRe.exec(c);if(!u)return null;let d=u.findIndex((E,_)=>_>0&&E!==void 0),f=this.matchIndexes[d];return u.splice(0,d),Object.assign(u,f)}}class r{constructor(){this.rules=[],this.multiRegexes=[],this.count=0,this.lastIndex=0,this.regexIndex=0}getMatcher(c){if(this.multiRegexes[c])return this.multiRegexes[c];let u=new n;return this.rules.slice(c).forEach(([d,f])=>u.addRule(d,f)),u.compile(),this.multiRegexes[c]=u,u}resumingScanAtSamePosition(){return this.regexIndex!==0}considerAll(){this.regexIndex=0}addRule(c,u){this.rules.push([c,u]),u.type==="begin"&&this.count++}exec(c){let u=this.getMatcher(this.regexIndex);u.lastIndex=this.lastIndex;let d=u.exec(c);if(this.resumingScanAtSamePosition()&&!(d&&d.index===this.lastIndex)){let f=this.getMatcher(0);f.lastIndex=this.lastIndex+1,d=f.exec(c)}return d&&(this.regexIndex+=d.position+1,this.regexIndex===this.count&&this.considerAll()),d}}function s(o){let c=new r;return o.contains.forEach(u=>c.addRule(u.begin,{rule:u,type:"begin"})),o.terminatorEnd&&c.addRule(o.terminatorEnd,{type:"end"}),o.illegal&&c.addRule(o.illegal,{type:"illegal"}),c}function i(o,c){let u=o;if(o.isCompiled)return u;[uo,po,wo,mo].forEach(f=>f(o,c)),t.compilerExtensions.forEach(f=>f(o,c)),o.__beforeBegin=null,[ho,fo,go].forEach(f=>f(o,c)),o.isCompiled=!0;let d=null;return typeof o.keywords=="object"&&o.keywords.$pattern&&(o.keywords=Object.assign({},o.keywords),d=o.keywords.$pattern,delete o.keywords.$pattern),d=d||/\w+/,o.keywords&&(o.keywords=Ls(o.keywords,t.case_insensitive)),u.keywordPatternRe=e(d,!0),c&&(o.begin||(o.begin=/\B|\b/),u.beginRe=e(u.begin),!o.end&&!o.endsWithParent&&(o.end=/\B|\b/),o.end&&(u.endRe=e(u.end)),u.terminatorEnd=yt(u.end)||"",o.endsWithParent&&c.terminatorEnd&&(u.terminatorEnd+=(o.end?"|":"")+c.terminatorEnd)),o.illegal&&(u.illegalRe=e(o.illegal)),o.contains||(o.contains=[]),o.contains=[].concat(...o.contains.map(function(f){return Ao(f==="self"?o:f)})),o.contains.forEach(function(f){i(f,u)}),o.starts&&i(o.starts,c),u.matcher=s(u),u}if(t.compilerExtensions||(t.compilerExtensions=[]),t.contains&&t.contains.includes("self"))throw new Error("ERR: contains `self` is not supported at the top-level of a language.  See documentation.");return t.classNameAliases=Pe(t.classNameAliases||{}),i(t)}function Ms(t){return t?t.endsWithParent||Ms(t.starts):!1}function Ao(t){return t.variants&&!t.cachedVariants&&(t.cachedVariants=t.variants.map(function(e){return Pe(t,{variants:null},e)})),t.cachedVariants?t.cachedVariants:Ms(t)?Pe(t,{starts:t.starts?Pe(t.starts):null}):Object.isFrozen(t)?Pe(t):t}var No="11.12.0",jn=class extends Error{constructor(e,n){super(e),this.name="HTMLInjectionError",this.html=n}},Bn=ws,xs=Pe,Es=Symbol("nomatch"),ko=7,Is=function(t){let e=Object.create(null),n=Object.create(null),r=[],s=!0,i="Could not find the language '{}', did you forget to load/include a language module?",o={disableAutodetect:!0,name:"Plain text",contains:[]},c={ignoreUnescapedHTML:!1,throwUnescapedHTML:!1,noHighlightRe:/^(no-?highlight)$/i,languageDetectRe:/\blang(?:uage)?-([\w-]+)\b/i,classPrefix:"hljs-",cssSelector:"pre code",languages:null,__emitter:$n};function u(p){return c.noHighlightRe.test(p)}function d(p){let x=p.className+" ";x+=p.parentNode?p.parentNode.className:"";let A=c.languageDetectRe.exec(x);if(A){let O=re(A[1]);return O||(_s(i.replace("{}",A[1])),_s("Falling back to no-highlight mode for this block.",p)),O?A[1]:"no-highlight"}return x.split(/\s+/).find(O=>u(O)||re(O))}function f(p,x,A){let O="",$="";typeof x=="object"?(O=p,A=x.ignoreIllegals,$=x.language):(ot("10.7.0","highlight(lang, code, ...args) has been deprecated."),ot("10.7.0",`Please use highlight(code, options) instead.
https://github.com/highlightjs/highlight.js/issues/2277`),$=p,O=x),A===void 0&&(A=!0);let ee={code:O,language:$};Ce("before:highlight",ee);let oe=ee.result?ee.result:E(ee.language,ee.code,A);return oe.code=ee.code,Ce("after:highlight",oe),oe}function E(p,x,A,O){let $=Object.create(null);function ee(b,y){return b.keywords[y]}function oe(){if(!w.keywords){X.addText(D);return}let b=0;w.keywordPatternRe.lastIndex=0;let y=w.keywordPatternRe.exec(D),N="";for(;y;){N+=D.substring(b,y.index);let z=ce.case_insensitive?y[0].toLowerCase():y[0],K=ee(w,z);if(K){let[le,dt]=K;if(X.addText(N),N="",$[z]=($[z]||0)+1,$[z]<=ko&&($e+=dt),le.startsWith("_"))N+=y[0];else{let Me=ce.classNameAliases[le]||le;_e(y[0],Me)}}else N+=y[0];b=w.keywordPatternRe.lastIndex,y=w.keywordPatternRe.exec(D)}N+=D.substring(b),X.addText(N)}function Le(){if(D==="")return;let b=null;if(typeof w.subLanguage=="string"){if(!e[w.subLanguage]){X.addText(D);return}b=E(w.subLanguage,D,!0,Oe[w.subLanguage]),Oe[w.subLanguage]=b._top}else b=T(D,w.subLanguage.length?w.subLanguage:null);w.relevance>0&&($e+=b.relevance),X.__addSublanguage(b._emitter,b.language)}function C(){w.subLanguage!=null?Le():oe(),D=""}function _e(b,y){b!==""&&(X.startScope(y),X.addText(b),X.endScope())}function At(b,y){let N=1,z=y.length-1;for(;N<=z;){if(!b._emit[N]){N++;continue}let K=ce.classNameAliases[b[N]]||b[N],le=y[N];K?_e(le,K):(D=le,oe(),D=""),N++}}function Nt(b,y){return b.scope&&typeof b.scope=="string"&&X.openNode(ce.classNameAliases[b.scope]||b.scope),b.beginScope&&(b.beginScope._wrap?(_e(D,ce.classNameAliases[b.beginScope._wrap]||b.beginScope._wrap),D=""):b.beginScope._multi&&(At(b.beginScope,y),D="")),w=Object.create(b,{parent:{value:w}}),w}function kt(b,y,N){let z=Gi(b.endRe,N);if(z){if(b["on:end"]){let K=new Xt(b);b["on:end"](y,K),K.isMatchIgnored&&(z=!1)}if(z){for(;b.endsParent&&b.parent;)b=b.parent;return b}}if(b.endsWithParent)return kt(b.parent,y,N)}function un(b){return w.matcher.regexIndex===0?(D+=b[0],1):(Ze=!0,0)}function dn(b){let y=b[0],N=b.rule,z=new Xt(N),K=[N.__beforeBegin,N["on:begin"]];for(let le of K)if(le&&(le(b,z),z.isMatchIgnored))return un(y);return N.skip?D+=y:(N.excludeBegin&&(D+=y),C(),!N.returnBegin&&!N.excludeBegin&&(D=y)),Nt(N,b),N.returnBegin?0:y.length}function Rt(b){let y=b[0],N=x.substring(b.index),z=kt(w,b,N);if(!z)return Es;let K=w;w.endScope&&w.endScope._wrap?(C(),_e(y,w.endScope._wrap)):w.endScope&&w.endScope._multi?(C(),At(w.endScope,b)):K.skip?D+=y:(K.returnEnd||K.excludeEnd||(D+=y),C(),K.excludeEnd&&(D=y));do w.scope&&X.closeNode(),!w.skip&&!w.subLanguage&&($e+=w.relevance),w=w.parent;while(w!==z.parent);return z.starts&&Nt(z.starts,b),K.returnEnd?0:y.length}function hn(){let b=[];for(let y=w;y!==ce;y=y.parent)y.scope&&b.unshift(y.scope);b.forEach(y=>X.openNode(y))}let He={};function j(b,y){let N=y&&y[0];if(D+=b,N==null)return C(),0;if(He.type==="begin"&&y.type==="end"&&He.index===y.index&&N===""){if(D+=x.slice(y.index,y.index+1),!s){let z=new Error(`0 width match regex (${p})`);throw z.languageName=p,z.badRule=He.rule,z}return 1}if(He=y,y.type==="begin")return dn(y);if(y.type==="illegal"&&!A){let z=new Error('Illegal lexeme "'+N+'" for mode "'+(w.scope||"<unnamed>")+'"');throw z.mode=w,z}else if(y.type==="end"){let z=Rt(y);if(z!==Es)return z}if(y.type==="illegal"&&N==="")return y.index===x.length||(D+=`
`),1;if(Xe>1e5&&Xe>y.index*3)throw new Error("potential infinite loop, way more iterations than matches");return D+=N,N.length}let ce=re(p);if(!ce)throw We(i.replace("{}",p)),new Error('Unknown language: "'+p+'"');let G=So(ce),Fe="",w=O||G,Oe={},X=new c.__emitter(c);hn();let D="",$e=0,Te=0,Xe=0,Ze=!1;try{if(ce.__emitTokens)ce.__emitTokens(x,X);else{for(w.matcher.considerAll();;){Xe++,Ze?Ze=!1:w.matcher.considerAll(),w.matcher.lastIndex=Te;let b=w.matcher.exec(x);if(!b)break;let y=x.substring(Te,b.index),N=j(y,b);Te=b.index+N}j(x.substring(Te))}return X.finalize(),Fe=X.toHTML(),{language:p,value:Fe,relevance:$e,illegal:!1,_emitter:X,_top:w}}catch(b){if(b.message&&b.message.includes("Illegal"))return{language:p,value:Bn(x),illegal:!0,relevance:0,_illegalBy:{message:b.message,index:Te,context:x.slice(Te-100,Te+100),mode:b.mode,resultSoFar:Fe},_emitter:X};if(s)return{language:p,value:Bn(x),illegal:!1,relevance:0,errorRaised:b,_emitter:X,_top:w};throw b}}function _(p){let x={value:Bn(p),illegal:!1,relevance:0,_top:o,_emitter:new c.__emitter(c)};return x._emitter.addText(p),x}function T(p,x){x=x||c.languages||Object.keys(e);let A=_(p),O=x.filter(re).filter(ve).map(C=>E(C,p,!1));O.unshift(A);let $=O.sort((C,_e)=>{if(C.relevance!==_e.relevance)return _e.relevance-C.relevance;if(C.language&&_e.language){if(re(C.language).supersetOf===_e.language)return 1;if(re(_e.language).supersetOf===C.language)return-1}return 0}),[ee,oe]=$,Le=ee;return Le.secondBest=oe,Le}function H(p,x,A){let O=x&&n[x]||A;p.classList.add("hljs"),p.classList.add(`language-${O}`)}function F(p){let x=null,A=d(p);if(u(A))return;if(Ce("before:highlightElement",{el:p,language:A}),p.dataset.highlighted){console.log("Element previously highlighted. To highlight again, first unset `dataset.highlighted`.",p);return}if(p.children.length>0&&(c.ignoreUnescapedHTML||(console.warn("One of your code blocks includes unescaped HTML. This is a potentially serious security risk."),console.warn("https://github.com/highlightjs/highlight.js/wiki/security"),console.warn("The element with unescaped HTML:"),console.warn(p)),c.throwUnescapedHTML))throw new jn("One of your code blocks includes unescaped HTML.",p.innerHTML);x=p;let O=x.textContent,$=A?f(O,{language:A,ignoreIllegals:!0}):T(O);p.innerHTML=$.value,p.dataset.highlighted="yes",H(p,A,$.language),p.result={language:$.language,re:$.relevance,relevance:$.relevance},$.secondBest&&(p.secondBest={language:$.secondBest.language,relevance:$.secondBest.relevance}),Ce("after:highlightElement",{el:p,result:$,text:O})}function U(p){c=xs(c,p)}let L=()=>{R(),ot("10.6.0","initHighlighting() deprecated.  Use highlightAll() now.")};function k(){R(),ot("10.6.0","initHighlightingOnLoad() deprecated.  Use highlightAll() now.")}let I=!1;function R(){function p(){R()}if(document.readyState==="loading"){I||window.addEventListener("DOMContentLoaded",p,!1),I=!0;return}document.querySelectorAll(c.cssSelector).forEach(F)}function W(p,x){let A=null;try{A=x(t)}catch(O){if(We("Language definition for '{}' could not be registered.".replace("{}",p)),s)We(O);else throw O;A=o}A.name||(A.name=p),e[p]=A,A.rawDefinition=x.bind(null,t),A.aliases&&Q(A.aliases,{languageName:p})}function V(p){delete e[p];for(let x of Object.keys(n))n[x]===p&&delete n[x]}function ye(){return Object.keys(e)}function re(p){return p=(p||"").toLowerCase(),e[p]||e[n[p]]}function Q(p,{languageName:x}){typeof p=="string"&&(p=[p]),p.forEach(A=>{n[A.toLowerCase()]=x})}function ve(p){let x=re(p);return x&&!x.disableAutodetect}function Be(p){p["before:highlightBlock"]&&!p["before:highlightElement"]&&(p["before:highlightElement"]=x=>{p["before:highlightBlock"](Object.assign({block:x.el},x))}),p["after:highlightBlock"]&&!p["after:highlightElement"]&&(p["after:highlightElement"]=x=>{p["after:highlightBlock"](Object.assign({block:x.el},x))})}function Ye(p){Be(p),r.push(p)}function Re(p){let x=r.indexOf(p);x!==-1&&r.splice(x,1)}function Ce(p,x){let A=p;r.forEach(function(O){O[A]&&O[A](x)})}function we(p){return ot("10.7.0","highlightBlock will be removed entirely in v12.0"),ot("10.7.0","Please use highlightElement now."),F(p)}Object.assign(t,{highlight:f,highlightAuto:T,highlightAll:R,highlightElement:F,highlightBlock:we,configure:U,initHighlighting:L,initHighlightingOnLoad:k,registerLanguage:W,unregisterLanguage:V,listLanguages:ye,getLanguage:re,registerAliases:Q,autoDetection:ve,inherit:xs,addPlugin:Ye,removePlugin:Re}),t.debugMode=function(){s=!1},t.safeMode=function(){s=!0},t.versionString=No,t.regex={concat:qe,lookahead:Ss,either:Qt,optional:$i,anyNumberOfTimes:Fi};for(let p in Yt)typeof Yt[p]=="object"&&Ts(Yt[p]);return Object.assign(t,Yt),t},ct=Is({});ct.newInstance=()=>Is({});Ds.exports=ct;ct.HighlightJS=ct;ct.default=ct});var Ht=`/*
 * Syntax highlighting roles for highlight.js classes.
 * Mapping: docs/DESIGN_SYSTEM.md \xA72.3. Colors come from theme tokens.
 */
.hljs-keyword,
.hljs-built_in,
.hljs-literal,
.hljs-bullet,
.hljs-doctag {
  color: var(--_syntax-keyword);
}

.hljs-string,
.hljs-regexp,
.hljs-symbol,
.hljs-char,
.hljs-code,
.hljs-link {
  color: var(--_syntax-string);
}

.hljs-number {
  color: var(--_syntax-number);
}

.hljs-title,
.hljs-title.function_,
.hljs-section,
.hljs-selector-class,
.hljs-selector-id {
  color: var(--_syntax-function);
}

.hljs-type,
.hljs-title.class_,
.hljs-title.class_.inherited__ {
  color: var(--_syntax-type);
}

.hljs-comment,
.hljs-quote {
  color: var(--_syntax-comment);
  font-style: italic;
}

.hljs-attr,
.hljs-attribute,
.hljs-property,
.hljs-template-variable,
.hljs-variable.language_ {
  color: var(--_syntax-attr);
}

.hljs-tag,
.hljs-name,
.hljs-selector-tag,
.hljs-selector-pseudo,
.hljs-selector-attr {
  color: var(--_syntax-tag);
}

.hljs-meta,
.hljs-punctuation,
.hljs-operator,
.hljs-tag .hljs-punctuation {
  color: var(--_syntax-meta);
}

.hljs-meta .hljs-keyword {
  color: var(--_syntax-keyword);
}

.hljs-meta .hljs-string {
  color: var(--_syntax-string);
}

.hljs-addition {
  color: var(--_success);
}

.hljs-deletion {
  color: var(--_danger);
}

.hljs-section,
.hljs-strong {
  font-weight: 600;
}

.hljs-emphasis {
  font-style: italic;
}

.hljs-link {
  text-decoration: underline;
  text-underline-offset: 3px;
}
`;var Sr=`/*
 * Code view: used by <vt-code>, the Markdown source tab and the JSON raw view.
 */
.code-view {
  position: relative;
}

.code {
  display: grid;
  width: max-content;
  min-width: 100%;
  margin: 0;
  padding: var(--_space-3) 0;
  color: var(--_code-fg);
  font-family: var(--_font-mono);
  font-size: var(--_font-size);
  font-variant-ligatures: var(--vt-font-ligatures, none);
  line-height: var(--_line-height);
  tab-size: var(--_tab-size);
}

.wrap .code {
  width: auto;
}

.line {
  display: flex;
  min-width: 0;
}

/* Long code: off-screen blocks of lines skip layout and paint. */
.chunk.revealed {
  content-visibility: visible;
}

.chunk {
  display: block;
  content-visibility: auto;
  contain-intrinsic-block-size: auto
    calc(var(--_chunk-lines) * var(--_font-size) * var(--_line-height));
}

/* A block whose lines are not built yet keeps the height they will take. */
.chunk[data-pending] {
  block-size: calc(var(--_chunk-lines) * var(--_font-size) * var(--_line-height));
}

.gutter {
  position: sticky;
  left: 0;
  z-index: 1;
  flex: none;
  min-width: calc(var(--_digits, 2) * 1ch + 2 * var(--_space-3));
  padding: 0 var(--_space-3);
  border-right: 1px solid color-mix(in srgb, var(--_code-gutter) 35%, transparent);
  background: var(--_code-bg-solid);
  color: var(--_code-gutter);
  font-size: var(--_font-size-small);
  line-height: calc(var(--_font-size) * var(--_line-height));
  font-variant-numeric: tabular-nums;
  text-align: right;
  user-select: none;
  -webkit-user-select: none;
}

.gutter::before {
  content: attr(data-n);
}

.sign {
  flex: none;
  width: 2ch;
  padding-left: var(--_space-2);
  color: var(--_fg-muted);
  user-select: none;
  -webkit-user-select: none;
}

.content {
  flex: 1 1 auto;
  min-width: 0;
  padding: 0 var(--_space-4);
  white-space: pre;
}

.sign + .content {
  padding-left: var(--_space-1);
}

.wrap .content {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.line.highlighted {
  background: var(--_line-highlight);
}

.line.highlighted .gutter {
  box-shadow: inset 2px 0 0 var(--_accent);
  color: var(--_code-fg);
}

.line.added {
  background: var(--_diff-added);
}

.line.removed {
  background: var(--_diff-removed);
}

.line.added .sign::before {
  content: '+';
  color: var(--_success);
}

.line.removed .sign::before {
  content: '\\2212';
  color: var(--_danger);
}

.line.hunk .content {
  color: var(--_info);
}

/* Collapsible: show the first N lines, fade the rest. */
.collapsed .code {
  max-height: calc(
    (var(--_collapse-lines) + 0.6) * var(--_font-size) * var(--_line-height) + var(--_space-3)
  );
  overflow: hidden;
}

.collapsed .code-view::after {
  content: '';
  position: absolute;
  inset: auto 0 0;
  height: calc(0.9 * var(--_font-size) * var(--_line-height));
  background: linear-gradient(transparent, var(--_code-bg-solid));
  pointer-events: none;
}

.more {
  display: flex;
  justify-content: center;
  padding: var(--_space-2);
  border-top: 1px solid var(--_border);
  background: var(--_surface);
}

/* ---------- Editor: a transparent textarea laid over the highlighted code ---------- */

.editor {
  position: relative;
  width: max-content;
  min-width: 100%;
}

.editor.wrap {
  width: auto;
}

.editor-layer {
  pointer-events: none;
}

/* Bold or italic tokens can shift characters in some fonts: keep the layer regular. */
.editor-layer .code * {
  font-style: inherit !important;
  font-weight: inherit !important;
}

/* An empty last line still needs its height under the caret. */
.editor-layer .content:empty::before {
  content: '\\200b';
}

.editor-input {
  position: absolute;
  top: 0;
  left: var(--_editor-gutter, 0px);
  width: calc(100% - var(--_editor-gutter, 0px));
  height: 100%;
  margin: 0;
  padding: var(--_space-3) var(--_space-4);
  overflow: hidden;
  border: 0;
  outline: none;
  background: transparent;
  color: transparent;
  -webkit-text-fill-color: transparent;
  caret-color: var(--_code-fg);
  font-family: var(--_font-mono);
  font-size: var(--_font-size);
  font-variant-ligatures: var(--vt-font-ligatures, none);
  line-height: var(--_line-height);
  tab-size: var(--_tab-size);
  white-space: pre;
  overflow-wrap: normal;
  resize: none;
}

.editor.wrap .editor-input {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.editor-input::selection {
  background: color-mix(in srgb, var(--_accent) 32%, transparent);
}

.editor-input::placeholder {
  color: var(--_fg-muted);
  -webkit-text-fill-color: var(--_fg-muted);
  opacity: 1;
}

/* Long text: plain text while typing, highlighting after a pause. */
.editor.pending .editor-input {
  color: var(--_fg);
  -webkit-text-fill-color: var(--_fg);
}

.editor.pending .editor-layer .content {
  visibility: hidden;
}

.body:has(.editor-input:focus) {
  outline: 2px solid var(--_accent);
  outline-offset: -2px;
}

.edit-status {
  display: flex;
  align-items: center;
  gap: var(--_space-2);
  padding: var(--_space-2) var(--_space-3);
  border-top: 1px solid var(--_border);
  background: var(--_surface);
  font-family: var(--_font-ui);
  font-size: var(--_font-size-small);
}

.edit-status.ok {
  color: var(--_success);
}

.edit-status.bad {
  color: var(--_danger);
}

.edit-status .icon {
  width: 14px;
  height: 14px;
  flex: none;
}
`;var Ar=`/*
 * CSV table. Header names are data: their case is kept (no uppercase label style).
 */
.table-host {
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.table-body {
  background: var(--_surface);
}

.grid {
  min-width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  font-family: var(--_font-ui);
  font-size: var(--_font-size-ui);
  font-variant-numeric: tabular-nums;
}

.grid th,
.grid td {
  max-width: 40ch;
  padding: 6px var(--_space-3);
  border-bottom: 1px solid var(--_border);
  text-align: start;
  vertical-align: top;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.grid thead th {
  position: sticky;
  top: 0;
  z-index: 2;
  background: var(--_surface-sunken);
  color: var(--_fg);
  font-weight: 600;
  white-space: nowrap;
}

.grid tbody tr:hover > * {
  background: color-mix(in srgb, var(--_accent-soft) 60%, transparent);
}

.grid .col-number {
  text-align: end;
}

.grid .row-number {
  position: sticky;
  left: 0;
  z-index: 1;
  width: 1%;
  background: var(--_surface);
  color: var(--_fg-muted);
  font-weight: 400;
  text-align: end;
  white-space: nowrap;
}

.grid thead .row-number {
  z-index: 3;
  background: var(--_surface-sunken);
}

.grid .sort {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
  padding: 0;
  border: 0;
  background: none;
  color: inherit;
  font: inherit;
  cursor: pointer;
}

.grid .col-number .sort {
  flex-direction: row-reverse;
}

.grid .sort .name {
  overflow: hidden;
  text-overflow: ellipsis;
}

.grid .sort .icon {
  flex: none;
  width: 14px;
  height: 14px;
  color: var(--_fg-muted);
}

.grid [aria-sort='ascending'] .icon,
.grid [aria-sort='descending'] .icon {
  color: var(--_accent-fg);
}

.grid .no-rows {
  padding: var(--_space-5);
  color: var(--_fg-muted);
  text-align: center;
}

.pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--_space-3);
  min-height: 40px;
  padding: 0 var(--_space-2) 0 var(--_space-3);
  border-top: 1px solid var(--_border);
  background: var(--_surface);
  color: var(--_fg-muted);
  font-family: var(--_font-ui);
  font-size: var(--_font-size-small);
}
`;function De(t){if(t===null)return null;let e=t.trim().toLowerCase();return!(e==="false"||e==="off"||e==="no"||e==="0")}function Nr(t,{min:e,max:n,fallback:r}){if(t===null||t.length>32)return r;let s=t.trim();if(!/^[+-]?\d+$/.test(s))return r;let i=Number(s);return Number.isSafeInteger(i)?Math.min(n,Math.max(e,i)):r}function pt(t,e,n){if(t===null)return n;let r=t.trim().toLowerCase();return e.includes(r)?r:n}function kr(t,e){let n=0,r=e.length-1;for(;n<=r;){let s=n+r>>1,[i,o]=e[s];if(t<i)r=s-1;else if(t>o)n=s+1;else return!0}return!1}function Rr(t){if(t===null)return null;let e=t.trim().toLowerCase();return/^\d{1,6}(?:\.\d{1,4})?(?:px|em|rem|vh|svh|lvh|dvh|%|ch|lh)$/.test(e)?e:null}function Cr(t,e=200){if(!t)return"";let r=t.slice(0,e*4).replace(/[\u0000-\u001f\u007f-\u009f]/g,"").replace(/\s+/g," ").trim();return r.length>e?r.slice(0,e-1)+"\u2026":r}function Lr(t,e){let n=(t??"").split(/[\\/]/).pop()??"",r=/[\u0000-\u001f\u007f<>:"|?*]/g;return n.replace(r,"").replace(/^[.\s]+/,"").trim().slice(0,120)||e}var Or=`/*
 * Theme-independent tokens: typography, spacing, radius, motion.
 * Values: docs/DESIGN_SYSTEM.md \xA73, \xA74 and \xA77.
 * Each private \`--_\` variable reads the public \`--vt-\` variable first, so hosts can
 * override any token on the element or on an ancestor.
 */
:host {
  --_font-ui: var(
    --vt-font-ui,
    system-ui,
    -apple-system,
    'Segoe UI',
    'IBM Plex Sans',
    Roboto,
    sans-serif
  );
  --_font-mono: var(
    --vt-font-mono,
    'JetBrains Mono',
    ui-monospace,
    'Cascadia Code',
    'SF Mono',
    Menlo,
    Consolas,
    monospace
  );
  --_font-size: var(--vt-font-size, 14px);
  --_font-size-small: var(--vt-font-size-small, 12px);
  --_font-size-ui: var(--vt-font-size-ui, 13px);
  --_line-height: var(--vt-line-height, 1.6);
  --_space-1: var(--vt-space-1, 4px);
  --_space-2: var(--vt-space-2, 8px);
  --_space-3: var(--vt-space-3, 12px);
  --_space-4: var(--vt-space-4, 16px);
  --_space-5: var(--vt-space-5, 24px);
  --_space-6: var(--vt-space-6, 32px);
  --_space-7: var(--vt-space-7, 48px);
  --_space-8: var(--vt-space-8, 64px);
  --_radius-sm: var(--vt-radius-sm, 6px);
  --_radius: var(--vt-radius, 10px);
  --_radius-lg: var(--vt-radius-lg, 16px);
  --_radius-full: var(--vt-radius-full, 999px);
  --_header-height: var(--vt-header-height, 40px);
  --_tab-size: var(--vt-tab-size, 4);
  --_duration-fast: var(--vt-duration-fast, 120ms);
  --_duration: var(--vt-duration, 180ms);
  --_easing: var(--vt-easing, cubic-bezier(0.2, 0, 0, 1));
}

@media (prefers-reduced-motion: reduce) {
  :host {
    --_duration-fast: 0ms;
    --_duration: 0ms;
  }
}
`;var Mr=`/*
 * Shared component frame: container, header, toolbar, tabs, search, states.
 * Anatomy: docs/DESIGN_SYSTEM.md \xA76. Colors come only from theme tokens.
 */
:host {
  display: block;
  min-width: 0;
  margin-block: var(--vt-margin, 0);
}

:host([hidden]) {
  display: none;
}

[hidden] {
  display: none !important;
}

*,
*::before,
*::after {
  box-sizing: border-box;
}

.vt {
  /* Code areas: interface colors by default, replaced by a syntax theme when one is set. */
  --_code-bg: var(--_surface-sunken);
  --_code-bg-solid: var(--_surface-sunken);
  --_code-fg: var(--_fg);
  --_code-gutter: color-mix(in srgb, var(--_fg-muted) 70%, transparent);
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow: hidden;
  color: var(--_fg);
  background: var(--_surface);
  border: 1px solid var(--_border);
  border-radius: var(--_radius);
  font-family: var(--_font-ui);
  font-size: var(--_font-size-ui);
  line-height: 1.4;
  text-align: start;
  -webkit-text-size-adjust: 100%;
}

/* Chrome always uses the UI font, even when the content inherits the page font. */
.header,
.search,
.notice,
.message,
.empty,
.more,
.toolbar,
.toc {
  font-family: var(--_font-ui);
  font-size: var(--_font-size-ui);
  line-height: 1.4;
}

/* ---------- Header ---------- */

.header {
  display: flex;
  flex-wrap: nowrap;
  align-items: center;
  gap: var(--_space-2);
  min-height: var(--_header-height);
  padding: 0 var(--_space-2) 0 var(--_space-3);
  border-bottom: 1px solid var(--_border);
  background: var(--_surface);
}

.dot {
  flex: none;
  width: 8px;
  height: 8px;
  border-radius: var(--_radius-full);
  background: var(--_accent);
}

.title {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  color: var(--_fg);
  font-weight: 500;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.spacer {
  flex: 1 1 auto;
}

.badge {
  flex: none;
  padding: 2px 6px;
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  font-weight: 600;
  line-height: 1.4;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}

.vt {
  position: relative;
}

.toolbar {
  display: flex;
  flex: none;
  align-items: center;
  gap: 2px;
}

.toolbar.floating {
  position: absolute;
  top: var(--_space-2);
  right: var(--_space-2);
  z-index: 3;
  padding: 2px;
  border: 1px solid var(--_border);
  border-radius: var(--_radius-sm);
  background: var(--_surface);
  opacity: 0;
  transition: opacity var(--_duration-fast) var(--_easing);
}

.vt:hover .toolbar.floating,
.toolbar.floating:focus-within {
  opacity: 1;
}

@media (hover: none) {
  .toolbar.floating {
    opacity: 1;
  }
}

/* ---------- Buttons ---------- */

.btn {
  display: inline-grid;
  place-items: center;
  flex: none;
  width: 28px;
  height: 28px;
  padding: 0;
  border: 0;
  border-radius: var(--_radius-sm);
  background: transparent;
  color: var(--_fg-muted);
  font: inherit;
  cursor: pointer;
  transition:
    background-color var(--_duration-fast) var(--_easing),
    color var(--_duration-fast) var(--_easing);
}

.btn:hover {
  background: var(--_accent-soft);
  color: var(--_fg);
}

.btn[aria-pressed='true'] {
  background: var(--_accent-soft);
  color: var(--_accent-fg);
}

.btn.done {
  color: var(--_success);
}

.btn:disabled {
  opacity: 0.45;
  cursor: default;
  background: transparent;
}

.icon {
  width: 16px;
  height: 16px;
  pointer-events: none;
}

.text-btn {
  display: inline-flex;
  align-items: center;
  gap: var(--_space-1);
  min-height: 28px;
  padding: 0 var(--_space-2);
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-sm);
  background: var(--_surface);
  color: var(--_fg);
  font: inherit;
  font-weight: 500;
  cursor: pointer;
  transition: background-color var(--_duration-fast) var(--_easing);
}

.text-btn:hover {
  background: var(--_accent-soft);
}

.text-btn.done {
  border-color: var(--_success);
  color: var(--_success);
}

.pathbar .text-btn {
  min-height: 24px;
  font-size: var(--_font-size-small);
}

:focus-visible {
  outline: 2px solid var(--_accent);
  outline-offset: 2px;
}

:focus:not(:focus-visible) {
  outline: none;
}

@media (pointer: coarse) {
  .btn {
    width: 44px;
    height: 44px;
  }

  .text-btn,
  .tab {
    min-height: 44px;
  }
}

/* ---------- Tabs (WAI-ARIA tabs pattern) ---------- */

.tabs {
  display: flex;
  align-self: stretch;
  align-items: stretch;
  gap: var(--_space-1);
  min-width: 0;
  overflow-x: auto;
  scrollbar-width: none;
}

.tab {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 0 var(--_space-2);
  border: 0;
  background: transparent;
  color: var(--_fg-muted);
  font: inherit;
  font-weight: 500;
  white-space: nowrap;
  cursor: pointer;
  transition: color var(--_duration-fast) var(--_easing);
}

.tab::after {
  content: '';
  position: absolute;
  right: var(--_space-2);
  bottom: -1px;
  left: var(--_space-2);
  height: 2px;
  border-radius: 2px;
  background: transparent;
  transition: background-color var(--_duration) var(--_easing);
}

.tab:hover {
  color: var(--_fg);
}

.tab[aria-selected='true'] {
  color: var(--_fg);
}

.tab[aria-selected='true']::after {
  background: var(--_accent);
}

.tab:focus-visible {
  outline-offset: -2px;
}

.tab .icon {
  width: 14px;
  height: 14px;
}

/* ---------- Search ---------- */

.search {
  display: flex;
  align-items: center;
  gap: var(--_space-1);
  padding: var(--_space-2) var(--_space-2) var(--_space-2) var(--_space-3);
  border-bottom: 1px solid var(--_border);
  background: var(--_surface);
}

.search-input {
  flex: 1 1 auto;
  min-width: 0;
  height: 28px;
  padding: 0 var(--_space-2);
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
  color: var(--_fg);
  font: inherit;
}

.search-input::placeholder {
  color: var(--_fg-muted);
  opacity: 1;
}

.search-input:focus-visible {
  outline-offset: 0;
  border-color: var(--_accent);
}

.search-count {
  flex: none;
  min-width: 5ch;
  color: var(--_fg-muted);
  font-variant-numeric: tabular-nums;
  text-align: end;
  white-space: nowrap;
}

mark.match {
  border-radius: 2px;
  background: var(--_highlight);
  color: inherit;
}

mark.match.current {
  background: var(--_highlight-current);
  box-shadow: 0 0 0 1px var(--_warning);
}

/* ---------- Body ---------- */

.body {
  position: relative;
  min-width: 0;
  max-height: var(--_max-height, none);
  overflow: auto;
  background: var(--_code-bg);
  overscroll-behavior: contain;
  scrollbar-width: thin;
  scrollbar-color: var(--_border-strong) transparent;
}

.body:focus-visible {
  outline-offset: -2px;
}

/* ---------- States ---------- */

.notice {
  display: flex;
  align-items: center;
  gap: var(--_space-2);
  padding: var(--_space-2) var(--_space-3);
  border-bottom: 1px solid var(--_border);
  background: var(--_surface);
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
}

.notice .icon {
  flex: none;
  width: 14px;
  height: 14px;
  color: var(--_warning);
}

.message {
  display: flex;
  align-items: flex-start;
  gap: var(--_space-2);
  padding: var(--_space-4);
  background: var(--_surface);
  overflow-wrap: anywhere;
}

.message .icon {
  flex: none;
  margin-top: 1px;
  color: var(--_danger);
}

.message-title {
  margin: 0;
  color: var(--_danger);
  font-weight: 600;
}

.message-detail {
  margin: var(--_space-1) 0 0;
  color: var(--_fg-muted);
}

.empty {
  padding: var(--_space-5) var(--_space-4);
  color: var(--_fg-muted);
  text-align: center;
}

.loader {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--_space-3);
  min-height: 140px;
  padding: var(--_space-5);
  color: var(--_fg-muted);
  /* Fast loads show nothing: the loader only appears after a short delay. */
  opacity: 0;
  animation: vt-loader-in var(--_duration) var(--_easing) 300ms forwards;
}

.loader-mark {
  width: 44px;
  height: 44px;
  overflow: visible;
}

.loader-frame {
  fill: none;
  stroke: currentColor;
  stroke-width: 9;
}

.loader-dot {
  fill: var(--_accent);
  transform-origin: 29px 29px;
  animation: vt-loader-dot 1.4s var(--_easing) infinite;
}

.loader-v {
  fill: none;
  stroke: var(--_accent);
  stroke-width: 11;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-dasharray: 100;
  animation: vt-loader-v 1.4s var(--_easing) infinite;
}

.loader-label {
  font-size: var(--_font-size-small);
}

@keyframes vt-loader-in {
  to {
    opacity: 1;
  }
}

@keyframes vt-loader-v {
  0% {
    stroke-dashoffset: 100;
  }
  45%,
  70% {
    stroke-dashoffset: 0;
  }
  100% {
    stroke-dashoffset: -100;
  }
}

@keyframes vt-loader-dot {
  0%,
  100% {
    opacity: 0.35;
    transform: scale(0.8);
  }
  50% {
    opacity: 1;
    transform: scale(1);
  }
}

@media (prefers-reduced-motion: reduce) {
  .loader {
    animation-duration: 0ms;
  }

  .loader-v,
  .loader-dot {
    animation: none;
    stroke-dashoffset: 0;
    opacity: 1;
  }
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}

/* ---------- Full screen ---------- */

:host(:fullscreen) {
  display: block;
  width: 100%;
  height: 100%;
}

.vt[data-fullscreen] {
  height: 100%;
  border-radius: 0;
  border-width: 0;
}

/* Window mode: used where the Fullscreen API is not available. */
.vt[data-fullscreen='window'] {
  position: fixed;
  inset: 0;
  z-index: 2147483000;
  height: auto;
}

.vt[data-fullscreen] > .panel,
.vt[data-fullscreen] > .body {
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  min-height: 0;
}

.vt[data-fullscreen] .body {
  flex: 1 1 auto;
  max-height: none;
}

.vt[data-fullscreen] .panel.split {
  display: grid;
  grid-template-rows: minmax(0, 1fr);
}

.vt[data-fullscreen] .panel.split:is([data-preview='top'], [data-preview='bottom']) {
  grid-template-rows: minmax(0, 1fr) minmax(0, 1fr);
}

.vt[data-fullscreen] .panel.split > .body {
  height: auto;
  min-height: 0;
}
`;async function Tn(t,e=document){if(navigator.clipboard&&window.isSecureContext)try{return await navigator.clipboard.writeText(t),!0}catch{}return ni(t,e)}function ni(t,e){let n=document.createElement("textarea");n.value=t,n.setAttribute("readonly",""),n.setAttribute("aria-hidden","true"),n.style.position="fixed",n.style.opacity="0",n.style.pointerEvents="none",(e instanceof Document?e.body:e).appendChild(n);try{return n.select(),document.execCommand("copy")}catch{return!1}finally{n.remove()}}function Ir(t,e,n="text/plain"){let r=new Blob([t],{type:`${n};charset=utf-8`}),s=URL.createObjectURL(r),i=document.createElement("a");i.href=s,i.download=e,i.rel="noopener",i.style.display="none",document.body.appendChild(i),i.click(),i.remove(),setTimeout(()=>URL.revokeObjectURL(s),1e3)}var wn=Object.freeze({theme:"auto",lightTheme:"light",darkTheme:"dark",lang:"en",maxSize:2097152,highlightLimit:3e5,maxDepth:512,fetchTimeout:15e3,languagesUrl:"",syntaxTheme:"",syntaxThemeDark:"",syntaxThemesUrl:"",vendorUrl:""}),ri=Object.freeze({maxSize:50*1024*1024,highlightLimit:5*1024*1024,maxDepth:1e4,fetchTimeout:12e4}),at={...wn},Sn=new Set;function ae(){return Object.freeze({...at})}function si(t){if(!t||typeof t!="object")return ae();let e={...at};for(let[r,s]of Object.entries(t))ai(r,s);let n=new Set(Object.keys(at).filter(r=>at[r]!==e[r]));if(n.size)for(let r of Sn)r(n);return ae()}function ai(t,e){if(!Object.prototype.hasOwnProperty.call(wn,t)){console.warn(`[vitrine] Unknown configuration option "${t}".`);return}let n=t;if(typeof wn[n]==="number"){let s=ri[n];if(typeof e!="number"||!Number.isFinite(e)||e<=0){console.warn(`[vitrine] Option "${t}" must be a positive number.`);return}at[n]=Math.min(Math.floor(e),s??e);return}if(typeof e!="string"||e.length>2048){console.warn(`[vitrine] Option "${t}" must be a string.`);return}at[n]=e.trim()}function Dr(t){return Sn.add(t),()=>Sn.delete(t)}function v(t,e={},...n){let r=document.createElement(t);if(e.class&&(r.className=e.class),e.part&&r.setAttribute("part",e.part),e.attrs)for(let[s,i]of Object.entries(e.attrs))i===!1||i===null||i===void 0||r.setAttribute(s,i===!0?"":String(i));if(e.text!==void 0&&(r.textContent=e.text),e.on)for(let[s,i]of Object.entries(e.on))r.addEventListener(s,i);return ii(r,n),r}function ii(t,e){for(let n of e)n==null||n===!1||t.append(typeof n=="string"?document.createTextNode(n):n)}var Pr=0;function Ft(t){return Pr+=1,`vt-${t}-${Pr}`}function $t(t){let e=t.replace(/\r\n?/g,`
`).split(`
`);for(;e.length&&e[0].trim()==="";)e.shift();for(;e.length&&e[e.length-1].trim()==="";)e.pop();let n=1/0;for(let r of e){if(r.trim()==="")continue;let s=/^[ \t]*/.exec(r);if(n=Math.min(n,s?s[0].length:0),n===0)break}return!Number.isFinite(n)||n===0?e.join(`
`):e.map(r=>r.slice(n)).join(`
`)}function Ur(t,e){let n,r=(...s)=>{clearTimeout(n),n=setTimeout(()=>t(...s),e)};return r.cancel=()=>clearTimeout(n),r}function zr(t){try{return new URL(t,document.baseURI).origin===location.origin}catch{return!1}}var ie=class extends Error{constructor(e,n={},r){super(e,r===void 0?void 0:{cause:r}),this.name="VitrineError",this.code=e,this.params=n}},oi=new Set(["text/plain","text/markdown","text/x-markdown","application/json","text/json"]);function Br(t){for(let r of Array.from(t.children)){let s=ci(r);if(s!==null)return s}let e="";for(let r of Array.from(t.childNodes))r.nodeType===Node.TEXT_NODE||r.nodeType===Node.CDATA_SECTION_NODE?e+=r.nodeValue??"":r.nodeType===Node.ELEMENT_NODE&&(e+=r.textContent??"");let n=$t(e);return n===""?null:n}function ci(t){if(t instanceof HTMLTemplateElement){let e=t.content.children.length>0;return $t(e?t.innerHTML:t.content.textContent??"")}return t instanceof HTMLScriptElement&&oi.has(t.type.trim().toLowerCase())?$t(t.textContent??""):null}function jt(t,e){if(t.length>e)throw new ie("tooLarge",{size:t.length,limit:e})}async function Hr(t,e){let n=li(t),r=zr(n.href);if(!r&&!e.allowRemote)throw new ie("remoteBlocked");let s=new AbortController,i=setTimeout(()=>s.abort(new ie("timeout")),e.timeout),o=()=>s.abort(e.signal?.reason);e.signal?.addEventListener("abort",o,{once:!0}),e.signal?.aborted&&o();try{let c=await fetch(n.href,{mode:r?"same-origin":"cors",credentials:"same-origin",redirect:"follow",referrerPolicy:"strict-origin-when-cross-origin",signal:s.signal});if(!c.ok)throw new ie("loadFailed",{url:Fr(n),reason:`HTTP ${c.status}`});let u=Number(c.headers.get("content-length"));if(Number.isFinite(u)&&u>e.maxSize*4)throw new ie("tooLarge",{size:u,limit:e.maxSize});return await ui(c,e.maxSize,s)}catch(c){throw di(c,s.signal,n)}finally{clearTimeout(i),e.signal?.removeEventListener("abort",o)}}function li(t){let e;try{e=new URL(t.trim(),document.baseURI)}catch{throw new ie("unsafeUrl")}if(e.protocol!=="http:"&&e.protocol!=="https:")throw new ie("unsafeUrl");return e}async function ui(t,e,n){if(!t.body){let o=await t.text();return jt(o,e),o}let r=t.body.getReader(),s=new TextDecoder,i="";for(;;){let{done:o,value:c}=await r.read();if(o)break;if(i+=s.decode(c,{stream:!0}),i.length>e)throw n.abort(),new ie("tooLarge",{size:`> ${e}`,limit:e})}return i+=s.decode(),jt(i,e),i}function di(t,e,n){if(t instanceof ie)return t;if(e.aborted&&e.reason instanceof ie)return e.reason;if(t instanceof DOMException&&t.name==="AbortError")return t;let r=t instanceof Error?t.message:String(t);return new ie("loadFailed",{url:Fr(n),reason:r},t)}function Fr(t){let e=t.origin===location.origin?t.pathname+t.search:t.href;return e.length>120?e.slice(0,119)+"\u2026":e}function $r(t){return t instanceof DOMException&&t.name==="AbortError"}var ue=Object.freeze({READY:"vt-ready",COPY:"vt-copy",SEARCH:"vt-search",TAB_CHANGE:"vt-tab-change",INPUT:"vt-input",CHANGE:"vt-change",MODE_CHANGE:"vt-mode-change",TAG_ADD:"vt-tag-add",TAG_REMOVE:"vt-tag-remove",TAG_CREATE:"vt-tag-create",TAG_CLICK:"vt-tag-click",SORT:"vt-sort",FULLSCREEN_CHANGE:"vt-fullscreen-change",LAYOUT_CHANGE:"vt-layout-change",SELECT:"vt-select",TOGGLE:"vt-toggle",FILTER_CHANGE:"vt-filter-change",TYPING_END:"vt-typing-end",CHANGE_NAVIGATE:"vt-change-navigate",ERROR:"vt-error"});function pe(t,e,n){return t.dispatchEvent(new CustomEvent(e,{detail:n,bubbles:!0,composed:!0,cancelable:!0}))}var Nn=Object.freeze({copy:"Copy",copyCode:"Copy code",copied:"Copied",copyFailed:"Copy failed",copySource:"Copy source",download:"Download",search:"Search",searchPlaceholder:"Search\u2026",searchNext:"Next match",searchPrevious:"Previous match",searchClose:"Close search",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"No matches",searchResults:"{total} matches",wrap:"Toggle line wrap",showMore:"Show all {count} lines",preview:"Preview",source:"Source",split:"Split",swapPanes:"Swap panes",stackPanes:"Stack panes",syncScroll:"Sync scrolling",tabs:"View",actions:"Actions",toc:"Table of contents",anchor:"Link to this section",table:"Table",tree:"Tree",raw:"Raw",expandAll:"Expand all",collapseAll:"Collapse all",copyPath:"Copy path",copyValue:"Copy value",items:"{count} items",item:"1 item",keys:"{count} keys",key:"1 key",showMoreItems:"Show {count} more",showFullString:"Show full string ({count} characters)",truncated:"Partially expanded: too many nodes.",loading:"Loading\u2026",errorTitle:"Unable to display content",invalidJson:"Invalid JSON at line {line}, column {column}: {message}.",invalidJsonRaw:"Invalid JSON at line {line}, column {column} \u2014 showing raw text.",empty:"Nothing to display",tooLarge:"Content is too large ({size} characters, limit {limit}).",tooDeep:"Nesting is too deep (limit {limit}).",tooComplex:"This document is nested too deeply to display.",unserializable:"This value cannot be converted to JSON (circular reference or BigInt).",highlightSkipped:"Content is large: syntax highlighting is disabled.",loadFailed:'Could not load "{url}": {reason}',remoteBlocked:'Cross-origin URL blocked. Add the "allow-remote" attribute to allow it.',unsafeUrl:"URL blocked: only http(s) URLs can be loaded.",timeout:"Request timed out.",added:"Added",removed:"Removed",code:"Code",edit:"Edit",splitView:"Side by side",unifiedView:"Unified",diffStats:"+{added} \u2212{removed}",diffSimplified:"Many changes: the comparison is simplified to removed and added blocks.",noDifferences:"No differences",previousChange:"Previous change",nextChange:"Next change",changePosition:"{current} of {total}",changeTotal:"{count} changes",terminal:"Terminal",command:"Command",copyCommand:"Copy command",copyCommands:"Copy commands",replay:"Replay",showMoreLines:"Show {count} more lines",files:"Files",copyTree:"Copy tree",treeStats:"{folders} folders, {files} files",invalidTree:"This tree could not be read: {message}",treeTruncated:"Only the first {limit} entries are shown.",status_added:"added",status_removed:"removed",status_modified:"modified",status_highlighted:"highlighted",httpExchange:"Exchange",httpRequest:"Request",httpResponse:"Response",httpBody:"Body",httpHeaders:"Headers",httpQuery:"Query",httpNone:"None",httpNoBody:"No body",copyUrl:"Copy URL",codeLanguage:"Language",showSecrets:"Show secrets",hideSecrets:"Hide secrets",secretsShown:"Secrets shown",secretsHidden:"Secrets hidden",secretsInCode:"Credentials are masked in this code. Replace them with your own.",invalidHttp:"This HTTP message could not be read: {message}",log:"Log",followLog:"Follow new lines",levelToggle:"Show or hide {level} entries",logNoMatch:"No entry matches the filters.",chartView:"Chart",legend:"Legend",seriesToggle:"Show or hide {name}",copyData:"Copy data",chartSummary:"{type} with {series} series and {points} points.",chartRange:"{name} from {min} to {max}",chart_line:"Line chart",chart_area:"Area chart",chart_bar:"Bar chart",chart_pie:"Donut chart",chartError:"This data could not be charted: {message}",chartTruncated:"Only the first 5,000 points of each series are shown.",chartLoadFailed:"The chart library could not be loaded: {message}",openapiInvalid:"This API description could not be read: {message}",openapiYamlFailed:"The YAML reader could not be loaded: {message}",openapiTruncated:"Only the first 2,000 endpoints are shown.",openapiServers:"Servers",openapiAuth:"Authentication",openapiEndpoints:"Endpoints",openapiTags:"Tags",openapiAllTags:"All",openapiNoMatch:"No endpoint matches.",openapiDeprecated:"deprecated",openapiParameters:"Parameters",openapiName:"Name",openapiIn:"In",openapiType:"Type",openapiDescription:"Description",openapiRequired:"required",openapiRequestBody:"Request body",openapiResponses:"Responses",openapiExample:"Example",openapiExampleValue:"Example",unchangedLines:"Show {count} unchanged lines",copyPatch:"Copy patch",changes:"Changes",original:"Original",modified:"Modified",patch:"Patch",tags:"Tags",noTags:"No tags",addTag:"Add a tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:'Create "{tag}"',removeTag:"Remove {tag}",tagAdded:"{tag} added",tagRemoved:"{tag} removed",pressAgainToRemove:"Press Backspace again to remove {tag}",tagDuplicate:"{tag} is already selected.",tagDisabled:"{tag} cannot be selected.",tagLimit:"You can select up to {max} tags.",tagNotAllowed:"{tag} is not in the list.",tagTooLong:"{tag} is too long.",tagInvalid:"{tag} is not a valid tag.",tagRefused:"{tag} was refused.",tagsRequired:"Select at least one tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Browse all tags",otherTags:"Other",clearTags:"Remove all tags",filterTags:"Filter tags",tagsFound:"{count} tags",invalidTags:'The tags must be a JSON array, or an object with "value" and "options".',rowsRange:"Rows {from}\u2013{to} of {total}",noRows:"No rows",firstPage:"First page",previousPage:"Previous page",nextPage:"Next page",lastPage:"Last page",sortBy:"Sort by {name}",column:"Column {n}",rowNumber:"Row",csvStatus:"{rows} rows \xD7 {columns} columns",csvUnclosed:"Unclosed quote starting at line {line}.",tooManyColumns:"Only the first {limit} columns are shown.",matchingRows:"{count} matching rows",undo:"Undo",redo:"Redo",fullscreen:"Full screen",exitFullscreen:"Exit full screen",stopEditing:"Stop editing",editor:"Editor",validJson:"Valid JSON"}),hi=Object.freeze({copy:"Copier",copyCode:"Copier le code",copied:"Copi\xE9",copyFailed:"\xC9chec de la copie",copySource:"Copier la source",download:"T\xE9l\xE9charger",search:"Rechercher",searchPlaceholder:"Rechercher\u2026",searchNext:"R\xE9sultat suivant",searchPrevious:"R\xE9sultat pr\xE9c\xE9dent",searchClose:"Fermer la recherche",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"Aucun r\xE9sultat",searchResults:"{total} r\xE9sultats",wrap:"Activer/d\xE9sactiver le retour \xE0 la ligne",showMore:"Afficher les {count} lignes",preview:"Aper\xE7u",source:"Source",split:"C\xF4te \xE0 c\xF4te",swapPanes:"Inverser les panneaux",stackPanes:"Empiler les panneaux",syncScroll:"Synchroniser le d\xE9filement",tabs:"Affichage",actions:"Actions",toc:"Table des mati\xE8res",anchor:"Lien vers cette section",table:"Tableau",tree:"Arbre",raw:"Brut",expandAll:"Tout d\xE9plier",collapseAll:"Tout replier",copyPath:"Copier le chemin",copyValue:"Copier la valeur",items:"{count} \xE9l\xE9ments",item:"1 \xE9l\xE9ment",keys:"{count} cl\xE9s",key:"1 cl\xE9",showMoreItems:"Afficher {count} de plus",showFullString:"Afficher toute la cha\xEEne ({count} caract\xE8res)",truncated:"D\xE9pliage partiel : trop de n\u0153uds.",loading:"Chargement\u2026",errorTitle:"Impossible d\u2019afficher le contenu",invalidJson:"JSON invalide \xE0 la ligne {line}, colonne {column} : {message}.",invalidJsonRaw:"JSON invalide \xE0 la ligne {line}, colonne {column} \u2014 affichage du texte brut.",empty:"Rien \xE0 afficher",tooLarge:"Contenu trop volumineux ({size} caract\xE8res, limite {limit}).",tooDeep:"Imbrication trop profonde (limite {limit}).",tooComplex:"Ce document est trop imbriqu\xE9 pour \xEAtre affich\xE9.",unserializable:"Cette valeur ne peut pas \xEAtre convertie en JSON (r\xE9f\xE9rence circulaire ou BigInt).",highlightSkipped:"Contenu volumineux : coloration syntaxique d\xE9sactiv\xE9e.",loadFailed:"Impossible de charger \xAB {url} \xBB : {reason}",remoteBlocked:"URL d\u2019une autre origine bloqu\xE9e. Ajoutez l\u2019attribut \xAB allow-remote \xBB pour l\u2019autoriser.",unsafeUrl:"URL bloqu\xE9e : seules les URL http(s) peuvent \xEAtre charg\xE9es.",timeout:"D\xE9lai de la requ\xEAte d\xE9pass\xE9.",added:"Ajout\xE9",removed:"Supprim\xE9",code:"Code",edit:"Modifier",splitView:"C\xF4te \xE0 c\xF4te",unifiedView:"Unifi\xE9",diffStats:"+{added} \u2212{removed}",diffSimplified:"Beaucoup de changements : la comparaison est simplifi\xE9e en blocs retir\xE9s et ajout\xE9s.",noDifferences:"Aucune diff\xE9rence",previousChange:"Modification pr\xE9c\xE9dente",nextChange:"Modification suivante",changePosition:"{current} sur {total}",changeTotal:"Modifications : {count}",terminal:"Terminal",command:"Commande",copyCommand:"Copier la commande",copyCommands:"Copier les commandes",replay:"Rejouer",showMoreLines:"Afficher {count} lignes de plus",files:"Fichiers",copyTree:"Copier l'arborescence",treeStats:"{folders} dossiers, {files} fichiers",invalidTree:"Impossible de lire cette arborescence : {message}",treeTruncated:"Seules les {limit} premi\xE8res entr\xE9es sont affich\xE9es.",status_added:"ajout\xE9",status_removed:"supprim\xE9",status_modified:"modifi\xE9",status_highlighted:"mis en \xE9vidence",httpExchange:"\xC9change",httpRequest:"Requ\xEAte",httpResponse:"R\xE9ponse",httpBody:"Corps",httpHeaders:"En-t\xEAtes",httpQuery:"Param\xE8tres",httpNone:"Aucun",httpNoBody:"Pas de corps",copyUrl:"Copier l'URL",codeLanguage:"Langage",showSecrets:"Afficher les secrets",hideSecrets:"Masquer les secrets",secretsShown:"Secrets affich\xE9s",secretsHidden:"Secrets masqu\xE9s",secretsInCode:"Les identifiants sont masqu\xE9s dans ce code. Remplacez-les par les v\xF4tres.",invalidHttp:"Impossible de lire ce message HTTP : {message}",log:"Journal",followLog:"Suivre les nouvelles lignes",levelToggle:"Afficher ou masquer les entr\xE9es {level}",logNoMatch:"Aucune entr\xE9e ne correspond aux filtres.",chartView:"Graphique",legend:"L\xE9gende",seriesToggle:"Afficher ou masquer {name}",copyData:"Copier les donn\xE9es",chartSummary:"{type} avec {series} s\xE9ries et {points} points.",chartRange:"{name} de {min} \xE0 {max}",chart_line:"Graphique en courbes",chart_area:"Graphique en aires",chart_bar:"Graphique en barres",chart_pie:"Graphique en anneau",chartError:"Impossible de tracer ces donn\xE9es : {message}",chartTruncated:"Seuls les 5 000 premiers points de chaque s\xE9rie sont affich\xE9s.",chartLoadFailed:"Impossible de charger la biblioth\xE8que de graphiques : {message}",openapiInvalid:"Impossible de lire cette description d\u2019API : {message}",openapiYamlFailed:"Impossible de charger le lecteur YAML : {message}",openapiTruncated:"Seuls les 2 000 premiers points d\u2019acc\xE8s sont affich\xE9s.",openapiServers:"Serveurs",openapiAuth:"Authentification",openapiEndpoints:"Points d\u2019acc\xE8s",openapiTags:"Tags",openapiAllTags:"Tous",openapiNoMatch:"Aucun point d\u2019acc\xE8s ne correspond.",openapiDeprecated:"obsol\xE8te",openapiParameters:"Param\xE8tres",openapiName:"Nom",openapiIn:"Emplacement",openapiType:"Type",openapiDescription:"Description",openapiRequired:"requis",openapiRequestBody:"Corps de la requ\xEAte",openapiResponses:"R\xE9ponses",openapiExample:"Exemple",openapiExampleValue:"Exemple",unchangedLines:"Afficher {count} lignes inchang\xE9es",copyPatch:"Copier le patch",changes:"Modifications",original:"Original",modified:"Modifi\xE9",patch:"Patch",tags:"Tags",noTags:"Aucun tag",addTag:"Ajouter un tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:"Cr\xE9er \xAB {tag} \xBB",removeTag:"Retirer {tag}",tagAdded:"{tag} ajout\xE9",tagRemoved:"{tag} retir\xE9",pressAgainToRemove:"Appuyez de nouveau sur Retour arri\xE8re pour retirer {tag}",tagDuplicate:"{tag} est d\xE9j\xE0 s\xE9lectionn\xE9.",tagDisabled:"{tag} ne peut pas \xEAtre s\xE9lectionn\xE9.",tagLimit:"Vous pouvez s\xE9lectionner jusqu\u2019\xE0 {max} tags.",tagNotAllowed:"{tag} n\u2019est pas dans la liste.",tagTooLong:"{tag} est trop long.",tagInvalid:"{tag} n\u2019est pas un tag valide.",tagRefused:"{tag} a \xE9t\xE9 refus\xE9.",tagsRequired:"S\xE9lectionnez au moins un tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Parcourir tous les tags",otherTags:"Autres",clearTags:"Retirer tous les tags",filterTags:"Filtrer les tags",tagsFound:"{count} tags",invalidTags:"Les tags doivent \xEAtre un tableau JSON, ou un objet avec \xAB value \xBB et \xAB options \xBB.",rowsRange:"Lignes {from}\u2013{to} sur {total}",noRows:"Aucune ligne",firstPage:"Premi\xE8re page",previousPage:"Page pr\xE9c\xE9dente",nextPage:"Page suivante",lastPage:"Derni\xE8re page",sortBy:"Trier par {name}",column:"Colonne {n}",rowNumber:"Ligne",csvStatus:"{rows} lignes \xD7 {columns} colonnes",csvUnclosed:"Guillemet non ferm\xE9 \xE0 partir de la ligne {line}.",tooManyColumns:"Seules les {limit} premi\xE8res colonnes sont affich\xE9es.",matchingRows:"{count} lignes correspondantes",undo:"Annuler",redo:"R\xE9tablir",fullscreen:"Plein \xE9cran",exitFullscreen:"Quitter le plein \xE9cran",stopEditing:"Terminer la modification",editor:"\xC9diteur",validJson:"JSON valide"}),Gt=new Map([["en",Nn],["fr",hi]]);function fi(t,e){if(typeof t!="string"||!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(t))throw new TypeError(`[vitrine] Invalid locale code "${t}".`);let n={};for(let[r,s]of Object.entries(e??{}))Object.prototype.hasOwnProperty.call(Nn,r)&&typeof s=="string"&&(n[r]=s.slice(0,500));Gt.set(t,Object.freeze({...Gt.get(t)??{},...n}));for(let r of An)r()}var An=new Set;function jr(t){return An.add(t),()=>An.delete(t)}function kn(t){let e=Gt.get(t),n=Gt.get(String(t).split("-")[0]);return(r,s)=>{let i=e?.[r]??n?.[r]??Nn[r]??String(r);return s?i.replace(/\{(\w+)\}/g,(o,c)=>Object.prototype.hasOwnProperty.call(s,c)?String(s[c]):o):i}}function de(t,e){try{return new Intl.NumberFormat(e).format(t)}catch{return String(t)}}var Gr=`/* Vitrine Light \u2014 default light theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
[data-theme='light'] {
  color-scheme: light;
  --vt-bg: #f3f4f1;
  --vt-surface: #ffffff;
  --vt-surface-sunken: #eaece7;
  --vt-surface-raised: #ffffff;
  --vt-border: #d6d9d2;
  --vt-border-strong: #b9beb4;
  --vt-fg: #11151c;
  --vt-fg-muted: #4a5260;
  --vt-accent: #14b8a6;
  --vt-accent-fg: #0a6e6f;
  --vt-on-accent: #11151c;
  --vt-accent-soft: rgba(20, 184, 166, 0.12);
  --vt-highlight: rgba(242, 169, 59, 0.35);
  --vt-highlight-current: rgba(242, 169, 59, 0.7);
  --vt-line-highlight: rgba(20, 184, 166, 0.1);
  --vt-success: #0a6e6f;
  --vt-warning: #a6510b;
  --vt-danger: #b2384f;
  --vt-info: #2f55c9;
  --vt-diff-added: rgba(20, 184, 166, 0.12);
  --vt-diff-removed: rgba(178, 56, 79, 0.12);
  --vt-shadow: 0 8px 24px rgba(17, 21, 28, 0.12);
  --vt-syntax-keyword: #7a3ec8;
  --vt-syntax-string: #0a6e6f;
  --vt-syntax-number: #a6510b;
  --vt-syntax-function: #2f55c9;
  --vt-syntax-type: #b2384f;
  --vt-syntax-comment: #5f6773;
  --vt-syntax-attr: #2f55c9;
  --vt-syntax-tag: #b2384f;
  --vt-syntax-meta: #4a5260;
}
`;var Wr=`/* Vitrine Dark \u2014 default dark theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
[data-theme='dark'] {
  color-scheme: dark;
  --vt-bg: #11151c;
  --vt-surface: #171c25;
  --vt-surface-sunken: #0c0f14;
  --vt-surface-raised: #1e2430;
  --vt-border: #262d3a;
  --vt-border-strong: #3a4354;
  --vt-fg: #e8eae6;
  --vt-fg-muted: #9aa3b2;
  --vt-accent: #14b8a6;
  --vt-accent-fg: #14b8a6;
  --vt-on-accent: #11151c;
  --vt-accent-soft: rgba(20, 184, 166, 0.16);
  --vt-highlight: rgba(242, 169, 59, 0.3);
  --vt-highlight-current: rgba(242, 169, 59, 0.6);
  --vt-line-highlight: rgba(20, 184, 166, 0.12);
  --vt-success: #14b8a6;
  --vt-warning: #f2a93b;
  --vt-danger: #ff8f73;
  --vt-info: #7c9cff;
  --vt-diff-added: rgba(20, 184, 166, 0.16);
  --vt-diff-removed: rgba(255, 143, 115, 0.14);
  --vt-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
  --vt-syntax-keyword: #c4a5ff;
  --vt-syntax-string: #5eead4;
  --vt-syntax-number: #f2a93b;
  --vt-syntax-function: #7c9cff;
  --vt-syntax-type: #ff8f73;
  --vt-syntax-comment: #8a93a3;
  --vt-syntax-attr: #7c9cff;
  --vt-syntax-tag: #ff8f73;
  --vt-syntax-meta: #9aa3b2;
}
`;var qr=`/* Vitrine Dim \u2014 softer, blue-grey dark theme for long reading sessions. */
[data-theme='dim'] {
  color-scheme: dark;
  --vt-bg: #1b2230;
  --vt-surface: #212a3a;
  --vt-surface-sunken: #192030;
  --vt-surface-raised: #29334a;
  --vt-border: #33405a;
  --vt-border-strong: #46557a;
  --vt-fg: #dce2ec;
  --vt-fg-muted: #a3adc0;
  --vt-accent: #14b8a6;
  --vt-accent-fg: #2dd4bf;
  --vt-on-accent: #11151c;
  --vt-accent-soft: rgba(45, 212, 191, 0.16);
  --vt-highlight: rgba(242, 169, 59, 0.3);
  --vt-highlight-current: rgba(242, 169, 59, 0.6);
  --vt-line-highlight: rgba(45, 212, 191, 0.12);
  --vt-success: #2dd4bf;
  --vt-warning: #f2a93b;
  --vt-danger: #ff9b82;
  --vt-info: #8faeff;
  --vt-diff-added: rgba(45, 212, 191, 0.16);
  --vt-diff-removed: rgba(255, 155, 130, 0.16);
  --vt-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  --vt-syntax-keyword: #c9aeff;
  --vt-syntax-string: #6ee7d5;
  --vt-syntax-number: #f5b85c;
  --vt-syntax-function: #8faeff;
  --vt-syntax-type: #ff9b82;
  --vt-syntax-comment: #95a0b5;
  --vt-syntax-attr: #8faeff;
  --vt-syntax-tag: #ff9b82;
  --vt-syntax-meta: #a3adc0;
}
`;var Vr=`/* Vitrine Paper \u2014 warm, low-glare light theme. */
[data-theme='paper'] {
  color-scheme: light;
  --vt-bg: #f4efe4;
  --vt-surface: #fbf8f1;
  --vt-surface-sunken: #f0e9da;
  --vt-surface-raised: #fffdf8;
  --vt-border: #ddd3c0;
  --vt-border-strong: #c3b79f;
  --vt-fg: #2b2620;
  --vt-fg-muted: #5c5347;
  --vt-accent: #14b8a6;
  --vt-accent-fg: #0a6566;
  --vt-on-accent: #11151c;
  --vt-accent-soft: rgba(20, 184, 166, 0.14);
  --vt-highlight: rgba(242, 169, 59, 0.38);
  --vt-highlight-current: rgba(242, 169, 59, 0.72);
  --vt-line-highlight: rgba(20, 184, 166, 0.11);
  --vt-success: #0a6566;
  --vt-warning: #974a09;
  --vt-danger: #a63148;
  --vt-info: #2b4fbd;
  --vt-diff-added: rgba(20, 184, 166, 0.14);
  --vt-diff-removed: rgba(166, 49, 72, 0.12);
  --vt-shadow: 0 8px 24px rgba(43, 38, 32, 0.12);
  --vt-syntax-keyword: #7239bd;
  --vt-syntax-string: #0a6566;
  --vt-syntax-number: #974a09;
  --vt-syntax-function: #2b4fbd;
  --vt-syntax-type: #a63148;
  --vt-syntax-comment: #6b6255;
  --vt-syntax-attr: #2b4fbd;
  --vt-syntax-tag: #a63148;
  --vt-syntax-meta: #5c5347;
}
`;var Kr=`/* Vitrine High Contrast \u2014 maximum legibility (WCAG AAA text contrast). */
[data-theme='high-contrast'] {
  color-scheme: dark;
  --vt-bg: #000000;
  --vt-surface: #000000;
  --vt-surface-sunken: #0a0a0a;
  --vt-surface-raised: #141414;
  --vt-border: #8a8a8a;
  --vt-border-strong: #ffffff;
  --vt-fg: #ffffff;
  --vt-fg-muted: #d6d6d6;
  --vt-accent: #2ee6d0;
  --vt-accent-fg: #5eead4;
  --vt-on-accent: #000000;
  --vt-accent-soft: rgba(46, 230, 208, 0.22);
  --vt-highlight: rgba(255, 214, 0, 0.35);
  --vt-highlight-current: rgba(255, 214, 0, 0.55);
  --vt-line-highlight: rgba(46, 230, 208, 0.18);
  --vt-success: #5eead4;
  --vt-warning: #ffd166;
  --vt-danger: #ffa08a;
  --vt-info: #a8c1ff;
  --vt-diff-added: rgba(46, 230, 208, 0.22);
  --vt-diff-removed: rgba(255, 160, 138, 0.24);
  --vt-shadow: 0 0 0 1px #ffffff;
  --vt-syntax-keyword: #dcc2ff;
  --vt-syntax-string: #7cf5e0;
  --vt-syntax-number: #ffd166;
  --vt-syntax-function: #a8c1ff;
  --vt-syntax-type: #ffb3a1;
  --vt-syntax-comment: #c8c8c8;
  --vt-syntax-attr: #a8c1ff;
  --vt-syntax-tag: #ffb3a1;
  --vt-syntax-meta: #e0e0e0;
}
`;var vi=Object.freeze(["bg","surface","surface-sunken","surface-raised","border","border-strong","fg","fg-muted","accent","accent-fg","on-accent","accent-soft","highlight","highlight-current","line-highlight","success","warning","danger","info","diff-added","diff-removed","shadow","syntax-keyword","syntax-string","syntax-number","syntax-function","syntax-type","syntax-comment","syntax-attr","syntax-tag","syntax-meta"]),Ne=new Map,Ge=new CSSStyleSheet,_i=/^[a-z][a-z0-9-]{0,39}$/,xi=new Set(["auto"]);function Ei(t){let e=/\[data-theme='([a-z0-9-]+)'\]/.exec(t)?.[1];if(!e)throw new Error("[vitrine] Theme file without a [data-theme] selector.");let n=/color-scheme:\s*(light|dark)\s*;/.exec(t)?.[1]==="dark"?"dark":"light",r={};for(let[,s,i]of t.matchAll(/--vt-([a-z0-9-]+)\s*:\s*([^;]+);/g))r[s]=i.trim();return{name:e,definition:{colorScheme:n,tokens:r}}}for(let t of[Gr,Wr,qr,Vr,Kr]){let{name:e,definition:n}=Ei(t);Ne.set(e,n)}var Ti=Object.freeze([...Ne.keys()]);function wi(t){return typeof t!="string"||t.length===0||t.length>200||/[;{}<>\\]/.test(t)?!1:!/(?:url|image|image-set|cross-fade|element|src)\s*\(|@import|expression/i.test(t)}function Si(t,e={}){if(typeof t!="string"||!_i.test(t)||xi.has(t))throw new TypeError(`[vitrine] Invalid theme name "${t}". Use lowercase letters, digits, "-".`);let n=e.colorScheme==="dark"?"dark":e.colorScheme==="light"?"light":void 0,r=e.extends??(n==="dark"?"dark":"light"),s=Ne.get(r);if(!s)throw new TypeError(`[vitrine] Unknown base theme "${r}".`);let i={...s.tokens};for(let[o,c]of Object.entries(e.tokens??{})){let u=o.replace(/^--vt-/,"");vi.includes(u)?wi(c)?i[u]=c.trim():console.warn(`[vitrine] Unsafe or invalid value for theme token "${o}" ignored.`):console.warn(`[vitrine] Unknown theme token "${o}" ignored.`)}return Ne.set(t,{colorScheme:n??s.colorScheme,tokens:i}),Yr(),Xr(),t}function Ai(){return[...Ne.keys()]}function Ln(t){let e=Ne.get(t);return e?{colorScheme:e.colorScheme,tokens:{...e.tokens}}:void 0}function Yr(){for(;Ge.cssRules.length;)Ge.deleteRule(0);for(let[t,e]of Ne){let n=Ge.insertRule(`.vt[data-theme="${t}"] {}`,Ge.cssRules.length),r=Ge.cssRules[n].style;r.setProperty("color-scheme",e.colorScheme);for(let[s,i]of Object.entries(e.tokens))r.setProperty(`--_${s}`,`var(--vt-${s}, ${i})`)}}Yr();var Rn=typeof matchMedia=="function"?matchMedia("(prefers-color-scheme: dark)"):null,Cn=new Set;function Xr(){for(let t of Cn)t()}Rn?.addEventListener?.("change",Xr);function Zr(t){return Cn.add(t),()=>Cn.delete(t)}function Qr(t){let e=ae(),n=t?.trim().toLowerCase()||e.theme;if(n!=="auto"&&!Ne.has(n)&&(n=Ne.has(e.theme)?e.theme:"auto"),n!=="auto")return n;let r=Rn?.matches?e.darkTheme:e.lightTheme;return Ne.has(r)?r:Rn?.matches?"dark":"light"}var Ni="",Jr="",ki="";function es(t){Ni=t}function ts(t){ki=t}function On(t){Jr=t}function ns(){return Jr}var Mn=Object.freeze({"1c-light":0,"a11y-dark":1,"a11y-light":0,agate:1,"an-old-hope":1,androidstudio:1,"arduino-light":0,arta:1,ascetic:0,"atom-one-dark":1,"atom-one-dark-reasonable":1,"atom-one-light":0,"base16-3024":1,"base16-apathy":1,"base16-apprentice":1,"base16-ashes":1,"base16-atelier-cave":1,"base16-atelier-cave-light":0,"base16-atelier-dune":1,"base16-atelier-dune-light":0,"base16-atelier-estuary":1,"base16-atelier-estuary-light":0,"base16-atelier-forest":1,"base16-atelier-forest-light":0,"base16-atelier-heath":1,"base16-atelier-heath-light":0,"base16-atelier-lakeside":1,"base16-atelier-lakeside-light":0,"base16-atelier-plateau":1,"base16-atelier-plateau-light":0,"base16-atelier-savanna":1,"base16-atelier-savanna-light":0,"base16-atelier-seaside":1,"base16-atelier-seaside-light":0,"base16-atelier-sulphurpool":1,"base16-atelier-sulphurpool-light":0,"base16-atlas":1,"base16-bespin":1,"base16-black-metal":1,"base16-black-metal-bathory":1,"base16-black-metal-burzum":1,"base16-black-metal-dark-funeral":1,"base16-black-metal-gorgoroth":1,"base16-black-metal-immortal":1,"base16-black-metal-khold":1,"base16-black-metal-marduk":1,"base16-black-metal-mayhem":1,"base16-black-metal-nile":1,"base16-black-metal-venom":1,"base16-brewer":1,"base16-bright":1,"base16-brogrammer":1,"base16-brush-trees":0,"base16-brush-trees-dark":1,"base16-chalk":1,"base16-circus":1,"base16-classic-dark":1,"base16-classic-light":0,"base16-codeschool":1,"base16-colors":1,"base16-cupcake":0,"base16-cupertino":0,"base16-danqing":1,"base16-darcula":1,"base16-dark-violet":1,"base16-darkmoss":1,"base16-darktooth":1,"base16-decaf":1,"base16-default-dark":1,"base16-default-light":0,"base16-dirtysea":0,"base16-dracula":1,"base16-edge-dark":1,"base16-edge-light":0,"base16-eighties":1,"base16-embers":1,"base16-equilibrium-dark":1,"base16-equilibrium-gray-dark":1,"base16-equilibrium-gray-light":0,"base16-equilibrium-light":0,"base16-espresso":1,"base16-eva":1,"base16-eva-dim":1,"base16-flat":1,"base16-framer":1,"base16-fruit-soda":0,"base16-gigavolt":1,"base16-github":0,"base16-google-dark":1,"base16-google-light":0,"base16-grayscale-dark":1,"base16-grayscale-light":0,"base16-green-screen":1,"base16-gruvbox-dark-hard":1,"base16-gruvbox-dark-medium":1,"base16-gruvbox-dark-pale":1,"base16-gruvbox-dark-soft":1,"base16-gruvbox-light-hard":0,"base16-gruvbox-light-medium":0,"base16-gruvbox-light-soft":0,"base16-hardcore":1,"base16-harmonic16-dark":1,"base16-harmonic16-light":0,"base16-heetch-dark":1,"base16-heetch-light":0,"base16-helios":1,"base16-hopscotch":1,"base16-horizon-dark":1,"base16-horizon-light":0,"base16-humanoid-dark":1,"base16-humanoid-light":0,"base16-ia-dark":1,"base16-ia-light":0,"base16-icy-dark":1,"base16-ir-black":1,"base16-isotope":1,"base16-kimber":1,"base16-london-tube":1,"base16-macintosh":1,"base16-marrakesh":1,"base16-materia":1,"base16-material":1,"base16-material-darker":1,"base16-material-lighter":0,"base16-material-palenight":1,"base16-material-vivid":1,"base16-mellow-purple":1,"base16-mexico-light":0,"base16-mocha":1,"base16-monokai":1,"base16-nebula":1,"base16-nord":1,"base16-nova":1,"base16-ocean":1,"base16-oceanicnext":1,"base16-one-light":0,"base16-onedark":1,"base16-outrun-dark":1,"base16-papercolor-dark":1,"base16-papercolor-light":0,"base16-paraiso":1,"base16-pasque":1,"base16-phd":1,"base16-pico":1,"base16-pop":1,"base16-porple":1,"base16-qualia":1,"base16-railscasts":1,"base16-rebecca":1,"base16-ros-pine":1,"base16-ros-pine-dawn":0,"base16-ros-pine-moon":1,"base16-sagelight":0,"base16-sandcastle":1,"base16-seti-ui":1,"base16-shapeshifter":0,"base16-silk-dark":1,"base16-silk-light":0,"base16-snazzy":1,"base16-solar-flare":1,"base16-solar-flare-light":0,"base16-solarized-dark":1,"base16-solarized-light":0,"base16-spacemacs":1,"base16-summercamp":1,"base16-summerfruit-dark":1,"base16-summerfruit-light":0,"base16-synth-midnight-terminal-dark":1,"base16-synth-midnight-terminal-light":0,"base16-tango":1,"base16-tender":1,"base16-tomorrow":0,"base16-tomorrow-night":1,"base16-twilight":1,"base16-unikitty-dark":1,"base16-unikitty-light":0,"base16-vulcan":1,"base16-windows-10":1,"base16-windows-10-light":0,"base16-windows-95":1,"base16-windows-95-light":0,"base16-windows-high-contrast":1,"base16-windows-high-contrast-light":0,"base16-windows-nt":1,"base16-windows-nt-light":0,"base16-woodland":1,"base16-xcode-dusk":1,"base16-zenburn":1,"brown-paper":0,"codepen-embed":1,"color-brewer":0,"cybertopia-cherry":0,"cybertopia-dimmer":0,"cybertopia-icecap":0,"cybertopia-saturated":0,dark:1,default:0,devibeans:1,docco:0,equinox:0,far:1,felipec:1,foundation:0,github:0,"github-dark":1,"github-dark-dimmed":1,gml:1,googlecode:0,"gradient-dark":1,"gradient-light":0,grayscale:0,hybrid:1,idea:0,"intellij-light":0,"ir-black":1,"isbl-editor-dark":1,"isbl-editor-light":0,"kimbie-dark":1,"kimbie-light":0,lightfair:0,lioshi:1,magula:0,"mono-blue":0,monokai:1,"monokai-sublime":1,"night-owl":1,"nnfx-dark":1,"nnfx-light":0,nord:1,obsidian:1,"panda-syntax-dark":1,"panda-syntax-light":0,"paraiso-dark":1,"paraiso-light":0,pojoaque:0,purebasic:0,"qtcreator-dark":1,"qtcreator-light":0,rainbow:1,"rose-pine":1,"rose-pine-dawn":0,"rose-pine-moon":1,routeros:0,"school-book":0,"shades-of-purple":1,srcery:1,"stackoverflow-dark":1,"stackoverflow-light":0,sunburst:1,"tokyo-night-dark":1,"tokyo-night-light":0,"tomorrow-night-blue":1,"tomorrow-night-bright":1,vs:0,"vs-dark":1,vs2015:1,xcode:0,xt256:1});var In=new Map,rs=new Map;function ss(t){if(typeof t!="string")return null;let e=t.trim().toLowerCase().replace(/\//g,"-");return!e||e.length>60?null:Object.prototype.hasOwnProperty.call(Mn,e)?e:null}function Ri(){return Object.keys(Mn)}function as(t){return rs.get(t)}function is(t){let e=In.get(t);if(e)return e;let n=Ci(t);return In.set(t,n),n}async function Ci(t){let e=ae().syntaxThemesUrl||ns();if(!e)return null;try{let n=new URL(`${t}.css`,new URL(e.endsWith("/")?e:`${e}/`,document.baseURI));if(n.protocol!=="https:"&&n.protocol!=="http:")return null;let r=await fetch(n.href,{credentials:"same-origin"});if(!r.ok)throw new Error(`HTTP ${r.status}`);let s=await r.text(),i=new CSSStyleSheet;return i.replaceSync(s),rs.set(t,i),i}catch(n){return console.warn(`[vitrine] Could not load the "${t}" syntax theme.`,n),In.delete(t),null}}var os="http://www.w3.org/2000/svg";var gt=["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"}],mt=["path",{d:"M14 2v4a2 2 0 0 0 2 2h4"}],Li={copy:[["rect",{width:"14",height:"14",x:"8",y:"8",rx:"2",ry:"2"}],["path",{d:"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}]],check:[["path",{d:"M20 6 9 17l-5-5"}]],search:[["path",{d:"m21 21-4.34-4.34"}],["circle",{cx:"11",cy:"11",r:"8"}]],"chevron-up":[["path",{d:"m18 15-6-6-6 6"}]],"chevron-down":[["path",{d:"m6 9 6 6 6-6"}]],"chevron-right":[["path",{d:"m9 18 6-6-6-6"}]],wrap:[["path",{d:"m16 16-3 3 3 3"}],["path",{d:"M3 12h14.5a1 1 0 0 1 0 7H13"}],["path",{d:"M3 19h6"}],["path",{d:"M3 5h18"}]],download:[["path",{d:"M12 15V3"}],["path",{d:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"}],["path",{d:"m7 10 5 5 5-5"}]],"expand-all":[["path",{d:"m7 15 5 5 5-5"}],["path",{d:"m7 9 5-5 5 5"}]],"collapse-all":[["path",{d:"m7 20 5-5 5 5"}],["path",{d:"m7 4 5 5 5-5"}]],link:[["path",{d:"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"}],["path",{d:"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"}]],eye:[["path",{d:"M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"}],["circle",{cx:"12",cy:"12",r:"3"}]],code:[["path",{d:"m16 18 6-6-6-6"}],["path",{d:"m8 6-6 6 6 6"}]],columns:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M12 3v18"}]],list:[["path",{d:"M3 5h.01"}],["path",{d:"M3 12h.01"}],["path",{d:"M3 19h.01"}],["path",{d:"M8 5h13"}],["path",{d:"M8 12h13"}],["path",{d:"M8 19h13"}]],pencil:[["path",{d:"M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"}],["path",{d:"m15 5 4 4"}]],"chevron-left":[["path",{d:"m15 18-6-6 6-6"}]],"chevrons-left":[["path",{d:"m11 17-5-5 5-5"}],["path",{d:"m18 17-5-5 5-5"}]],"chevrons-right":[["path",{d:"m6 17 5-5-5-5"}],["path",{d:"m13 17 5-5-5-5"}]],sort:[["path",{d:"m21 16-4 4-4-4"}],["path",{d:"M17 20V4"}],["path",{d:"m3 8 4-4 4 4"}],["path",{d:"M7 4v16"}]],"sort-up":[["path",{d:"m5 12 7-7 7 7"}],["path",{d:"M12 19V5"}]],"sort-down":[["path",{d:"M12 5v14"}],["path",{d:"m19 12-7 7-7-7"}]],table:[["path",{d:"M12 3v18"}],["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 9h18"}],["path",{d:"M3 15h18"}]],undo:[["path",{d:"M9 14 4 9l5-5"}],["path",{d:"M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11"}]],redo:[["path",{d:"m15 14 5-5-5-5"}],["path",{d:"M20 9H9.5A5.5 5.5 0 0 0 4 14.5A5.5 5.5 0 0 0 9.5 20H13"}]],maximize:[["path",{d:"M15 3h6v6"}],["path",{d:"m21 3-7 7"}],["path",{d:"m3 21 7-7"}],["path",{d:"M9 21H3v-6"}]],minimize:[["path",{d:"m14 10 7-7"}],["path",{d:"M20 10h-6V4"}],["path",{d:"m3 21 7-7"}],["path",{d:"M4 14h6v6"}]],swap:[["path",{d:"M8 3 4 7l4 4"}],["path",{d:"M4 7h16"}],["path",{d:"m16 21 4-4-4-4"}],["path",{d:"M20 17H4"}]],rows:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 12h18"}]],"sync-scroll":[["path",{d:"M9 17H7A5 5 0 0 1 7 7h2"}],["path",{d:"M15 7h2a5 5 0 1 1 0 10h-2"}],["line",{x1:"8",x2:"16",y1:"12",y2:"12"}]],alert:[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}],["path",{d:"M12 9v4"}],["path",{d:"M12 17h.01"}]],close:[["path",{d:"M18 6 6 18"}],["path",{d:"m6 6 12 12"}]],replay:[["path",{d:"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"}],["path",{d:"M3 3v5h5"}]],chart:[["path",{d:"M3 3v16a2 2 0 0 0 2 2h16"}],["path",{d:"m19 9-5 5-4-4-3 3"}]],follow:[["path",{d:"M12 17V3"}],["path",{d:"m6 11 6 6 6-6"}],["path",{d:"M19 21H5"}]],terminal:[["path",{d:"M12 19h8"}],["path",{d:"m4 17 6-6-6-6"}]],folder:[["path",{d:"M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"}]],"folder-open":[["path",{d:"m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"}]],file:[gt,mt],"file-code":[gt,mt,["path",{d:"m10 13-2 2 2 2"}],["path",{d:"m14 17 2-2-2-2"}]],"file-text":[gt,mt,["path",{d:"M10 9H8"}],["path",{d:"M16 13H8"}],["path",{d:"M16 17H8"}]],"file-image":[gt,mt,["circle",{cx:"10",cy:"12",r:"2"}],["path",{d:"m20 17-1.296-1.296a2.41 2.41 0 0 0-3.408 0L9 22"}]],"file-data":[gt,mt,["path",{d:"M10 12a1 1 0 0 0-1 1v1a1 1 0 0 1-1 1 1 1 0 0 1 1 1v1a1 1 0 0 0 1 1"}],["path",{d:"M14 18a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1 1 1 0 0 1-1-1v-1a1 1 0 0 0-1-1"}]],lock:[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2"}],["path",{d:"M7 11V7a5 5 0 0 1 10 0v4"}]],"eye-off":[["path",{d:"M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"}],["path",{d:"M14.084 14.158a3 3 0 0 1-4.242-4.242"}],["path",{d:"M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"}],["path",{d:"m2 2 20 20"}]]};function ke(t){let e=document.createElementNS(os,"svg");e.setAttribute("viewBox","0 0 24 24"),e.setAttribute("fill","none"),e.setAttribute("stroke","currentColor"),e.setAttribute("stroke-width","2.1"),e.setAttribute("stroke-linecap","round"),e.setAttribute("stroke-linejoin","round"),e.setAttribute("aria-hidden","true"),e.setAttribute("focusable","false"),e.setAttribute("class","icon");for(let[n,r]of Li[t]??[]){let s=document.createElementNS(os,n);for(let[i,o]of Object.entries(r))s.setAttribute(i,o);e.append(s)}return e}var Dn=new WeakMap,bt=null;function Oi(){return bt||typeof IntersectionObserver>"u"||(bt=new IntersectionObserver(t=>{for(let e of t)e.isIntersecting&&Pn(e.target)},{rootMargin:"600px 0px"})),bt}function cs(t,e){Dn.set(t,e);let n=Oi();n?n.observe(t):Pn(t)}function Pn(t){let e=Dn.get(t);e&&(Dn.delete(t),bt?.unobserve(t),e())}function ls(t){for(let e of Array.from(t.querySelectorAll(".chunk[data-pending]")))Pn(e)}var Un=5e3,Wt=200;function Mi(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}function Ii(t,e,n=Un){let r=[];if(!e)return{starts:r,capped:!1};let s=new RegExp(Mi(e),"gi"),i;for(;(i=s.exec(t))!==null;){if(r.length===n)return{starts:r,capped:!0};r.push(i.index),i[0].length===0&&(s.lastIndex+=1)}return{starts:r,capped:!1}}var it=class{constructor(e,n={}){this.root=e,this.skip=n.skip??"",this.matches=[],this.current=-1}run(e){this.clear();let n=e.slice(0,Wt);if(!n)return{total:0,capped:!1};ls(this.root);let{nodes:r,starts:s,text:i}=this.collectText(),{starts:o,capped:c}=Ii(i,n),u=o.map(()=>[]);for(let d=o.length-1;d>=0;d-=1){let f=o[d],E=f+n.length,_=Di(s,E-1);for(;_>=0&&s[_]+(r[_].nodeValue??"").length>f;){let T=s[_],H=Math.max(f,T)-T,F=Math.min(E,T+(r[_].nodeValue??"").length)-T;F>H&&u[d].unshift(Pi(r[_],H,F,d)),_-=1}}return this.matches=u,{total:u.length,capped:c}}collectText(){let e=this.skip,n=document.createTreeWalker(this.root,NodeFilter.SHOW_TEXT,{acceptNode(c){let u=c.parentElement;return e&&u&&u.closest(e)?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT}}),r=[],s=[],i=[],o=0;for(let c=n.nextNode();c;c=n.nextNode()){let u=c.nodeValue??"";u&&(r.push(c),s.push(o),i.push(u),o+=u.length)}return{nodes:r,starts:s,text:i.join("")}}go(e){if(!this.matches.length)return null;let n=this.matches.length,r=(e%n+n)%n;for(let s of this.matches[this.current]??[])s.classList.remove("current");this.current=r;for(let s of this.matches[r])s.classList.add("current");return this.matches[r][0]??null}unsetCurrent(){for(let e of this.matches[this.current]??[])e.classList.remove("current");this.current=-1}clear(){let e=new Set;for(let n of this.matches)for(let r of n){let s=r.parentNode;s&&(r.replaceWith(...Array.from(r.childNodes)),e.add(s))}for(let n of e)n.normalize();this.matches=[],this.current=-1}};function Di(t,e){let n=0,r=t.length-1;for(;n<r;){let s=n+r+1>>1;t[s]<=e?n=s:r=s-1}return n}function Pi(t,e,n,r){let s=t.splitText(e);s.splitText(n-e);let i=document.createElement("mark");return i.className="match",i.setAttribute("part","match"),i.dataset.match=String(r),s.replaceWith(i),i.appendChild(s),i}function ge(t){let e=v("button",{class:"btn",part:`button${t.part?` ${t.part}`:""}`,attrs:{type:"button","aria-label":t.label,title:t.label,"aria-pressed":t.pressed===void 0?null:String(t.pressed),"data-focus-key":t.key},on:{click:t.onClick}});return e.append(ke(t.icon)),e}function ds(t,e,n){let r=t.querySelector("svg");r&&(r.replaceWith(ke(n?"check":"alert")),t.classList.toggle("done",n),setTimeout(()=>{t.querySelector("svg")?.replaceWith(ke(e)),t.classList.remove("done")},1500))}var qt=class{constructor(e,n,r=""){this.t=e,this.handlers=n,this.total=0,this.capped=!1,this.index=-1;let s=Ft("search");this.input=v("input",{class:"search-input",part:"search-input",attrs:{id:s,type:"search",placeholder:e("searchPlaceholder"),"aria-label":e("search"),maxlength:Wt,autocomplete:"off",spellcheck:"false",enterkeyhint:"search","data-focus-key":"search-input"}}),this.input.value=r.slice(0,Wt),this.count=v("span",{class:"search-count",part:"search-count",attrs:{"aria-hidden":"true"}});let i=ge({icon:"chevron-up",label:e("searchPrevious"),onClick:()=>this.step(-1),key:"search-prev"}),o=ge({icon:"chevron-down",label:e("searchNext"),onClick:()=>this.step(1),key:"search-next"}),c=ge({icon:"close",label:e("searchClose"),onClick:()=>n.onClose(),key:"search-close"});this.element=v("div",{class:"search",part:"search",attrs:{role:"search"}},this.input,this.count,i,o,c);let u=Ur(()=>this.run(),150);this.input.addEventListener("input",u),this.input.addEventListener("keydown",d=>{d.key==="Enter"?(d.preventDefault(),u.cancel(),this.input.value!==this.lastQuery?this.run():this.step(d.shiftKey?-1:1)):d.key==="Escape"&&(d.preventDefault(),d.stopPropagation(),this.input.value?(this.input.value="",this.run()):n.onClose())}),this.lastQuery=void 0}run(){let e=this.input.value;this.lastQuery=e;let{total:n,capped:r}=this.handlers.run(e);this.total=n,this.capped=r,this.index=-1,n>0?this.step(1):this.updateCount(),this.handlers.onResult?.(e,n,r)}step(e){this.total&&(this.index=((this.index+e)%this.total+this.total)%this.total,this.handlers.go(this.index),this.updateCount())}updateCount(){if(!this.input.value)this.count.textContent="";else if(!this.total)this.count.textContent=this.t("searchNone");else{let e=this.capped?"searchCountCapped":"searchCount";this.count.textContent=this.t(e,{current:this.index+1,total:this.total})}}focus(){this.input.focus(),this.input.select()}};function hs({tabs:t,selected:e,label:n,onSelect:r,panelId:s}){let i=v("div",{class:"tabs",part:"tabs",attrs:{role:"tablist","aria-label":n}}),o=t.map(c=>{let u=c.id===e;return v("button",{class:"tab",part:u?"tab tab-active":"tab",attrs:{type:"button",role:"tab","aria-selected":String(u),"aria-controls":s,tabindex:u?"0":"-1","data-tab":c.id,"data-focus-key":`tab-${c.id}`},on:{click:()=>r(c.id)}},c.icon?ke(c.icon):null,c.label)});return i.append(...o),i.addEventListener("keydown",c=>{let u=o.findIndex(f=>f===c.target);if(u<0)return;let d=-1;c.key==="ArrowRight"?d=(u+1)%o.length:c.key==="ArrowLeft"?d=(u-1+o.length)%o.length:c.key==="Home"?d=0:c.key==="End"&&(d=o.length-1),!(d<0)&&(c.preventDefault(),r(t[d].id))}),i}function fs(t){return v("div",{class:"loader",part:"loading",attrs:{role:"status"}},Ui(),v("span",{class:"loader-label",text:t("loading")}))}var us="http://www.w3.org/2000/svg";function Ui(){let t=document.createElementNS(us,"svg");t.setAttribute("viewBox","0 0 120 120"),t.setAttribute("class","loader-mark"),t.setAttribute("aria-hidden","true"),t.setAttribute("focusable","false");let e=[["rect",{class:"loader-frame",x:"12",y:"16",width:"96",height:"88",rx:"18"}],["path",{class:"loader-frame",d:"M12 42 L108 42"}],["circle",{class:"loader-dot",cx:"29",cy:"29",r:"5"}],["path",{class:"loader-v",d:"M42 60 L60 86 L78 60",pathLength:"100"}]];for(let[n,r]of e){let s=document.createElementNS(us,n);for(let[i,o]of Object.entries(r))s.setAttribute(i,o);t.append(s)}return t}function ps(t,e){return v("div",{class:"message",part:"error",attrs:{role:"alert"}},ke("alert"),v("div",{},v("p",{class:"message-title",text:t}),e?v("p",{class:"message-detail",text:e}):null))}function zn(t){return v("div",{class:"notice",part:"notice",attrs:{role:"note"}},ke("alert"),v("span",{text:t}))}function gs(t){return v("div",{class:"empty",part:"empty",text:t("empty")})}var ms=new Map;function Vt(t){let e=ms.get(t);return e||(e=new CSSStyleSheet,e.replaceSync(t),ms.set(t,e)),e}var zi=Object.freeze(["variant","theme","src","allow-remote","max-height","copy","search","download","header","dot","title","label","lang-ui","mode","edit-toggle","placeholder","syntax-theme","syntax-theme-dark","badge","history","fullscreen","status"]),Kt=class extends HTMLElement{static type="base";static componentAttributes=[];static presets={simple:{},full:{}};static allowEmpty=!1;static keepCarriageReturns=!1;static upgradeProperties=["content"];static styles=[];static get observedAttributes(){return[...zi,...this.componentAttributes]}constructor(){super(),this.root=this.attachShadow({mode:"open"}),this.frame=v("div",{class:"vt",part:"container"}),this.syntaxTheme=null,this.updateSheets(null),this.live=v("div",{class:"sr-only",attrs:{"aria-live":"polite","aria-atomic":"true"}}),this.root.append(this.frame,this.live),this._content=void 0,this.text=null,this.error=null,this.loading=!1,this.searchOpen=!1,this.searchQuery="",this.searchBar=null,this.t=kn("en"),this._loadToken=0,this._abort=null,this._renderQueued=!1,this._readyPending=!1,this._cleanups=[],this._observer=null,this._connected=!1,this.modeState=null,this.editHistory=null,this._historyCleanup=null,this._escapeFullscreen=null}get content(){return this.text??""}set content(e){let n=e==null?void 0:String(e);n!==void 0&&n===this._content&&n===this.text||(this._content=n,this._connected&&this.reload())}upgradeProperty(e){if(Object.prototype.hasOwnProperty.call(this,e)){let n=this[e];delete this[e],this[e]=n}}connectedCallback(){for(let n of this.constructor.upgradeProperties)this.upgradeProperty(n);this._cleanups.push(Dr(n=>n.has("maxSize")?this.reload():this.requestRender()),Zr(()=>this.applyTheme()),jr(()=>this.requestRender())),this._observer=new MutationObserver(()=>{this._content===void 0&&!this.hasAttribute("src")&&this.reload()}),this._observer.observe(this,{childList:!0,characterData:!0,subtree:!0});let e=()=>{document.fullscreenElement===this?this.setFullscreen("native"):this.frame.dataset.fullscreen==="native"&&this.setFullscreen(null)};document.addEventListener("fullscreenchange",e),this._cleanups.push(()=>document.removeEventListener("fullscreenchange",e)),this._connected=!0,this.reload()}disconnectedCallback(){this._connected=!1;for(let e of this._cleanups.splice(0))e();this._observer?.disconnect(),this._observer=null,this._abort?.abort(),this._abort=null}attributeChangedCallback(e,n,r){n===r||!this.isConnected||(e==="mode"&&(this.modeState=null),e==="src"||e==="allow-remote"?this.reload():e==="theme"?this.applyTheme():this.requestRender())}reload(){let e=++this._loadToken;this._abort?.abort(),this._abort=null;let n=ae(),r=this.getAttribute("src");if(this._content!==void 0)this.setText(this._content);else if(r!==null&&r.trim()!==""){this.loading=!0,this.error=null,this.requestRender();let s=new AbortController;this._abort=s,Hr(r,{allowRemote:De(this.getAttribute("allow-remote"))===!0,maxSize:n.maxSize,timeout:n.fetchTimeout,signal:s.signal}).then(i=>e===this._loadToken&&this.setText(i),i=>e===this._loadToken&&!$r(i)&&this.setError(i))}else this.setText(this.readInline()??"")}setText(e){this.loading=!1,this.editHistory=null;try{jt(e,ae().maxSize)}catch(r){this.setError(r);return}let n=this.constructor;this.text=e.replace(n.keepCarriageReturns?/\r\n/g:/\r\n?/g,`
`),this.error=null,this.contentChanged(),this._readyPending=!0,this.requestRender()}setError(e){this.loading=!1,this._readyPending=!1,this.error=e,this.text=null,this.contentChanged(),this.requestRender();let{title:n,detail:r}=this.describeError(e);pe(this,ue.ERROR,{message:r||n,cause:e})}describeError(e){let n=this.t;if(e instanceof ie){let r={...e.params};for(let s of["size","limit"])typeof r[s]=="number"&&(r[s]=de(Number(r[s]),this.locale));return{title:n("errorTitle"),detail:n(e.code,r)}}return{title:n("errorTitle"),detail:e instanceof Error?e.message:String(e)}}get editing(){return(this.modeState??pt(this.getAttribute("mode"),["view","edit"],"view"))==="edit"}edited(e){this.text=e,this._content=e,this.contentEdited(e),pe(this,ue.INPUT,{value:e})}contentEdited(e){}historyButtons(e){if(this.editHistory=e.history,De(this.getAttribute("history"))===!1)return[];let n=ge({icon:"undo",label:this.t("undo"),key:"undo",part:"undo-button",onClick:()=>e.undo()}),r=ge({icon:"redo",label:this.t("redo"),key:"redo",part:"redo-button",onClick:()=>e.redo()}),s=()=>{n.disabled=!e.history.canUndo,r.disabled=!e.history.canRedo};return s(),this._historyCleanup?.(),this._historyCleanup=e.history.subscribe(s),[n,r]}fullscreenButton(){if(!this.feature("fullscreen"))return null;let e=!!this.frame.dataset.fullscreen;return ge({icon:e?"minimize":"maximize",label:this.t(e?"exitFullscreen":"fullscreen"),key:"fullscreen",part:"fullscreen-button",pressed:e,onClick:()=>this.toggleFullscreen()})}async toggleFullscreen(){let e=this.frame.dataset.fullscreen;if(e==="native"){await document.exitFullscreen?.().catch(()=>{});return}if(e==="window"){this.setFullscreen(null);return}if(document.fullscreenEnabled&&this.requestFullscreen)try{await this.requestFullscreen({navigationUI:"hide"});return}catch{}this.setFullscreen("window")}setFullscreen(e){e?this.frame.dataset.fullscreen=e:delete this.frame.dataset.fullscreen,e==="window"?(this._escapeFullscreen=n=>{n.key==="Escape"&&!n.defaultPrevented&&this.setFullscreen(null)},this.frame.addEventListener("keydown",this._escapeFullscreen)):this._escapeFullscreen&&(this.frame.removeEventListener("keydown",this._escapeFullscreen),this._escapeFullscreen=null),this.render(),this.root.querySelector('[data-focus-key="fullscreen"]')?.focus(),pe(this,ue.FULLSCREEN_CHANGE,{fullscreen:!!e})}editToggleButton(){return this.feature("edit-toggle")?ge({icon:this.editing?"eye":"pencil",label:this.t(this.editing?"stopEditing":"edit"),key:"edit-toggle",part:"edit-button",pressed:this.editing,onClick:()=>{this.modeState=this.editing?"view":"edit",this.render(),pe(this,ue.MODE_CHANGE,{mode:this.modeState}),this.modeState==="edit"&&this.root.querySelector(".editor-input")?.focus()}}):null}readInline(){return Br(this)}contentChanged(){}get variant(){return pt(this.getAttribute("variant"),["simple","full"],"simple")}feature(e){let n=De(this.getAttribute(e));return n!==null?n:this.constructor.presets[this.variant][e]??!1}get locale(){let e=this.getAttribute("lang-ui")?.trim();return e&&/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(e)?e:ae().lang}get heading(){return Cr(this.getAttribute("label")??this.getAttribute("title"))}requestRender(){this._renderQueued||(this._renderQueued=!0,queueMicrotask(()=>{this._renderQueued=!1,this.isConnected&&this.render()}))}applyTheme(){let e=Qr(this.getAttribute("theme"));this.frame.dataset.theme=e,this.applySyntaxTheme(Ln(e)?.colorScheme==="dark")}applySyntaxTheme(e){let n=ae(),r=e&&this.getAttribute("syntax-theme-dark")||this.getAttribute("syntax-theme")||e&&n.syntaxThemeDark||n.syntaxTheme,s=ss(r);if(this.syntaxTheme=s,!s){this.updateSheets(null);return}let i=as(s);if(i){this.updateSheets(i);return}is(s).then(o=>{o&&this.syntaxTheme===s&&this.updateSheets(o)})}updateSheets(e){let r=this.constructor.styles.map(Vt),s=[Vt(Or),Ge,Vt(Mr),...r];this.frame.toggleAttribute("data-syntax-theme",!!e),this.root.adoptedStyleSheets=e?[...s.filter(i=>i!==Vt(Ht)),e]:s}render(){let e=this.activeFocusKey(),n=this.root.activeElement,r=n instanceof HTMLTextAreaElement||n instanceof HTMLInputElement?[n.selectionStart,n.selectionEnd]:null;this.t=kn(this.locale),this.applyTheme();let s=Rr(this.getAttribute("max-height"));if(s?this.frame.style.setProperty("--_max-height",s):this.frame.style.removeProperty("--_max-height"),this.searchBar=null,this.frame.replaceChildren(),this.loading){this.frame.append(...this.chrome(null),v("div",{class:"body",part:"body"},fs(this.t))),this.frame.setAttribute("aria-busy","true");return}if(this.frame.removeAttribute("aria-busy"),this.error){let{title:o,detail:c}=this.describeError(this.error);this.frame.append(...this.chrome(null),ps(o,c));return}if(!this.text&&!this.editing&&!this.constructor.allowEmpty)this.frame.append(...this.chrome(null),gs(this.t));else{this.renderContent(this.frame);let o=this.searchBar;this.searchOpen&&this.searchQuery&&o?.run()}this.restoreFocus(e);let i=this.root.activeElement;if(r&&(i instanceof HTMLTextAreaElement||i instanceof HTMLInputElement)&&r[0]!==null)try{i.setSelectionRange(r[0],r[1])}catch{}this._readyPending&&(this._readyPending=!1,pe(this,ue.READY,{type:this.constructor.type}))}renderContent(e){throw new Error("renderContent() must be implemented.")}chrome(e){let n=(e?.actions??[]).filter(o=>o!==null),r=n.length?v("div",{class:"toolbar",part:"toolbar",attrs:{role:"toolbar","aria-label":this.t("actions")}},...n):null;if(!this.feature("header"))return r?.classList.add("floating"),[r,e?.tabs??null,this.searchBar?.element??null].filter(o=>o!==null);let s=this.heading,i=v("div",{class:"header",part:"header"},this.feature("dot")?v("span",{class:"dot",part:"status-dot",attrs:{"aria-hidden":"true"}}):null,s?v("span",{class:"title",part:"title",text:s,attrs:{title:s}}):null,e?.tabs??null,s?null:v("span",{class:"spacer"}),e?.badge&&De(this.getAttribute("badge"))!==!1?v("span",{class:"badge",part:"badge",text:e.badge}):null);return r&&i.append(r),this.searchBar?[i,this.searchBar.element]:[i]}copyButton(e,n=this.t("copy"),r="copy"){let s=ge({icon:"copy",label:n,key:r,part:"copy-button",onClick:async()=>{let i=e(),o=await Tn(i,this.root);ds(s,"copy",o),this.announce(this.t(o?"copied":"copyFailed")),o&&pe(this,ue.COPY,{text:i})}});return s}copyTextButton(e,n,r){let s=v("button",{class:"text-btn",part:"copy-button",text:n,attrs:{type:"button","data-focus-key":r},on:{click:async()=>{let i=e(),o=await Tn(i,this.root);s.textContent=this.t(o?"copied":"copyFailed"),s.classList.toggle("done",o),setTimeout(()=>{s.textContent=n,s.classList.remove("done")},1500),this.announce(this.t(o?"copied":"copyFailed")),o&&pe(this,ue.COPY,{text:i})}}});return s}downloadName(e){let n=this.getAttribute("download"),r=n&&De(n)!==!1&&!/^(?:true|on|yes)$/i.test(n.trim())?n:null,s=/\.[a-z0-9]{1,10}$/i.test(this.heading)?this.heading:null;return Lr(r??s,e)}downloadButton(e,n,r){return ge({icon:"download",label:this.t("download"),key:"download",part:"download-button",onClick:()=>Ir(e(),n,r)})}searchButton(e){return this.feature("search")?(this.searchOpen&&(this.searchBar=new qt(this.t,{run:n=>(this.searchQuery=n,e.run(n)),go:n=>e.go(n),onResult:(n,r,s)=>{n&&this.announce(r?this.t("searchResults",{total:s?`${r}+`:r}):this.t("searchNone")),pe(this,ue.SEARCH,{query:n,matches:r})},onClose:()=>{e.clear(),this.searchOpen=!1,this.searchQuery="",this.render(),this.root.querySelector('[data-focus-key="search"]')?.focus()}},this.searchQuery)),ge({icon:"search",label:this.t("search"),key:"search",part:"search-button",pressed:this.searchOpen,onClick:()=>{this.searchOpen=!this.searchOpen,this.searchOpen||(this.searchQuery=""),this.render(),this.searchOpen&&this.searchBar?.focus()}})):null}announce(e){this.live.textContent="",setTimeout(()=>{this.live.textContent=e},50)}activeFocusKey(){let e=this.root.activeElement;return e instanceof HTMLElement?e.dataset.focusKey??null:null}restoreFocus(e){if(!e)return;let n=this.root.querySelector(`[data-focus-key="${CSS.escape(e)}"]`);n instanceof HTMLElement&&n.focus({preventScroll:!0})}};var Us=Xa(Ps(),1);var _t=Us.default;function zs(t){let e=t.regex,n={},r={begin:/\$\{/,end:/\}/,contains:["self",{begin:/:-/,contains:[n]}]};Object.assign(n,{className:"variable",variants:[{begin:e.concat(/\$[\w\d#@][\w\d_]*/,"(?![\\w\\d])(?![$])")},r]});let s={className:"subst",begin:/\$\(/,end:/\)/,contains:[t.BACKSLASH_ESCAPE]},i=t.inherit(t.COMMENT(),{match:[/(^|\s)/,/#.*$/],scope:{2:"comment"}}),o={begin:/<<-?\s*(?=\w+)/,starts:{contains:[t.END_SAME_AS_BEGIN({begin:/(\w+)/,end:/(\w+)/,className:"string"})]}},c={className:"string",begin:/"/,end:/"/,contains:[t.BACKSLASH_ESCAPE,n,s]};s.contains.push(c);let u={match:/\\"/},d={className:"string",begin:/'/,end:/'/},f={match:/\\'/},E={begin:/\$?\(\(/,end:/\)\)/,contains:[{begin:/\d+#[0-9a-f]+/,className:"number"},t.NUMBER_MODE,n]},_=["fish","bash","zsh","sh","csh","ksh","tcsh","dash","scsh"],T=t.SHEBANG({binary:`(${_.join("|")})`,relevance:10}),H={className:"function",begin:/\w[\w\d_]*\s*\(\s*\)\s*\{/,returnBegin:!0,contains:[t.inherit(t.TITLE_MODE,{begin:/\w[\w\d_]*/})],relevance:0},F=["if","then","else","elif","fi","time","for","while","until","in","do","done","case","esac","coproc","function","select"],U=["true","false"],L={match:/(\/[a-z._-]+)+/},k=["break","cd","continue","eval","exec","exit","export","getopts","hash","pwd","readonly","return","shift","test","times","trap","umask","unset"],I=["alias","bind","builtin","caller","command","declare","echo","enable","help","let","local","logout","mapfile","printf","read","readarray","source","sudo","type","typeset","ulimit","unalias"],R=["autoload","bg","bindkey","bye","cap","chdir","clone","comparguments","compcall","compctl","compdescribe","compfiles","compgroups","compquote","comptags","comptry","compvalues","dirs","disable","disown","echotc","echoti","emulate","fc","fg","float","functions","getcap","getln","history","integer","jobs","kill","limit","log","noglob","popd","print","pushd","pushln","rehash","sched","setcap","setopt","stat","suspend","ttyctl","unfunction","unhash","unlimit","unsetopt","vared","wait","whence","where","which","zcompile","zformat","zftp","zle","zmodload","zparseopts","zprof","zpty","zregexparse","zsocket","zstyle","ztcp"],W=["chcon","chgrp","chown","chmod","cp","dd","df","dir","dircolors","ln","ls","mkdir","mkfifo","mknod","mktemp","mv","realpath","rm","rmdir","shred","sync","touch","truncate","vdir","b2sum","base32","base64","cat","cksum","comm","csplit","cut","expand","fmt","fold","head","join","md5sum","nl","numfmt","od","paste","ptx","pr","sha1sum","sha224sum","sha256sum","sha384sum","sha512sum","shuf","sort","split","sum","tac","tail","tr","tsort","unexpand","uniq","wc","arch","basename","chroot","date","dirname","du","echo","env","expr","factor","groups","hostid","id","link","logname","nice","nohup","nproc","pathchk","pinky","printenv","printf","pwd","readlink","runcon","seq","sleep","stat","stdbuf","stty","tee","test","timeout","tty","uname","unlink","uptime","users","who","whoami","yes"];return{name:"Bash",aliases:["sh","zsh"],keywords:{$pattern:/\b[a-z][a-z0-9._-]+\b/,keyword:F,literal:U,built_in:[...k,...I,"set","shopt",...R,...W]},contains:[T,t.SHEBANG(),H,E,i,o,L,c,u,d,f,n]}}function Bs(t){let e=t.regex;return{name:"Diff",aliases:["patch"],contains:[{className:"meta",relevance:10,match:e.either(/^@@ +-\d+,\d+ +\+\d+,\d+ +@@/,/^@@ +-\d+ +\+\d+,\d+ +@@/,/^@@ +-\d+,\d+ +\+\d+ +@@/,/^@@ +-\d+ +\+\d+ +@@/,/^\*\*\* +\d+,\d+ +\*\*\*\*$/,/^--- +\d+,\d+ +----$/)},{className:"comment",variants:[{begin:e.either(/Index: /,/^index/,/={3,}/,/^-{3}/,/^\*{3} /,/^\+{3}/,/^diff --git/),end:/$/},{match:/^\*{15}$/}]},{className:"addition",begin:/^\+/,end:/$/},{className:"deletion",begin:/^-/,end:/$/},{className:"addition",begin:/^!/,end:/$/}]}}var Hs="[A-Za-z$_][0-9A-Za-z$_]*",Ro=["as","in","of","if","for","while","finally","var","new","function","do","return","void","else","break","catch","instanceof","with","throw","case","default","try","switch","continue","typeof","delete","let","yield","const","class","debugger","async","await","static","import","from","export","extends","using"],Co=["true","false","null","undefined","NaN","Infinity"],Fs=["Object","Function","Boolean","Symbol","Math","Date","Number","BigInt","String","RegExp","Array","Float32Array","Float64Array","Int8Array","Uint8Array","Uint8ClampedArray","Int16Array","Int32Array","Uint16Array","Uint32Array","BigInt64Array","BigUint64Array","Set","Map","WeakSet","WeakMap","ArrayBuffer","SharedArrayBuffer","Atomics","DataView","JSON","Promise","Generator","GeneratorFunction","AsyncFunction","Reflect","Proxy","Intl","WebAssembly"],$s=["Error","EvalError","InternalError","RangeError","ReferenceError","SyntaxError","TypeError","URIError"],js=["setInterval","setTimeout","clearInterval","clearTimeout","require","exports","eval","isFinite","isNaN","parseFloat","parseInt","decodeURI","decodeURIComponent","encodeURI","encodeURIComponent","escape","unescape"],Lo=["arguments","this","super","console","window","document","localStorage","sessionStorage","module","self","global"],Oo=[].concat(js,Fs,$s);function Gs(t){let e=t.regex,n=(A,{after:O})=>{let $="</"+A[0].slice(1);return A.input.indexOf($,O)!==-1},r=Hs,s={begin:"<>",end:"</>"},i=/<[A-Za-z0-9\\._:-]+\s*\/>/,o={begin:/<[A-Za-z0-9\\._:-]+/,end:/\/[A-Za-z0-9\\._:-]+>|\/>/,isTrulyOpeningTag:(A,O)=>{let $=A[0].length+A.index,ee=A.input[$];if(ee==="<"||ee===","){O.ignoreMatch();return}ee===">"&&(n(A,{after:$})||O.ignoreMatch());let oe,Le=A.input.substring($);if(oe=Le.match(/^\s*=/)){O.ignoreMatch();return}if((oe=Le.match(/^\s+extends\s+/))&&oe.index===0){O.ignoreMatch();return}}},c={$pattern:Hs,keyword:Ro,literal:Co,built_in:Oo,"variable.language":Lo},u="[0-9](_?[0-9])*",d=`\\.(${u})`,f="0|[1-9](_?[0-9])*|0[0-7]*[89][0-9]*",E={className:"number",variants:[{begin:`(\\b(${f})((${d})|\\.)?|(${d}))[eE][+-]?(${u})\\b`},{begin:`\\b(${f})\\b((${d})\\b|\\.)?|(${d})\\b`},{begin:"\\b(0|[1-9](_?[0-9])*)n\\b"},{begin:"\\b0[xX][0-9a-fA-F](_?[0-9a-fA-F])*n?\\b"},{begin:"\\b0[bB][0-1](_?[0-1])*n?\\b"},{begin:"\\b0[oO][0-7](_?[0-7])*n?\\b"},{begin:"\\b0[0-7]+n?\\b"}],relevance:0},_={className:"subst",begin:"\\$\\{",end:"\\}",keywords:c,contains:[]},T={begin:".?html`",end:"",starts:{end:"`",returnEnd:!1,contains:[t.BACKSLASH_ESCAPE,_],subLanguage:"xml"}},H={begin:".?css`",end:"",starts:{end:"`",returnEnd:!1,contains:[t.BACKSLASH_ESCAPE,_],subLanguage:"css"}},F={begin:".?gql`",end:"",starts:{end:"`",returnEnd:!1,contains:[t.BACKSLASH_ESCAPE,_],subLanguage:"graphql"}},U={className:"string",begin:"`",end:"`",contains:[t.BACKSLASH_ESCAPE,_]},k={className:"comment",variants:[t.COMMENT(/\/\*\*(?!\/)/,"\\*/",{relevance:0,contains:[{begin:"(?=@[A-Za-z]+)",relevance:0,contains:[{className:"doctag",begin:"@[A-Za-z]+"},{className:"type",begin:"\\{",end:"\\}",excludeEnd:!0,excludeBegin:!0,relevance:0},{className:"variable",begin:r+"(?=\\s*(-)|$)",endsParent:!0,relevance:0},{begin:/(?=[^\n])\s/,relevance:0}]}]}),t.C_BLOCK_COMMENT_MODE,t.C_LINE_COMMENT_MODE]},I=[t.APOS_STRING_MODE,t.QUOTE_STRING_MODE,T,H,F,U,{match:/\$\d+/},E];_.contains=I.concat({begin:/\{/,end:/\}/,keywords:c,contains:["self"].concat(I)});let R=[].concat(k,_.contains),W=R.concat([{begin:/(\s*)\(/,end:/\)/,keywords:c,contains:["self"].concat(R)}]),V={className:"params",begin:/(\s*)\(/,end:/\)/,excludeBegin:!0,excludeEnd:!0,keywords:c,contains:W},ye={variants:[{match:[/class/,/\s+/,r,/\s+/,/extends/,/\s+/,e.concat(r,"(",e.concat(/\./,r),")*")],scope:{1:"keyword",3:"title.class",5:"keyword",7:"title.class.inherited"}},{match:[/class/,/\s+/,r],scope:{1:"keyword",3:"title.class"}}]},re={relevance:0,match:e.either(/\bJSON/,/\b[A-Z][a-z]+([A-Z][a-z]*|\d)*/,/\b[A-Z]{2,}([A-Z][a-z]+|\d)+([A-Z][a-z]*)*/,/\b[A-Z]{2,}[a-z]+([A-Z][a-z]+|\d)*([A-Z][a-z]*)*/),className:"title.class",keywords:{_:[...Fs,...$s]}},Q={label:"use_strict",className:"meta",relevance:10,begin:/^\s*['"]use (strict|asm)['"]/},ve={variants:[{match:[/function/,/\s+/,r,/(?=\s*\()/]},{match:[/function/,/\s*(?=\()/]}],className:{1:"keyword",3:"title.function"},label:"func.def",contains:[V],illegal:/%/},Be={relevance:0,match:/\b[A-Z][A-Z_0-9]+\b/,className:"variable.constant"};function Ye(A){return e.concat("(?!",A.join("|"),")")}let Re={match:e.concat(/\b/,Ye([...js,"super","import","await"].map(A=>`${A}\\s*\\(`)),r,e.lookahead(/\s*\(/)),className:"title.function",relevance:0},Ce={begin:e.concat(/\./,e.lookahead(e.concat(r,/(?![0-9A-Za-z$_(])/))),end:r,excludeBegin:!0,keywords:"prototype",className:"property",relevance:0},we={match:[/get|set/,/\s+/,r,/(?=\()/],className:{1:"keyword",3:"title.function"},contains:[{begin:/\(\)/},V]},p="(\\([^()]*(\\([^()]*(\\([^()]*\\)[^()]*)*\\)[^()]*)*\\)|"+t.UNDERSCORE_IDENT_RE+")\\s*=>",x={match:[/const|var|let/,/\s+/,r,/\s*/,/=\s*/,/(async\s*)?/,e.lookahead(p)],keywords:"async",className:{1:"keyword",3:"title.function"},contains:[V]};return{name:"JavaScript",aliases:["js","jsx","mjs","cjs"],keywords:c,exports:{PARAMS_CONTAINS:W,CLASS_REFERENCE:re},illegal:/#(?![$_A-Za-z])/,contains:[t.SHEBANG({label:"shebang",binary:"node",relevance:5}),Q,t.APOS_STRING_MODE,t.QUOTE_STRING_MODE,T,H,F,U,k,{match:/\$\d+/},E,re,{scope:"attr",match:r+e.lookahead(":"),relevance:0},x,{begin:"("+t.RE_STARTERS_RE+"|\\b(case|return|throw)\\b)\\s*",keywords:"return throw case",relevance:0,contains:[k,t.REGEXP_MODE,{className:"function",begin:p,returnBegin:!0,end:"\\s*=>",contains:[{className:"params",variants:[{begin:t.UNDERSCORE_IDENT_RE,relevance:0},{className:null,begin:/\(\s*\)/,skip:!0},{begin:/(\s*)\(/,end:/\)/,excludeBegin:!0,excludeEnd:!0,keywords:c,contains:W}]}]},{begin:/,/,relevance:0},{match:/\s+/,relevance:0},{variants:[{begin:s.begin,end:s.end},{match:i},{begin:o.begin,"on:begin":o.isTrulyOpeningTag,end:o.end}],subLanguage:"xml",contains:[{begin:o.begin,end:o.end,skip:!0,contains:["self"]}]}]},ve,{beginKeywords:"while if switch catch for"},{begin:"\\b(?!function)"+t.UNDERSCORE_IDENT_RE+"\\([^()]*(\\([^()]*(\\([^()]*\\)[^()]*)*\\)[^()]*)*\\)\\s*\\{",returnBegin:!0,label:"func.def",contains:[V,t.inherit(t.TITLE_MODE,{begin:r,className:"title.function"})]},{match:/\.\.\./,relevance:0},Ce,{match:"\\$"+r,relevance:0},{match:[/\bconstructor(?=\s*\()/],className:{1:"title.function"},contains:[V]},Re,Be,ye,we,{match:/\$[(.]/}]}}var Mo="([-+]?)(\\b0[xX][a-fA-F0-9]+|(\\b\\d+(\\.\\d*)?|\\.\\d+)([eE][-+]?\\d+)?)|NaN|[-+]?Infinity",Io={scope:"number",match:Mo,relevance:0};function Ws(t){let e={className:"attr",begin:/(("(\\.|[^\\"\r\n])*")|('(\\.|[^\\'\r\n])*'))(?=\s*:)/,relevance:1.01},n={match:/[{}[\],:]/,className:"punctuation",relevance:0},r=["true","false","null"],s={scope:"literal",beginKeywords:r.join(" ")};return{name:"JSON",aliases:["jsonc","json5"],keywords:{literal:r},contains:[e,n,t.APOS_STRING_MODE,t.QUOTE_STRING_MODE,s,Io,t.C_LINE_COMMENT_MODE,t.C_BLOCK_COMMENT_MODE],illegal:"\\S"}}function qs(t){let e=t.regex,n={begin:/<\/?[A-Za-z_]/,end:">",subLanguage:"xml",relevance:0},r={match:/^ {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/},s={className:"code",variants:[{begin:"(`{3,})[^`](.|\\n)*?\\1`*[ ]*"},{begin:"(~{3,})[^~](.|\\n)*?\\1~*[ ]*"},{begin:"```",end:"```+[ ]*$"},{begin:"~~~",end:"~~~+[ ]*$"},{begin:"`.+?`"},{begin:"(?=^( {4}|\\t))",contains:[{begin:"^( {4}|\\t)",end:"(\\n)$"}],relevance:0}]},i={className:"bullet",begin:"^[ 	]*([*+-]|(\\d+\\.))(?=\\s+)",end:"\\s+",excludeEnd:!0},o={begin:/^\[[^\n]+\]:/,returnBegin:!0,contains:[{className:"symbol",begin:/\[/,end:/\]/,excludeBegin:!0,excludeEnd:!0},{className:"link",begin:/:\s*/,end:/$/,excludeBegin:!0}]},c=/[A-Za-z][A-Za-z0-9+.-]*/,u={variants:[{begin:/\[.+?\]\[.*?\]/,relevance:0},{begin:/\[.+?\]\(((data|javascript|mailto):|(?:http|ftp)s?:\/\/).*?\)/,relevance:2},{begin:e.concat(/\[.+?\]\(/,c,/:\/\/.*?\)/),relevance:2},{begin:/\[.+?\]\([./?&#].*?\)/,relevance:1},{begin:/\[.*?\]\(.*?\)/,relevance:0}],returnBegin:!0,contains:[{match:/\[(?=\])/},{className:"string",relevance:0,begin:"\\[",end:"\\]",excludeBegin:!0,returnEnd:!0},{className:"link",relevance:0,begin:"\\]\\(",end:"\\)",excludeBegin:!0,excludeEnd:!0},{className:"symbol",relevance:0,begin:"\\]\\[",end:"\\]",excludeBegin:!0,excludeEnd:!0}]},d={className:"strong",contains:[],variants:[{begin:/_{2}(?!\s)/,end:/_{2}/},{begin:/\*{2}(?!\s)/,end:/\*{2}/}]},f={className:"emphasis",contains:[],variants:[{begin:/\*(?![*\s])/,end:/\*/},{begin:/_(?![_\s])/,end:/_/,relevance:0}]},E=t.inherit(d,{contains:[]}),_=t.inherit(f,{contains:[]});d.contains.push(_),f.contains.push(E);let T=[n,u];return[d,f,E,_].forEach(L=>{L.contains=L.contains.concat(T)}),T=T.concat(d,f),{name:"Markdown",aliases:["md","mkdown","mkd"],contains:[{className:"section",variants:[{begin:"^#{1,6}",end:"$",contains:T},{begin:"(?=^.+?\\n[=-]{2,}$)",contains:[{begin:"^[=-]*$"},{begin:"^",end:"\\n",contains:T}]}]},n,i,r,d,f,{className:"quote",begin:"^>\\s+",contains:T,end:"$"},s,u,o,{scope:"literal",match:/&([a-zA-Z0-9]+|#[0-9]{1,7}|#[Xx][0-9a-fA-F]{1,6});/}]}}function Vs(t){return{name:"Plain text",aliases:["text","txt"],disableAutodetect:!0}}function Ks(t){let e=t.regex,n=new RegExp("[\\p{XID_Start}_]\\p{XID_Continue}*","u"),r=["and","as","assert","async","await","break","case","class","continue","def","del","elif","else","except","finally","for","from","global","if","import","in","is","lambda","lazy","match","nonlocal|10","not","or","pass","raise","return","try","while","with","yield"],c={$pattern:/[A-Za-z]\w+|__\w+__/,keyword:r,built_in:["__import__","abs","aiter","all","anext","any","ascii","bin","bool","breakpoint","bytearray","bytes","callable","chr","classmethod","compile","complex","delattr","dict","dir","divmod","enumerate","eval","exec","filter","float","format","frozendict","frozenset","getattr","globals","hasattr","hash","help","hex","id","input","int","isinstance","issubclass","iter","len","list","locals","map","max","memoryview","min","next","object","oct","open","ord","pow","print","property","range","repr","reversed","round","sentinel","set","setattr","slice","sorted","staticmethod","str","sum","super","tuple","type","vars","zip"],literal:["__debug__","Ellipsis","False","None","NotImplemented","True"],type:["Any","Callable","Coroutine","Dict","List","Literal","Generic","Optional","Sequence","Set","Tuple","Type","Union"]},u={className:"meta",begin:/^(>>>|\.\.\.) /},d={className:"subst",begin:/\{/,end:/\}/,keywords:c,illegal:/#/},f={begin:/\{\{/,relevance:0},E={className:"string",contains:[t.BACKSLASH_ESCAPE],variants:[{begin:/([uU]|[bB]|[rR]|[bB][rR]|[rR][bB])?'''/,end:/'''/,contains:[t.BACKSLASH_ESCAPE,u],relevance:10},{begin:/([uU]|[bB]|[rR]|[bB][rR]|[rR][bB])?"""/,end:/"""/,contains:[t.BACKSLASH_ESCAPE,u],relevance:10},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])'''/,end:/'''/,contains:[t.BACKSLASH_ESCAPE,u,f,d]},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])"""/,end:/"""/,contains:[t.BACKSLASH_ESCAPE,u,f,d]},{begin:/([uU]|[rR])'/,end:/'/,relevance:10},{begin:/([uU]|[rR])"/,end:/"/,relevance:10},{begin:/([bB]|[bB][rR]|[rR][bB])'/,end:/'/},{begin:/([bB]|[bB][rR]|[rR][bB])"/,end:/"/},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])'/,end:/'/,contains:[t.BACKSLASH_ESCAPE,f,d]},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])"/,end:/"/,contains:[t.BACKSLASH_ESCAPE,f,d]},t.APOS_STRING_MODE,t.QUOTE_STRING_MODE]},_="[0-9](_?[0-9])*",T=`(\\b(${_}))?\\.(${_})|\\b(${_})\\.`,H=`\\b|${r.join("|")}`,F={className:"number",relevance:0,variants:[{begin:`(\\b(${_})|(${T}))[eE][+-]?(${_})[jJ]?(?=${H})`},{begin:`(${T})[jJ]?`},{begin:`\\b([1-9](_?[0-9])*|0+(_?0)*)[lLjJ]?(?=${H})`},{begin:`\\b0[bB](_?[01])+[lL]?(?=${H})`},{begin:`\\b0[oO](_?[0-7])+[lL]?(?=${H})`},{begin:`\\b0[xX](_?[0-9a-fA-F])+[lL]?(?=${H})`},{begin:`\\b(${_})[jJ](?=${H})`}]},U={className:"comment",begin:e.lookahead(/# type:/),end:/$/,keywords:c,contains:[{begin:/# type:/},{begin:/#/,end:/\b\B/,endsWithParent:!0}]},L={className:"params",variants:[{className:"",begin:/\(\s*\)/,skip:!0},{begin:/\(/,end:/\)/,excludeBegin:!0,excludeEnd:!0,keywords:c,contains:["self",u,F,E,t.HASH_COMMENT_MODE]}]};return d.contains=[E,F,u],{name:"Python",aliases:["py","gyp","ipython"],unicodeRegex:!0,keywords:c,illegal:/(<\/|\?)|=>/,contains:[u,F,{scope:"variable.language",match:/\bself\b/},{beginKeywords:"if",relevance:0},{match:/\bor\b/,scope:"keyword"},E,U,t.HASH_COMMENT_MODE,{match:[/\bdef/,/\s+/,n],scope:{1:"keyword",3:"title.function"},contains:[L]},{variants:[{match:[/\bclass/,/\s+/,n,/\s*/,/\(\s*/,n,/\s*\)/]},{match:[/\bclass/,/\s+/,n]}],scope:{1:"keyword",3:"title.class",6:"title.class.inherited"}},{className:"meta",begin:/^[\t ]*@/,end:/(?=#)|$/,contains:[F,L,E]}]}}function Ys(t){return{name:"Shell Session",aliases:["console","shellsession"],contains:[{className:"meta.prompt",begin:/^\s{0,3}[./~\w\d[\]()@-]*[>%$#][ ]?/,starts:{end:/[^\\](?=\s*$)/,subLanguage:"bash"}}]}}function Xs(t){let e=t.regex,n=e.concat(/[\p{L}_]/u,e.optional(/[\p{L}0-9_.-]*:/u),/[\p{L}0-9_.-]*/u),r=/[\p{L}0-9._:-]+/u,s={className:"symbol",begin:/&[a-z]+;|&#[0-9]+;|&#x[a-f0-9]+;/},i={begin:/\s/,contains:[{className:"keyword",begin:/#?[a-z_][a-z1-9_-]+/,illegal:/\n/}]},o=t.inherit(i,{begin:/\(/,end:/\)/}),c=t.inherit(t.APOS_STRING_MODE,{className:"string"}),u=t.inherit(t.QUOTE_STRING_MODE,{className:"string"}),d={endsWithParent:!0,illegal:/</,relevance:0,contains:[{className:"attr",begin:r,relevance:0},{begin:/=\s*/,relevance:0,contains:[{className:"string",endsParent:!0,variants:[{begin:/"/,end:/"/,contains:[s]},{begin:/'/,end:/'/,contains:[s]},{begin:/[^\s"'=<>`]+/}]}]}]};return{name:"HTML, XML",aliases:["html","xhtml","rss","atom","xjb","xsd","xsl","plist","wsf","svg"],case_insensitive:!0,unicodeRegex:!0,contains:[{className:"meta",begin:/<![a-z]/,end:/>/,relevance:10,contains:[i,u,c,o,{begin:/\[/,end:/\]/,contains:[{className:"meta",begin:/<![a-z]/,end:/>/,contains:[i,o,u,c]}]}]},t.COMMENT(/<!--/,/-->/,{relevance:10}),{begin:/<!\[CDATA\[/,end:/\]\]>/,relevance:10},s,{className:"meta",end:/\?>/,variants:[{begin:/<\?xml/,relevance:10,contains:[u]},{begin:/<\?[a-z][a-z0-9]+/}]},{className:"tag",begin:/<style(?=\s|>)/,end:/>/,keywords:{name:"style"},contains:[d],starts:{end:/<\/style>/,returnEnd:!0,subLanguage:"css"}},{className:"tag",begin:/<script(?=\s|>)/,end:/>/,keywords:{name:"script"},contains:[d],starts:{end:/<\/script>/,returnEnd:!0,subLanguage:"javascript"}},{className:"tag",begin:/<>|<\/>/},{className:"tag",begin:e.concat(/</,e.lookahead(e.concat(n,e.either(/\/>/,/>/,/\s/)))),end:/\/?>/,contains:[{className:"name",begin:n,relevance:0,starts:d}]},{className:"tag",begin:e.concat(/<\//,e.lookahead(e.concat(n,/>/))),contains:[{className:"name",begin:n,relevance:0},{begin:/>/,relevance:0,endsParent:!0}]}]}}function Zs(t){let e="true false yes no null",n="[\\w#;/?:@&=+$,.~*'()[\\]]+",r={className:"attr",variants:[{begin:/[\w*@][\w*@ :()\./-]*:(?=[ \t]|$)/},{begin:/"[\w*@][\w*@ :()\./-]*":(?=[ \t]|$)/},{begin:/'[\w*@][\w*@ :()\./-]*':(?=[ \t]|$)/}]},s={className:"template-variable",variants:[{begin:/\{\{/,end:/\}\}/},{begin:/%\{/,end:/\}/}]},i={className:"string",relevance:0,begin:/'/,end:/'/,contains:[{match:/''/,scope:"char.escape",relevance:0}]},o={className:"string",relevance:0,variants:[{begin:/"/,end:/"/},{begin:/\S+/}],contains:[t.BACKSLASH_ESCAPE,s]},c=t.inherit(o,{variants:[{begin:/'/,end:/'/,contains:[{begin:/''/,relevance:0}]},{begin:/"/,end:/"/},{begin:/[^\s,{}[\]]+/}]}),_={className:"number",begin:"\\b"+"[0-9]{4}(-[0-9][0-9]){0,2}"+"([Tt \\t][0-9][0-9]?(:[0-9][0-9]){2})?"+"(\\.[0-9]*)?"+"([ \\t])*(Z|[-+][0-9][0-9]?(:[0-9][0-9])?)?"+"\\b"},T={end:",",endsWithParent:!0,excludeEnd:!0,keywords:e,relevance:0},H={begin:/\{/,end:/\}/,contains:[T],illegal:"\\n",relevance:0},F={begin:"\\[",end:"\\]",contains:[T],illegal:"\\n",relevance:0},U=[r,{className:"meta",begin:"^---\\s*$",relevance:10},{className:"string",begin:"[\\|>]([1-9]?[+-])?[ ]*\\n( +)[^ ][^\\n]*\\n(\\2[^\\n]+\\n?)*"},{begin:"<%[%=-]?",end:"[%-]?%>",subLanguage:"ruby",excludeBegin:!0,excludeEnd:!0,relevance:0},{className:"type",begin:"!\\w+!"+n},{className:"type",begin:"!<"+n+">"},{className:"type",begin:"!"+n},{className:"type",begin:"!!"+n},{className:"meta",begin:"&"+t.UNDERSCORE_IDENT_RE+"$"},{className:"meta",begin:"\\*"+t.UNDERSCORE_IDENT_RE+"$"},{className:"bullet",begin:"-(?=[ ]|$)",relevance:0},t.HASH_COMMENT_MODE,{beginKeywords:e,keywords:{literal:e}},_,{className:"number",begin:t.C_NUMBER_RE+"\\b",relevance:0},H,F,i,o],L=[...U];return L.pop(),L.push(c),T.contains=L,{name:"YAML",case_insensitive:!0,aliases:["yml"],contains:U}}function Do(t,e){this.v=t,this.k=e}function Qs(t,e){(e==null||e>t.length)&&(e=t.length);for(var n=0,r=Array(e);n<e;n++)r[n]=t[n];return r}function Po(t){if(Array.isArray(t))return t}function Uo(t,e){var n=t==null?null:typeof Symbol<"u"&&t[Symbol.iterator]||t["@@iterator"];if(n!=null){var r,s,i,o,c=[],u=!0,d=!1;try{if(i=(n=n.call(t)).next,e===0){if(Object(n)!==n)return;u=!1}else for(;!(u=(r=i.call(n)).done)&&(c.push(r.value),c.length!==e);u=!0);}catch(f){d=!0,s=f}finally{try{if(!u&&n.return!=null&&(o=n.return(),Object(o)!==o))return}finally{if(d)throw s}}return c}}function zo(){throw new TypeError(`Invalid attempt to destructure non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function Bo(t,e){return Po(t)||Uo(t,e)||Ho(t,e)||zo()}function Ho(t,e){if(t){if(typeof t=="string")return Qs(t,e);var n={}.toString.call(t).slice(8,-1);return n==="Object"&&t.constructor&&(n=t.constructor.name),n==="Map"||n==="Set"?Array.from(t):n==="Arguments"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)?Qs(t,e):void 0}}function en(t){var e,n;function r(i,o){try{var c=t[i](o),u=c.value,d=u instanceof Do;Promise.resolve(d?u.v:u).then(function(f){if(d){var E=i==="return"&&u.k?i:"next";if(!u.k||f.done)return r(E,f);f=t[E](f).value}s(!!c.done,f)},function(f){r("throw",f)})}catch(f){s(2,f)}}function s(i,o){i===2?e.reject(o):e.resolve({value:o,done:i}),(e=e.next)?r(e.key,e.arg):n=null}this._invoke=function(i,o){return new Promise(function(c,u){var d={key:i,arg:o,resolve:c,reject:u,next:null};n?n=n.next=d:(e=n=d,r(i,o))})},typeof t.return!="function"&&(this.return=void 0)}en.prototype[typeof Symbol=="function"&&Symbol.asyncIterator||"@@asyncIterator"]=function(){return this},en.prototype.next=function(t){return this._invoke("next",t)},en.prototype.throw=function(t){return this._invoke("throw",t)},en.prototype.return=function(t){return this._invoke("return",t)};var fa=Object.entries,Js=Object.setPrototypeOf,Fo=Object.isFrozen,$o=Object.getPrototypeOf,jo=Object.getOwnPropertyDescriptor,J=Object.freeze,te=Object.seal,lt=Object.create,pa=typeof Reflect<"u"&&Reflect,Qn=pa.apply,Jn=pa.construct;J||(J=function(e){return e});te||(te=function(e){return e});Qn||(Qn=function(e,n){for(var r=arguments.length,s=new Array(r>2?r-2:0),i=2;i<r;i++)s[i-2]=arguments[i];return e.apply(n,s)});Jn||(Jn=function(e){for(var n=arguments.length,r=new Array(n>1?n-1:0),s=1;s<n;s++)r[s-1]=arguments[s];return new e(...r)});var Ve=Z(Array.prototype.forEach);Array.prototype.indexOf;var Go=Z(Array.prototype.lastIndexOf),ea=Z(Array.prototype.pop),xt=Z(Array.prototype.push);Array.prototype.slice;var Wo=Z(Array.prototype.splice),ut=Array.isArray,wt=Z(String.prototype.toLowerCase),qn=Z(String.prototype.toString),ta=Z(String.prototype.match),Et=Z(String.prototype.replace),na=Z(String.prototype.indexOf),qo=Z(String.prototype.trim),Vo=Z(Number.prototype.toString),Ko=Z(Boolean.prototype.toString),ra=typeof BigInt>"u"?null:Z(BigInt.prototype.toString),sa=typeof Symbol>"u"?null:Z(Symbol.prototype.toString),he=Z(Object.prototype.hasOwnProperty),Tt=Z(Object.prototype.toString),ne=Z(RegExp.prototype.test),Ue=Yo(TypeError);function Z(t){return function(e){e instanceof RegExp&&(e.lastIndex=0);for(var n=arguments.length,r=new Array(n>1?n-1:0),s=1;s<n;s++)r[s-1]=arguments[s];return Qn(t,e,r)}}function Yo(t){return function(){for(var e=arguments.length,n=new Array(e),r=0;r<e;r++)n[r]=arguments[r];return Jn(t,n)}}function B(t,e){let n=arguments.length>2&&arguments[2]!==void 0?arguments[2]:wt;if(Js&&Js(t,null),!ut(e))return t;let r=e.length;for(;r--;){let s=e[r];if(typeof s=="string"){let i=n(s);i!==s&&(Fo(e)||(e[r]=i),s=i)}t[s]=!0}return t}function Xo(t){for(let e=0;e<t.length;e++)he(t,e)||(t[e]=null);return t}function be(t){let e=lt(null);for(let r of fa(t)){var n=Bo(r,2);let s=n[0],i=n[1];he(t,s)&&(ut(i)?e[s]=Xo(i):i&&typeof i=="object"&&i.constructor===Object?e[s]=be(i):e[s]=i)}return e}function Zo(t){switch(typeof t){case"string":return t;case"number":return Vo(t);case"boolean":return Ko(t);case"bigint":return ra?ra(t):"0";case"symbol":return sa?sa(t):"Symbol()";case"undefined":return Tt(t);case"function":case"object":{if(t===null)return Tt(t);let e=t,n=Ee(e,"toString");if(typeof n=="function"){let r=n(e);return typeof r=="string"?r:Tt(r)}return Tt(t)}default:return Tt(t)}}function Ee(t,e){for(;t!==null;){let r=jo(t,e);if(r){if(r.get)return Z(r.get);if(typeof r.value=="function")return Z(r.value)}t=$o(t)}function n(){return null}return n}function Qo(t){try{return ne(t,""),!0}catch{return!1}}var aa=J(["a","abbr","acronym","address","area","article","aside","audio","b","bdi","bdo","big","blink","blockquote","body","br","button","canvas","caption","center","cite","code","col","colgroup","content","data","datalist","dd","decorator","del","details","dfn","dialog","dir","div","dl","dt","element","em","fieldset","figcaption","figure","font","footer","form","h1","h2","h3","h4","h5","h6","head","header","hgroup","hr","html","i","img","input","ins","kbd","label","legend","li","main","map","mark","marquee","menu","menuitem","meter","nav","nobr","ol","optgroup","option","output","p","picture","pre","progress","q","rp","rt","ruby","s","samp","search","section","select","shadow","slot","small","source","spacer","span","strike","strong","style","sub","summary","sup","table","tbody","td","template","textarea","tfoot","th","thead","time","tr","track","tt","u","ul","var","video","wbr"]),Vn=J(["svg","a","altglyph","altglyphdef","altglyphitem","animatecolor","animatemotion","animatetransform","circle","clippath","defs","desc","ellipse","enterkeyhint","exportparts","filter","font","g","glyph","glyphref","hkern","image","inputmode","line","lineargradient","marker","mask","metadata","mpath","part","path","pattern","polygon","polyline","radialgradient","rect","stop","style","switch","symbol","text","textpath","title","tref","tspan","view","vkern"]),Kn=J(["feBlend","feColorMatrix","feComponentTransfer","feComposite","feConvolveMatrix","feDiffuseLighting","feDisplacementMap","feDistantLight","feDropShadow","feFlood","feFuncA","feFuncB","feFuncG","feFuncR","feGaussianBlur","feImage","feMerge","feMergeNode","feMorphology","feOffset","fePointLight","feSpecularLighting","feSpotLight","feTile","feTurbulence"]),Jo=J(["animate","color-profile","cursor","discard","font-face","font-face-format","font-face-name","font-face-src","font-face-uri","foreignobject","hatch","hatchpath","mesh","meshgradient","meshpatch","meshrow","missing-glyph","script","set","solidcolor","unknown","use"]),Yn=J(["math","menclose","merror","mfenced","mfrac","mglyph","mi","mlabeledtr","mmultiscripts","mn","mo","mover","mpadded","mphantom","mroot","mrow","ms","mspace","msqrt","mstyle","msub","msup","msubsup","mtable","mtd","mtext","mtr","munder","munderover","mprescripts"]),ec=J(["maction","maligngroup","malignmark","mlongdiv","mscarries","mscarry","msgroup","mstack","msline","msrow","semantics","annotation","annotation-xml","mprescripts","none"]),ia=J(["#text"]),oa=J(["accept","action","align","alt","autocapitalize","autocomplete","autopictureinpicture","autoplay","background","bgcolor","border","capture","cellpadding","cellspacing","checked","cite","class","clear","color","cols","colspan","command","commandfor","controls","controlslist","coords","crossorigin","datetime","decoding","default","dir","disabled","disablepictureinpicture","disableremoteplayback","download","draggable","enctype","enterkeyhint","exportparts","face","for","headers","height","hidden","high","href","hreflang","id","inert","inputmode","integrity","ismap","kind","label","lang","list","loading","loop","low","max","maxlength","media","method","min","minlength","multiple","muted","name","nonce","noshade","novalidate","nowrap","open","optimum","part","pattern","placeholder","playsinline","popover","popovertarget","popovertargetaction","poster","preload","pubdate","radiogroup","readonly","rel","required","rev","reversed","role","rows","rowspan","spellcheck","scope","selected","shape","size","sizes","slot","span","srclang","start","src","srcset","step","style","summary","tabindex","title","translate","type","usemap","valign","value","width","wrap","xmlns"]),Xn=J(["accent-height","accumulate","additive","alignment-baseline","amplitude","ascent","attributename","attributetype","azimuth","basefrequency","baseline-shift","begin","bias","by","class","clip","clippathunits","clip-path","clip-rule","color","color-interpolation","color-interpolation-filters","color-profile","color-rendering","cx","cy","d","dx","dy","diffuseconstant","direction","display","divisor","dominant-baseline","dur","edgemode","elevation","end","exponent","fill","fill-opacity","fill-rule","filter","filterunits","flood-color","flood-opacity","font-family","font-size","font-size-adjust","font-stretch","font-style","font-variant","font-weight","fx","fy","g1","g2","glyph-name","glyphref","gradientunits","gradienttransform","height","href","id","image-rendering","in","in2","intercept","k","k1","k2","k3","k4","kerning","keypoints","keysplines","keytimes","lang","lengthadjust","letter-spacing","kernelmatrix","kernelunitlength","lighting-color","local","marker-end","marker-mid","marker-start","markerheight","markerunits","markerwidth","maskcontentunits","maskunits","max","mask","mask-type","media","method","mode","min","name","numoctaves","offset","operator","opacity","order","orient","orientation","origin","overflow","paint-order","path","pathlength","patterncontentunits","patterntransform","patternunits","pointer-events","points","preservealpha","preserveaspectratio","primitiveunits","r","rx","ry","radius","refx","refy","repeatcount","repeatdur","restart","result","rotate","scale","seed","shape-rendering","slope","specularconstant","specularexponent","spreadmethod","startoffset","stddeviation","stitchtiles","stop-color","stop-opacity","stroke-dasharray","stroke-dashoffset","stroke-linecap","stroke-linejoin","stroke-miterlimit","stroke-opacity","stroke","stroke-width","style","surfacescale","systemlanguage","tabindex","tablevalues","targetx","targety","transform","transform-origin","text-anchor","text-decoration","text-orientation","text-rendering","textlength","type","u1","u2","unicode","values","vector-effect","viewbox","visibility","version","vert-adv-y","vert-origin-x","vert-origin-y","width","word-spacing","wrap","writing-mode","xchannelselector","ychannelselector","x","x1","x2","xmlns","y","y1","y2","z","zoomandpan"]),ca=J(["accent","accentunder","align","bevelled","close","columnalign","columnlines","columnspacing","columnspan","denomalign","depth","dir","display","displaystyle","encoding","fence","frame","height","href","id","largeop","length","linethickness","lquote","lspace","mathbackground","mathcolor","mathsize","mathvariant","maxsize","minsize","movablelimits","notation","numalign","open","rowalign","rowlines","rowspacing","rowspan","rspace","rquote","scriptlevel","scriptminsize","scriptsizemultiplier","selection","separator","separators","stretchy","subscriptshift","supscriptshift","symmetric","voffset","width","xmlns"]),tn=J(["xlink:href","xml:id","xlink:title","xml:space","xmlns:xlink"]),tc=te(/{{[\w\W]*|^[\w\W]*}}/g),nc=te(/<%[\w\W]*|^[\w\W]*%>/g),rc=te(/\${[\w\W]*/g),sc=te(/^data-[\-\w.\u00B7-\uFFFF]+$/),ac=te(/^aria-[\-\w]+$/),la=te(/^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i),ic=te(/^(?:\w+script|data):/i),oc=te(/[\u0000-\u0020\u00A0\u1680\u180E\u2000-\u2029\u205F\u3000]/g),cc=te(/^html$/i),lc=te(/^[a-z][.\w]*(-[.\w]+)+$/i),ua=te(/<[/\w!]/g),da=te(/<[/\w]/g),uc=te(/<\/no(script|embed|frames)/i),dc=te(/\/>/i),me={element:1,attribute:2,text:3,cdataSection:4,entityReference:5,entityNode:6,processingInstruction:7,comment:8,document:9,documentType:10,documentFragment:11,notation:12},ga=["style","script","xmp","iframe","noembed","noframes","plaintext","noscript"],hc=J(B({},ga)),fc=(function(){let t={};return Ve(ga,e=>{t[e]=te(new RegExp("</"+e+"(?=[\\t\\n\\f\\r />])","i"))}),J(t)})(),pc=function(){return typeof window>"u"?null:window},gc=function(e,n){if(typeof e!="object"||typeof e.createPolicy!="function")return null;let r=null,s="data-tt-policy-suffix";n&&n.hasAttribute(s)&&(r=n.getAttribute(s));let i="dompurify"+(r?"#"+r:"");try{return e.createPolicy(i,{createHTML(o){return o},createScriptURL(o){return o}})}catch{return console.warn("TrustedTypes policy "+i+" could not be created."),null}},ha=function(){return{afterSanitizeAttributes:[],afterSanitizeElements:[],afterSanitizeShadowDOM:[],beforeSanitizeAttributes:[],beforeSanitizeElements:[],beforeSanitizeShadowDOM:[],uponSanitizeAttribute:[],uponSanitizeElement:[],uponSanitizeShadowNode:[]}},ze=function(e,n,r,s){return he(e,n)&&ut(e[n])?B(s.base?be(s.base):{},e[n],s.transform):r},Zn=function(e,n,r){let s=he(e,n)?e[n]:void 0;return s&&typeof s=="object"?be(s):r()};function ma(){let t=arguments.length>0&&arguments[0]!==void 0?arguments[0]:pc(),e=g=>ma(g);if(e.version="3.4.16",e.removed=[],!t||!t.document||t.document.nodeType!==me.document||!t.Element)return e.isSupported=!1,e;let n=t.document,r=n,s=r.currentScript;t.DocumentFragment;let i=t.HTMLTemplateElement,o=t.Node,c=t.Element,u=t.NodeFilter;t.NamedNodeMap===void 0&&(t.NamedNodeMap||t.MozNamedAttrMap),t.HTMLFormElement;let d=t.DOMParser,f=t.trustedTypes,E=c.prototype,_=Ee(E,"cloneNode"),T=Ee(E,"remove"),H=Ee(E,"removeAttributeNode"),F=Ee(E,"nextSibling"),U=Ee(E,"childNodes"),L=Ee(E,"parentNode"),k=Ee(E,"shadowRoot"),I=Ee(E,"attributes"),R=o&&o.prototype?Ee(o.prototype,"nodeType"):null,W=o&&o.prototype?Ee(o.prototype,"nodeName"):null,V=o&&o.prototype?Ee(o.prototype,"ownerDocument"):null,ye=function(a){return R?R(a):a.nodeType},re=function(a){return W?W(a):a.nodeName};if(typeof i=="function"){let g=n.createElement("template");g.content&&g.content.ownerDocument&&(n=g.content.ownerDocument)}let Q,ve="",Be,Ye=!1,Re=0,Ce=function(){if(Re>0)throw Ue('A configured TRUSTED_TYPES_POLICY callback (createHTML or createScriptURL) must not call DOMPurify.sanitize, as that causes infinite recursion. Do not pass a policy whose callbacks wrap DOMPurify as TRUSTED_TYPES_POLICY; see the "DOMPurify and Trusted Types" section of the README.')},we=function(a){Ce(),Re++;try{return Q.createHTML(a)}finally{Re--}},p=function(a){Ce(),Re++;try{return Q.createScriptURL(a)}finally{Re--}},x=function(){return Ye||(Be=gc(f,s),Ye=!0),Be},A=n,O=A.implementation,$=A.createNodeIterator,ee=A.createDocumentFragment,oe=A.getElementsByTagName,Le=r.importNode,C=ha();e.isSupported=typeof fa=="function"&&typeof L=="function"&&O&&O.createHTMLDocument!==void 0;let _e=tc,At=nc,Nt=rc,kt=sc,un=ac,dn=ic,Rt=oc,hn=lc,He=la,j=null,ce=B({},[...aa,...Vn,...Kn,...Yn,...ia]),G=null,Fe=B({},[...oa,...Xn,...ca,...tn]),w=Object.seal(lt(null,{tagNameCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},attributeNameCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},allowCustomizedBuiltInElements:{writable:!0,configurable:!1,enumerable:!0,value:!1}})),Oe=null,X=null,D=Object.seal(lt(null,{tagCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},attributeCheck:{writable:!0,configurable:!1,enumerable:!0,value:null}})),$e=!0,Te=!0,Xe=!1,Ze=!0,b=!1,y=!0,N=!1,z=!1,K=null,le=null,dt=!1,Me=!1,Ct=!1,Lt=!1,tr=!0,nr=!1,rr="user-content-",fn=!0,pn=!1,Qe={},Je=null,sr=B({},["annotation-xml","audio","colgroup","desc","foreignobject","head","iframe","math","mi","mn","mo","ms","mtext","noembed","noframes","noscript","plaintext","script","selectedcontent","style","svg","template","thead","title","video","xmp"]),ar=null,ir=B({},["audio","video","img","source","image","track"]),or=null,cr=B({},["alt","class","for","id","label","name","pattern","placeholder","role","summary","title","value","style","xmlns"]),Ot="http://www.w3.org/1998/Math/MathML",Mt="http://www.w3.org/2000/svg",Se="http://www.w3.org/1999/xhtml",et=Se,gn=!1,mn=null,Na=B({},[Ot,Mt,Se],qn),lr=J(["mi","mo","mn","ms","mtext"]),bn=B({},lr),ur=J(["annotation-xml"]),yn=B({},ur),ka=B({},["title","style","font","a","script"]),ht=null,Ra=["application/xhtml+xml","text/html"],Ca="text/html",Y=null,tt=null,La=n.createElement("form"),dr=function(a){return a instanceof RegExp||a instanceof Function},vn=function(){let a=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};if(tt&&tt===a)return;(!a||typeof a!="object")&&(a={}),a=be(a),ht=Ra.indexOf(a.PARSER_MEDIA_TYPE)===-1?Ca:a.PARSER_MEDIA_TYPE,Y=ht==="application/xhtml+xml"?qn:wt,j=ze(a,"ALLOWED_TAGS",ce,{transform:Y}),G=ze(a,"ALLOWED_ATTR",Fe,{transform:Y}),mn=ze(a,"ALLOWED_NAMESPACES",Na,{transform:qn}),or=ze(a,"ADD_URI_SAFE_ATTR",cr,{transform:Y,base:cr}),ar=ze(a,"ADD_DATA_URI_TAGS",ir,{transform:Y,base:ir}),Je=ze(a,"FORBID_CONTENTS",sr,{transform:Y}),Oe=ze(a,"FORBID_TAGS",be({}),{transform:Y}),X=ze(a,"FORBID_ATTR",be({}),{transform:Y}),Qe=he(a,"USE_PROFILES")?a.USE_PROFILES&&typeof a.USE_PROFILES=="object"?be(a.USE_PROFILES):a.USE_PROFILES:!1,$e=a.ALLOW_ARIA_ATTR!==!1,Te=a.ALLOW_DATA_ATTR!==!1,Xe=a.ALLOW_UNKNOWN_PROTOCOLS||!1,Ze=a.ALLOW_SELF_CLOSE_IN_ATTR!==!1,b=a.SAFE_FOR_TEMPLATES||!1,y=a.SAFE_FOR_XML!==!1,N=a.WHOLE_DOCUMENT||!1,Me=a.RETURN_DOM||!1,Ct=a.RETURN_DOM_FRAGMENT||!1,Lt=a.RETURN_TRUSTED_TYPE||!1,dt=a.FORCE_BODY||!1,tr=a.SANITIZE_DOM!==!1,nr=a.SANITIZE_NAMED_PROPS||!1,fn=a.KEEP_CONTENT!==!1,pn=a.IN_PLACE||!1,He=Qo(a.ALLOWED_URI_REGEXP)?a.ALLOWED_URI_REGEXP:la,et=typeof a.NAMESPACE=="string"?a.NAMESPACE:Se,bn=Zn(a,"MATHML_TEXT_INTEGRATION_POINTS",()=>B({},lr)),yn=Zn(a,"HTML_INTEGRATION_POINTS",()=>B({},ur));let l=Zn(a,"CUSTOM_ELEMENT_HANDLING",()=>lt(null));if(w=lt(null),he(l,"tagNameCheck")&&dr(l.tagNameCheck)&&(w.tagNameCheck=l.tagNameCheck),he(l,"attributeNameCheck")&&dr(l.attributeNameCheck)&&(w.attributeNameCheck=l.attributeNameCheck),he(l,"allowCustomizedBuiltInElements")&&typeof l.allowCustomizedBuiltInElements=="boolean"&&(w.allowCustomizedBuiltInElements=l.allowCustomizedBuiltInElements),te(w),b&&(Te=!1),Ct&&(Me=!0),Qe&&(j=B({},ia),G=lt(null),Qe.html===!0&&(B(j,aa),B(G,oa)),Qe.svg===!0&&(B(j,Vn),B(G,Xn),B(G,tn)),Qe.svgFilters===!0&&(B(j,Kn),B(G,Xn),B(G,tn)),Qe.mathMl===!0&&(B(j,Yn),B(G,ca),B(G,tn))),D.tagCheck=null,D.attributeCheck=null,he(a,"ADD_TAGS")&&(typeof a.ADD_TAGS=="function"?D.tagCheck=a.ADD_TAGS:ut(a.ADD_TAGS)&&(j===ce&&(j=be(j)),B(j,a.ADD_TAGS,Y))),he(a,"ADD_ATTR")&&(typeof a.ADD_ATTR=="function"?D.attributeCheck=a.ADD_ATTR:ut(a.ADD_ATTR)&&(G===Fe&&(G=be(G)),B(G,a.ADD_ATTR,Y))),he(a,"ADD_FORBID_CONTENTS")&&ut(a.ADD_FORBID_CONTENTS)&&(Je===sr&&(Je=be(Je)),B(Je,a.ADD_FORBID_CONTENTS,Y)),fn&&(j["#text"]=!0),N&&B(j,["html","head","body"]),j.table&&(B(j,["tbody"]),delete Oe.tbody),a.TRUSTED_TYPES_POLICY){if(typeof a.TRUSTED_TYPES_POLICY.createHTML!="function")throw Ue('TRUSTED_TYPES_POLICY configuration option must provide a "createHTML" hook.');if(typeof a.TRUSTED_TYPES_POLICY.createScriptURL!="function")throw Ue('TRUSTED_TYPES_POLICY configuration option must provide a "createScriptURL" hook.');let h=Q;Q=a.TRUSTED_TYPES_POLICY;try{ve=we("")}catch(m){throw Q=h,m}}else a.TRUSTED_TYPES_POLICY===null?(Q=void 0,ve=""):(Q===void 0&&(Q=x()),Q&&typeof ve=="string"&&(ve=we("")));J&&J(a),tt=a},hr=B({},[...Vn,...Kn,...Jo]),fr=B({},[...Yn,...ec]),Oa=function(a,l,h){return l.namespaceURI===Se?a==="svg":l.namespaceURI===Ot?a==="svg"&&(h==="annotation-xml"||bn[h]):!!hr[a]},Ma=function(a,l,h){return l.namespaceURI===Se?a==="math":l.namespaceURI===Mt?a==="math"&&yn[h]:!!fr[a]},Ia=function(a,l,h){return l.namespaceURI===Mt&&!yn[h]||l.namespaceURI===Ot&&!bn[h]?!1:!fr[a]&&(ka[a]||!hr[a])},Da=function(a){let l=L(a);(!l||!l.tagName)&&(l={namespaceURI:et,tagName:"template"});let h=wt(a.tagName),m=wt(l.tagName);return mn[a.namespaceURI]?a.namespaceURI===Mt?Oa(h,l,m):a.namespaceURI===Ot?Ma(h,l,m):a.namespaceURI===Se?Ia(h,l,m):!!(ht==="application/xhtml+xml"&&mn[a.namespaceURI]):!1},Ie=function(a){xt(e.removed,{element:a});try{L(a).removeChild(a)}catch{if(T(a),!L(a))throw Ue("a node selected for removal could not be detached from its tree and cannot be safely returned; refusing to sanitize in place")}},pr=function(a,l,h){try{H(a,l)}catch{try{a.removeAttribute(h)}catch{}}},It=function(a){Dt(a);let l=U(a);if(l){let m=[];Ve(l,S=>{xt(m,S)}),Ve(m,S=>{try{T(S)}catch{}})}let h=I(a);if(h)for(let m=h.length-1;m>=0;--m){let S=h[m],M=S&&S.name;typeof M=="string"&&pr(a,S,M)}},je=function(a,l,h){if(!h)try{h=l.getAttributeNode(a)}catch{h=null}xt(e.removed,{attribute:h||null,from:l});try{h?H(l,h):l.removeAttribute(a)}catch{try{l.removeAttribute(a)}catch{}}if(a==="is")if(Me||Ct)try{Ie(l)}catch{}else try{l.setAttribute(a,"")}catch{}},Pa=function(a){let l=I(a);if(l)for(let h=l.length-1;h>=0;--h){let m=l[h],S=m&&m.name;typeof S!="string"||G[Y(S)]||pr(a,m,S)}},Dt=function(a){let l=[a];for(;l.length>0;){let h=l.pop();ye(h)===me.element&&Pa(h);let m=U(h);if(m)for(let S=m.length-1;S>=0;--S)l.push(m[S])}},gr=function(a,l){return y?a==="patchsrc"?!0:a==="for"&&l!=="label"&&l!=="output":!1},Ua=function(a){if(!y)return;let l=[a];for(;l.length>0;){let h=l.pop(),m=ye(h);if(m===me.processingInstruction||m===me.comment&&ne(da,h.data)){try{T(h)}catch{}continue}if(m===me.element){let M=h,P=Y(re(h));try{M.hasAttribute&&M.hasAttribute("patchsrc")&&M.removeAttribute("patchsrc"),M.hasAttribute&&M.hasAttribute("for")&&gr("for",P)&&M.removeAttribute("for")}catch{}}let S=U(h);if(S)for(let M=S.length-1;M>=0;--M)l.push(S[M])}},mr=function(a){let l=null,h=null;if(dt)a="<remove></remove>"+a;else{let M=ta(a,/^[\r\n\t ]+/);h=M&&M[0]}ht==="application/xhtml+xml"&&et===Se&&(a='<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>'+a+"</body></html>");let m=Q?we(a):a;if(et===Se)try{l=new d().parseFromString(m,ht)}catch{}if(!l||!l.documentElement){l=O.createDocument(et,"template",null);try{l.documentElement.innerHTML=gn?ve:m}catch{}}let S=l.body||l.documentElement;return a&&h&&S.insertBefore(n.createTextNode(h),S.childNodes[0]||null),et===Se?oe.call(l,N?"html":"body")[0]:N?l.documentElement:S},br=function(a){let l=V?V(a):a.ownerDocument;return $.call(l||a,a,u.SHOW_ELEMENT|u.SHOW_COMMENT|u.SHOW_TEXT|u.SHOW_PROCESSING_INSTRUCTION|u.SHOW_CDATA_SECTION,null)},Pt=function(a){return a=Et(a,_e," "),a=Et(a,At," "),a=Et(a,Nt," "),a},_n=function(a){var l;a.normalize();let h=V?V(a):a.ownerDocument,m=$.call(h||a,a,u.SHOW_TEXT|u.SHOW_COMMENT|u.SHOW_CDATA_SECTION|u.SHOW_PROCESSING_INSTRUCTION,null),S=m.nextNode();for(;S;)S.data=Pt(S.data),S=m.nextNode();let M=(l=a.querySelectorAll)===null||l===void 0?void 0:l.call(a,"template");M&&Ve(M,P=>{nt(P.content)&&_n(P.content)})},Ut=function(a){let l=W?W(a):null;return typeof l!="string"||Y(l)!=="form"?!1:typeof a.nodeName!="string"||typeof a.textContent!="string"||typeof a.removeChild!="function"||a.attributes!==I(a)||typeof a.removeAttribute!="function"||typeof a.removeAttributeNode!="function"||typeof a.getAttributeNode!="function"||typeof a.setAttribute!="function"||typeof a.namespaceURI!="string"||typeof a.insertBefore!="function"||typeof a.hasChildNodes!="function"||a.nodeType!==R(a)||a.childNodes!==U(a)},nt=function(a){if(!R||typeof a!="object"||a===null)return!1;try{return R(a)===me.documentFragment}catch{return!1}},ft=function(a){if(!R||typeof a!="object"||a===null)return!1;try{return typeof R(a)=="number"}catch{return!1}};function Ae(g,a,l){g.length!==0&&Ve(g,h=>{h.call(e,a,l,tt)})}let za=function(a,l){return!!(y&&a.hasChildNodes()&&!ft(a.firstElementChild)&&ne(ua,a.textContent)&&ne(ua,a.innerHTML)||y&&a.namespaceURI===Se&&hc[l]&&(ft(a.firstElementChild)||typeof a.textContent=="string"&&ne(fc[l],a.textContent))||a.nodeType===me.processingInstruction||y&&a.nodeType===me.comment&&ne(da,a.data))},zt=function(a,l){if(a instanceof RegExp)return ne(a,l);if(a instanceof Function){for(var h=arguments.length,m=new Array(h>2?h-2:0),S=2;S<h;S++)m[S-2]=arguments[S];return!!a(l,...m)}return!1},Ba=function(a,l,h){if(!Oe[l]&&xr(l)&&zt(w.tagNameCheck,l))return!1;if(fn&&!Je[l]){let m=L(a),S=U(a);if(S&&m){let M=S.length;for(let P=M-1;P>=0;--P){let q=a===h?_(S[P],!0):S[P];m.insertBefore(q,F(a))}}}return Ie(a),!0},yr=function(a,l,h,m){return a.length===0?l:l===h||l===m?be(l):l},rt=function(a,l){return a===l||L(a)!==null?!1:(pn&&Dt(a),!0)},vr=function(a,l){if(Ae(C.beforeSanitizeElements,a,null),rt(a,l))return!0;if(Ut(a))return Ie(a),!0;let h=Y(re(a));if(j=yr(C.uponSanitizeElement,j,ce,K),Ae(C.uponSanitizeElement,a,{tagName:h,allowedTags:j}),rt(a,l))return!0;if(za(a,h))return Ie(a),!0;if(Oe[h]||!(D.tagCheck instanceof Function&&D.tagCheck(h))&&!j[h]){let m=Ba(a,h,l);return m===!1&&(Ae(C.afterSanitizeElements,a,null),rt(a,l))?!0:m}if(ye(a)===me.element&&!Da(a)||(h==="noscript"||h==="noembed"||h==="noframes")&&ne(uc,a.innerHTML))return Ie(a),!0;if(b&&a.nodeType===me.text){let m=Pt(a.textContent);a.textContent!==m&&(xt(e.removed,{element:a.cloneNode()}),a.textContent=m)}return Ae(C.afterSanitizeElements,a,null),rt(a,l)},_r=function(a,l,h){if(X[l]||gr(l,a)||tr&&(l==="id"||l==="name")&&(h in n||h in La))return!1;let m=G[l]||D.attributeCheck instanceof Function&&D.attributeCheck(l,a);return Te&&ne(kt,l)||$e&&ne(un,l)?!0:m?or[l]||ne(He,Et(h,Rt,""))||(l==="src"||l==="xlink:href"||l==="href")&&a!=="script"&&na(h,"data:")===0&&ar[a]||Xe&&!ne(dn,Et(h,Rt,""))?!0:!h:xr(a)&&zt(w.tagNameCheck,a)&&zt(w.attributeNameCheck,l,a)||l==="is"&&w.allowCustomizedBuiltInElements&&zt(w.tagNameCheck,h)},Ha=B({},["annotation-xml","color-profile","font-face","font-face-format","font-face-name","font-face-src","font-face-uri","missing-glyph"]),xr=function(a){return!Ha[wt(a)]&&ne(hn,a)},Fa=function(a,l,h,m){if(Q&&typeof f=="object"&&typeof f.getAttributeType=="function"&&!h)switch(f.getAttributeType(a,l)){case"TrustedHTML":return we(m);case"TrustedScriptURL":return p(m)}return m},$a=function(a,l,h,m){try{return h?a.setAttributeNS(h,l,m):a.setAttribute(l,m),Ut(a)?(Ie(a),!1):!0}catch{return je(l,a),!1}},Er=function(a,l){if(Ae(C.beforeSanitizeAttributes,a,null),rt(a,l))return;let h=a.attributes;if(!h||Ut(a))return;G=yr(C.uponSanitizeAttribute,G,Fe,le);let m={attrName:"",attrValue:"",keepAttr:!0,allowedAttributes:G,forceKeepAttr:void 0},S=h.length,M=Y(a.nodeName);for(;S--;){let P=h[S],q=P.name,xe=P.namespaceURI,fe=P.value,st=Y(q),En=fe,se=q==="value"?En:qo(En),Tr=!1;if(m.attrName=st,m.attrValue=se,m.keepAttr=!0,m.forceKeepAttr=void 0,Ae(C.uponSanitizeAttribute,a,m),se=m.attrValue,nr&&(st==="id"||st==="name")&&na(se,rr)!==0&&(je(q,a,P),se=rr+se,Tr=!0),y&&ne(/((--!?|])>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,se)){je(q,a,P);continue}if(st==="attributename"&&ta(se,"href")){je(q,a,P);continue}if(!m.forceKeepAttr){if(!m.keepAttr){je(q,a,P);continue}if(!Ze&&ne(dc,se)){je(q,a,P);continue}if(b&&(se=Pt(se)),!_r(M,st,se)){je(q,a,P);continue}se=Fa(M,st,xe,se),se!==En&&$a(a,q,xe,se)&&Tr&&ea(e.removed)}}Ae(C.afterSanitizeAttributes,a,null),rt(a,l)},Bt=function(a){let l=null,h=br(a);for(Ae(C.beforeSanitizeShadowDOM,a,null);l=h.nextNode();)if(Ae(C.uponSanitizeShadowNode,l,null),vr(l,a),Er(l,a),nt(l.content)&&Bt(l.content),ye(l)===me.element){let m=k(l);nt(m)&&(xn(m),Bt(m))}Ae(C.afterSanitizeShadowDOM,a,null)},xn=function(a){let l=[{node:a,shadow:null}];for(;l.length>0;){let h=l.pop();if(h.shadow){Bt(h.shadow);continue}let m=h.node,S=ye(m)===me.element,M=U(m);if(M)for(let P=M.length-1;P>=0;--P)l.push({node:M[P],shadow:null});if(S){let P=W?W(m):null;if(typeof P=="string"&&Y(P)==="template"){let q=m.content;nt(q)&&l.push({node:q,shadow:null})}}if(S){let P=k(m);nt(P)&&l.push({node:null,shadow:P},{node:P,shadow:null})}}};return e.sanitize=function(g){let a=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},l=null,h=null,m=null,S=null;if(gn=!g,gn&&(g="<!-->"),typeof g!="string"&&!ft(g)&&(g=Zo(g),typeof g!="string"))throw Ue("dirty is not a string, aborting");if(!e.isSupported)return g;z?(j=K,G=le):vn(a),(C.uponSanitizeElement.length>0||C.uponSanitizeAttribute.length>0)&&(j=be(j)),C.uponSanitizeAttribute.length>0&&(G=be(G)),e.removed=[];let M=pn&&typeof g!="string"&&ft(g);if(M){Ua(g);let xe=re(g);if(typeof xe=="string"){let fe=Y(xe);if(!j[fe]||Oe[fe])throw It(g),Ue("root node is forbidden and cannot be sanitized in-place")}if(Ut(g))throw It(g),Ue("root node is clobbered and cannot be sanitized in-place");try{xn(g)}catch(fe){throw It(g),fe}}else if(ft(g))l=mr("<!---->"),h=l.ownerDocument.importNode(g,!0),h.nodeType===me.element&&h.nodeName==="BODY"||h.nodeName==="HTML"?l=h:l.appendChild(h),xn(l);else{if(!Me&&!b&&!N&&g.indexOf("<")===-1)return Q&&Lt?we(g):g;if(l=mr(g),!l)return Me?null:Lt?ve:""}l&&dt&&Ie(l.firstChild);let P=M?g:l;try{let xe=br(P);for(;m=xe.nextNode();)vr(m,P),Er(m,P),nt(m.content)&&Bt(m.content)}catch(xe){throw M&&(It(g),Ve(e.removed,fe=>{fe.element&&Dt(fe.element)})),xe}if(M){let xe=!1;if(Ve(e.removed,fe=>{fe.element&&(fe.element===g&&(xe=!0),Dt(fe.element))}),xe)throw Ue("a node selected for removal could not be safely returned; refusing to sanitize in place");return b&&_n(g),g}if(Me){if(b&&_n(l),Ct)for(S=ee.call(l.ownerDocument);l.firstChild;)S.appendChild(l.firstChild);else S=l;return(G.shadowroot||G.shadowrootmode)&&(S=Le.call(r,S,!0)),S}let q=N?l.outerHTML:l.innerHTML;return N&&j["!doctype"]&&l.ownerDocument&&l.ownerDocument.doctype&&l.ownerDocument.doctype.name&&ne(cc,l.ownerDocument.doctype.name)&&(q="<!DOCTYPE "+l.ownerDocument.doctype.name+`>
`+q),b&&(q=Pt(q)),Q&&Lt?we(q):q},e.setConfig=function(){let g=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};vn(g),z=!0,K=j,le=G},e.clearConfig=function(){tt=null,z=!1,K=null,le=null,Q=Be,ve=""},e.isValidAttribute=function(g,a,l){tt||vn({});let h=Y(g),m=Y(a);return _r(h,m,l)},e.addHook=function(g,a){typeof a=="function"&&he(C,g)&&xt(C[g],a)},e.removeHook=function(g,a){if(he(C,g)){if(a!==void 0){let l=Go(C[g],a);return l===-1?void 0:Wo(C[g],l,1)[0]}return ea(C[g])}},e.removeHooks=function(g){he(C,g)&&(C[g]=[])},e.removeAllHooks=function(){C=ha()},e}var nn=ma();var ba="vitrine",Zl=Object.freeze(["a","abbr","b","blockquote","br","caption","code","col","colgroup","dd","del","details","div","dl","dt","em","figcaption","figure","h1","h2","h3","h4","h5","h6","hr","i","img","input","ins","kbd","li","mark","ol","p","pre","q","s","samp","small","span","strong","sub","summary","sup","table","tbody","td","tfoot","th","thead","tr","u","ul","var"]),Ql=Object.freeze(["align","alt","checked","class","colspan","dir","disabled","height","href","lang","open","rowspan","span","src","start","title","type","width"]);var St;function er(){if(St!==void 0)return St;St=null;let t=globalThis.trustedTypes;if(t&&typeof t.createPolicy=="function")try{St=t.createPolicy(ba,{createHTML:e=>e,createScriptURL:e=>e})}catch{console.warn(`[vitrine] Could not create the "${ba}" Trusted Types policy. Add it to your CSP "trusted-types" directive.`)}return St??null}function mc(t){let e=document.createDocumentFragment();return e.append(document.createTextNode(String(t))),e}var Ke;function bc(){if(Ke!==void 0)return Ke;Ke=!1;try{if(!nn.isSupported)return!1;let t=nn.sanitize('<img src="x" onerror="1"><script>1<\/script><a href="javascript:1">a</a>',{RETURN_DOM_FRAGMENT:!0,...er()?{TRUSTED_TYPES_POLICY:er()}:{}}),e=t.querySelector("img");Ke=t instanceof DocumentFragment&&e!==null&&!e.hasAttribute("onerror")&&t.querySelector("script")===null&&!t.querySelector("a")?.hasAttribute("href")}catch{Ke=!1}return Ke||console.warn("[vitrine] HTML sanitizer unavailable: rich content is shown as plain text."),Ke}var yc=/^(?:hljs-[\w-]{1,40}|[a-z]{1,20}_{1,2})$/;function ya(t){if(!bc())return mc(t);let e=er(),n={ALLOWED_TAGS:["span"],ALLOWED_ATTR:["class"],ALLOW_DATA_ATTR:!1,ALLOW_ARIA_ATTR:!1,RETURN_DOM_FRAGMENT:!0,KEEP_CONTENT:!0};e&&(n.TRUSTED_TYPES_POLICY=e);let r=nn.sanitize(String(t),n);for(let s of Array.from(r.querySelectorAll("[class]"))){let i=Array.from(s.classList).filter(o=>yc.test(o));i.length?s.setAttribute("class",i.join(" ")):s.removeAttribute("class")}return r}var vc={bash:zs,diff:Bs,javascript:Gs,json:Ws,markdown:qs,plaintext:Vs,python:Ks,shell:Ys,xml:Xs,yaml:Zs};for(let[t,e]of Object.entries(vc))_t.registerLanguage(t,e);_t.configure({ignoreUnescapedHTML:!0,throwUnescapedHTML:!1});function _c(t){return!!_t.getLanguage(t)}function va(t,e){if(e==="plaintext"||!_c(e)){let r=document.createDocumentFragment();return r.append(document.createTextNode(t)),r}let n=_t.highlight(t,{language:e,ignoreIllegals:!0});return ya(n.value)}function _a(t){let e=[],n=[],r=document.createDocumentFragment(),s=r,i=()=>{e.push(r),r=document.createDocumentFragment(),s=r;for(let c of n){let u=c.cloneNode(!1);s.appendChild(u),s=u}},o=c=>{if(c.nodeType===Node.TEXT_NODE){(c.nodeValue??"").split(`
`).forEach((f,E)=>{E>0&&i(),f&&s.appendChild(document.createTextNode(f))});return}if(c.nodeType!==Node.ELEMENT_NODE)return;let u=c;s.appendChild(u.cloneNode(!1)),s=s.lastChild,n.push(u);for(let d of Array.from(u.childNodes))o(d);n.pop(),s=s.parentNode};for(let c of Array.from(t.childNodes))o(c);return e.push(r),e}var xc=1e3,xa=200;function Ec(t){let e=[],n=[];for(let r of t)r.startsWith("@@")?(e.push("hunk"),n.push(r)):/^(?:\+\+\+|---)(?: |$)|^diff |^index /.test(r)?(e.push("meta"),n.push(r)):r.startsWith("+")?(e.push("added"),n.push(r.slice(1))):r.startsWith("-")?(e.push("removed"),n.push(r.slice(1))):(e.push("context"),n.push(r.startsWith(" ")?r.slice(1):r));return{kinds:e,code:n}}function rn(t,e){let r=(t.endsWith(`
`)&&!e.trailingNewline?t.slice(0,-1):t).split(`
`),s=null;if(e.diff){let k=Ec(r);s=k.kinds,r=k.code}let i=r.join(`
`),o=i.length>e.highlightLimit,c=o||e.language==="plaintext",u=c?null:_a(va(i,e.language)),d=c?i.split(`
`):null,f=u?u.length:d.length,E=e.startLine+f-1,_=Math.max(String(e.startLine).length,String(E).length),T=v("pre",{class:"code",part:"code"});T.style.setProperty("--_digits",String(_));let H=k=>{let I=e.startLine+k,R=s?.[k],W=v("span",{class:"line",part:"line",attrs:{"data-line":I}});if(e.highlightRanges.length&&kr(I,e.highlightRanges)&&(W.classList.add("highlighted"),W.setAttribute("part","line line-highlighted")),R&&R!=="context"&&W.classList.add(R),e.lineNumbers&&W.append(v("span",{class:"gutter",part:"gutter line-number",attrs:{"aria-hidden":"true","data-n":I}})),s){let ye=R==="added"?e.diffLabels?.added:R==="removed"?e.diffLabels?.removed:"";W.append(v("span",{class:"sign"},ye?v("span",{class:"sr-only",text:`${ye}: `}):null))}let V=v("span",{class:"content"});return u?V.append(u[k]):d?.[k]&&V.append(d[k]),k<f-1&&V.append(`
`),W.append(V),W},F=(k,I,R)=>{let W=document.createDocumentFragment();for(let V=I;V<R;V+=1)W.appendChild(H(V));k.appendChild(W)},U=document.createDocumentFragment();if(e.chunk!==!1&&f>xc)for(let k=0;k<f;k+=xa){let I=Math.min(f,k+xa),R=v("span",{class:"chunk",attrs:{"data-first":e.startLine+k,"data-count":I-k}});R.style.setProperty("--_chunk-lines",String(I-k)),U.append(R),k===0?F(R,k,I):(R.setAttribute("data-pending",""),cs(R,()=>{R.removeAttribute("data-pending"),F(R,k,I)}))}else F(U,0,f);return T.append(U),{element:v("div",{class:"code-view"},T),code:T,lineCount:f,highlightSkipped:o}}function sn(t){t&&(t.closest(".chunk")?.classList.add("revealed"),t.scrollIntoView({block:"nearest",inline:"nearest"}))}var an=class{constructor(e){this.steps=[{value:e,start:0,end:0}],this.index=0,this.lastKind="",this.lastTime=0,this.listeners=new Set}get canUndo(){return this.index>0}get canRedo(){return this.index<this.steps.length-1}get current(){return this.steps[this.index]}record(e,n){if(e.value===this.current.value)return;let r=Date.now(),i=(n==="insertText"||n.startsWith("delete"))&&n===this.lastKind&&r-this.lastTime<600&&!this.canRedo;this.steps.length=this.index+1,i&&this.index>0?this.steps[this.index]=e:(this.steps.push(e),this.index+=1),this.lastKind=n,this.lastTime=r,this.trim(),this.notify()}undo(){return this.canUndo?(this.index-=1,this.lastKind="",this.notify(),this.current):null}redo(){return this.canRedo?(this.index+=1,this.lastKind="",this.notify(),this.current):null}trim(){let e=this.steps.reduce((n,r)=>n+r.value.length,0);for(;this.steps.length>1&&(this.steps.length>300||e>2e7)&&this.index>0;)e-=this.steps.shift().value.length,this.index-=1}subscribe(e){return this.listeners.add(e),()=>this.listeners.delete(e)}notify(){for(let e of this.listeners)e()}};var Tc=6e4,wc=250,on="  ",cn=class{constructor(e){this.options=e,this.text=e.text,this.tabReleased=!1,this.changedSinceFocus=!1,this.timer=void 0,this.textarea=v("textarea",{class:"editor-input",part:"editor",attrs:{"aria-label":e.label,placeholder:e.placeholder??null,spellcheck:"false",autocapitalize:"off",autocomplete:"off",autocorrect:"off",wrap:e.wrap?"soft":"off","data-focus-key":"editor"}}),this.textarea.value=e.text,this.history=e.history&&e.history.current.value===e.text?e.history:new an(e.text),this.layer=this.buildLayer(e.text),this.element=v("div",{class:e.wrap?"editor wrap":"editor"},this.layer,this.textarea),this.textarea.addEventListener("input",n=>this.onInput(n.inputType||"other")),this.textarea.addEventListener("beforeinput",n=>{(n.inputType==="historyUndo"||n.inputType==="historyRedo")&&(n.preventDefault(),n.inputType==="historyUndo"?this.undo():this.redo())}),this.textarea.addEventListener("keydown",n=>this.onKeyDown(n)),this.textarea.addEventListener("focus",()=>{this.changedSinceFocus=!1}),this.textarea.addEventListener("blur",()=>{this.changedSinceFocus&&e.onChange?.(this.text)})}buildLayer(e){let n=rn(e,{language:this.options.language,lineNumbers:this.options.lineNumbers,startLine:1,highlightRanges:this.options.highlightRanges??[],diff:!1,highlightLimit:this.options.highlightLimit,trailingNewline:!0,chunk:!1});return n.element.classList.add("editor-layer"),n.element.setAttribute("aria-hidden","true"),n.element}refresh(){clearTimeout(this.timer);let e=this.buildLayer(this.text);this.layer.replaceWith(e),this.layer=e,this.element.classList.remove("pending"),this.align()}align(){let e=this.layer.querySelector(".gutter"),n=e?e.getBoundingClientRect().width:0;this.element.style.setProperty("--_editor-gutter",`${n}px`)}setHighlightRanges(e){this.options.highlightRanges=e,this.refresh()}onInput(e){this.text=this.textarea.value.replace(/\r\n?/g,`
`),this.changedSinceFocus=!0,this.history.record({value:this.text,start:this.textarea.selectionStart,end:this.textarea.selectionEnd},e),this.text.length<=Tc?this.refresh():(this.element.classList.add("pending"),clearTimeout(this.timer),this.timer=setTimeout(()=>this.refresh(),wc)),this.options.onInput(this.text)}onKeyDown(e){let n=e.ctrlKey||e.metaKey,r=e.key.toLowerCase();if(n&&!e.altKey&&(r==="z"||r==="y")){e.preventDefault(),r==="y"||e.shiftKey?this.redo():this.undo();return}if(e.key==="Escape"){this.tabReleased=!0;return}if(e.key==="Tab"&&!this.tabReleased&&!e.ctrlKey&&!e.metaKey&&!e.altKey){e.preventDefault(),e.shiftKey?this.outdent():this.indent();return}if(e.key!=="Tab"&&(this.tabReleased=!1),e.key==="Enter"&&!e.shiftKey&&!e.ctrlKey&&!e.metaKey&&!e.isComposing){let{value:s,selectionStart:i}=this.textarea,o=s.lastIndexOf(`
`,i-1)+1,c=/^[ \t]*/.exec(s.slice(o,i))?.[0]??"";c&&(e.preventDefault(),this.insert(`
${c}`))}}indent(){let{value:e,selectionStart:n,selectionEnd:r}=this.textarea;if(n===r||!e.slice(n,r).includes(`
`)){this.insert(on);return}let s=e.lastIndexOf(`
`,n-1)+1,i=e.slice(s,r),o=i.replace(/^/gm,on);this.replaceRange(s,r,o),this.textarea.setSelectionRange(n+on.length,r+(o.length-i.length))}outdent(){let{value:e,selectionStart:n,selectionEnd:r}=this.textarea,s=e.lastIndexOf(`
`,n-1)+1,i=e.slice(s,r),o=new RegExp(`^(?:\\t| {1,${on.length}})`,"gm"),c=(/^(?:\t| {1,2})/.exec(i)?.[0]??"").length,u=i.replace(o,"");u!==i&&(this.replaceRange(s,r,u),this.textarea.setSelectionRange(Math.max(s,n-c),r-(i.length-u.length)))}insert(e){this.textarea.focus(),document.execCommand?.("insertText",!1,e)||(this.textarea.setRangeText(e,this.textarea.selectionStart,this.textarea.selectionEnd,"end"),this.onInput("insertText"))}replaceRange(e,n,r){this.textarea.setSelectionRange(e,n),this.insert(r)}undo(){this.restore(this.history.undo())}redo(){this.restore(this.history.redo())}restore(e){e&&(this.textarea.value=e.value,this.textarea.focus(),this.textarea.setSelectionRange(e.start,e.end),this.text=e.value,this.changedSinceFocus=!0,this.refresh(),this.options.onInput(this.text))}destroy(){clearTimeout(this.timer)}};var Sc=Object.freeze([",",";","	","|"]);function Ac(t){let e=t.slice(0,2e4).split(/\r?\n/).slice(0,20).filter(s=>s.trim()),n=",",r=0;for(let s of Sc){let i=e.map(u=>Nc(u,s));if(!i.length||i[0]===0)continue;let c=i.filter(u=>u===i[0]).length/i.length*10+Math.min(i[0],10);c>r&&(n=s,r=c)}return n}function Nc(t,e){let n=0,r=!1;for(let s of t)s==='"'?r=!r:s===e&&!r&&(n+=1);return n}function Ea(t,e={}){let n=t.charCodeAt(0)===65279?t.slice(1):t,r=e.delimiter??Ac(n),s=[],i=[],o="",c=!1,u=0,d=1,f=0,E=!1,_=0,T=n.length,H=()=>{i.length<1e3?i.push(o):E=!0,o=""},F=()=>{H(),f=Math.max(f,i.length),s.push(i),i=[]};for(;_<T;){let L=n[_];if(c){if(L==='"'){if(n[_+1]==='"'){o+='"',_+=2;continue}c=!1,_+=1;continue}let k=n.indexOf('"',_),I=k===-1?T:k,R=n.slice(_,I);d+=kc(R),o+=R,_=I;continue}L==='"'&&o===""?(c=!0,u=d,_+=1):L===r?(H(),_+=1):L===`
`||L==="\r"?(F(),_+=L==="\r"&&n[_+1]===`
`?2:1,d+=1):(o+=L,_+=1)}return(o!==""||i.length)&&F(),{rows:s,delimiter:r,columns:f,truncatedColumns:E,error:c?{message:"Unclosed quoted field",line:u}:null}}function kc(t){let e=0;for(let n=t.indexOf(`
`);n!==-1;n=t.indexOf(`
`,n+1))e+=1;return e}var Rc=/^[+-]?(?:\d{1,3}(?:[ ,]\d{3})+|\d+)?(?:[.]\d+)?(?:e[+-]?\d+)?%?$/i,Cc=/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/,Lc=/^(?:true|false|yes|no)$/i;function Ta(t,e){let n=0,r={number:0,date:0,boolean:0};for(let s=0;s<t.length&&n<500;s+=1){let i=(t[s][e]??"").trim();i&&(n+=1,Rc.test(i)&&/\d/.test(i)?r.number+=1:Cc.test(i)?r.date+=1:Lc.test(i)&&(r.boolean+=1))}return n?r.number===n?"number":r.date===n?"date":r.boolean===n?"boolean":"text":"text"}function wa(t,e){let n=t.trim();return e==="number"?Number(n.replace(/[ ,%]/g,"")):e==="date"?Date.parse(n):n.toLowerCase()}var Mc=["table","raw"],Ic={",":",",comma:",",";":";",semicolon:";",tab:"	","\\t":"	","|":"|",pipe:"|"},Sa=1e3,ln=class extends Kt{static type="csv";static componentAttributes=Object.freeze(["delimiter","header-row","page-size","sortable","line-numbers","tabs","view"]);static presets={simple:{"header-row":!0},full:{header:!0,dot:!0,copy:!0,search:!0,download:!0,tabs:!0,sortable:!0,"line-numbers":!0,"header-row":!0,fullscreen:!0}};static styles=[Ht,Sr,Ar];constructor(){super(),this.parsed=null,this.parsedText=null,this.sort=null,this.page=0,this.viewState=null,this.panelId=Ft("panel"),this.query="",this.searchMatches=[],this.current=-1,this.tableHost=null,this.editor=null,this.status=null,this.parseTimer=void 0}attributeChangedCallback(e,n,r){e==="view"&&(this.viewState=null),(e==="page-size"||e==="header-row")&&(this.page=0),super.attributeChangedCallback(e,n,r)}contentChanged(){this.parsed=null,this.sort=null,this.page=0}get rows(){return this.parse().rows.map(e=>[...e])}parse(){let e=this.text??"",n=(this.getAttribute("delimiter")??"").trim().toLowerCase(),r=Ic[n],s=`${r??"auto"}`;return(!this.parsed||this.parsed.key!==s||this.parsedText!==e)&&(this.parsed={key:s,result:Ea(e,r?{delimiter:r}:{})},this.parsedText=e),this.parsed.result}get view(){return this.viewState??pt(this.getAttribute("view"),Mc,this.editing?"raw":"table")}get pageSize(){return Nr(this.getAttribute("page-size"),{min:10,max:1e3,fallback:100})}model(){let e=this.parse(),n=this.feature("header-row"),r=n?e.rows[0]??[]:[],s=n?e.rows.slice(1):e.rows,i=Array.from({length:e.columns},(c,u)=>r[u]?.trim()||this.t("column",{n:u+1})),o=i.map((c,u)=>Ta(s,u));return{names:i,types:o,data:s,result:e}}order(e,n){let r=e.map((i,o)=>o);if(this.sort){let{column:i,direction:o}=this.sort,c=n[i]??"text",u=e.map(f=>(f[i]??"").trim()?wa(f[i],c):null),d=o==="ascending"?1:-1;r.sort((f,E)=>{let _=u[f],T=u[E];if(_===null||T===null||typeof _=="number"&&Number.isNaN(_)||typeof T=="number"&&Number.isNaN(T)){let H=_===null||Number.isNaN(_),F=T===null||Number.isNaN(T);return H===F?f-E:H?1:-1}return _<T?-d:_>T?d:f-E})}if(!this.query)return r;let s=this.query.toLowerCase();return r.filter(i=>e[i].some(o=>o.toLowerCase().includes(s)))}renderContent(e){let n=this.t,r=this.view,s=this.feature("tabs")?hs({tabs:[{id:"table",label:n("table"),icon:"table"},{id:"raw",label:n("raw"),icon:"code"}],selected:r,label:n("tabs"),panelId:this.panelId,onSelect:d=>this.selectView(d)}):null,i=v("div",{class:"panel",attrs:{id:this.panelId,role:s?"tabpanel":null}}),o,c=[];if(r==="raw"&&this.editing){let d=this.createEditor();i.append(v("div",{class:"body editor-body",part:"body"},d.element)),De(this.getAttribute("status"))!==!1&&i.append(this.status);let f=null;o={run:E=>(f=new it(d.layer.querySelector("pre.code")),f.run(E)),go:E=>sn(f?.go(E)??null),clear:()=>f?.clear()},c=this.historyButtons(d)}else if(r==="raw"){let d=rn(this.text??"",{language:"plaintext",lineNumbers:this.feature("line-numbers"),startLine:1,highlightRanges:[],diff:!1,highlightLimit:ae().highlightLimit});i.append(v("div",{class:"body",part:"body",attrs:{tabindex:"0",role:"region","aria-label":this.heading||"CSV"}},d.element));let f=new it(d.code);o={run:E=>f.run(E),go:E=>sn(f.go(E)),clear:()=>f.clear()}}else this.tableHost=v("div",{class:"table-host"}),i.append(...this.notices(),this.tableHost),this.renderTable(),o={run:d=>this.search(d),go:d=>this.goToMatch(d),clear:()=>this.search("")};let u=[this.searchButton(o),...c,this.editToggleButton(),this.fullscreenButton(),this.feature("download")?this.downloadButton(()=>this.text??"",this.downloadName("data.csv"),"text/csv"):null,this.feature("copy")?this.copyButton(()=>this.text??"",n("copy")):null];e.append(...this.chrome({badge:s?"":"CSV",tabs:s,actions:u}),i),this.editor?.align()}notices(){let{result:e}=this.model(),n=this.t,r=[];return e.error&&r.push(zn(n("csvUnclosed",{line:e.error.line}))),e.truncatedColumns&&r.push(zn(n("tooManyColumns",{limit:de(1e3,this.locale)}))),r}renderTable(){if(!this.tableHost)return;let e=this.t,{names:n,types:r,data:s}=this.model(),i=this.order(s,r),o=this.pageSize,c=Math.max(1,Math.ceil(i.length/o));this.page=Math.min(this.page,c-1);let u=this.page*o,d=i.slice(u,u+o),f=this.feature("line-numbers"),E=this.feature("sortable"),_=v("tr");f&&_.append(v("th",{class:"row-number",attrs:{scope:"col"}},v("span",{class:"sr-only",text:e("rowNumber")}))),n.forEach((U,L)=>{let k=this.sort?.column===L?this.sort.direction:null,I=v("th",{class:`col-${r[L]}`,part:"header-cell",attrs:{scope:"col","aria-sort":E?k??"none":null}});if(E){let R=v("button",{class:"sort",attrs:{type:"button","data-focus-key":`sort-${L}`,title:e("sortBy",{name:U})},on:{click:()=>this.sortBy(L,U)}},v("span",{class:"name",text:U}),ke(k==="ascending"?"sort-up":k==="descending"?"sort-down":"sort"));I.append(R)}else I.append(v("span",{class:"name",text:U}));_.append(I)});let T=v("tbody");for(let U of d){let L=s[U],k=v("tr");f&&k.append(v("th",{class:"row-number",part:"row-number",attrs:{scope:"row"},text:de(U+1,this.locale)}));for(let I=0;I<n.length;I+=1){let R=L[I]??"";k.append(v("td",{class:`col-${r[I]}`,part:"cell",attrs:{"data-row":U,"data-column":I},text:R.length>Sa?`${R.slice(0,Sa)}\u2026`:R}))}T.append(k)}d.length||T.append(v("tr",{},v("td",{class:"no-rows",attrs:{colspan:n.length+(f?1:0)},text:e("noRows")})));let H=v("table",{class:"grid",part:"table"},v("caption",{class:"sr-only",text:this.heading||"CSV"}),v("thead",{},_),T),F=v("div",{class:"body table-body",part:"body",attrs:{tabindex:"0",role:"region","aria-label":this.heading||e("table")}},H);this.tableHost.replaceChildren(F,this.pager(i.length,c)),this.query&&this.highlightMatches(T)}pager(e,n){let r=this.t,s=e?this.page*this.pageSize+1:0,i=Math.min(e,(this.page+1)*this.pageSize),o=d=>{this.page=Math.max(0,Math.min(n-1,d)),this.renderTable()},c=(d,f,E,_)=>{let T=ge({icon:d,label:r(f),key:f,onClick:()=>o(E)});return T.disabled=_,T},u=this.query?`${r("matchingRows",{count:de(e,this.locale)})} \xB7 ${r("rowsRange",{from:de(s,this.locale),to:de(i,this.locale),total:de(e,this.locale)})}`:r("rowsRange",{from:de(s,this.locale),to:de(i,this.locale),total:de(e,this.locale)});return v("div",{class:"pager",part:"pager"},v("span",{class:"pager-info",attrs:{"aria-live":"polite"},text:u}),n>1?v("div",{class:"toolbar"},c("chevrons-left","firstPage",0,this.page===0),c("chevron-left","previousPage",this.page-1,this.page===0),c("chevron-right","nextPage",this.page+1,this.page>=n-1),c("chevrons-right","lastPage",n-1,this.page>=n-1)):null)}sortBy(e,n){let r=this.sort?.column!==e?"ascending":this.sort.direction==="ascending"?"descending":null;this.sort=r?{column:e,direction:r}:null,this.page=0,this.renderTable(),this.root.querySelector(`[data-focus-key="sort-${e}"]`)?.focus(),pe(this,ue.SORT,{column:e,name:n,direction:r??"none"})}search(e){this.query=e,this.page=0,this.searchMatches=[],this.current=-1;let n=!1;if(e){let{types:r,data:s}=this.model(),i=e.toLowerCase();for(let o of this.order(s,r))if(s[o].forEach((c,u)=>{this.searchMatches.length>=Un?n=!0:c.toLowerCase().includes(i)&&this.searchMatches.push({row:o,column:u})}),n)break}return this.renderTable(),{total:this.searchMatches.length,capped:n}}goToMatch(e){let n=this.searchMatches[e];if(!n)return;this.current=e;let{types:r,data:s}=this.model(),i=this.order(s,r).indexOf(n.row),o=Math.floor(i/this.pageSize);o!==this.page?(this.page=o,this.renderTable()):this.highlightMatches(this.tableHost?.querySelector("tbody"))}highlightMatches(e){let n=this.searchMatches[this.current];for(let r of e.querySelectorAll("td[data-row]")){let s=new it(r);if(s.clear(),!s.run(this.query).total)continue;if(n&&Number(r.getAttribute("data-row"))===n.row&&Number(r.getAttribute("data-column"))===n.column){for(let o of s.matches)for(let c of o)c.classList.add("current");sn(s.matches[0]?.[0]??null)}}}createEditor(){this.editor?.destroy();let e=new cn({text:this.text??"",language:"plaintext",lineNumbers:this.feature("line-numbers"),wrap:!1,highlightLimit:ae().highlightLimit,label:this.heading||`CSV ${this.t("editor").toLowerCase()}`,placeholder:this.getAttribute("placeholder")??void 0,onInput:n=>this.edited(n),onChange:n=>pe(this,ue.CHANGE,{value:n}),history:this.editHistory??void 0});return this.editor=e,this.status=v("div",{class:"edit-status",part:"status",attrs:{role:"status"}}),this.showStatus(),e}showStatus(){if(!this.status)return;let{names:e,data:n,result:r}=this.model(),s=this.t,i=!r.error;this.status.className=`edit-status ${i?"ok":"bad"}`;let o=i?s("csvStatus",{rows:de(n.length,this.locale),columns:de(e.length,this.locale)}):s("csvUnclosed",{line:r.error.line});this.status.replaceChildren(ke(i?"check":"alert"),v("span",{text:o}))}contentEdited(){this.parsed=null,clearTimeout(this.parseTimer),this.parseTimer=setTimeout(()=>{this.showStatus(),this.searchOpen&&this.searchQuery&&this.searchBar?.run()},150)}selectView(e){e!==this.view&&(this.viewState=e,this.render(),this.root.querySelector(`[data-tab="${e}"]`)?.focus(),pe(this,ue.TAB_CHANGE,{tab:e}))}disconnectedCallback(){clearTimeout(this.parseTimer),this.editor?.destroy(),super.disconnectedCallback()}};function Aa(t){es(new URL("languages/",t).href),On(new URL("syntax-themes/",t).href),ts(new URL("vendor/",t).href)}Aa(new URL("../",import.meta.url));customElements.get("vt-csv")||customElements.define("vt-csv",ln);export{Ti as BUILT_IN_THEMES,ue as EVENTS,ln as VtCsv,si as configure,ae as getConfig,Ln as getTheme,Ri as listSyntaxThemes,Ai as listThemes,fi as registerLocale,Si as registerTheme};
/*! Bundled license information:

dompurify/dist/purify.es.mjs:
  (*! @license DOMPurify 3.4.16 | (c) Cure53 and other contributors | Released under the Apache license 2.0 and Mozilla Public License 2.0 | github.com/cure53/DOMPurify/blob/3.4.16/LICENSE *)
  (*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/babel/babel/blob/main/packages/babel-helpers/LICENSE *)
*/
