/*! Vitrine | MIT | Source e7db1ebd587b27f41988a0da9785310eaa6f2f08 | See app/static/vendor/vitrine/LICENSE and THIRD_PARTY_NOTICES.md */
var Gs=Object.create;var yr=Object.defineProperty;var Ws=Object.getOwnPropertyDescriptor;var qs=Object.getOwnPropertyNames;var Ks=Object.getPrototypeOf,Vs=Object.prototype.hasOwnProperty;var Ys=(t,e)=>()=>{try{return e||t((e={exports:{}}).exports,e),e.exports}catch(n){throw e=0,n}};var Xs=(t,e,n,r)=>{if(e&&typeof e=="object"||typeof e=="function")for(let a of qs(e))!Vs.call(t,a)&&a!==n&&yr(t,a,{get:()=>e[a],enumerable:!(r=Ws(e,a))||r.enumerable});return t};var Zs=(t,e,n)=>(n=t!=null?Gs(Ks(t)):{},Xs(e||!t||!t.__esModule?yr(n,"default",{value:t,enumerable:!0}):n,t));var Ia=Ys((Xl,Ma)=>{function xa(t){return t instanceof Map?t.clear=t.delete=t.set=function(){throw new Error("map is read-only")}:t instanceof Set&&(t.add=t.clear=t.delete=function(){throw new Error("set is read-only")}),Object.freeze(t),Object.getOwnPropertyNames(t).forEach(e=>{let n=t[e],r=typeof n;(r==="object"||r==="function")&&!Object.isFrozen(n)&&xa(n)}),t}var Yt=class{constructor(e){e.data===void 0&&(e.data={}),this.data=e.data,this.isMatchIgnored=!1}ignoreMatch(){this.isMatchIgnored=!0}};function Ea(t){return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;")}function Me(t,...e){let n=Object.create(null);for(let r in t)n[r]=t[r];return e.forEach(function(r){for(let a in r)n[a]=r[a]}),n}var Fi="</span>",ga=t=>!!t.scope,ji=(t,{prefix:e})=>{if(t.startsWith("language:"))return t.replace("language:","language-");if(t.includes(".")){let n=t.split(".");return[`${e}${n.shift()}`,...n.map((r,a)=>`${r}${"_".repeat(a+1)}`)].join(" ")}return`${e}${t}`},Dn=class{constructor(e,n){this.buffer="",this.classPrefix=n.classPrefix,e.walk(this)}addText(e){this.buffer+=Ea(e)}openNode(e){if(!ga(e))return;let n=ji(e.scope,{prefix:this.classPrefix});this.span(n)}closeNode(e){ga(e)&&(this.buffer+=Fi)}value(){return this.buffer}span(e){this.buffer+=`<span class="${e}">`}},ma=(t={})=>{let e={children:[]};return Object.assign(e,t),e},Pn=class t{constructor(){this.rootNode=ma(),this.stack=[this.rootNode]}get top(){return this.stack[this.stack.length-1]}get root(){return this.rootNode}add(e){this.top.children.push(e)}openNode(e){let n=ma({scope:e});this.add(n),this.stack.push(n)}closeNode(){if(this.stack.length>1)return this.stack.pop()}closeAllNodes(){for(;this.closeNode(););}toJSON(){return JSON.stringify(this.rootNode,null,4)}walk(e){return this.constructor._walk(e,this.rootNode)}static _walk(e,n){return typeof n=="string"?e.addText(n):n.children&&(e.openNode(n),n.children.forEach(r=>this._walk(e,r)),e.closeNode(n)),e}static _collapse(e){typeof e!="string"&&e.children&&(e.children.every(n=>typeof n=="string")?e.children=[e.children.join("")]:e.children.forEach(n=>{t._collapse(n)}))}},Un=class extends Pn{constructor(e){super(),this.options=e}addText(e){e!==""&&this.add(e)}startScope(e){this.openNode(e)}endScope(){this.closeNode()}__addSublanguage(e,n){let r=e.root;n&&(r.scope=`language:${n}`),this.add(r)}toHTML(){return new Dn(this,this.options).value()}finalize(){return this.closeAllNodes(),!0}};function vt(t){return t?typeof t=="string"?t:t.source:null}function Ta(t){return We("(?=",t,")")}function $i(t){return We("(?:",t,")*")}function Gi(t){return We("(?:",t,")?")}function We(...t){return t.map(n=>vt(n)).join("")}function Wi(t){let e=t[t.length-1];return typeof e=="object"&&e.constructor===Object?(t.splice(t.length-1,1),e):{}}function Zt(...t){return"("+(Wi(t).capture?"":"?:")+t.map(r=>vt(r)).join("|")+")"}function wa(t){return new RegExp(t.toString()+"|").exec("").length-1}function qi(t,e){let n=t&&t.exec(e);return n&&n.index===0}var Ki=new RegExp(Zt(/\[(?:[^\\\]]|\\.)*\]/,/\(\?<(?![=!])[^>]+>/,/\(\?'[^']+'/,/\(\??/,/\\([1-9][0-9]*)/,/\\./));function Bn(t,{joinWith:e}){let n=0;return t.map(r=>{n+=1;let a=n,i=vt(r),o="";for(;i.length>0;){let l=Ki.exec(i);if(!l){o+=i;break}o+=i.substring(0,l.index),i=i.substring(l.index+l[0].length),l[0][0]==="\\"&&l[1]?o+="\\"+String(Number(l[1])+a):(o+=l[0],(l[0]==="("||/^\(\?[<']/.test(l[0]))&&n++)}return o}).map(r=>`(${r})`).join(e)}var Vi=/\b\B/,Aa="[a-zA-Z]\\w*",Hn="[a-zA-Z_]\\w*",Sa="\\b\\d+(\\.\\d+)?",ka="(-?)(\\b0[xX][a-fA-F0-9]+|(\\b\\d+(\\.\\d*)?|\\.\\d+)([eE][-+]?\\d+)?)",Na="\\b(0b[01]+)",Yi="!|!=|!==|%|%=|&|&&|&=|\\*|\\*=|\\+|\\+=|,|-|-=|/=|/|:|;|<<|<<=|<=|<|===|==|=|>>>=|>>=|>=|>>>|>>|>|\\?|\\[|\\{|\\(|\\^|\\^=|\\||\\|=|\\|\\||~",Xi=(t={})=>{let e=/^#![ ]*\//;return t.binary&&(t.begin=We(e,/.*\b/,t.binary,/\b.*/)),Me({scope:"meta",begin:e,end:/$/,relevance:0,"on:begin":(n,r)=>{n.index!==0&&r.ignoreMatch()}},t)},_t={begin:"\\\\[\\s\\S]",relevance:0},Zi={scope:"string",begin:"'",end:"'",illegal:"\\n",contains:[_t]},Ji={scope:"string",begin:'"',end:'"',illegal:"\\n",contains:[_t]},Qi={begin:/\b(a|an|the|are|I'm|isn't|don't|doesn't|won't|but|just|should|pretty|simply|enough|gonna|going|wtf|so|such|will|you|your|they|like|more)\b/},Jt=function(t,e,n={}){let r=Me({scope:"comment",begin:t,end:e,contains:[]},n);r.contains.push({scope:"doctag",begin:"[ ]*(?=(TODO|FIXME|NOTE|BUG|OPTIMIZE|HACK|XXX):)",end:/(TODO|FIXME|NOTE|BUG|OPTIMIZE|HACK|XXX):/,excludeBegin:!0,relevance:0});let a=Zt("I","a","is","so","us","to","at","if","in","it","on",/[A-Za-z]+['](d|ve|re|ll|t|s|n)/,/[A-Za-z]+[-][a-z]+/,/[A-Za-z][a-z]{2,}/);return r.contains.push({begin:We(/[ ]+/,"(",a,/[.]?[:]?([.][ ]|[ ])/,"){3}")}),r},eo=Jt("//","$"),to=Jt("/\\*","\\*/"),no=Jt("#","$"),ro={scope:"number",begin:Sa,relevance:0},ao={scope:"number",begin:ka,relevance:0},so={scope:"number",begin:Na,relevance:0},io={scope:"regexp",begin:/\/(?=[^/\n]*\/)/,end:/\/[gimuy]*/,contains:[_t,{begin:/\[/,end:/\]/,relevance:0,contains:[_t]}]},oo={scope:"title",begin:Aa,relevance:0},co={scope:"title",begin:Hn,relevance:0},lo={begin:"\\.\\s*"+Hn,relevance:0},uo=function(t){return Object.assign(t,{"on:begin":(e,n)=>{n.data._beginMatch=e[1]},"on:end":(e,n)=>{n.data._beginMatch!==e[1]&&n.ignoreMatch()}})},Vt=Object.freeze({__proto__:null,APOS_STRING_MODE:Zi,BACKSLASH_ESCAPE:_t,BINARY_NUMBER_MODE:so,BINARY_NUMBER_RE:Na,COMMENT:Jt,C_BLOCK_COMMENT_MODE:to,C_LINE_COMMENT_MODE:eo,C_NUMBER_MODE:ao,C_NUMBER_RE:ka,END_SAME_AS_BEGIN:uo,HASH_COMMENT_MODE:no,IDENT_RE:Aa,MATCH_NOTHING_RE:Vi,METHOD_GUARD:lo,NUMBER_MODE:ro,NUMBER_RE:Sa,PHRASAL_WORDS_MODE:Qi,QUOTE_STRING_MODE:Ji,REGEXP_MODE:io,RE_STARTERS_RE:Yi,SHEBANG:Xi,TITLE_MODE:oo,UNDERSCORE_IDENT_RE:Hn,UNDERSCORE_TITLE_MODE:co});function ho(t,e){t.input[t.index-1]==="."&&e.ignoreMatch()}function fo(t,e){t.className!==void 0&&(t.scope=t.className,delete t.className)}function po(t,e){e&&t.beginKeywords&&(t.begin="\\b("+t.beginKeywords.split(" ").join("|")+")(?!\\.)(?=\\b|\\s)",t.__beforeBegin=ho,t.keywords=t.keywords||t.beginKeywords,delete t.beginKeywords,t.relevance===void 0&&(t.relevance=0))}function go(t,e){Array.isArray(t.illegal)&&(t.illegal=Zt(...t.illegal))}function mo(t,e){if(t.match){if(t.begin||t.end)throw new Error("begin & end are not supported with match");t.begin=t.match,delete t.match}}function bo(t,e){t.relevance===void 0&&(t.relevance=1)}var yo=(t,e)=>{if(!t.beforeMatch)return;if(t.starts)throw new Error("beforeMatch cannot be used with starts");let n=Object.assign({},t);Object.keys(t).forEach(r=>{delete t[r]}),t.keywords=n.keywords,t.begin=We(n.beforeMatch,Ta(n.begin)),t.starts={relevance:0,contains:[Object.assign(n,{endsParent:!0})]},t.relevance=0,delete n.beforeMatch},vo=["of","and","for","in","not","or","if","then","parent","list","value"],_o="keyword";function Ra(t,e,n=_o){let r=Object.create(null);return typeof t=="string"?a(n,t.split(" ")):Array.isArray(t)?a(n,t):Object.keys(t).forEach(function(i){Object.assign(r,Ra(t[i],e,i))}),r;function a(i,o){e&&(o=o.map(l=>l.toLowerCase())),o.forEach(function(l){let u=l.split("|");r[u[0]]=[i,xo(u[0],u[1])]})}}function xo(t,e){return e?Number(e):Eo(t)?0:1}function Eo(t){return vo.includes(t.toLowerCase())}var ba={},Ge=t=>{console.error(t)},ya=(t,...e)=>{console.log(`WARN: ${t}`,...e)},ot=(t,e)=>{ba[`${t}/${e}`]||(console.log(`Deprecated as of ${t}. ${e}`),ba[`${t}/${e}`]=!0)},Xt=new Error;function Oa(t,e,{key:n}){let r=0,a=t[n],i={},o={};for(let l=1;l<=e.length;l++)o[l+r]=a[l],i[l+r]=!0,r+=wa(e[l-1]);t[n]=o,t[n]._emit=i,t[n]._multi=!0}function To(t){if(Array.isArray(t.begin)){if(t.skip||t.excludeBegin||t.returnBegin)throw Ge("skip, excludeBegin, returnBegin not compatible with beginScope: {}"),Xt;if(typeof t.beginScope!="object"||t.beginScope===null)throw Ge("beginScope must be object"),Xt;Oa(t,t.begin,{key:"beginScope"}),t.begin=Bn(t.begin,{joinWith:""})}}function wo(t){if(Array.isArray(t.end)){if(t.skip||t.excludeEnd||t.returnEnd)throw Ge("skip, excludeEnd, returnEnd not compatible with endScope: {}"),Xt;if(typeof t.endScope!="object"||t.endScope===null)throw Ge("endScope must be object"),Xt;Oa(t,t.end,{key:"endScope"}),t.end=Bn(t.end,{joinWith:""})}}function Ao(t){t.scope&&typeof t.scope=="object"&&t.scope!==null&&(t.beginScope=t.scope,delete t.scope)}function So(t){Ao(t),typeof t.beginScope=="string"&&(t.beginScope={_wrap:t.beginScope}),typeof t.endScope=="string"&&(t.endScope={_wrap:t.endScope}),To(t),wo(t)}function ko(t){function e(o,l){return new RegExp(vt(o),"m"+(t.case_insensitive?"i":"")+(t.unicodeRegex?"u":"")+(l?"g":""))}class n{constructor(){this.matchIndexes={},this.regexes=[],this.matchAt=1,this.position=0}addRule(l,u){u.position=this.position++,this.matchIndexes[this.matchAt]=u,this.regexes.push([u,l]),this.matchAt+=wa(l)+1}compile(){this.regexes.length===0&&(this.exec=()=>null);let l=this.regexes.map(u=>u[1]);this.matcherRe=e(Bn(l,{joinWith:"|"}),!0),this.lastIndex=0}exec(l){this.matcherRe.lastIndex=this.lastIndex;let u=this.matcherRe.exec(l);if(!u)return null;let m=u.findIndex((A,R)=>R>0&&A!==void 0),b=this.matchIndexes[m];return u.splice(0,m),Object.assign(u,b)}}class r{constructor(){this.rules=[],this.multiRegexes=[],this.count=0,this.lastIndex=0,this.regexIndex=0}getMatcher(l){if(this.multiRegexes[l])return this.multiRegexes[l];let u=new n;return this.rules.slice(l).forEach(([m,b])=>u.addRule(m,b)),u.compile(),this.multiRegexes[l]=u,u}resumingScanAtSamePosition(){return this.regexIndex!==0}considerAll(){this.regexIndex=0}addRule(l,u){this.rules.push([l,u]),u.type==="begin"&&this.count++}exec(l){let u=this.getMatcher(this.regexIndex);u.lastIndex=this.lastIndex;let m=u.exec(l);if(this.resumingScanAtSamePosition()&&!(m&&m.index===this.lastIndex)){let b=this.getMatcher(0);b.lastIndex=this.lastIndex+1,m=b.exec(l)}return m&&(this.regexIndex+=m.position+1,this.regexIndex===this.count&&this.considerAll()),m}}function a(o){let l=new r;return o.contains.forEach(u=>l.addRule(u.begin,{rule:u,type:"begin"})),o.terminatorEnd&&l.addRule(o.terminatorEnd,{type:"end"}),o.illegal&&l.addRule(o.illegal,{type:"illegal"}),l}function i(o,l){let u=o;if(o.isCompiled)return u;[fo,mo,So,yo].forEach(b=>b(o,l)),t.compilerExtensions.forEach(b=>b(o,l)),o.__beforeBegin=null,[po,go,bo].forEach(b=>b(o,l)),o.isCompiled=!0;let m=null;return typeof o.keywords=="object"&&o.keywords.$pattern&&(o.keywords=Object.assign({},o.keywords),m=o.keywords.$pattern,delete o.keywords.$pattern),m=m||/\w+/,o.keywords&&(o.keywords=Ra(o.keywords,t.case_insensitive)),u.keywordPatternRe=e(m,!0),l&&(o.begin||(o.begin=/\B|\b/),u.beginRe=e(u.begin),!o.end&&!o.endsWithParent&&(o.end=/\B|\b/),o.end&&(u.endRe=e(u.end)),u.terminatorEnd=vt(u.end)||"",o.endsWithParent&&l.terminatorEnd&&(u.terminatorEnd+=(o.end?"|":"")+l.terminatorEnd)),o.illegal&&(u.illegalRe=e(o.illegal)),o.contains||(o.contains=[]),o.contains=[].concat(...o.contains.map(function(b){return No(b==="self"?o:b)})),o.contains.forEach(function(b){i(b,u)}),o.starts&&i(o.starts,l),u.matcher=a(u),u}if(t.compilerExtensions||(t.compilerExtensions=[]),t.contains&&t.contains.includes("self"))throw new Error("ERR: contains `self` is not supported at the top-level of a language.  See documentation.");return t.classNameAliases=Me(t.classNameAliases||{}),i(t)}function La(t){return t?t.endsWithParent||La(t.starts):!1}function No(t){return t.variants&&!t.cachedVariants&&(t.cachedVariants=t.variants.map(function(e){return Me(t,{variants:null},e)})),t.cachedVariants?t.cachedVariants:La(t)?Me(t,{starts:t.starts?Me(t.starts):null}):Object.isFrozen(t)?Me(t):t}var Ro="11.12.0",zn=class extends Error{constructor(e,n){super(e),this.name="HTMLInjectionError",this.html=n}},In=Ea,va=Me,_a=Symbol("nomatch"),Oo=7,Ca=function(t){let e=Object.create(null),n=Object.create(null),r=[],a=!0,i="Could not find the language '{}', did you forget to load/include a language module?",o={disableAutodetect:!0,name:"Plain text",contains:[]},l={ignoreUnescapedHTML:!1,throwUnescapedHTML:!1,noHighlightRe:/^(no-?highlight)$/i,languageDetectRe:/\blang(?:uage)?-([\w-]+)\b/i,classPrefix:"hljs-",cssSelector:"pre code",languages:null,__emitter:Un};function u(h){return l.noHighlightRe.test(h)}function m(h){let v=h.className+" ";v+=h.parentNode?h.parentNode.className:"";let E=l.languageDetectRe.exec(v);if(E){let k=re(E[1]);return k||(ya(i.replace("{}",E[1])),ya("Falling back to no-highlight mode for this block.",h)),k?E[1]:"no-highlight"}return v.split(/\s+/).find(k=>u(k)||re(k))}function b(h,v,E){let k="",U="";typeof v=="object"?(k=h,E=v.ignoreIllegals,U=v.language):(ot("10.7.0","highlight(lang, code, ...args) has been deprecated."),ot("10.7.0",`Please use highlight(code, options) instead.
https://github.com/highlightjs/highlight.js/issues/2277`),U=h,k=v),E===void 0&&(E=!0);let ee={code:k,language:U};ke("before:highlight",ee);let ie=ee.result?ee.result:A(ee.language,ee.code,E);return ie.code=ee.code,ke("after:highlight",ie),ie}function A(h,v,E,k){let U=Object.create(null);function ee(g,y){return g.keywords[y]}function ie(){if(!_.keywords){X.addText(L);return}let g=0;_.keywordPatternRe.lastIndex=0;let y=_.keywordPatternRe.exec(L),T="";for(;y;){T+=L.substring(g,y.index);let I=oe.case_insensitive?y[0].toLowerCase():y[0],V=ee(_,I);if(V){let[ce,dt]=V;if(X.addText(T),T="",U[I]=(U[I]||0)+1,U[I]<=Oo&&(He+=dt),ce.startsWith("_"))T+=y[0];else{let Le=oe.classNameAliases[ce]||ce;me(y[0],Le)}}else T+=y[0];g=_.keywordPatternRe.lastIndex,y=_.keywordPatternRe.exec(L)}T+=L.substring(g),X.addText(T)}function Ne(){if(L==="")return;let g=null;if(typeof _.subLanguage=="string"){if(!e[_.subLanguage]){X.addText(L);return}g=A(_.subLanguage,L,!0,Oe[_.subLanguage]),Oe[_.subLanguage]=g._top}else g=O(L,_.subLanguage.length?_.subLanguage:null);_.relevance>0&&(He+=g.relevance),X.__addSublanguage(g._emitter,g.language)}function S(){_.subLanguage!=null?Ne():ie(),L=""}function me(g,y){g!==""&&(X.startScope(y),X.addText(g),X.endScope())}function kt(g,y){let T=1,I=y.length-1;for(;T<=I;){if(!g._emit[T]){T++;continue}let V=oe.classNameAliases[g[T]]||g[T],ce=y[T];V?me(ce,V):(L=ce,ie(),L=""),T++}}function Nt(g,y){return g.scope&&typeof g.scope=="string"&&X.openNode(oe.classNameAliases[g.scope]||g.scope),g.beginScope&&(g.beginScope._wrap?(me(L,oe.classNameAliases[g.beginScope._wrap]||g.beginScope._wrap),L=""):g.beginScope._multi&&(kt(g.beginScope,y),L="")),_=Object.create(g,{parent:{value:_}}),_}function Rt(g,y,T){let I=qi(g.endRe,T);if(I){if(g["on:end"]){let V=new Yt(g);g["on:end"](y,V),V.isMatchIgnored&&(I=!1)}if(I){for(;g.endsParent&&g.parent;)g=g.parent;return g}}if(g.endsWithParent)return Rt(g.parent,y,T)}function sn(g){return _.matcher.regexIndex===0?(L+=g[0],1):(Ze=!0,0)}function on(g){let y=g[0],T=g.rule,I=new Yt(T),V=[T.__beforeBegin,T["on:begin"]];for(let ce of V)if(ce&&(ce(g,I),I.isMatchIgnored))return sn(y);return T.skip?L+=y:(T.excludeBegin&&(L+=y),S(),!T.returnBegin&&!T.excludeBegin&&(L=y)),Nt(T,g),T.returnBegin?0:y.length}function Ot(g){let y=g[0],T=v.substring(g.index),I=Rt(_,g,T);if(!I)return _a;let V=_;_.endScope&&_.endScope._wrap?(S(),me(y,_.endScope._wrap)):_.endScope&&_.endScope._multi?(S(),kt(_.endScope,g)):V.skip?L+=y:(V.returnEnd||V.excludeEnd||(L+=y),S(),V.excludeEnd&&(L=y));do _.scope&&X.closeNode(),!_.skip&&!_.subLanguage&&(He+=_.relevance),_=_.parent;while(_!==I.parent);return I.starts&&Nt(I.starts,g),V.returnEnd?0:y.length}function cn(){let g=[];for(let y=_;y!==oe;y=y.parent)y.scope&&g.unshift(y.scope);g.forEach(y=>X.openNode(y))}let ze={};function z(g,y){let T=y&&y[0];if(L+=g,T==null)return S(),0;if(ze.type==="begin"&&y.type==="end"&&ze.index===y.index&&T===""){if(L+=v.slice(y.index,y.index+1),!a){let I=new Error(`0 width match regex (${h})`);throw I.languageName=h,I.badRule=ze.rule,I}return 1}if(ze=y,y.type==="begin")return on(y);if(y.type==="illegal"&&!E){let I=new Error('Illegal lexeme "'+T+'" for mode "'+(_.scope||"<unnamed>")+'"');throw I.mode=_,I}else if(y.type==="end"){let I=Ot(y);if(I!==_a)return I}if(y.type==="illegal"&&T==="")return y.index===v.length||(L+=`
`),1;if(Xe>1e5&&Xe>y.index*3)throw new Error("potential infinite loop, way more iterations than matches");return L+=T,T.length}let oe=re(h);if(!oe)throw Ge(i.replace("{}",h)),new Error('Unknown language: "'+h+'"');let B=ko(oe),Be="",_=k||B,Oe={},X=new l.__emitter(l);cn();let L="",He=0,ve=0,Xe=0,Ze=!1;try{if(oe.__emitTokens)oe.__emitTokens(v,X);else{for(_.matcher.considerAll();;){Xe++,Ze?Ze=!1:_.matcher.considerAll(),_.matcher.lastIndex=ve;let g=_.matcher.exec(v);if(!g)break;let y=v.substring(ve,g.index),T=z(y,g);ve=g.index+T}z(v.substring(ve))}return X.finalize(),Be=X.toHTML(),{language:h,value:Be,relevance:He,illegal:!1,_emitter:X,_top:_}}catch(g){if(g.message&&g.message.includes("Illegal"))return{language:h,value:In(v),illegal:!0,relevance:0,_illegalBy:{message:g.message,index:ve,context:v.slice(ve-100,ve+100),mode:g.mode,resultSoFar:Be},_emitter:X};if(a)return{language:h,value:In(v),illegal:!1,relevance:0,errorRaised:g,_emitter:X,_top:_};throw g}}function R(h){let v={value:In(h),illegal:!1,relevance:0,_top:o,_emitter:new l.__emitter(l)};return v._emitter.addText(h),v}function O(h,v){v=v||l.languages||Object.keys(e);let E=R(h),k=v.filter(re).filter(ge).map(S=>A(S,h,!1));k.unshift(E);let U=k.sort((S,me)=>{if(S.relevance!==me.relevance)return me.relevance-S.relevance;if(S.language&&me.language){if(re(S.language).supersetOf===me.language)return 1;if(re(me.language).supersetOf===S.language)return-1}return 0}),[ee,ie]=U,Ne=ee;return Ne.secondBest=ie,Ne}function j(h,v,E){let k=v&&n[v]||E;h.classList.add("hljs"),h.classList.add(`language-${k}`)}function H(h){let v=null,E=m(h);if(u(E))return;if(ke("before:highlightElement",{el:h,language:E}),h.dataset.highlighted){console.log("Element previously highlighted. To highlight again, first unset `dataset.highlighted`.",h);return}if(h.children.length>0&&(l.ignoreUnescapedHTML||(console.warn("One of your code blocks includes unescaped HTML. This is a potentially serious security risk."),console.warn("https://github.com/highlightjs/highlight.js/wiki/security"),console.warn("The element with unescaped HTML:"),console.warn(h)),l.throwUnescapedHTML))throw new zn("One of your code blocks includes unescaped HTML.",h.innerHTML);v=h;let k=v.textContent,U=E?b(k,{language:E,ignoreIllegals:!0}):O(k);h.innerHTML=U.value,h.dataset.highlighted="yes",j(h,E,U.language),h.result={language:U.language,re:U.relevance,relevance:U.relevance},U.secondBest&&(h.secondBest={language:U.secondBest.language,relevance:U.secondBest.relevance}),ke("after:highlightElement",{el:h,result:U,text:k})}function $(h){l=va(l,h)}let G=()=>{M(),ot("10.6.0","initHighlighting() deprecated.  Use highlightAll() now.")};function P(){M(),ot("10.6.0","initHighlightingOnLoad() deprecated.  Use highlightAll() now.")}let W=!1;function M(){function h(){M()}if(document.readyState==="loading"){W||window.addEventListener("DOMContentLoaded",h,!1),W=!0;return}document.querySelectorAll(l.cssSelector).forEach(H)}function F(h,v){let E=null;try{E=v(t)}catch(k){if(Ge("Language definition for '{}' could not be registered.".replace("{}",h)),a)Ge(k);else throw k;E=o}E.name||(E.name=h),e[h]=E,E.rawDefinition=v.bind(null,t),E.aliases&&J(E.aliases,{languageName:h})}function K(h){delete e[h];for(let v of Object.keys(n))n[v]===h&&delete n[v]}function pe(){return Object.keys(e)}function re(h){return h=(h||"").toLowerCase(),e[h]||e[n[h]]}function J(h,{languageName:v}){typeof h=="string"&&(h=[h]),h.forEach(E=>{n[E.toLowerCase()]=v})}function ge(h){let v=re(h);return v&&!v.disableAutodetect}function Ue(h){h["before:highlightBlock"]&&!h["before:highlightElement"]&&(h["before:highlightElement"]=v=>{h["before:highlightBlock"](Object.assign({block:v.el},v))}),h["after:highlightBlock"]&&!h["after:highlightElement"]&&(h["after:highlightElement"]=v=>{h["after:highlightBlock"](Object.assign({block:v.el},v))})}function Ye(h){Ue(h),r.push(h)}function Se(h){let v=r.indexOf(h);v!==-1&&r.splice(v,1)}function ke(h,v){let E=h;r.forEach(function(k){k[E]&&k[E](v)})}function xe(h){return ot("10.7.0","highlightBlock will be removed entirely in v12.0"),ot("10.7.0","Please use highlightElement now."),H(h)}Object.assign(t,{highlight:b,highlightAuto:O,highlightAll:M,highlightElement:H,highlightBlock:xe,configure:$,initHighlighting:G,initHighlightingOnLoad:P,registerLanguage:F,unregisterLanguage:K,listLanguages:pe,getLanguage:re,registerAliases:J,autoDetection:ge,inherit:va,addPlugin:Ye,removePlugin:Se}),t.debugMode=function(){a=!1},t.safeMode=function(){a=!0},t.versionString=Ro,t.regex={concat:We,lookahead:Ta,either:Zt,optional:Gi,anyNumberOfTimes:$i};for(let h in Vt)typeof Vt[h]=="object"&&xa(Vt[h]);return Object.assign(t,Vt),t},ct=Ca({});ct.newInstance=()=>Ca({});Ma.exports=ct;ct.HighlightJS=ct;ct.default=ct});var vn=Object.freeze({theme:"auto",lightTheme:"light",darkTheme:"dark",lang:"en",maxSize:2097152,highlightLimit:3e5,maxDepth:512,fetchTimeout:15e3,languagesUrl:"",syntaxTheme:"",syntaxThemeDark:"",syntaxThemesUrl:"",vendorUrl:""}),Js=Object.freeze({maxSize:50*1024*1024,highlightLimit:5*1024*1024,maxDepth:1e4,fetchTimeout:12e4}),st={...vn},_n=new Set;function le(){return Object.freeze({...st})}function Qs(t){if(!t||typeof t!="object")return le();let e={...st};for(let[r,a]of Object.entries(t))ei(r,a);let n=new Set(Object.keys(st).filter(r=>st[r]!==e[r]));if(n.size)for(let r of _n)r(n);return le()}function ei(t,e){if(!Object.prototype.hasOwnProperty.call(vn,t)){console.warn(`[vitrine] Unknown configuration option "${t}".`);return}let n=t;if(typeof vn[n]==="number"){let a=Js[n];if(typeof e!="number"||!Number.isFinite(e)||e<=0){console.warn(`[vitrine] Option "${t}" must be a positive number.`);return}st[n]=Math.min(Math.floor(e),a??e);return}if(typeof e!="string"||e.length>2048){console.warn(`[vitrine] Option "${t}" must be a string.`);return}st[n]=e.trim()}function vr(t){return _n.add(t),()=>_n.delete(t)}var we=Object.freeze({READY:"vt-ready",COPY:"vt-copy",SEARCH:"vt-search",TAB_CHANGE:"vt-tab-change",INPUT:"vt-input",CHANGE:"vt-change",MODE_CHANGE:"vt-mode-change",TAG_ADD:"vt-tag-add",TAG_REMOVE:"vt-tag-remove",TAG_CREATE:"vt-tag-create",TAG_CLICK:"vt-tag-click",SORT:"vt-sort",FULLSCREEN_CHANGE:"vt-fullscreen-change",LAYOUT_CHANGE:"vt-layout-change",SELECT:"vt-select",TOGGLE:"vt-toggle",FILTER_CHANGE:"vt-filter-change",TYPING_END:"vt-typing-end",CHANGE_NAVIGATE:"vt-change-navigate",STEP_TOGGLE:"vt-step-toggle",JOB_CHANGE:"vt-job-change",MATCH:"vt-match",BULK_ACTION:"vt-bulk-action",CELL_EDIT:"vt-cell-edit",COLUMN_CHANGE:"vt-column-change",ROW_ACTIVATE:"vt-row-activate",ERROR:"vt-error"});function Re(t,e,n){return t.dispatchEvent(new CustomEvent(e,{detail:n,bubbles:!0,composed:!0,cancelable:!0}))}var En=Object.freeze({copy:"Copy",copyCode:"Copy code",copied:"Copied",copyFailed:"Copy failed",copySource:"Copy source",download:"Download",search:"Search",searchPlaceholder:"Search\u2026",searchNext:"Next match",searchPrevious:"Previous match",searchClose:"Close search",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"No matches",searchResults:"{total} matches",wrap:"Toggle line wrap",showMore:"Show all {count} lines",preview:"Preview",source:"Source",split:"Split",swapPanes:"Swap panes",stackPanes:"Stack panes",syncScroll:"Sync scrolling",tabs:"View",actions:"Actions",toc:"Table of contents",anchor:"Link to this section",table:"Table",tree:"Tree",raw:"Raw",expandAll:"Expand all",collapseAll:"Collapse all",copyPath:"Copy path",copyValue:"Copy value",items:"{count} items",item:"1 item",keys:"{count} keys",key:"1 key",showMoreItems:"Show {count} more",showFullString:"Show full string ({count} characters)",truncated:"Partially expanded: too many nodes.",loading:"Loading\u2026",errorTitle:"Unable to display content",invalidJson:"Invalid JSON at line {line}, column {column}: {message}.",invalidJsonRaw:"Invalid JSON at line {line}, column {column} \u2014 showing raw text.",empty:"Nothing to display",tooLarge:"Content is too large ({size} characters, limit {limit}).",tooDeep:"Nesting is too deep (limit {limit}).",tooComplex:"This document is nested too deeply to display.",unserializable:"This value cannot be converted to JSON (circular reference or BigInt).",highlightSkipped:"Content is large: syntax highlighting is disabled.",loadFailed:'Could not load "{url}": {reason}',remoteBlocked:'Cross-origin URL blocked. Add the "allow-remote" attribute to allow it.',unsafeUrl:"URL blocked: only http(s) URLs can be loaded.",timeout:"Request timed out.",added:"Added",removed:"Removed",code:"Code",edit:"Edit",splitView:"Side by side",unifiedView:"Unified",diffStats:"+{added} \u2212{removed}",diffSimplified:"Many changes: the comparison is simplified to removed and added blocks.",noDifferences:"No differences",previousChange:"Previous change",nextChange:"Next change",changePosition:"{current} of {total}",changeTotal:"{count} changes",terminal:"Terminal",command:"Command",copyCommand:"Copy command",copyCommands:"Copy commands",replay:"Replay",showMoreLines:"Show {count} more lines",files:"Files",copyTree:"Copy tree",treeStats:"{folders} folders, {files} files",invalidTree:"This tree could not be read: {message}",treeTruncated:"Only the first {limit} entries are shown.",status_added:"added",status_removed:"removed",status_modified:"modified",status_highlighted:"highlighted",httpExchange:"Exchange",httpRequest:"Request",httpResponse:"Response",httpBody:"Body",httpHeaders:"Headers",httpQuery:"Query",httpNone:"None",httpNoBody:"No body",copyUrl:"Copy URL",codeLanguage:"Language",showSecrets:"Show secrets",hideSecrets:"Hide secrets",secretsShown:"Secrets shown",secretsHidden:"Secrets hidden",secretsInCode:"Credentials are masked in this code. Replace them with your own.",invalidHttp:"This HTTP message could not be read: {message}",log:"Log",followLog:"Follow new lines",levelToggle:"Show or hide {level} entries",logNoMatch:"No entry matches the filters.",chartView:"Chart",legend:"Legend",seriesToggle:"Show or hide {name}",copyData:"Copy data",chartSummary:"{type} with {series} series and {points} points.",chartRange:"{name} from {min} to {max}",chart_line:"Line chart",chart_area:"Area chart",chart_bar:"Bar chart",chart_pie:"Donut chart",chartError:"This data could not be charted: {message}",chartTruncated:"Only the first 5,000 points of each series are shown.",chartLoadFailed:"The chart library could not be loaded: {message}",openapiInvalid:"This API description could not be read: {message}",openapiYamlFailed:"The YAML reader could not be loaded: {message}",openapiTruncated:"Only the first 2,000 endpoints are shown.",openapiServers:"Servers",openapiAuth:"Authentication",openapiEndpoints:"Endpoints",openapiTags:"Tags",openapiAllTags:"All",openapiNoMatch:"No endpoint matches.",openapiDeprecated:"deprecated",openapiParameters:"Parameters",openapiName:"Name",openapiIn:"In",openapiType:"Type",openapiDescription:"Description",openapiRequired:"required",openapiRequestBody:"Request body",openapiResponses:"Responses",openapiExample:"Example",openapiExampleValue:"Example",unchangedLines:"Show {count} unchanged lines",copyPatch:"Copy patch",changes:"Changes",original:"Original",modified:"Modified",patch:"Patch",tags:"Tags",noTags:"No tags",addTag:"Add a tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:'Create "{tag}"',removeTag:"Remove {tag}",tagAdded:"{tag} added",tagRemoved:"{tag} removed",pressAgainToRemove:"Press Backspace again to remove {tag}",tagDuplicate:"{tag} is already selected.",tagDisabled:"{tag} cannot be selected.",tagLimit:"You can select up to {max} tags.",tagNotAllowed:"{tag} is not in the list.",tagTooLong:"{tag} is too long.",tagInvalid:"{tag} is not a valid tag.",tagRefused:"{tag} was refused.",tagsRequired:"Select at least one tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Browse all tags",otherTags:"Other",clearTags:"Remove all tags",filterTags:"Filter tags",tagsFound:"{count} tags",invalidTags:'The tags must be a JSON array, or an object with "value" and "options".',rowsRange:"Rows {from}\u2013{to} of {total}",noRows:"No rows",firstPage:"First page",previousPage:"Previous page",nextPage:"Next page",lastPage:"Last page",sortBy:"Sort by {name}",column:"Column {n}",rowNumber:"Row",csvStatus:"{rows} rows \xD7 {columns} columns",csvUnclosed:"Unclosed quote starting at line {line}.",tooManyColumns:"Only the first {limit} columns are shown.",matchingRows:"{count} matching rows",undo:"Undo",redo:"Redo",fullscreen:"Full screen",exitFullscreen:"Exit full screen",stopEditing:"Stop editing",editor:"Editor",validJson:"Valid JSON"}),ti=Object.freeze({copy:"Copier",copyCode:"Copier le code",copied:"Copi\xE9",copyFailed:"\xC9chec de la copie",copySource:"Copier la source",download:"T\xE9l\xE9charger",search:"Rechercher",searchPlaceholder:"Rechercher\u2026",searchNext:"R\xE9sultat suivant",searchPrevious:"R\xE9sultat pr\xE9c\xE9dent",searchClose:"Fermer la recherche",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"Aucun r\xE9sultat",searchResults:"{total} r\xE9sultats",wrap:"Activer/d\xE9sactiver le retour \xE0 la ligne",showMore:"Afficher les {count} lignes",preview:"Aper\xE7u",source:"Source",split:"C\xF4te \xE0 c\xF4te",swapPanes:"Inverser les panneaux",stackPanes:"Empiler les panneaux",syncScroll:"Synchroniser le d\xE9filement",tabs:"Affichage",actions:"Actions",toc:"Table des mati\xE8res",anchor:"Lien vers cette section",table:"Tableau",tree:"Arbre",raw:"Brut",expandAll:"Tout d\xE9plier",collapseAll:"Tout replier",copyPath:"Copier le chemin",copyValue:"Copier la valeur",items:"{count} \xE9l\xE9ments",item:"1 \xE9l\xE9ment",keys:"{count} cl\xE9s",key:"1 cl\xE9",showMoreItems:"Afficher {count} de plus",showFullString:"Afficher toute la cha\xEEne ({count} caract\xE8res)",truncated:"D\xE9pliage partiel : trop de n\u0153uds.",loading:"Chargement\u2026",errorTitle:"Impossible d\u2019afficher le contenu",invalidJson:"JSON invalide \xE0 la ligne {line}, colonne {column} : {message}.",invalidJsonRaw:"JSON invalide \xE0 la ligne {line}, colonne {column} \u2014 affichage du texte brut.",empty:"Rien \xE0 afficher",tooLarge:"Contenu trop volumineux ({size} caract\xE8res, limite {limit}).",tooDeep:"Imbrication trop profonde (limite {limit}).",tooComplex:"Ce document est trop imbriqu\xE9 pour \xEAtre affich\xE9.",unserializable:"Cette valeur ne peut pas \xEAtre convertie en JSON (r\xE9f\xE9rence circulaire ou BigInt).",highlightSkipped:"Contenu volumineux : coloration syntaxique d\xE9sactiv\xE9e.",loadFailed:"Impossible de charger \xAB {url} \xBB : {reason}",remoteBlocked:"URL d\u2019une autre origine bloqu\xE9e. Ajoutez l\u2019attribut \xAB allow-remote \xBB pour l\u2019autoriser.",unsafeUrl:"URL bloqu\xE9e : seules les URL http(s) peuvent \xEAtre charg\xE9es.",timeout:"D\xE9lai de la requ\xEAte d\xE9pass\xE9.",added:"Ajout\xE9",removed:"Supprim\xE9",code:"Code",edit:"Modifier",splitView:"C\xF4te \xE0 c\xF4te",unifiedView:"Unifi\xE9",diffStats:"+{added} \u2212{removed}",diffSimplified:"Beaucoup de changements : la comparaison est simplifi\xE9e en blocs retir\xE9s et ajout\xE9s.",noDifferences:"Aucune diff\xE9rence",previousChange:"Modification pr\xE9c\xE9dente",nextChange:"Modification suivante",changePosition:"{current} sur {total}",changeTotal:"Modifications : {count}",terminal:"Terminal",command:"Commande",copyCommand:"Copier la commande",copyCommands:"Copier les commandes",replay:"Rejouer",showMoreLines:"Afficher {count} lignes de plus",files:"Fichiers",copyTree:"Copier l'arborescence",treeStats:"{folders} dossiers, {files} fichiers",invalidTree:"Impossible de lire cette arborescence : {message}",treeTruncated:"Seules les {limit} premi\xE8res entr\xE9es sont affich\xE9es.",status_added:"ajout\xE9",status_removed:"supprim\xE9",status_modified:"modifi\xE9",status_highlighted:"mis en \xE9vidence",httpExchange:"\xC9change",httpRequest:"Requ\xEAte",httpResponse:"R\xE9ponse",httpBody:"Corps",httpHeaders:"En-t\xEAtes",httpQuery:"Param\xE8tres",httpNone:"Aucun",httpNoBody:"Pas de corps",copyUrl:"Copier l'URL",codeLanguage:"Langage",showSecrets:"Afficher les secrets",hideSecrets:"Masquer les secrets",secretsShown:"Secrets affich\xE9s",secretsHidden:"Secrets masqu\xE9s",secretsInCode:"Les identifiants sont masqu\xE9s dans ce code. Remplacez-les par les v\xF4tres.",invalidHttp:"Impossible de lire ce message HTTP : {message}",log:"Journal",followLog:"Suivre les nouvelles lignes",levelToggle:"Afficher ou masquer les entr\xE9es {level}",logNoMatch:"Aucune entr\xE9e ne correspond aux filtres.",chartView:"Graphique",legend:"L\xE9gende",seriesToggle:"Afficher ou masquer {name}",copyData:"Copier les donn\xE9es",chartSummary:"{type} avec {series} s\xE9ries et {points} points.",chartRange:"{name} de {min} \xE0 {max}",chart_line:"Graphique en courbes",chart_area:"Graphique en aires",chart_bar:"Graphique en barres",chart_pie:"Graphique en anneau",chartError:"Impossible de tracer ces donn\xE9es : {message}",chartTruncated:"Seuls les 5 000 premiers points de chaque s\xE9rie sont affich\xE9s.",chartLoadFailed:"Impossible de charger la biblioth\xE8que de graphiques : {message}",openapiInvalid:"Impossible de lire cette description d\u2019API : {message}",openapiYamlFailed:"Impossible de charger le lecteur YAML : {message}",openapiTruncated:"Seuls les 2 000 premiers points d\u2019acc\xE8s sont affich\xE9s.",openapiServers:"Serveurs",openapiAuth:"Authentification",openapiEndpoints:"Points d\u2019acc\xE8s",openapiTags:"Tags",openapiAllTags:"Tous",openapiNoMatch:"Aucun point d\u2019acc\xE8s ne correspond.",openapiDeprecated:"obsol\xE8te",openapiParameters:"Param\xE8tres",openapiName:"Nom",openapiIn:"Emplacement",openapiType:"Type",openapiDescription:"Description",openapiRequired:"requis",openapiRequestBody:"Corps de la requ\xEAte",openapiResponses:"R\xE9ponses",openapiExample:"Exemple",openapiExampleValue:"Exemple",unchangedLines:"Afficher {count} lignes inchang\xE9es",copyPatch:"Copier le patch",changes:"Modifications",original:"Original",modified:"Modifi\xE9",patch:"Patch",tags:"Tags",noTags:"Aucun tag",addTag:"Ajouter un tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:"Cr\xE9er \xAB {tag} \xBB",removeTag:"Retirer {tag}",tagAdded:"{tag} ajout\xE9",tagRemoved:"{tag} retir\xE9",pressAgainToRemove:"Appuyez de nouveau sur Retour arri\xE8re pour retirer {tag}",tagDuplicate:"{tag} est d\xE9j\xE0 s\xE9lectionn\xE9.",tagDisabled:"{tag} ne peut pas \xEAtre s\xE9lectionn\xE9.",tagLimit:"Vous pouvez s\xE9lectionner jusqu\u2019\xE0 {max} tags.",tagNotAllowed:"{tag} n\u2019est pas dans la liste.",tagTooLong:"{tag} est trop long.",tagInvalid:"{tag} n\u2019est pas un tag valide.",tagRefused:"{tag} a \xE9t\xE9 refus\xE9.",tagsRequired:"S\xE9lectionnez au moins un tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Parcourir tous les tags",otherTags:"Autres",clearTags:"Retirer tous les tags",filterTags:"Filtrer les tags",tagsFound:"{count} tags",invalidTags:"Les tags doivent \xEAtre un tableau JSON, ou un objet avec \xAB value \xBB et \xAB options \xBB.",rowsRange:"Lignes {from}\u2013{to} sur {total}",noRows:"Aucune ligne",firstPage:"Premi\xE8re page",previousPage:"Page pr\xE9c\xE9dente",nextPage:"Page suivante",lastPage:"Derni\xE8re page",sortBy:"Trier par {name}",column:"Colonne {n}",rowNumber:"Ligne",csvStatus:"{rows} lignes \xD7 {columns} colonnes",csvUnclosed:"Guillemet non ferm\xE9 \xE0 partir de la ligne {line}.",tooManyColumns:"Seules les {limit} premi\xE8res colonnes sont affich\xE9es.",matchingRows:"{count} lignes correspondantes",undo:"Annuler",redo:"R\xE9tablir",fullscreen:"Plein \xE9cran",exitFullscreen:"Quitter le plein \xE9cran",stopEditing:"Terminer la modification",editor:"\xC9diteur",validJson:"JSON valide"}),xr={},_r=new Map;var Ft=new Map([["en",En],["fr",ti]]);function ni(t,e){if(typeof t!="string"||!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(t))throw new TypeError(`[vitrine] Invalid locale code "${t}".`);let n={};for(let[r,a]of Object.entries(e??{}))(Object.prototype.hasOwnProperty.call(En,r)||Object.prototype.hasOwnProperty.call(xr,r))&&typeof a=="string"&&(n[r]=a.slice(0,500));Ft.set(t,Object.freeze({...Ft.get(t)??{},...n}));for(let r of xn)r()}var xn=new Set;function Er(t){return xn.add(t),()=>xn.delete(t)}function Tn(t){let e=Ft.get(t),n=Ft.get(String(t).split("-")[0]);return(r,a)=>{let i=String(t).split("-")[0],o=e?.[r]??n?.[r]??_r.get(t)?.[r]??_r.get(i)?.[r]??En[r]??xr[r]??String(r);return a?o.replace(/\{(\w+)\}/g,(l,u)=>Object.prototype.hasOwnProperty.call(a,u)?String(a[u]):l):o}}function Tr(t,e){try{return new Intl.NumberFormat(e).format(t)}catch{return String(t)}}var wr=`/* Vitrine Light \u2014 default light theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
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
`;var Ar=`/* Vitrine Dark \u2014 default dark theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
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
`;var Sr=`/* Vitrine Dim \u2014 softer, blue-grey dark theme for long reading sessions. */
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
`;var kr=`/* Vitrine Paper \u2014 warm, low-glare light theme. */
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
`;var Nr=`/* Vitrine High Contrast \u2014 maximum legibility (WCAG AAA text contrast). */
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
`;var ci=Object.freeze(["bg","surface","surface-sunken","surface-raised","border","border-strong","fg","fg-muted","accent","accent-fg","on-accent","accent-soft","highlight","highlight-current","line-highlight","success","warning","danger","info","diff-added","diff-removed","shadow","syntax-keyword","syntax-string","syntax-number","syntax-function","syntax-type","syntax-comment","syntax-attr","syntax-tag","syntax-meta"]),Ae=new Map,je=new CSSStyleSheet,li=/^[a-z][a-z0-9-]{0,39}$/,ui=new Set(["auto"]);function di(t){let e=/\[data-theme='([a-z0-9-]+)'\]/.exec(t)?.[1];if(!e)throw new Error("[vitrine] Theme file without a [data-theme] selector.");let n=/color-scheme:\s*(light|dark)\s*;/.exec(t)?.[1]==="dark"?"dark":"light",r={};for(let[,a,i]of t.matchAll(/--vt-([a-z0-9-]+)\s*:\s*([^;]+);/g))r[a]=i.trim();return{name:e,definition:{colorScheme:n,tokens:r}}}for(let t of[wr,Ar,Sr,kr,Nr]){let{name:e,definition:n}=di(t);Ae.set(e,n)}var hi=Object.freeze([...Ae.keys()]);function fi(t){return typeof t!="string"||t.length===0||t.length>200||/[;{}<>\\]/.test(t)?!1:!/(?:url|image|image-set|cross-fade|element|src)\s*\(|@import|expression/i.test(t)}function pi(t,e={}){if(typeof t!="string"||!li.test(t)||ui.has(t))throw new TypeError(`[vitrine] Invalid theme name "${t}". Use lowercase letters, digits, "-".`);let n=e.colorScheme==="dark"?"dark":e.colorScheme==="light"?"light":void 0,r=e.extends??(n==="dark"?"dark":"light"),a=Ae.get(r);if(!a)throw new TypeError(`[vitrine] Unknown base theme "${r}".`);let i={...a.tokens};for(let[o,l]of Object.entries(e.tokens??{})){let u=o.replace(/^--vt-/,"");ci.includes(u)?fi(l)?i[u]=l.trim():console.warn(`[vitrine] Unsafe or invalid value for theme token "${o}" ignored.`):console.warn(`[vitrine] Unknown theme token "${o}" ignored.`)}return Ae.set(t,{colorScheme:n??a.colorScheme,tokens:i}),Rr(),Or(),t}function gi(){return[...Ae.keys()]}function Sn(t){let e=Ae.get(t);return e?{colorScheme:e.colorScheme,tokens:{...e.tokens}}:void 0}function Rr(){for(;je.cssRules.length;)je.deleteRule(0);for(let[t,e]of Ae){let n=je.insertRule(`.vt[data-theme="${t}"] {}`,je.cssRules.length),r=je.cssRules[n].style;r.setProperty("color-scheme",e.colorScheme);for(let[a,i]of Object.entries(e.tokens))r.setProperty(`--_${a}`,`var(--vt-${a}, ${i})`)}}Rr();var wn=typeof matchMedia=="function"?matchMedia("(prefers-color-scheme: dark)"):null,An=new Set;function Or(){for(let t of An)t()}wn?.addEventListener?.("change",Or);function Lr(t){return An.add(t),()=>An.delete(t)}function Cr(t){let e=le(),n=t?.trim().toLowerCase()||e.theme;if(n!=="auto"&&!Ae.has(n)&&(n=Ae.has(e.theme)?e.theme:"auto"),n!=="auto")return n;let r=wn?.matches?e.darkTheme:e.lightTheme;return Ae.has(r)?r:wn?.matches?"dark":"light"}var Mr="",Ir="",Dr="";function kn(t){Mr=t}function Pr(){return Mr}function Ur(t){Dr=t}function Kc(){return Dr}function Nn(t){Ir=t}function zr(){return Ir}var Rn=Object.freeze({"1c-light":0,"a11y-dark":1,"a11y-light":0,agate:1,"an-old-hope":1,androidstudio:1,"arduino-light":0,arta:1,ascetic:0,"atom-one-dark":1,"atom-one-dark-reasonable":1,"atom-one-light":0,"base16-3024":1,"base16-apathy":1,"base16-apprentice":1,"base16-ashes":1,"base16-atelier-cave":1,"base16-atelier-cave-light":0,"base16-atelier-dune":1,"base16-atelier-dune-light":0,"base16-atelier-estuary":1,"base16-atelier-estuary-light":0,"base16-atelier-forest":1,"base16-atelier-forest-light":0,"base16-atelier-heath":1,"base16-atelier-heath-light":0,"base16-atelier-lakeside":1,"base16-atelier-lakeside-light":0,"base16-atelier-plateau":1,"base16-atelier-plateau-light":0,"base16-atelier-savanna":1,"base16-atelier-savanna-light":0,"base16-atelier-seaside":1,"base16-atelier-seaside-light":0,"base16-atelier-sulphurpool":1,"base16-atelier-sulphurpool-light":0,"base16-atlas":1,"base16-bespin":1,"base16-black-metal":1,"base16-black-metal-bathory":1,"base16-black-metal-burzum":1,"base16-black-metal-dark-funeral":1,"base16-black-metal-gorgoroth":1,"base16-black-metal-immortal":1,"base16-black-metal-khold":1,"base16-black-metal-marduk":1,"base16-black-metal-mayhem":1,"base16-black-metal-nile":1,"base16-black-metal-venom":1,"base16-brewer":1,"base16-bright":1,"base16-brogrammer":1,"base16-brush-trees":0,"base16-brush-trees-dark":1,"base16-chalk":1,"base16-circus":1,"base16-classic-dark":1,"base16-classic-light":0,"base16-codeschool":1,"base16-colors":1,"base16-cupcake":0,"base16-cupertino":0,"base16-danqing":1,"base16-darcula":1,"base16-dark-violet":1,"base16-darkmoss":1,"base16-darktooth":1,"base16-decaf":1,"base16-default-dark":1,"base16-default-light":0,"base16-dirtysea":0,"base16-dracula":1,"base16-edge-dark":1,"base16-edge-light":0,"base16-eighties":1,"base16-embers":1,"base16-equilibrium-dark":1,"base16-equilibrium-gray-dark":1,"base16-equilibrium-gray-light":0,"base16-equilibrium-light":0,"base16-espresso":1,"base16-eva":1,"base16-eva-dim":1,"base16-flat":1,"base16-framer":1,"base16-fruit-soda":0,"base16-gigavolt":1,"base16-github":0,"base16-google-dark":1,"base16-google-light":0,"base16-grayscale-dark":1,"base16-grayscale-light":0,"base16-green-screen":1,"base16-gruvbox-dark-hard":1,"base16-gruvbox-dark-medium":1,"base16-gruvbox-dark-pale":1,"base16-gruvbox-dark-soft":1,"base16-gruvbox-light-hard":0,"base16-gruvbox-light-medium":0,"base16-gruvbox-light-soft":0,"base16-hardcore":1,"base16-harmonic16-dark":1,"base16-harmonic16-light":0,"base16-heetch-dark":1,"base16-heetch-light":0,"base16-helios":1,"base16-hopscotch":1,"base16-horizon-dark":1,"base16-horizon-light":0,"base16-humanoid-dark":1,"base16-humanoid-light":0,"base16-ia-dark":1,"base16-ia-light":0,"base16-icy-dark":1,"base16-ir-black":1,"base16-isotope":1,"base16-kimber":1,"base16-london-tube":1,"base16-macintosh":1,"base16-marrakesh":1,"base16-materia":1,"base16-material":1,"base16-material-darker":1,"base16-material-lighter":0,"base16-material-palenight":1,"base16-material-vivid":1,"base16-mellow-purple":1,"base16-mexico-light":0,"base16-mocha":1,"base16-monokai":1,"base16-nebula":1,"base16-nord":1,"base16-nova":1,"base16-ocean":1,"base16-oceanicnext":1,"base16-one-light":0,"base16-onedark":1,"base16-outrun-dark":1,"base16-papercolor-dark":1,"base16-papercolor-light":0,"base16-paraiso":1,"base16-pasque":1,"base16-phd":1,"base16-pico":1,"base16-pop":1,"base16-porple":1,"base16-qualia":1,"base16-railscasts":1,"base16-rebecca":1,"base16-ros-pine":1,"base16-ros-pine-dawn":0,"base16-ros-pine-moon":1,"base16-sagelight":0,"base16-sandcastle":1,"base16-seti-ui":1,"base16-shapeshifter":0,"base16-silk-dark":1,"base16-silk-light":0,"base16-snazzy":1,"base16-solar-flare":1,"base16-solar-flare-light":0,"base16-solarized-dark":1,"base16-solarized-light":0,"base16-spacemacs":1,"base16-summercamp":1,"base16-summerfruit-dark":1,"base16-summerfruit-light":0,"base16-synth-midnight-terminal-dark":1,"base16-synth-midnight-terminal-light":0,"base16-tango":1,"base16-tender":1,"base16-tomorrow":0,"base16-tomorrow-night":1,"base16-twilight":1,"base16-unikitty-dark":1,"base16-unikitty-light":0,"base16-vulcan":1,"base16-windows-10":1,"base16-windows-10-light":0,"base16-windows-95":1,"base16-windows-95-light":0,"base16-windows-high-contrast":1,"base16-windows-high-contrast-light":0,"base16-windows-nt":1,"base16-windows-nt-light":0,"base16-woodland":1,"base16-xcode-dusk":1,"base16-zenburn":1,"brown-paper":0,"codepen-embed":1,"color-brewer":0,"cybertopia-cherry":0,"cybertopia-dimmer":0,"cybertopia-icecap":0,"cybertopia-saturated":0,dark:1,default:0,devibeans:1,docco:0,equinox:0,far:1,felipec:1,foundation:0,github:0,"github-dark":1,"github-dark-dimmed":1,gml:1,googlecode:0,"gradient-dark":1,"gradient-light":0,grayscale:0,hybrid:1,idea:0,"intellij-light":0,"ir-black":1,"isbl-editor-dark":1,"isbl-editor-light":0,"kimbie-dark":1,"kimbie-light":0,lightfair:0,lioshi:1,magula:0,"mono-blue":0,monokai:1,"monokai-sublime":1,"night-owl":1,"nnfx-dark":1,"nnfx-light":0,nord:1,obsidian:1,"panda-syntax-dark":1,"panda-syntax-light":0,"paraiso-dark":1,"paraiso-light":0,pojoaque:0,purebasic:0,"qtcreator-dark":1,"qtcreator-light":0,rainbow:1,"rose-pine":1,"rose-pine-dawn":0,"rose-pine-moon":1,routeros:0,"school-book":0,"shades-of-purple":1,srcery:1,"stackoverflow-dark":1,"stackoverflow-light":0,sunburst:1,"tokyo-night-dark":1,"tokyo-night-light":0,"tomorrow-night-blue":1,"tomorrow-night-bright":1,vs:0,"vs-dark":1,vs2015:1,xcode:0,xt256:1});var On=new Map,Br=new Map;function Hr(t){if(typeof t!="string")return null;let e=t.trim().toLowerCase().replace(/\//g,"-");return!e||e.length>60?null:Object.prototype.hasOwnProperty.call(Rn,e)?e:null}function mi(){return Object.keys(Rn)}function Fr(t){return Br.get(t)}function jr(t){let e=On.get(t);if(e)return e;let n=bi(t);return On.set(t,n),n}async function bi(t){let e=le().syntaxThemesUrl||zr();if(!e)return null;try{let n=new URL(`${t}.css`,new URL(e.endsWith("/")?e:`${e}/`,document.baseURI));if(n.protocol!=="https:"&&n.protocol!=="http:")return null;let r=await fetch(n.href,{credentials:"same-origin"});if(!r.ok)throw new Error(`HTTP ${r.status}`);let a=await r.text(),i=new CSSStyleSheet;return i.replaceSync(a),Br.set(t,i),i}catch(n){return console.warn(`[vitrine] Could not load the "${t}" syntax theme.`,n),On.delete(t),null}}function tl(t){kn(new URL("languages/",t).href),Nn(new URL("syntax-themes/",t).href),Ur(new URL("vendor/",t).href)}var $r=`/*
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
`;var dl=`/*
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
`;function it(t){if(t===null)return null;let e=t.trim().toLowerCase();return!(e==="false"||e==="off"||e==="no"||e==="0")}function hl(t,{min:e,max:n,fallback:r}){if(t===null||t.length>32)return r;let a=t.trim();if(!/^[+-]?\d+$/.test(a))return r;let i=Number(a);return Number.isSafeInteger(i)?Math.min(n,Math.max(e,i)):r}function Ln(t,e,n){if(t===null)return n;let r=t.trim().toLowerCase();return e.includes(r)?r:n}function fl(t,e){if(t===null||t.length>1e3)return null;let n=[];for(let r of t.split(",")){let a=r.trim().toLowerCase();e.includes(a)&&!n.includes(a)&&n.push(a)}return n.length?n:null}var _i=500;function pl(t){if(!t||t.length>1e3*10)return[];let e=[];for(let r of t.split(",")){if(e.length>=_i)break;let a=/^\s*(\d{1,9})\s*(?:-\s*(\d{1,9})\s*)?$/.exec(r);if(!a)continue;let i=Number(a[1]),o=a[2]===void 0?i:Number(a[2]);e.push([Math.min(i,o),Math.max(i,o)])}e.sort((r,a)=>r[0]-a[0]);let n=[];for(let r of e){let a=n[n.length-1];a&&r[0]<=a[1]+1?a[1]=Math.max(a[1],r[1]):n.push([r[0],r[1]])}return n}function Gr(t,e){let n=0,r=e.length-1;for(;n<=r;){let a=n+r>>1,[i,o]=e[a];if(t<i)r=a-1;else if(t>o)n=a+1;else return!0}return!1}function Wr(t){if(t===null)return null;let e=t.trim().toLowerCase();return/^\d{1,6}(?:\.\d{1,4})?(?:px|em|rem|vh|svh|lvh|dvh|%|ch|lh)$/.test(e)?e:null}function qr(t,e=200){if(!t)return"";let r=t.slice(0,e*4).replace(/[\u0000-\u001f\u007f-\u009f]/g,"").replace(/\s+/g," ").trim();return r.length>e?r.slice(0,e-1)+"\u2026":r}function Kr(t,e){let n=(t??"").split(/[\\/]/).pop()??"",r=/[\u0000-\u001f\u007f<>:"|?*]/g;return n.replace(r,"").replace(/^[.\s]+/,"").trim().slice(0,120)||e}function w(t,e={},...n){let r=document.createElement(t);if(e.class&&(r.className=e.class),e.part&&r.setAttribute("part",e.part),e.attrs)for(let[a,i]of Object.entries(e.attrs))i===!1||i===null||i===void 0||r.setAttribute(a,i===!0?"":String(i));if(e.text!==void 0&&(r.textContent=e.text),e.on)for(let[a,i]of Object.entries(e.on))r.addEventListener(a,i);return xi(r,n),r}function xi(t,e){for(let n of e)n==null||n===!1||t.append(typeof n=="string"?document.createTextNode(n):n)}var Vr=0;function Yr(t){return Vr+=1,`vt-${t}-${Vr}`}function jt(t){let e=t.replace(/\r\n?/g,`
`).split(`
`);for(;e.length&&e[0].trim()==="";)e.shift();for(;e.length&&e[e.length-1].trim()==="";)e.pop();let n=1/0;for(let r of e){if(r.trim()==="")continue;let a=/^[ \t]*/.exec(r);if(n=Math.min(n,a?a[0].length:0),n===0)break}return!Number.isFinite(n)||n===0?e.join(`
`):e.map(r=>r.slice(n)).join(`
`)}function Xr(t,e){let n,r=(...a)=>{clearTimeout(n),n=setTimeout(()=>t(...a),e)};return r.cancel=()=>clearTimeout(n),r}var Ei=new Set(["http:","https:","mailto:","tel:"]),Ti=/^data:image\/(?:png|gif|jpe?g|webp|avif);base64,[a-z0-9+/]+=*$/i;function pt(t,e={}){if(typeof t!="string")return!1;let n=t.replace(/^[\u0000- ]+|[\u0000- ]+$/g,"").replace(/[\t\n\r]/g,"");if(n===""||e.allowDataImage&&Ti.test(n))return!0;let r=/^([a-z][a-z0-9+.-]*):/i.exec(n);return r?Ei.has(r[1].toLowerCase()+":"):!0}function gt(t){try{return new URL(t,document.baseURI).origin===location.origin}catch{return!1}}var se=class extends Error{constructor(e,n={},r){super(e,r===void 0?void 0:{cause:r}),this.name="VitrineError",this.code=e,this.params=n}},wi=new Set(["text/plain","text/markdown","text/x-markdown","application/json","text/json","application/xml","text/xml"]);function Zr(t){for(let r of Array.from(t.children)){let a=Ai(r);if(a!==null)return a}let e="";for(let r of Array.from(t.childNodes))r.nodeType===Node.TEXT_NODE||r.nodeType===Node.CDATA_SECTION_NODE?e+=r.nodeValue??"":r.nodeType===Node.ELEMENT_NODE&&(e+=r.textContent??"");let n=jt(e);return n===""?null:n}function Ai(t){if(t instanceof HTMLTemplateElement){let e=t.content.children.length>0;return jt(e?t.innerHTML:t.content.textContent??"")}return t instanceof HTMLScriptElement&&wi.has(t.type.trim().toLowerCase())?jt(t.textContent??""):null}function $t(t,e){if(t.length>e)throw new se("tooLarge",{size:t.length,limit:e})}async function Jr(t,e){let n=Si(t),r=gt(n.href);if(!r&&!e.allowRemote)throw new se("remoteBlocked");let a=new AbortController,i=setTimeout(()=>a.abort(new se("timeout")),e.timeout),o=()=>a.abort(e.signal?.reason);e.signal?.addEventListener("abort",o,{once:!0}),e.signal?.aborted&&o();try{let l=await fetch(n.href,{mode:r?"same-origin":"cors",credentials:"same-origin",redirect:"follow",referrerPolicy:"strict-origin-when-cross-origin",signal:a.signal});if(!l.ok)throw new se("loadFailed",{url:Qr(n),reason:`HTTP ${l.status}`});let u=Number(l.headers.get("content-length"));if(Number.isFinite(u)&&u>e.maxSize*4)throw new se("tooLarge",{size:u,limit:e.maxSize});return await ki(l,e.maxSize,a)}catch(l){throw Ni(l,a.signal,n)}finally{clearTimeout(i),e.signal?.removeEventListener("abort",o)}}function Si(t){let e;try{e=new URL(t.trim(),document.baseURI)}catch{throw new se("unsafeUrl")}if(e.protocol!=="http:"&&e.protocol!=="https:")throw new se("unsafeUrl");return e}async function ki(t,e,n){if(!t.body){let o=await t.text();return $t(o,e),o}let r=t.body.getReader(),a=new TextDecoder,i="";for(;;){let{done:o,value:l}=await r.read();if(o)break;if(i+=a.decode(l,{stream:!0}),i.length>e)throw n.abort(),new se("tooLarge",{size:`> ${e}`,limit:e})}return i+=a.decode(),$t(i,e),i}function Ni(t,e,n){if(t instanceof se)return t;if(e.aborted&&e.reason instanceof se)return e.reason;if(t instanceof DOMException&&t.name==="AbortError")return t;let r=t instanceof Error?t.message:String(t);return new se("loadFailed",{url:Qr(n),reason:r},t)}function Qr(t){let e=t.origin===location.origin?t.pathname+t.search:t.href;return e.length>120?e.slice(0,119)+"\u2026":e}function ea(t){return t instanceof DOMException&&t.name==="AbortError"}var ta="http://www.w3.org/2000/svg";var mt=["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"}],bt=["path",{d:"M14 2v4a2 2 0 0 0 2 2h4"}],Ri={copy:[["rect",{width:"14",height:"14",x:"8",y:"8",rx:"2",ry:"2"}],["path",{d:"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}]],check:[["path",{d:"M20 6 9 17l-5-5"}]],search:[["path",{d:"m21 21-4.34-4.34"}],["circle",{cx:"11",cy:"11",r:"8"}]],"chevron-up":[["path",{d:"m18 15-6-6-6 6"}]],"chevron-down":[["path",{d:"m6 9 6 6 6-6"}]],"chevron-right":[["path",{d:"m9 18 6-6-6-6"}]],wrap:[["path",{d:"m16 16-3 3 3 3"}],["path",{d:"M3 12h14.5a1 1 0 0 1 0 7H13"}],["path",{d:"M3 19h6"}],["path",{d:"M3 5h18"}]],download:[["path",{d:"M12 15V3"}],["path",{d:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"}],["path",{d:"m7 10 5 5 5-5"}]],"expand-all":[["path",{d:"m7 15 5 5 5-5"}],["path",{d:"m7 9 5-5 5 5"}]],"collapse-all":[["path",{d:"m7 20 5-5 5 5"}],["path",{d:"m7 4 5 5 5-5"}]],link:[["path",{d:"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"}],["path",{d:"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"}]],eye:[["path",{d:"M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"}],["circle",{cx:"12",cy:"12",r:"3"}]],code:[["path",{d:"m16 18 6-6-6-6"}],["path",{d:"m8 6-6 6 6 6"}]],columns:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M12 3v18"}]],list:[["path",{d:"M3 5h.01"}],["path",{d:"M3 12h.01"}],["path",{d:"M3 19h.01"}],["path",{d:"M8 5h13"}],["path",{d:"M8 12h13"}],["path",{d:"M8 19h13"}]],pencil:[["path",{d:"M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"}],["path",{d:"m15 5 4 4"}]],"chevron-left":[["path",{d:"m15 18-6-6 6-6"}]],"chevrons-left":[["path",{d:"m11 17-5-5 5-5"}],["path",{d:"m18 17-5-5 5-5"}]],"chevrons-right":[["path",{d:"m6 17 5-5-5-5"}],["path",{d:"m13 17 5-5-5-5"}]],sort:[["path",{d:"m21 16-4 4-4-4"}],["path",{d:"M17 20V4"}],["path",{d:"m3 8 4-4 4 4"}],["path",{d:"M7 4v16"}]],"sort-up":[["path",{d:"m5 12 7-7 7 7"}],["path",{d:"M12 19V5"}]],"sort-down":[["path",{d:"M12 5v14"}],["path",{d:"m19 12-7 7-7-7"}]],table:[["path",{d:"M12 3v18"}],["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 9h18"}],["path",{d:"M3 15h18"}]],undo:[["path",{d:"M9 14 4 9l5-5"}],["path",{d:"M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11"}]],redo:[["path",{d:"m15 14 5-5-5-5"}],["path",{d:"M20 9H9.5A5.5 5.5 0 0 0 4 14.5A5.5 5.5 0 0 0 9.5 20H13"}]],maximize:[["path",{d:"M15 3h6v6"}],["path",{d:"m21 3-7 7"}],["path",{d:"m3 21 7-7"}],["path",{d:"M9 21H3v-6"}]],minimize:[["path",{d:"m14 10 7-7"}],["path",{d:"M20 10h-6V4"}],["path",{d:"m3 21 7-7"}],["path",{d:"M4 14h6v6"}]],swap:[["path",{d:"M8 3 4 7l4 4"}],["path",{d:"M4 7h16"}],["path",{d:"m16 21 4-4-4-4"}],["path",{d:"M20 17H4"}]],filter:[["path",{d:"M22 3H2l8 9.46V19l4 2v-8.54L22 3z"}]],keyboard:[["rect",{width:"20",height:"16",x:"2",y:"4",rx:"2"}],["path",{d:"M6 8h.01M10 8h.01M14 8h.01M18 8h.01M8 12h.01M12 12h.01M16 12h.01M7 16h10"}]],rows:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 12h18"}]],"sync-scroll":[["path",{d:"M9 17H7A5 5 0 0 1 7 7h2"}],["path",{d:"M15 7h2a5 5 0 1 1 0 10h-2"}],["line",{x1:"8",x2:"16",y1:"12",y2:"12"}]],alert:[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}],["path",{d:"M12 9v4"}],["path",{d:"M12 17h.01"}]],close:[["path",{d:"M18 6 6 18"}],["path",{d:"m6 6 12 12"}]],replay:[["path",{d:"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"}],["path",{d:"M3 3v5h5"}]],chart:[["path",{d:"M3 3v16a2 2 0 0 0 2 2h16"}],["path",{d:"m19 9-5 5-4-4-3 3"}]],follow:[["path",{d:"M12 17V3"}],["path",{d:"m6 11 6 6 6-6"}],["path",{d:"M19 21H5"}]],terminal:[["path",{d:"M12 19h8"}],["path",{d:"m4 17 6-6-6-6"}]],folder:[["path",{d:"M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"}]],"folder-open":[["path",{d:"m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"}]],file:[mt,bt],"file-code":[mt,bt,["path",{d:"m10 13-2 2 2 2"}],["path",{d:"m14 17 2-2-2-2"}]],"file-text":[mt,bt,["path",{d:"M10 9H8"}],["path",{d:"M16 13H8"}],["path",{d:"M16 17H8"}]],"file-image":[mt,bt,["circle",{cx:"10",cy:"12",r:"2"}],["path",{d:"m20 17-1.296-1.296a2.41 2.41 0 0 0-3.408 0L9 22"}]],"file-data":[mt,bt,["path",{d:"M10 12a1 1 0 0 0-1 1v1a1 1 0 0 1-1 1 1 1 0 0 1 1 1v1a1 1 0 0 0 1 1"}],["path",{d:"M14 18a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1 1 1 0 0 1-1-1v-1a1 1 0 0 0-1-1"}]],lock:[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2"}],["path",{d:"M7 11V7a5 5 0 0 1 10 0v4"}]],"eye-off":[["path",{d:"M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"}],["path",{d:"M14.084 14.158a3 3 0 0 1-4.242-4.242"}],["path",{d:"M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"}],["path",{d:"m2 2 20 20"}]],"status-circle":[["circle",{cx:"12",cy:"12",r:"9"}]],"status-running":[["path",{d:"M21 12a9 9 0 1 1-6.22-8.56"}]],"status-skipped":[["circle",{cx:"12",cy:"12",r:"9"}],["path",{d:"m5.7 5.7 12.6 12.6"}]],"status-success":[["circle",{cx:"12",cy:"12",r:"9"}],["path",{d:"m8.5 12 2.5 2.5 4.5-5"}]],"status-failure":[["circle",{cx:"12",cy:"12",r:"9"}],["path",{d:"m15 9-6 6"}],["path",{d:"m9 9 6 6"}]]};function $e(t){let e=document.createElementNS(ta,"svg");e.setAttribute("viewBox","0 0 24 24"),e.setAttribute("fill","none"),e.setAttribute("stroke","currentColor"),e.setAttribute("stroke-width","2.1"),e.setAttribute("stroke-linecap","round"),e.setAttribute("stroke-linejoin","round"),e.setAttribute("aria-hidden","true"),e.setAttribute("focusable","false"),e.setAttribute("class","icon");for(let[n,r]of Ri[t]??[]){let a=document.createElementNS(ta,n);for(let[i,o]of Object.entries(r))a.setAttribute(i,o);e.append(a)}return e}var Cn=new WeakMap,yt=null;function Oi(){return yt||typeof IntersectionObserver>"u"||(yt=new IntersectionObserver(t=>{for(let e of t)e.isIntersecting&&Gt(e.target)},{rootMargin:"600px 0px"})),yt}function na(t,e){Cn.set(t,e);let n=Oi();n?n.observe(t):Gt(t)}function Gt(t){let e=Cn.get(t);e&&(Cn.delete(t),yt?.unobserve(t),e())}function ra(t){for(let e of Array.from(t.querySelectorAll(".chunk[data-pending]")))Gt(e)}function El(t,e){for(let n of Array.from(t.querySelectorAll(".chunk[data-pending]"))){let r=Number(n.getAttribute("data-first")),a=Number(n.getAttribute("data-count"));if(e>=r&&e<r+a){Gt(n);break}}return t.querySelector(`.line[data-line="${e}"]`)}var Li=5e3,Wt=200;function Ci(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}function Mi(t,e,n=Li){let r=[];if(!e)return{starts:r,capped:!1};let a=new RegExp(Ci(e),"gi"),i;for(;(i=a.exec(t))!==null;){if(r.length===n)return{starts:r,capped:!0};r.push(i.index),i[0].length===0&&(a.lastIndex+=1)}return{starts:r,capped:!1}}var aa=class{constructor(e,n={}){this.root=e,this.skip=n.skip??"",this.matches=[],this.current=-1}run(e){this.clear();let n=e.slice(0,Wt);if(!n)return{total:0,capped:!1};ra(this.root);let{nodes:r,starts:a,text:i}=this.collectText(),{starts:o,capped:l}=Mi(i,n),u=o.map(()=>[]);for(let m=o.length-1;m>=0;m-=1){let b=o[m],A=b+n.length,R=Ii(a,A-1);for(;R>=0&&a[R]+(r[R].nodeValue??"").length>b;){let O=a[R],j=Math.max(b,O)-O,H=Math.min(A,O+(r[R].nodeValue??"").length)-O;H>j&&u[m].unshift(Di(r[R],j,H,m)),R-=1}}return this.matches=u,{total:u.length,capped:l}}collectText(){let e=this.skip,n=document.createTreeWalker(this.root,NodeFilter.SHOW_TEXT,{acceptNode(l){let u=l.parentElement;return e&&u&&u.closest(e)?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT}}),r=[],a=[],i=[],o=0;for(let l=n.nextNode();l;l=n.nextNode()){let u=l.nodeValue??"";u&&(r.push(l),a.push(o),i.push(u),o+=u.length)}return{nodes:r,starts:a,text:i.join("")}}go(e){if(!this.matches.length)return null;let n=this.matches.length,r=(e%n+n)%n;for(let a of this.matches[this.current]??[])a.classList.remove("current");this.current=r;for(let a of this.matches[r])a.classList.add("current");return this.matches[r][0]??null}unsetCurrent(){for(let e of this.matches[this.current]??[])e.classList.remove("current");this.current=-1}clear(){let e=new Set;for(let n of this.matches)for(let r of n){let a=r.parentNode;a&&(r.replaceWith(...Array.from(r.childNodes)),e.add(a))}for(let n of e)n.normalize();this.matches=[],this.current=-1}};function Ii(t,e){let n=0,r=t.length-1;for(;n<r;){let a=n+r+1>>1;t[a]<=e?n=a:r=a-1}return n}function Di(t,e,n,r){let a=t.splitText(e);a.splitText(n-e);let i=document.createElement("mark");return i.className="match",i.setAttribute("part","match"),i.dataset.match=String(r),a.replaceWith(i),i.appendChild(a),i}function Al(t,e){let n=[];return{run(r){let a=!1;return n=t.map(i=>{let o=i.run(r);return a||=o.capped,o.total}),{total:n.reduce((i,o)=>i+o,0),capped:a}},go(r){let a=r;for(let i=0;i<t.length;i+=1){if(a<n[i]){for(let l of t)l!==t[i]&&l.unsetCurrent();let o=t[i].go(a);o&&e(o);return}a-=n[i]}},clear(){for(let r of t)r.clear()}}}function _e(t){let e=w("button",{class:"btn",part:`button${t.part?` ${t.part}`:""}`,attrs:{type:"button","aria-label":t.label,title:t.label,"aria-pressed":t.pressed===void 0?null:String(t.pressed),"data-focus-key":t.key},on:{click:t.onClick}});return e.append($e(t.icon)),e}function ia(t,e,n){let r=t.querySelector("svg");r&&(r.replaceWith($e(n?"check":"alert")),t.classList.toggle("done",n),setTimeout(()=>{t.querySelector("svg")?.replaceWith($e(e)),t.classList.remove("done")},1500))}var qt=class{constructor(e,n,r=""){this.t=e,this.handlers=n,this.total=0,this.capped=!1,this.index=-1;let a=Yr("search");this.input=w("input",{class:"search-input",part:"search-input",attrs:{id:a,type:"search",placeholder:e("searchPlaceholder"),"aria-label":e("search"),maxlength:Wt,autocomplete:"off",spellcheck:"false",enterkeyhint:"search","data-focus-key":"search-input"}}),this.input.value=r.slice(0,Wt),this.count=w("span",{class:"search-count",part:"search-count",attrs:{"aria-hidden":"true"}});let i=_e({icon:"chevron-up",label:e("searchPrevious"),onClick:()=>this.step(-1),key:"search-prev"}),o=_e({icon:"chevron-down",label:e("searchNext"),onClick:()=>this.step(1),key:"search-next"}),l=_e({icon:"close",label:e("searchClose"),onClick:()=>n.onClose(),key:"search-close"});this.element=w("div",{class:"search",part:"search",attrs:{role:"search"}},this.input,this.count,i,o,l);let u=Xr(()=>this.run(),150);this.input.addEventListener("input",u),this.input.addEventListener("keydown",m=>{m.key==="Enter"?(m.preventDefault(),u.cancel(),this.input.value!==this.lastQuery?this.run():this.step(m.shiftKey?-1:1)):m.key==="Escape"&&(m.preventDefault(),m.stopPropagation(),this.input.value?(this.input.value="",this.run()):n.onClose())}),this.lastQuery=void 0}run(){let e=this.input.value;this.lastQuery=e;let{total:n,capped:r}=this.handlers.run(e);this.total=n,this.capped=r,this.index=-1,n>0?this.step(1):this.updateCount(),this.handlers.onResult?.(e,n,r)}step(e){this.total&&(this.index=((this.index+e)%this.total+this.total)%this.total,this.handlers.go(this.index),this.updateCount())}updateCount(){if(!this.input.value)this.count.textContent="";else if(!this.total)this.count.textContent=this.t("searchNone");else{let e=this.capped?"searchCountCapped":"searchCount";this.count.textContent=this.t(e,{current:this.index+1,total:this.total})}}focus(){this.input.focus(),this.input.select()}};function Ol({tabs:t,selected:e,label:n,onSelect:r,panelId:a}){let i=w("div",{class:"tabs",part:"tabs",attrs:{role:"tablist","aria-label":n}}),o=t.map(l=>{let u=l.id===e;return w("button",{class:"tab",part:u?"tab tab-active":"tab",attrs:{type:"button",role:"tab","aria-selected":String(u),"aria-controls":a,tabindex:u?"0":"-1","data-tab":l.id,"data-focus-key":`tab-${l.id}`},on:{click:()=>r(l.id)}},l.icon?$e(l.icon):null,l.label)});return i.append(...o),i.addEventListener("keydown",l=>{let u=o.findIndex(b=>b===l.target);if(u<0)return;let m=-1;l.key==="ArrowRight"?m=(u+1)%o.length:l.key==="ArrowLeft"?m=(u-1+o.length)%o.length:l.key==="Home"?m=0:l.key==="End"&&(m=o.length-1),!(m<0)&&(l.preventDefault(),r(t[m].id))}),i}function oa(t){return w("div",{class:"loader",part:"loading",attrs:{role:"status"}},Pi(),w("span",{class:"loader-label",text:t("loading")}))}var sa="http://www.w3.org/2000/svg";function Pi(){let t=document.createElementNS(sa,"svg");t.setAttribute("viewBox","0 0 120 120"),t.setAttribute("class","loader-mark"),t.setAttribute("aria-hidden","true"),t.setAttribute("focusable","false");let e=[["rect",{class:"loader-frame",x:"12",y:"16",width:"96",height:"88",rx:"18"}],["path",{class:"loader-frame",d:"M12 42 L108 42"}],["circle",{class:"loader-dot",cx:"29",cy:"29",r:"5"}],["path",{class:"loader-v",d:"M42 60 L60 86 L78 60",pathLength:"100"}]];for(let[n,r]of e){let a=document.createElementNS(sa,n);for(let[i,o]of Object.entries(r))a.setAttribute(i,o);t.append(a)}return t}function ca(t,e){return w("div",{class:"message",part:"error",attrs:{role:"alert"}},$e("alert"),w("div",{},w("p",{class:"message-title",text:t}),e?w("p",{class:"message-detail",text:e}):null))}function Ll(t){return w("div",{class:"notice",part:"notice",attrs:{role:"note"}},$e("alert"),w("span",{text:t}))}function la(t){return w("div",{class:"empty",part:"empty",text:t("empty")})}var ua=`/*
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
`;var da=`/*
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
  /*
   * Without a height limit the page must keep scrolling: a body that only scrolls
   * sideways (long lines) would otherwise swallow vertical wheel and touch scrolling.
   */
  overscroll-behavior: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--_border-strong) transparent;
}

:host([max-height]) .body,
.vt[data-fullscreen] .body {
  overscroll-behavior: contain;
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
`;async function Mn(t,e=document){if(navigator.clipboard&&window.isSecureContext)try{return await navigator.clipboard.writeText(t),!0}catch{}return Bi(t,e)}function Bi(t,e){let n=document.createElement("textarea");n.value=t,n.setAttribute("readonly",""),n.setAttribute("aria-hidden","true"),n.style.position="fixed",n.style.opacity="0",n.style.pointerEvents="none",(e instanceof Document?e.body:e).appendChild(n);try{return n.select(),document.execCommand("copy")}catch{return!1}finally{n.remove()}}function ha(t,e,n="text/plain"){let r=new Blob([t],{type:`${n};charset=utf-8`}),a=URL.createObjectURL(r),i=document.createElement("a");i.href=a,i.download=e,i.rel="noopener",i.style.display="none",document.body.appendChild(i),i.click(),i.remove(),setTimeout(()=>URL.revokeObjectURL(a),1e3)}var fa=new Map;function Kt(t){let e=fa.get(t);return e||(e=new CSSStyleSheet,e.replaceSync(t),fa.set(t,e)),e}var Hi=Object.freeze(["variant","theme","src","allow-remote","max-height","copy","search","download","header","dot","title","label","lang-ui","mode","edit-toggle","placeholder","syntax-theme","syntax-theme-dark","badge","history","fullscreen","status"]),pa=class extends HTMLElement{static type="base";static componentAttributes=[];static presets={simple:{},full:{}};static allowEmpty=!1;static keepCarriageReturns=!1;static upgradeProperties=["content"];static styles=[];static get observedAttributes(){return[...Hi,...this.componentAttributes]}constructor(){super(),this.root=this.attachShadow({mode:"open"}),this.frame=w("div",{class:"vt",part:"container"}),this.syntaxTheme=null,this.updateSheets(null),this.live=w("div",{class:"sr-only",attrs:{"aria-live":"polite","aria-atomic":"true"}}),this.root.append(this.frame,this.live),this._content=void 0,this.text=null,this.error=null,this.loading=!1,this.searchOpen=!1,this.searchQuery="",this.searchBar=null,this.t=Tn("en"),this._loadToken=0,this._abort=null,this._renderQueued=!1,this._readyPending=!1,this._cleanups=[],this._observer=null,this._connected=!1,this.modeState=null,this.editHistory=null,this._historyCleanup=null,this._escapeFullscreen=null}get content(){return this.text??""}set content(e){let n=e==null?void 0:String(e);n!==void 0&&n===this._content&&n===this.text||(this._content=n,this._connected&&this.reload())}upgradeProperty(e){if(Object.prototype.hasOwnProperty.call(this,e)){let n=this[e];delete this[e],this[e]=n}}connectedCallback(){for(let n of this.constructor.upgradeProperties)this.upgradeProperty(n);this._cleanups.push(vr(n=>n.has("maxSize")?this.reload():this.requestRender()),Lr(()=>this.applyTheme()),Er(()=>this.requestRender())),this._observer=new MutationObserver(()=>{this._content===void 0&&!this.hasAttribute("src")&&this.reload()}),this._observer.observe(this,{childList:!0,characterData:!0,subtree:!0});let e=()=>{document.fullscreenElement===this?this.setFullscreen("native"):this.frame.dataset.fullscreen==="native"&&this.setFullscreen(null)};document.addEventListener("fullscreenchange",e),this._cleanups.push(()=>document.removeEventListener("fullscreenchange",e)),this._connected=!0,this.reload()}disconnectedCallback(){this._connected=!1;for(let e of this._cleanups.splice(0))e();this._observer?.disconnect(),this._observer=null,this._abort?.abort(),this._abort=null}attributeChangedCallback(e,n,r){n===r||!this.isConnected||(e==="mode"&&(this.modeState=null),e==="src"||e==="allow-remote"?this.reload():e==="theme"?this.applyTheme():this.requestRender())}reload(){let e=++this._loadToken;this._abort?.abort(),this._abort=null;let n=le(),r=this.getAttribute("src");if(this._content!==void 0)this.setText(this._content);else if(r!==null&&r.trim()!==""){this.loading=!0,this.error=null,this.requestRender();let a=new AbortController;this._abort=a,Jr(r,{allowRemote:it(this.getAttribute("allow-remote"))===!0,maxSize:n.maxSize,timeout:n.fetchTimeout,signal:a.signal}).then(i=>e===this._loadToken&&this.setText(i),i=>e===this._loadToken&&!ea(i)&&this.setError(i))}else this.setText(this.readInline()??"")}setText(e){this.loading=!1,this.editHistory=null;try{$t(e,le().maxSize)}catch(r){this.setError(r);return}let n=this.constructor;this.text=e.replace(n.keepCarriageReturns?/\r\n/g:/\r\n?/g,`
`),this.error=null,this.contentChanged(),this._readyPending=!0,this.requestRender()}setError(e){this.loading=!1,this._readyPending=!1,this.error=e,this.text=null,this.contentChanged(),this.requestRender();let{title:n,detail:r}=this.describeError(e);Re(this,we.ERROR,{message:r||n,cause:e})}describeError(e){let n=this.t;if(e instanceof se){let r={...e.params};for(let a of["size","limit"])typeof r[a]=="number"&&(r[a]=Tr(Number(r[a]),this.locale));return{title:n("errorTitle"),detail:n(e.code,r)}}return{title:n("errorTitle"),detail:e instanceof Error?e.message:String(e)}}get editing(){return(this.modeState??Ln(this.getAttribute("mode"),["view","edit"],"view"))==="edit"}edited(e){this.text=e,this._content=e,this.contentEdited(e),Re(this,we.INPUT,{value:e})}contentEdited(e){}historyButtons(e){if(this.editHistory=e.history,it(this.getAttribute("history"))===!1)return[];let n=_e({icon:"undo",label:this.t("undo"),key:"undo",part:"undo-button",onClick:()=>e.undo()}),r=_e({icon:"redo",label:this.t("redo"),key:"redo",part:"redo-button",onClick:()=>e.redo()}),a=()=>{n.disabled=!e.history.canUndo,r.disabled=!e.history.canRedo};return a(),this._historyCleanup?.(),this._historyCleanup=e.history.subscribe(a),[n,r]}fullscreenButton(){if(!this.feature("fullscreen"))return null;let e=!!this.frame.dataset.fullscreen;return _e({icon:e?"minimize":"maximize",label:this.t(e?"exitFullscreen":"fullscreen"),key:"fullscreen",part:"fullscreen-button",pressed:e,onClick:()=>this.toggleFullscreen()})}async toggleFullscreen(){let e=this.frame.dataset.fullscreen;if(e==="native"){await document.exitFullscreen?.().catch(()=>{});return}if(e==="window"){this.setFullscreen(null);return}if(document.fullscreenEnabled&&this.requestFullscreen)try{await this.requestFullscreen({navigationUI:"hide"});return}catch{}this.setFullscreen("window")}setFullscreen(e){e?this.frame.dataset.fullscreen=e:delete this.frame.dataset.fullscreen,e==="window"?(this._escapeFullscreen=n=>{n.key==="Escape"&&!n.defaultPrevented&&this.setFullscreen(null)},this.frame.addEventListener("keydown",this._escapeFullscreen)):this._escapeFullscreen&&(this.frame.removeEventListener("keydown",this._escapeFullscreen),this._escapeFullscreen=null),this.render(),this.root.querySelector('[data-focus-key="fullscreen"]')?.focus(),Re(this,we.FULLSCREEN_CHANGE,{fullscreen:!!e})}editToggleButton(){return this.feature("edit-toggle")?_e({icon:this.editing?"eye":"pencil",label:this.t(this.editing?"stopEditing":"edit"),key:"edit-toggle",part:"edit-button",pressed:this.editing,onClick:()=>{this.modeState=this.editing?"view":"edit",this.render(),Re(this,we.MODE_CHANGE,{mode:this.modeState}),this.modeState==="edit"&&this.root.querySelector(".editor-input")?.focus()}}):null}readInline(){return Zr(this)}contentChanged(){}get variant(){return Ln(this.getAttribute("variant"),["simple","full"],"simple")}feature(e){let n=it(this.getAttribute(e));return n!==null?n:this.constructor.presets[this.variant][e]??!1}get locale(){let e=this.getAttribute("lang-ui")?.trim();return e&&/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(e)?e:le().lang}get heading(){return qr(this.getAttribute("label")??this.getAttribute("title"))}requestRender(){this._renderQueued||(this._renderQueued=!0,queueMicrotask(()=>{this._renderQueued=!1,this.isConnected&&this.render()}))}applyTheme(){let e=Cr(this.getAttribute("theme"));this.frame.dataset.theme=e,this.applySyntaxTheme(Sn(e)?.colorScheme==="dark")}applySyntaxTheme(e){let n=le(),r=e&&this.getAttribute("syntax-theme-dark")||this.getAttribute("syntax-theme")||e&&n.syntaxThemeDark||n.syntaxTheme,a=Hr(r);if(this.syntaxTheme=a,!a){this.updateSheets(null);return}let i=Fr(a);if(i){this.updateSheets(i);return}jr(a).then(o=>{o&&this.syntaxTheme===a&&this.updateSheets(o)})}updateSheets(e){let r=this.constructor.styles.map(Kt),a=[Kt(ua),je,Kt(da),...r];this.frame.toggleAttribute("data-syntax-theme",!!e),this.root.adoptedStyleSheets=e?[...a.filter(i=>i!==Kt($r)),e]:a}render(){let e=this.activeFocusKey(),n=this.root.activeElement,r=n instanceof HTMLTextAreaElement||n instanceof HTMLInputElement?[n.selectionStart,n.selectionEnd]:null;this.t=Tn(this.locale),this.applyTheme();let a=Wr(this.getAttribute("max-height"));if(a?this.frame.style.setProperty("--_max-height",a):this.frame.style.removeProperty("--_max-height"),this.searchBar=null,this.frame.replaceChildren(),this.loading){this.frame.append(...this.chrome(null),w("div",{class:"body",part:"body"},oa(this.t))),this.frame.setAttribute("aria-busy","true");return}if(this.frame.removeAttribute("aria-busy"),this.error){let{title:o,detail:l}=this.describeError(this.error);this.frame.append(...this.chrome(null),ca(o,l));return}if(!this.text&&!this.editing&&!this.constructor.allowEmpty)this.frame.append(...this.chrome(null),la(this.t));else{this.renderContent(this.frame);let o=this.searchBar;this.searchOpen&&this.searchQuery&&o?.run()}this.restoreFocus(e);let i=this.root.activeElement;if(r&&(i instanceof HTMLTextAreaElement||i instanceof HTMLInputElement)&&r[0]!==null)try{i.setSelectionRange(r[0],r[1])}catch{}this._readyPending&&(this._readyPending=!1,Re(this,we.READY,{type:this.constructor.type}))}renderContent(e){throw new Error("renderContent() must be implemented.")}chrome(e){let n=(e?.actions??[]).filter(o=>o!==null),r=n.length?w("div",{class:"toolbar",part:"toolbar",attrs:{role:"toolbar","aria-label":this.t("actions")}},...n):null;if(!this.feature("header"))return r?.classList.add("floating"),[r,e?.tabs??null,this.searchBar?.element??null].filter(o=>o!==null);let a=this.heading,i=w("div",{class:"header",part:"header"},this.feature("dot")?w("span",{class:"dot",part:"status-dot",attrs:{"aria-hidden":"true"}}):null,a?w("span",{class:"title",part:"title",text:a,attrs:{title:a}}):null,e?.tabs??null,a?null:w("span",{class:"spacer"}),e?.badge&&it(this.getAttribute("badge"))!==!1?w("span",{class:"badge",part:"badge",text:e.badge}):null);return r&&i.append(r),this.searchBar?[i,this.searchBar.element]:[i]}copyButton(e,n=this.t("copy"),r="copy"){let a=_e({icon:"copy",label:n,key:r,part:"copy-button",onClick:async()=>{let i=e(),o=await Mn(i,this.root);ia(a,"copy",o),this.announce(this.t(o?"copied":"copyFailed")),o&&Re(this,we.COPY,{text:i})}});return a}copyTextButton(e,n,r){let a=w("button",{class:"text-btn",part:"copy-button",text:n,attrs:{type:"button","data-focus-key":r},on:{click:async()=>{let i=e(),o=await Mn(i,this.root);a.textContent=this.t(o?"copied":"copyFailed"),a.classList.toggle("done",o),setTimeout(()=>{a.textContent=n,a.classList.remove("done")},1500),this.announce(this.t(o?"copied":"copyFailed")),o&&Re(this,we.COPY,{text:i})}}});return a}downloadName(e){let n=this.getAttribute("download"),r=n&&it(n)!==!1&&!/^(?:true|on|yes)$/i.test(n.trim())?n:null,a=/\.[a-z0-9]{1,10}$/i.test(this.heading)?this.heading:null;return Kr(r??a,e)}downloadButton(e,n,r){return _e({icon:"download",label:this.t("download"),key:"download",part:"download-button",onClick:()=>ha(e(),n,r)})}searchButton(e){return this.feature("search")?(this.searchOpen&&(this.searchBar=new qt(this.t,{run:n=>(this.searchQuery=n,e.run(n)),go:n=>e.go(n),onResult:(n,r,a)=>{n&&this.announce(r?this.t("searchResults",{total:a?`${r}+`:r}):this.t("searchNone")),Re(this,we.SEARCH,{query:n,matches:r})},onClose:()=>{e.clear(),this.searchOpen=!1,this.searchQuery="",this.render(),this.root.querySelector('[data-focus-key="search"]')?.focus()}},this.searchQuery)),_e({icon:"search",label:this.t("search"),key:"search",part:"search-button",pressed:this.searchOpen,onClick:()=>{this.searchOpen=!this.searchOpen,this.searchOpen||(this.searchQuery=""),this.render(),this.searchOpen&&this.searchBar?.focus()}})):null}announce(e){this.live.textContent="",setTimeout(()=>{this.live.textContent=e},50)}activeFocusKey(){let e=this.root.activeElement;return e instanceof HTMLElement?e.dataset.focusKey??null:null}restoreFocus(e){if(!e)return;let n=this.root.querySelector(`[data-focus-key="${CSS.escape(e)}"]`);n instanceof HTMLElement&&n.focus({preventScroll:!0})}};var Da=Zs(Ia(),1);var Ie=Da.default;function Pa(t){let e=t.regex,n={},r={begin:/\$\{/,end:/\}/,contains:["self",{begin:/:-/,contains:[n]}]};Object.assign(n,{className:"variable",variants:[{begin:e.concat(/\$[\w\d#@][\w\d_]*/,"(?![\\w\\d])(?![$])")},r]});let a={className:"subst",begin:/\$\(/,end:/\)/,contains:[t.BACKSLASH_ESCAPE]},i=t.inherit(t.COMMENT(),{match:[/(^|\s)/,/#.*$/],scope:{2:"comment"}}),o={begin:/<<-?\s*(?=\w+)/,starts:{contains:[t.END_SAME_AS_BEGIN({begin:/(\w+)/,end:/(\w+)/,className:"string"})]}},l={className:"string",begin:/"/,end:/"/,contains:[t.BACKSLASH_ESCAPE,n,a]};a.contains.push(l);let u={match:/\\"/},m={className:"string",begin:/'/,end:/'/},b={match:/\\'/},A={begin:/\$?\(\(/,end:/\)\)/,contains:[{begin:/\d+#[0-9a-f]+/,className:"number"},t.NUMBER_MODE,n]},R=["fish","bash","zsh","sh","csh","ksh","tcsh","dash","scsh"],O=t.SHEBANG({binary:`(${R.join("|")})`,relevance:10}),j={className:"function",begin:/\w[\w\d_]*\s*\(\s*\)\s*\{/,returnBegin:!0,contains:[t.inherit(t.TITLE_MODE,{begin:/\w[\w\d_]*/})],relevance:0},H=["if","then","else","elif","fi","time","for","while","until","in","do","done","case","esac","coproc","function","select"],$=["true","false"],G={match:/(\/[a-z._-]+)+/},P=["break","cd","continue","eval","exec","exit","export","getopts","hash","pwd","readonly","return","shift","test","times","trap","umask","unset"],W=["alias","bind","builtin","caller","command","declare","echo","enable","help","let","local","logout","mapfile","printf","read","readarray","source","sudo","type","typeset","ulimit","unalias"],M=["autoload","bg","bindkey","bye","cap","chdir","clone","comparguments","compcall","compctl","compdescribe","compfiles","compgroups","compquote","comptags","comptry","compvalues","dirs","disable","disown","echotc","echoti","emulate","fc","fg","float","functions","getcap","getln","history","integer","jobs","kill","limit","log","noglob","popd","print","pushd","pushln","rehash","sched","setcap","setopt","stat","suspend","ttyctl","unfunction","unhash","unlimit","unsetopt","vared","wait","whence","where","which","zcompile","zformat","zftp","zle","zmodload","zparseopts","zprof","zpty","zregexparse","zsocket","zstyle","ztcp"],F=["chcon","chgrp","chown","chmod","cp","dd","df","dir","dircolors","ln","ls","mkdir","mkfifo","mknod","mktemp","mv","realpath","rm","rmdir","shred","sync","touch","truncate","vdir","b2sum","base32","base64","cat","cksum","comm","csplit","cut","expand","fmt","fold","head","join","md5sum","nl","numfmt","od","paste","ptx","pr","sha1sum","sha224sum","sha256sum","sha384sum","sha512sum","shuf","sort","split","sum","tac","tail","tr","tsort","unexpand","uniq","wc","arch","basename","chroot","date","dirname","du","echo","env","expr","factor","groups","hostid","id","link","logname","nice","nohup","nproc","pathchk","pinky","printenv","printf","pwd","readlink","runcon","seq","sleep","stat","stdbuf","stty","tee","test","timeout","tty","uname","unlink","uptime","users","who","whoami","yes"];return{name:"Bash",aliases:["sh","zsh"],keywords:{$pattern:/\b[a-z][a-z0-9._-]+\b/,keyword:H,literal:$,built_in:[...P,...W,"set","shopt",...M,...F]},contains:[O,t.SHEBANG(),j,A,i,o,G,l,u,m,b,n]}}function Ua(t){let e=t.regex;return{name:"Diff",aliases:["patch"],contains:[{className:"meta",relevance:10,match:e.either(/^@@ +-\d+,\d+ +\+\d+,\d+ +@@/,/^@@ +-\d+ +\+\d+,\d+ +@@/,/^@@ +-\d+,\d+ +\+\d+ +@@/,/^@@ +-\d+ +\+\d+ +@@/,/^\*\*\* +\d+,\d+ +\*\*\*\*$/,/^--- +\d+,\d+ +----$/)},{className:"comment",variants:[{begin:e.either(/Index: /,/^index/,/={3,}/,/^-{3}/,/^\*{3} /,/^\+{3}/,/^diff --git/),end:/$/},{match:/^\*{15}$/}]},{className:"addition",begin:/^\+/,end:/$/},{className:"deletion",begin:/^-/,end:/$/},{className:"addition",begin:/^!/,end:/$/}]}}var za="[A-Za-z$_][0-9A-Za-z$_]*",Lo=["as","in","of","if","for","while","finally","var","new","function","do","return","void","else","break","catch","instanceof","with","throw","case","default","try","switch","continue","typeof","delete","let","yield","const","class","debugger","async","await","static","import","from","export","extends","using"],Co=["true","false","null","undefined","NaN","Infinity"],Ba=["Object","Function","Boolean","Symbol","Math","Date","Number","BigInt","String","RegExp","Array","Float32Array","Float64Array","Int8Array","Uint8Array","Uint8ClampedArray","Int16Array","Int32Array","Uint16Array","Uint32Array","BigInt64Array","BigUint64Array","Set","Map","WeakSet","WeakMap","ArrayBuffer","SharedArrayBuffer","Atomics","DataView","JSON","Promise","Generator","GeneratorFunction","AsyncFunction","Reflect","Proxy","Intl","WebAssembly"],Ha=["Error","EvalError","InternalError","RangeError","ReferenceError","SyntaxError","TypeError","URIError"],Fa=["setInterval","setTimeout","clearInterval","clearTimeout","require","exports","eval","isFinite","isNaN","parseFloat","parseInt","decodeURI","decodeURIComponent","encodeURI","encodeURIComponent","escape","unescape"],Mo=["arguments","this","super","console","window","document","localStorage","sessionStorage","module","self","global"],Io=[].concat(Fa,Ba,Ha);function ja(t){let e=t.regex,n=(E,{after:k})=>{let U="</"+E[0].slice(1);return E.input.indexOf(U,k)!==-1},r=za,a={begin:"<>",end:"</>"},i=/<[A-Za-z0-9\\._:-]+\s*\/>/,o={begin:/<[A-Za-z0-9\\._:-]+/,end:/\/[A-Za-z0-9\\._:-]+>|\/>/,isTrulyOpeningTag:(E,k)=>{let U=E[0].length+E.index,ee=E.input[U];if(ee==="<"||ee===","){k.ignoreMatch();return}ee===">"&&(n(E,{after:U})||k.ignoreMatch());let ie,Ne=E.input.substring(U);if(ie=Ne.match(/^\s*=/)){k.ignoreMatch();return}if((ie=Ne.match(/^\s+extends\s+/))&&ie.index===0){k.ignoreMatch();return}}},l={$pattern:za,keyword:Lo,literal:Co,built_in:Io,"variable.language":Mo},u="[0-9](_?[0-9])*",m=`\\.(${u})`,b="0|[1-9](_?[0-9])*|0[0-7]*[89][0-9]*",A={className:"number",variants:[{begin:`(\\b(${b})((${m})|\\.)?|(${m}))[eE][+-]?(${u})\\b`},{begin:`\\b(${b})\\b((${m})\\b|\\.)?|(${m})\\b`},{begin:"\\b(0|[1-9](_?[0-9])*)n\\b"},{begin:"\\b0[xX][0-9a-fA-F](_?[0-9a-fA-F])*n?\\b"},{begin:"\\b0[bB][0-1](_?[0-1])*n?\\b"},{begin:"\\b0[oO][0-7](_?[0-7])*n?\\b"},{begin:"\\b0[0-7]+n?\\b"}],relevance:0},R={className:"subst",begin:"\\$\\{",end:"\\}",keywords:l,contains:[]},O={begin:".?html`",end:"",starts:{end:"`",returnEnd:!1,contains:[t.BACKSLASH_ESCAPE,R],subLanguage:"xml"}},j={begin:".?css`",end:"",starts:{end:"`",returnEnd:!1,contains:[t.BACKSLASH_ESCAPE,R],subLanguage:"css"}},H={begin:".?gql`",end:"",starts:{end:"`",returnEnd:!1,contains:[t.BACKSLASH_ESCAPE,R],subLanguage:"graphql"}},$={className:"string",begin:"`",end:"`",contains:[t.BACKSLASH_ESCAPE,R]},P={className:"comment",variants:[t.COMMENT(/\/\*\*(?!\/)/,"\\*/",{relevance:0,contains:[{begin:"(?=@[A-Za-z]+)",relevance:0,contains:[{className:"doctag",begin:"@[A-Za-z]+"},{className:"type",begin:"\\{",end:"\\}",excludeEnd:!0,excludeBegin:!0,relevance:0},{className:"variable",begin:r+"(?=\\s*(-)|$)",endsParent:!0,relevance:0},{begin:/(?=[^\n])\s/,relevance:0}]}]}),t.C_BLOCK_COMMENT_MODE,t.C_LINE_COMMENT_MODE]},W=[t.APOS_STRING_MODE,t.QUOTE_STRING_MODE,O,j,H,$,{match:/\$\d+/},A];R.contains=W.concat({begin:/\{/,end:/\}/,keywords:l,contains:["self"].concat(W)});let M=[].concat(P,R.contains),F=M.concat([{begin:/(\s*)\(/,end:/\)/,keywords:l,contains:["self"].concat(M)}]),K={className:"params",begin:/(\s*)\(/,end:/\)/,excludeBegin:!0,excludeEnd:!0,keywords:l,contains:F},pe={variants:[{match:[/class/,/\s+/,r,/\s+/,/extends/,/\s+/,e.concat(r,"(",e.concat(/\./,r),")*")],scope:{1:"keyword",3:"title.class",5:"keyword",7:"title.class.inherited"}},{match:[/class/,/\s+/,r],scope:{1:"keyword",3:"title.class"}}]},re={relevance:0,match:e.either(/\bJSON/,/\b[A-Z][a-z]+([A-Z][a-z]*|\d)*/,/\b[A-Z]{2,}([A-Z][a-z]+|\d)+([A-Z][a-z]*)*/,/\b[A-Z]{2,}[a-z]+([A-Z][a-z]+|\d)*([A-Z][a-z]*)*/),className:"title.class",keywords:{_:[...Ba,...Ha]}},J={label:"use_strict",className:"meta",relevance:10,begin:/^\s*['"]use (strict|asm)['"]/},ge={variants:[{match:[/function/,/\s+/,r,/(?=\s*\()/]},{match:[/function/,/\s*(?=\()/]}],className:{1:"keyword",3:"title.function"},label:"func.def",contains:[K],illegal:/%/},Ue={relevance:0,match:/\b[A-Z][A-Z_0-9]+\b/,className:"variable.constant"};function Ye(E){return e.concat("(?!",E.join("|"),")")}let Se={match:e.concat(/\b/,Ye([...Fa,"super","import","await"].map(E=>`${E}\\s*\\(`)),r,e.lookahead(/\s*\(/)),className:"title.function",relevance:0},ke={begin:e.concat(/\./,e.lookahead(e.concat(r,/(?![0-9A-Za-z$_(])/))),end:r,excludeBegin:!0,keywords:"prototype",className:"property",relevance:0},xe={match:[/get|set/,/\s+/,r,/(?=\()/],className:{1:"keyword",3:"title.function"},contains:[{begin:/\(\)/},K]},h="(\\([^()]*(\\([^()]*(\\([^()]*\\)[^()]*)*\\)[^()]*)*\\)|"+t.UNDERSCORE_IDENT_RE+")\\s*=>",v={match:[/const|var|let/,/\s+/,r,/\s*/,/=\s*/,/(async\s*)?/,e.lookahead(h)],keywords:"async",className:{1:"keyword",3:"title.function"},contains:[K]};return{name:"JavaScript",aliases:["js","jsx","mjs","cjs"],keywords:l,exports:{PARAMS_CONTAINS:F,CLASS_REFERENCE:re},illegal:/#(?![$_A-Za-z])/,contains:[t.SHEBANG({label:"shebang",binary:"node",relevance:5}),J,t.APOS_STRING_MODE,t.QUOTE_STRING_MODE,O,j,H,$,P,{match:/\$\d+/},A,re,{scope:"attr",match:r+e.lookahead(":"),relevance:0},v,{begin:"("+t.RE_STARTERS_RE+"|\\b(case|return|throw)\\b)\\s*",keywords:"return throw case",relevance:0,contains:[P,t.REGEXP_MODE,{className:"function",begin:h,returnBegin:!0,end:"\\s*=>",contains:[{className:"params",variants:[{begin:t.UNDERSCORE_IDENT_RE,relevance:0},{className:null,begin:/\(\s*\)/,skip:!0},{begin:/(\s*)\(/,end:/\)/,excludeBegin:!0,excludeEnd:!0,keywords:l,contains:F}]}]},{begin:/,/,relevance:0},{match:/\s+/,relevance:0},{variants:[{begin:a.begin,end:a.end},{match:i},{begin:o.begin,"on:begin":o.isTrulyOpeningTag,end:o.end}],subLanguage:"xml",contains:[{begin:o.begin,end:o.end,skip:!0,contains:["self"]}]}]},ge,{beginKeywords:"while if switch catch for"},{begin:"\\b(?!function)"+t.UNDERSCORE_IDENT_RE+"\\([^()]*(\\([^()]*(\\([^()]*\\)[^()]*)*\\)[^()]*)*\\)\\s*\\{",returnBegin:!0,label:"func.def",contains:[K,t.inherit(t.TITLE_MODE,{begin:r,className:"title.function"})]},{match:/\.\.\./,relevance:0},ke,{match:"\\$"+r,relevance:0},{match:[/\bconstructor(?=\s*\()/],className:{1:"title.function"},contains:[K]},Se,Ue,pe,xe,{match:/\$[(.]/}]}}var Do="([-+]?)(\\b0[xX][a-fA-F0-9]+|(\\b\\d+(\\.\\d*)?|\\.\\d+)([eE][-+]?\\d+)?)|NaN|[-+]?Infinity",Po={scope:"number",match:Do,relevance:0};function $a(t){let e={className:"attr",begin:/(("(\\.|[^\\"\r\n])*")|('(\\.|[^\\'\r\n])*'))(?=\s*:)/,relevance:1.01},n={match:/[{}[\],:]/,className:"punctuation",relevance:0},r=["true","false","null"],a={scope:"literal",beginKeywords:r.join(" ")};return{name:"JSON",aliases:["jsonc","json5"],keywords:{literal:r},contains:[e,n,t.APOS_STRING_MODE,t.QUOTE_STRING_MODE,a,Po,t.C_LINE_COMMENT_MODE,t.C_BLOCK_COMMENT_MODE],illegal:"\\S"}}function Ga(t){let e=t.regex,n={begin:/<\/?[A-Za-z_]/,end:">",subLanguage:"xml",relevance:0},r={match:/^ {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/},a={className:"code",variants:[{begin:"(`{3,})[^`](.|\\n)*?\\1`*[ ]*"},{begin:"(~{3,})[^~](.|\\n)*?\\1~*[ ]*"},{begin:"```",end:"```+[ ]*$"},{begin:"~~~",end:"~~~+[ ]*$"},{begin:"`.+?`"},{begin:"(?=^( {4}|\\t))",contains:[{begin:"^( {4}|\\t)",end:"(\\n)$"}],relevance:0}]},i={className:"bullet",begin:"^[ 	]*([*+-]|(\\d+\\.))(?=\\s+)",end:"\\s+",excludeEnd:!0},o={begin:/^\[[^\n]+\]:/,returnBegin:!0,contains:[{className:"symbol",begin:/\[/,end:/\]/,excludeBegin:!0,excludeEnd:!0},{className:"link",begin:/:\s*/,end:/$/,excludeBegin:!0}]},l=/[A-Za-z][A-Za-z0-9+.-]*/,u={variants:[{begin:/\[.+?\]\[.*?\]/,relevance:0},{begin:/\[.+?\]\(((data|javascript|mailto):|(?:http|ftp)s?:\/\/).*?\)/,relevance:2},{begin:e.concat(/\[.+?\]\(/,l,/:\/\/.*?\)/),relevance:2},{begin:/\[.+?\]\([./?&#].*?\)/,relevance:1},{begin:/\[.*?\]\(.*?\)/,relevance:0}],returnBegin:!0,contains:[{match:/\[(?=\])/},{className:"string",relevance:0,begin:"\\[",end:"\\]",excludeBegin:!0,returnEnd:!0},{className:"link",relevance:0,begin:"\\]\\(",end:"\\)",excludeBegin:!0,excludeEnd:!0},{className:"symbol",relevance:0,begin:"\\]\\[",end:"\\]",excludeBegin:!0,excludeEnd:!0}]},m={className:"strong",contains:[],variants:[{begin:/_{2}(?!\s)/,end:/_{2}/},{begin:/\*{2}(?!\s)/,end:/\*{2}/}]},b={className:"emphasis",contains:[],variants:[{begin:/\*(?![*\s])/,end:/\*/},{begin:/_(?![_\s])/,end:/_/,relevance:0}]},A=t.inherit(m,{contains:[]}),R=t.inherit(b,{contains:[]});m.contains.push(R),b.contains.push(A);let O=[n,u];return[m,b,A,R].forEach(G=>{G.contains=G.contains.concat(O)}),O=O.concat(m,b),{name:"Markdown",aliases:["md","mkdown","mkd"],contains:[{className:"section",variants:[{begin:"^#{1,6}",end:"$",contains:O},{begin:"(?=^.+?\\n[=-]{2,}$)",contains:[{begin:"^[=-]*$"},{begin:"^",end:"\\n",contains:O}]}]},n,i,r,m,b,{className:"quote",begin:"^>\\s+",contains:O,end:"$"},a,u,o,{scope:"literal",match:/&([a-zA-Z0-9]+|#[0-9]{1,7}|#[Xx][0-9a-fA-F]{1,6});/}]}}function Wa(t){return{name:"Plain text",aliases:["text","txt"],disableAutodetect:!0}}function qa(t){let e=t.regex,n=new RegExp("[\\p{XID_Start}_]\\p{XID_Continue}*","u"),r=["and","as","assert","async","await","break","case","class","continue","def","del","elif","else","except","finally","for","from","global","if","import","in","is","lambda","lazy","match","nonlocal|10","not","or","pass","raise","return","try","while","with","yield"],l={$pattern:/[A-Za-z]\w+|__\w+__/,keyword:r,built_in:["__import__","abs","aiter","all","anext","any","ascii","bin","bool","breakpoint","bytearray","bytes","callable","chr","classmethod","compile","complex","delattr","dict","dir","divmod","enumerate","eval","exec","filter","float","format","frozendict","frozenset","getattr","globals","hasattr","hash","help","hex","id","input","int","isinstance","issubclass","iter","len","list","locals","map","max","memoryview","min","next","object","oct","open","ord","pow","print","property","range","repr","reversed","round","sentinel","set","setattr","slice","sorted","staticmethod","str","sum","super","tuple","type","vars","zip"],literal:["__debug__","Ellipsis","False","None","NotImplemented","True"],type:["Any","Callable","Coroutine","Dict","List","Literal","Generic","Optional","Sequence","Set","Tuple","Type","Union"]},u={className:"meta",begin:/^(>>>|\.\.\.) /},m={className:"subst",begin:/\{/,end:/\}/,keywords:l,illegal:/#/},b={begin:/\{\{/,relevance:0},A={className:"string",contains:[t.BACKSLASH_ESCAPE],variants:[{begin:/([uU]|[bB]|[rR]|[bB][rR]|[rR][bB])?'''/,end:/'''/,contains:[t.BACKSLASH_ESCAPE,u],relevance:10},{begin:/([uU]|[bB]|[rR]|[bB][rR]|[rR][bB])?"""/,end:/"""/,contains:[t.BACKSLASH_ESCAPE,u],relevance:10},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])'''/,end:/'''/,contains:[t.BACKSLASH_ESCAPE,u,b,m]},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])"""/,end:/"""/,contains:[t.BACKSLASH_ESCAPE,u,b,m]},{begin:/([uU]|[rR])'/,end:/'/,relevance:10},{begin:/([uU]|[rR])"/,end:/"/,relevance:10},{begin:/([bB]|[bB][rR]|[rR][bB])'/,end:/'/},{begin:/([bB]|[bB][rR]|[rR][bB])"/,end:/"/},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])'/,end:/'/,contains:[t.BACKSLASH_ESCAPE,b,m]},{begin:/([fFtT][rR]|[rR][fFtT]|[fFtT])"/,end:/"/,contains:[t.BACKSLASH_ESCAPE,b,m]},t.APOS_STRING_MODE,t.QUOTE_STRING_MODE]},R="[0-9](_?[0-9])*",O=`(\\b(${R}))?\\.(${R})|\\b(${R})\\.`,j=`\\b|${r.join("|")}`,H={className:"number",relevance:0,variants:[{begin:`(\\b(${R})|(${O}))[eE][+-]?(${R})[jJ]?(?=${j})`},{begin:`(${O})[jJ]?`},{begin:`\\b([1-9](_?[0-9])*|0+(_?0)*)[lLjJ]?(?=${j})`},{begin:`\\b0[bB](_?[01])+[lL]?(?=${j})`},{begin:`\\b0[oO](_?[0-7])+[lL]?(?=${j})`},{begin:`\\b0[xX](_?[0-9a-fA-F])+[lL]?(?=${j})`},{begin:`\\b(${R})[jJ](?=${j})`}]},$={className:"comment",begin:e.lookahead(/# type:/),end:/$/,keywords:l,contains:[{begin:/# type:/},{begin:/#/,end:/\b\B/,endsWithParent:!0}]},G={className:"params",variants:[{className:"",begin:/\(\s*\)/,skip:!0},{begin:/\(/,end:/\)/,excludeBegin:!0,excludeEnd:!0,keywords:l,contains:["self",u,H,A,t.HASH_COMMENT_MODE]}]};return m.contains=[A,H,u],{name:"Python",aliases:["py","gyp","ipython"],unicodeRegex:!0,keywords:l,illegal:/(<\/|\?)|=>/,contains:[u,H,{scope:"variable.language",match:/\bself\b/},{beginKeywords:"if",relevance:0},{match:/\bor\b/,scope:"keyword"},A,$,t.HASH_COMMENT_MODE,{match:[/\bdef/,/\s+/,n],scope:{1:"keyword",3:"title.function"},contains:[G]},{variants:[{match:[/\bclass/,/\s+/,n,/\s*/,/\(\s*/,n,/\s*\)/]},{match:[/\bclass/,/\s+/,n]}],scope:{1:"keyword",3:"title.class",6:"title.class.inherited"}},{className:"meta",begin:/^[\t ]*@/,end:/(?=#)|$/,contains:[H,G,A]}]}}function Ka(t){return{name:"Shell Session",aliases:["console","shellsession"],contains:[{className:"meta.prompt",begin:/^\s{0,3}[./~\w\d[\]()@-]*[>%$#][ ]?/,starts:{end:/[^\\](?=\s*$)/,subLanguage:"bash"}}]}}function Va(t){let e=t.regex,n=e.concat(/[\p{L}_]/u,e.optional(/[\p{L}0-9_.-]*:/u),/[\p{L}0-9_.-]*/u),r=/[\p{L}0-9._:-]+/u,a={className:"symbol",begin:/&[a-z]+;|&#[0-9]+;|&#x[a-f0-9]+;/},i={begin:/\s/,contains:[{className:"keyword",begin:/#?[a-z_][a-z1-9_-]+/,illegal:/\n/}]},o=t.inherit(i,{begin:/\(/,end:/\)/}),l=t.inherit(t.APOS_STRING_MODE,{className:"string"}),u=t.inherit(t.QUOTE_STRING_MODE,{className:"string"}),m={endsWithParent:!0,illegal:/</,relevance:0,contains:[{className:"attr",begin:r,relevance:0},{begin:/=\s*/,relevance:0,contains:[{className:"string",endsParent:!0,variants:[{begin:/"/,end:/"/,contains:[a]},{begin:/'/,end:/'/,contains:[a]},{begin:/[^\s"'=<>`]+/}]}]}]};return{name:"HTML, XML",aliases:["html","xhtml","rss","atom","xjb","xsd","xsl","plist","wsf","svg"],case_insensitive:!0,unicodeRegex:!0,contains:[{className:"meta",begin:/<![a-z]/,end:/>/,relevance:10,contains:[i,u,l,o,{begin:/\[/,end:/\]/,contains:[{className:"meta",begin:/<![a-z]/,end:/>/,contains:[i,o,u,l]}]}]},t.COMMENT(/<!--/,/-->/,{relevance:10}),{begin:/<!\[CDATA\[/,end:/\]\]>/,relevance:10},a,{className:"meta",end:/\?>/,variants:[{begin:/<\?xml/,relevance:10,contains:[u]},{begin:/<\?[a-z][a-z0-9]+/}]},{className:"tag",begin:/<style(?=\s|>)/,end:/>/,keywords:{name:"style"},contains:[m],starts:{end:/<\/style>/,returnEnd:!0,subLanguage:"css"}},{className:"tag",begin:/<script(?=\s|>)/,end:/>/,keywords:{name:"script"},contains:[m],starts:{end:/<\/script>/,returnEnd:!0,subLanguage:"javascript"}},{className:"tag",begin:/<>|<\/>/},{className:"tag",begin:e.concat(/</,e.lookahead(e.concat(n,e.either(/\/>/,/>/,/\s/)))),end:/\/?>/,contains:[{className:"name",begin:n,relevance:0,starts:m}]},{className:"tag",begin:e.concat(/<\//,e.lookahead(e.concat(n,/>/))),contains:[{className:"name",begin:n,relevance:0},{begin:/>/,relevance:0,endsParent:!0}]}]}}function Ya(t){let e="true false yes no null",n="[\\w#;/?:@&=+$,.~*'()[\\]]+",r={className:"attr",variants:[{begin:/[\w*@][\w*@ :()\./-]*:(?=[ \t]|$)/},{begin:/"[\w*@][\w*@ :()\./-]*":(?=[ \t]|$)/},{begin:/'[\w*@][\w*@ :()\./-]*':(?=[ \t]|$)/}]},a={className:"template-variable",variants:[{begin:/\{\{/,end:/\}\}/},{begin:/%\{/,end:/\}/}]},i={className:"string",relevance:0,begin:/'/,end:/'/,contains:[{match:/''/,scope:"char.escape",relevance:0}]},o={className:"string",relevance:0,variants:[{begin:/"/,end:/"/},{begin:/\S+/}],contains:[t.BACKSLASH_ESCAPE,a]},l=t.inherit(o,{variants:[{begin:/'/,end:/'/,contains:[{begin:/''/,relevance:0}]},{begin:/"/,end:/"/},{begin:/[^\s,{}[\]]+/}]}),R={className:"number",begin:"\\b"+"[0-9]{4}(-[0-9][0-9]){0,2}"+"([Tt \\t][0-9][0-9]?(:[0-9][0-9]){2})?"+"(\\.[0-9]*)?"+"([ \\t])*(Z|[-+][0-9][0-9]?(:[0-9][0-9])?)?"+"\\b"},O={end:",",endsWithParent:!0,excludeEnd:!0,keywords:e,relevance:0},j={begin:/\{/,end:/\}/,contains:[O],illegal:"\\n",relevance:0},H={begin:"\\[",end:"\\]",contains:[O],illegal:"\\n",relevance:0},$=[r,{className:"meta",begin:"^---\\s*$",relevance:10},{className:"string",begin:"[\\|>]([1-9]?[+-])?[ ]*\\n( +)[^ ][^\\n]*\\n(\\2[^\\n]+\\n?)*"},{begin:"<%[%=-]?",end:"[%-]?%>",subLanguage:"ruby",excludeBegin:!0,excludeEnd:!0,relevance:0},{className:"type",begin:"!\\w+!"+n},{className:"type",begin:"!<"+n+">"},{className:"type",begin:"!"+n},{className:"type",begin:"!!"+n},{className:"meta",begin:"&"+t.UNDERSCORE_IDENT_RE+"$"},{className:"meta",begin:"\\*"+t.UNDERSCORE_IDENT_RE+"$"},{className:"bullet",begin:"-(?=[ ]|$)",relevance:0},t.HASH_COMMENT_MODE,{beginKeywords:e,keywords:{literal:e}},R,{className:"number",begin:t.C_NUMBER_RE+"\\b",relevance:0},j,H,i,o],G=[...$];return G.pop(),G.push(l),O.contains=G,{name:"YAML",case_insensitive:!0,aliases:["yml"],contains:$}}var Qt=Object.freeze({"1c":"",abnf:"",accesslog:"",actionscript:"as",ada:"",angelscript:"asc",apache:"apacheconf",applescript:"osascript",arcade:"",arduino:"ino",armasm:"arm",asciidoc:"adoc",aspectj:"",autohotkey:"ahk",autoit:"",avrasm:"",awk:"",axapta:"x++",bash:"sh zsh",basic:"",bnf:"",brainfuck:"bf",c:"h",cal:"",capnproto:"capnp",ceylon:"",clean:"dcl icl",clojure:"clj edn","clojure-repl":"",cmake:"cmake.in",coffeescript:"coffee cson iced",coq:"",cos:"cls",cpp:"c++ cc cxx h++ hh hpp hxx",crmsh:"crm pcmk",crystal:"cr",csharp:"c# cs",csp:"",css:"",d:"",dart:"",delphi:"dfm dpr pas pascal",diff:"patch",django:"jinja",dns:"bind zone",dockerfile:"docker",dos:"bat batch cmd",dsconfig:"",dts:"",dust:"dst",ebnf:"",elixir:"ex exs",elm:"",erb:"",erlang:"erl","erlang-repl":"",excel:"xls xlsx",fix:"",flix:"",fortran:"f90 f95",freedesktop:"desktop systemd",fsharp:"f# fs",gams:"gms",gauss:"gss",gcode:"nc",gherkin:"feature",glsl:"",gml:"",go:"golang",golo:"",gradle:"",graphql:"gql",groovy:"",haml:"",handlebars:"hbs html.handlebars html.hbs htmlbars",haskell:"hs",haxe:"hx",hsp:"",http:"https",hy:"hylang",inform7:"i7",ini:"toml",irpf90:"",isbl:"",java:"jsp",javascript:"cjs js jsx mjs","jboss-cli":"wildfly-cli",json:"json5 jsonc",julia:"","julia-repl":"jldoctest",kotlin:"kt ktm kts ktx",lasso:"lassoscript ls",latex:"tex",ldif:"",leaf:"",less:"",lisp:"",livecodeserver:"",livescript:"ls",llvm:"",lsl:"",lua:"pluto",makefile:"mak make mk",markdown:"md mkd mkdown",mathematica:"mma wl",matlab:"",maxima:"",mel:"",mercury:"m moo",mipsasm:"mips",mizar:"",mojolicious:"",monkey:"",moonscript:"moon",n1ql:"",nestedtext:"nt",nginx:"nginxconf",nim:"",nix:"nixos","node-repl":"",nsis:"",objectivec:"mm obj-c obj-c++ objc objective-c++",ocaml:"ml",openscad:"scad",oxygene:"",parser3:"",perl:"pl pm",pf:"pf.conf",pgsql:"postgres postgresql",php:"","php-template":"",plaintext:"text txt",pony:"",powershell:"ps ps1 pwsh",processing:"pde",profile:"",prolog:"",properties:"",protobuf:"proto",puppet:"pp",purebasic:"pb pbi",python:"gyp ipython py","python-repl":"pycon",q:"k kdb",qml:"qt",r:"",reasonml:"re",rib:"",roboconf:"graph instances",routeros:"mikrotik",rsl:"",ruby:"gemspec irb podspec rb thor",ruleslanguage:"",rust:"rs",sas:"",scala:"",scheme:"scm",scilab:"sci",scss:"",shell:"console shellsession",smali:"",smalltalk:"st",sml:"ml",sqf:"",sql:"",stan:"stanfuncs",stata:"ado do",step21:"p21 step stp",stylus:"styl",subunit:"",swift:"",taggerscript:"",tap:"",tcl:"tk",thrift:"",tp:"",twig:"craftcms",typescript:"cts mts ts tsx",vala:"",vbnet:"vb",vbscript:"vbs","vbscript-html":"",verilog:"sv svh v",vhdl:"",vim:"",wasm:"",wren:"",x86asm:"",xl:"tao",xml:"atom html plist rss svg wsf xhtml xjb xsd xsl",xquery:"xpath xq xqm",yaml:"yml",zephir:"zep"});function Uo(t,e){this.v=t,this.k=e}function Xa(t,e){(e==null||e>t.length)&&(e=t.length);for(var n=0,r=Array(e);n<e;n++)r[n]=t[n];return r}function zo(t){if(Array.isArray(t))return t}function Bo(t,e){var n=t==null?null:typeof Symbol<"u"&&t[Symbol.iterator]||t["@@iterator"];if(n!=null){var r,a,i,o,l=[],u=!0,m=!1;try{if(i=(n=n.call(t)).next,e===0){if(Object(n)!==n)return;u=!1}else for(;!(u=(r=i.call(n)).done)&&(l.push(r.value),l.length!==e);u=!0);}catch(b){m=!0,a=b}finally{try{if(!u&&n.return!=null&&(o=n.return(),Object(o)!==o))return}finally{if(m)throw a}}return l}}function Ho(){throw new TypeError(`Invalid attempt to destructure non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function Fo(t,e){return zo(t)||Bo(t,e)||jo(t,e)||Ho()}function jo(t,e){if(t){if(typeof t=="string")return Xa(t,e);var n={}.toString.call(t).slice(8,-1);return n==="Object"&&t.constructor&&(n=t.constructor.name),n==="Map"||n==="Set"?Array.from(t):n==="Arguments"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)?Xa(t,e):void 0}}function en(t){var e,n;function r(i,o){try{var l=t[i](o),u=l.value,m=u instanceof Uo;Promise.resolve(m?u.v:u).then(function(b){if(m){var A=i==="return"&&u.k?i:"next";if(!u.k||b.done)return r(A,b);b=t[A](b).value}a(!!l.done,b)},function(b){r("throw",b)})}catch(b){a(2,b)}}function a(i,o){i===2?e.reject(o):e.resolve({value:o,done:i}),(e=e.next)?r(e.key,e.arg):n=null}this._invoke=function(i,o){return new Promise(function(l,u){var m={key:i,arg:o,resolve:l,reject:u,next:null};n?n=n.next=m:(e=n=m,r(i,o))})},typeof t.return!="function"&&(this.return=void 0)}en.prototype[typeof Symbol=="function"&&Symbol.asyncIterator||"@@asyncIterator"]=function(){return this},en.prototype.next=function(t){return this._invoke("next",t)},en.prototype.throw=function(t){return this._invoke("throw",t)},en.prototype.return=function(t){return this._invoke("return",t)};var ds=Object.entries,Za=Object.setPrototypeOf,$o=Object.isFrozen,Go=Object.getPrototypeOf,Wo=Object.getOwnPropertyDescriptor,Q=Object.freeze,te=Object.seal,lt=Object.create,hs=typeof Reflect<"u"&&Reflect,Kn=hs.apply,Vn=hs.construct;Q||(Q=function(e){return e});te||(te=function(e){return e});Kn||(Kn=function(e,n){for(var r=arguments.length,a=new Array(r>2?r-2:0),i=2;i<r;i++)a[i-2]=arguments[i];return e.apply(n,a)});Vn||(Vn=function(e){for(var n=arguments.length,r=new Array(n>1?n-1:0),a=1;a<n;a++)r[a-1]=arguments[a];return new e(...r)});var qe=Z(Array.prototype.forEach);Array.prototype.indexOf;var qo=Z(Array.prototype.lastIndexOf),Ja=Z(Array.prototype.pop),xt=Z(Array.prototype.push);Array.prototype.slice;var Ko=Z(Array.prototype.splice),ut=Array.isArray,wt=Z(String.prototype.toLowerCase),Fn=Z(String.prototype.toString),Qa=Z(String.prototype.match),Et=Z(String.prototype.replace),es=Z(String.prototype.indexOf),Vo=Z(String.prototype.trim),Yo=Z(Number.prototype.toString),Xo=Z(Boolean.prototype.toString),ts=typeof BigInt>"u"?null:Z(BigInt.prototype.toString),ns=typeof Symbol>"u"?null:Z(Symbol.prototype.toString),ue=Z(Object.prototype.hasOwnProperty),Tt=Z(Object.prototype.toString),ne=Z(RegExp.prototype.test),De=Zo(TypeError);function Z(t){return function(e){e instanceof RegExp&&(e.lastIndex=0);for(var n=arguments.length,r=new Array(n>1?n-1:0),a=1;a<n;a++)r[a-1]=arguments[a];return Kn(t,e,r)}}function Zo(t){return function(){for(var e=arguments.length,n=new Array(e),r=0;r<e;r++)n[r]=arguments[r];return Vn(t,n)}}function D(t,e){let n=arguments.length>2&&arguments[2]!==void 0?arguments[2]:wt;if(Za&&Za(t,null),!ut(e))return t;let r=e.length;for(;r--;){let a=e[r];if(typeof a=="string"){let i=n(a);i!==a&&($o(e)||(e[r]=i),a=i)}t[a]=!0}return t}function Jo(t){for(let e=0;e<t.length;e++)ue(t,e)||(t[e]=null);return t}function fe(t){let e=lt(null);for(let r of ds(t)){var n=Fo(r,2);let a=n[0],i=n[1];ue(t,a)&&(ut(i)?e[a]=Jo(i):i&&typeof i=="object"&&i.constructor===Object?e[a]=fe(i):e[a]=i)}return e}function Qo(t){switch(typeof t){case"string":return t;case"number":return Yo(t);case"boolean":return Xo(t);case"bigint":return ts?ts(t):"0";case"symbol":return ns?ns(t):"Symbol()";case"undefined":return Tt(t);case"function":case"object":{if(t===null)return Tt(t);let e=t,n=ye(e,"toString");if(typeof n=="function"){let r=n(e);return typeof r=="string"?r:Tt(r)}return Tt(t)}default:return Tt(t)}}function ye(t,e){for(;t!==null;){let r=Wo(t,e);if(r){if(r.get)return Z(r.get);if(typeof r.value=="function")return Z(r.value)}t=Go(t)}function n(){return null}return n}function ec(t){try{return ne(t,""),!0}catch{return!1}}var rs=Q(["a","abbr","acronym","address","area","article","aside","audio","b","bdi","bdo","big","blink","blockquote","body","br","button","canvas","caption","center","cite","code","col","colgroup","content","data","datalist","dd","decorator","del","details","dfn","dialog","dir","div","dl","dt","element","em","fieldset","figcaption","figure","font","footer","form","h1","h2","h3","h4","h5","h6","head","header","hgroup","hr","html","i","img","input","ins","kbd","label","legend","li","main","map","mark","marquee","menu","menuitem","meter","nav","nobr","ol","optgroup","option","output","p","picture","pre","progress","q","rp","rt","ruby","s","samp","search","section","select","shadow","slot","small","source","spacer","span","strike","strong","style","sub","summary","sup","table","tbody","td","template","textarea","tfoot","th","thead","time","tr","track","tt","u","ul","var","video","wbr"]),jn=Q(["svg","a","altglyph","altglyphdef","altglyphitem","animatecolor","animatemotion","animatetransform","circle","clippath","defs","desc","ellipse","enterkeyhint","exportparts","filter","font","g","glyph","glyphref","hkern","image","inputmode","line","lineargradient","marker","mask","metadata","mpath","part","path","pattern","polygon","polyline","radialgradient","rect","stop","style","switch","symbol","text","textpath","title","tref","tspan","view","vkern"]),$n=Q(["feBlend","feColorMatrix","feComponentTransfer","feComposite","feConvolveMatrix","feDiffuseLighting","feDisplacementMap","feDistantLight","feDropShadow","feFlood","feFuncA","feFuncB","feFuncG","feFuncR","feGaussianBlur","feImage","feMerge","feMergeNode","feMorphology","feOffset","fePointLight","feSpecularLighting","feSpotLight","feTile","feTurbulence"]),tc=Q(["animate","color-profile","cursor","discard","font-face","font-face-format","font-face-name","font-face-src","font-face-uri","foreignobject","hatch","hatchpath","mesh","meshgradient","meshpatch","meshrow","missing-glyph","script","set","solidcolor","unknown","use"]),Gn=Q(["math","menclose","merror","mfenced","mfrac","mglyph","mi","mlabeledtr","mmultiscripts","mn","mo","mover","mpadded","mphantom","mroot","mrow","ms","mspace","msqrt","mstyle","msub","msup","msubsup","mtable","mtd","mtext","mtr","munder","munderover","mprescripts"]),nc=Q(["maction","maligngroup","malignmark","mlongdiv","mscarries","mscarry","msgroup","mstack","msline","msrow","semantics","annotation","annotation-xml","mprescripts","none"]),as=Q(["#text"]),ss=Q(["accept","action","align","alt","autocapitalize","autocomplete","autopictureinpicture","autoplay","background","bgcolor","border","capture","cellpadding","cellspacing","checked","cite","class","clear","color","cols","colspan","command","commandfor","controls","controlslist","coords","crossorigin","datetime","decoding","default","dir","disabled","disablepictureinpicture","disableremoteplayback","download","draggable","enctype","enterkeyhint","exportparts","face","for","headers","height","hidden","high","href","hreflang","id","inert","inputmode","integrity","ismap","kind","label","lang","list","loading","loop","low","max","maxlength","media","method","min","minlength","multiple","muted","name","nonce","noshade","novalidate","nowrap","open","optimum","part","pattern","placeholder","playsinline","popover","popovertarget","popovertargetaction","poster","preload","pubdate","radiogroup","readonly","rel","required","rev","reversed","role","rows","rowspan","spellcheck","scope","selected","shape","size","sizes","slot","span","srclang","start","src","srcset","step","style","summary","tabindex","title","translate","type","usemap","valign","value","width","wrap","xmlns"]),Wn=Q(["accent-height","accumulate","additive","alignment-baseline","amplitude","ascent","attributename","attributetype","azimuth","basefrequency","baseline-shift","begin","bias","by","class","clip","clippathunits","clip-path","clip-rule","color","color-interpolation","color-interpolation-filters","color-profile","color-rendering","cx","cy","d","dx","dy","diffuseconstant","direction","display","divisor","dominant-baseline","dur","edgemode","elevation","end","exponent","fill","fill-opacity","fill-rule","filter","filterunits","flood-color","flood-opacity","font-family","font-size","font-size-adjust","font-stretch","font-style","font-variant","font-weight","fx","fy","g1","g2","glyph-name","glyphref","gradientunits","gradienttransform","height","href","id","image-rendering","in","in2","intercept","k","k1","k2","k3","k4","kerning","keypoints","keysplines","keytimes","lang","lengthadjust","letter-spacing","kernelmatrix","kernelunitlength","lighting-color","local","marker-end","marker-mid","marker-start","markerheight","markerunits","markerwidth","maskcontentunits","maskunits","max","mask","mask-type","media","method","mode","min","name","numoctaves","offset","operator","opacity","order","orient","orientation","origin","overflow","paint-order","path","pathlength","patterncontentunits","patterntransform","patternunits","pointer-events","points","preservealpha","preserveaspectratio","primitiveunits","r","rx","ry","radius","refx","refy","repeatcount","repeatdur","restart","result","rotate","scale","seed","shape-rendering","slope","specularconstant","specularexponent","spreadmethod","startoffset","stddeviation","stitchtiles","stop-color","stop-opacity","stroke-dasharray","stroke-dashoffset","stroke-linecap","stroke-linejoin","stroke-miterlimit","stroke-opacity","stroke","stroke-width","style","surfacescale","systemlanguage","tabindex","tablevalues","targetx","targety","transform","transform-origin","text-anchor","text-decoration","text-orientation","text-rendering","textlength","type","u1","u2","unicode","values","vector-effect","viewbox","visibility","version","vert-adv-y","vert-origin-x","vert-origin-y","width","word-spacing","wrap","writing-mode","xchannelselector","ychannelselector","x","x1","x2","xmlns","y","y1","y2","z","zoomandpan"]),is=Q(["accent","accentunder","align","bevelled","close","columnalign","columnlines","columnspacing","columnspan","denomalign","depth","dir","display","displaystyle","encoding","fence","frame","height","href","id","largeop","length","linethickness","lquote","lspace","mathbackground","mathcolor","mathsize","mathvariant","maxsize","minsize","movablelimits","notation","numalign","open","rowalign","rowlines","rowspacing","rowspan","rspace","rquote","scriptlevel","scriptminsize","scriptsizemultiplier","selection","separator","separators","stretchy","subscriptshift","supscriptshift","symmetric","voffset","width","xmlns"]),tn=Q(["xlink:href","xml:id","xlink:title","xml:space","xmlns:xlink"]),rc=te(/{{[\w\W]*|^[\w\W]*}}/g),ac=te(/<%[\w\W]*|^[\w\W]*%>/g),sc=te(/\${[\w\W]*/g),ic=te(/^data-[\-\w.\u00B7-\uFFFF]+$/),oc=te(/^aria-[\-\w]+$/),os=te(/^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i),cc=te(/^(?:\w+script|data):/i),lc=te(/[\u0000-\u0020\u00A0\u1680\u180E\u2000-\u2029\u205F\u3000]/g),uc=te(/^html$/i),dc=te(/^[a-z][.\w]*(-[.\w]+)+$/i),cs=te(/<[/\w!]/g),ls=te(/<[/\w]/g),hc=te(/<\/no(script|embed|frames)/i),fc=te(/\/>/i),he={element:1,attribute:2,text:3,cdataSection:4,entityReference:5,entityNode:6,processingInstruction:7,comment:8,document:9,documentType:10,documentFragment:11,notation:12},fs=["style","script","xmp","iframe","noembed","noframes","plaintext","noscript"],pc=Q(D({},fs)),gc=(function(){let t={};return qe(fs,e=>{t[e]=te(new RegExp("</"+e+"(?=[\\t\\n\\f\\r />])","i"))}),Q(t)})(),mc=function(){return typeof window>"u"?null:window},bc=function(e,n){if(typeof e!="object"||typeof e.createPolicy!="function")return null;let r=null,a="data-tt-policy-suffix";n&&n.hasAttribute(a)&&(r=n.getAttribute(a));let i="dompurify"+(r?"#"+r:"");try{return e.createPolicy(i,{createHTML(o){return o},createScriptURL(o){return o}})}catch{return console.warn("TrustedTypes policy "+i+" could not be created."),null}},us=function(){return{afterSanitizeAttributes:[],afterSanitizeElements:[],afterSanitizeShadowDOM:[],beforeSanitizeAttributes:[],beforeSanitizeElements:[],beforeSanitizeShadowDOM:[],uponSanitizeAttribute:[],uponSanitizeElement:[],uponSanitizeShadowNode:[]}},Pe=function(e,n,r,a){return ue(e,n)&&ut(e[n])?D(a.base?fe(a.base):{},e[n],a.transform):r},qn=function(e,n,r){let a=ue(e,n)?e[n]:void 0;return a&&typeof a=="object"?fe(a):r()};function ps(){let t=arguments.length>0&&arguments[0]!==void 0?arguments[0]:mc(),e=f=>ps(f);if(e.version="3.4.16",e.removed=[],!t||!t.document||t.document.nodeType!==he.document||!t.Element)return e.isSupported=!1,e;let n=t.document,r=n,a=r.currentScript;t.DocumentFragment;let i=t.HTMLTemplateElement,o=t.Node,l=t.Element,u=t.NodeFilter;t.NamedNodeMap===void 0&&(t.NamedNodeMap||t.MozNamedAttrMap),t.HTMLFormElement;let m=t.DOMParser,b=t.trustedTypes,A=l.prototype,R=ye(A,"cloneNode"),O=ye(A,"remove"),j=ye(A,"removeAttributeNode"),H=ye(A,"nextSibling"),$=ye(A,"childNodes"),G=ye(A,"parentNode"),P=ye(A,"shadowRoot"),W=ye(A,"attributes"),M=o&&o.prototype?ye(o.prototype,"nodeType"):null,F=o&&o.prototype?ye(o.prototype,"nodeName"):null,K=o&&o.prototype?ye(o.prototype,"ownerDocument"):null,pe=function(s){return M?M(s):s.nodeType},re=function(s){return F?F(s):s.nodeName};if(typeof i=="function"){let f=n.createElement("template");f.content&&f.content.ownerDocument&&(n=f.content.ownerDocument)}let J,ge="",Ue,Ye=!1,Se=0,ke=function(){if(Se>0)throw De('A configured TRUSTED_TYPES_POLICY callback (createHTML or createScriptURL) must not call DOMPurify.sanitize, as that causes infinite recursion. Do not pass a policy whose callbacks wrap DOMPurify as TRUSTED_TYPES_POLICY; see the "DOMPurify and Trusted Types" section of the README.')},xe=function(s){ke(),Se++;try{return J.createHTML(s)}finally{Se--}},h=function(s){ke(),Se++;try{return J.createScriptURL(s)}finally{Se--}},v=function(){return Ye||(Ue=bc(b,a),Ye=!0),Ue},E=n,k=E.implementation,U=E.createNodeIterator,ee=E.createDocumentFragment,ie=E.getElementsByTagName,Ne=r.importNode,S=us();e.isSupported=typeof ds=="function"&&typeof G=="function"&&k&&k.createHTMLDocument!==void 0;let me=rc,kt=ac,Nt=sc,Rt=ic,sn=oc,on=cc,Ot=lc,cn=dc,ze=os,z=null,oe=D({},[...rs,...jn,...$n,...Gn,...as]),B=null,Be=D({},[...ss,...Wn,...is,...tn]),_=Object.seal(lt(null,{tagNameCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},attributeNameCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},allowCustomizedBuiltInElements:{writable:!0,configurable:!1,enumerable:!0,value:!1}})),Oe=null,X=null,L=Object.seal(lt(null,{tagCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},attributeCheck:{writable:!0,configurable:!1,enumerable:!0,value:null}})),He=!0,ve=!0,Xe=!1,Ze=!0,g=!1,y=!0,T=!1,I=!1,V=null,ce=null,dt=!1,Le=!1,Lt=!1,Ct=!1,Yn=!0,Xn=!1,Zn="user-content-",ln=!0,un=!1,Je={},Qe=null,Jn=D({},["annotation-xml","audio","colgroup","desc","foreignobject","head","iframe","math","mi","mn","mo","ms","mtext","noembed","noframes","noscript","plaintext","script","selectedcontent","style","svg","template","thead","title","video","xmp"]),Qn=null,er=D({},["audio","video","img","source","image","track"]),tr=null,nr=D({},["alt","class","for","id","label","name","pattern","placeholder","role","summary","title","value","style","xmlns"]),Mt="http://www.w3.org/1998/Math/MathML",It="http://www.w3.org/2000/svg",Ee="http://www.w3.org/1999/xhtml",et=Ee,dn=!1,hn=null,Ns=D({},[Mt,It,Ee],Fn),rr=Q(["mi","mo","mn","ms","mtext"]),fn=D({},rr),ar=Q(["annotation-xml"]),pn=D({},ar),Rs=D({},["title","style","font","a","script"]),ht=null,Os=["application/xhtml+xml","text/html"],Ls="text/html",Y=null,tt=null,Cs=n.createElement("form"),sr=function(s){return s instanceof RegExp||s instanceof Function},gn=function(){let s=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};if(tt&&tt===s)return;(!s||typeof s!="object")&&(s={}),s=fe(s),ht=Os.indexOf(s.PARSER_MEDIA_TYPE)===-1?Ls:s.PARSER_MEDIA_TYPE,Y=ht==="application/xhtml+xml"?Fn:wt,z=Pe(s,"ALLOWED_TAGS",oe,{transform:Y}),B=Pe(s,"ALLOWED_ATTR",Be,{transform:Y}),hn=Pe(s,"ALLOWED_NAMESPACES",Ns,{transform:Fn}),tr=Pe(s,"ADD_URI_SAFE_ATTR",nr,{transform:Y,base:nr}),Qn=Pe(s,"ADD_DATA_URI_TAGS",er,{transform:Y,base:er}),Qe=Pe(s,"FORBID_CONTENTS",Jn,{transform:Y}),Oe=Pe(s,"FORBID_TAGS",fe({}),{transform:Y}),X=Pe(s,"FORBID_ATTR",fe({}),{transform:Y}),Je=ue(s,"USE_PROFILES")?s.USE_PROFILES&&typeof s.USE_PROFILES=="object"?fe(s.USE_PROFILES):s.USE_PROFILES:!1,He=s.ALLOW_ARIA_ATTR!==!1,ve=s.ALLOW_DATA_ATTR!==!1,Xe=s.ALLOW_UNKNOWN_PROTOCOLS||!1,Ze=s.ALLOW_SELF_CLOSE_IN_ATTR!==!1,g=s.SAFE_FOR_TEMPLATES||!1,y=s.SAFE_FOR_XML!==!1,T=s.WHOLE_DOCUMENT||!1,Le=s.RETURN_DOM||!1,Lt=s.RETURN_DOM_FRAGMENT||!1,Ct=s.RETURN_TRUSTED_TYPE||!1,dt=s.FORCE_BODY||!1,Yn=s.SANITIZE_DOM!==!1,Xn=s.SANITIZE_NAMED_PROPS||!1,ln=s.KEEP_CONTENT!==!1,un=s.IN_PLACE||!1,ze=ec(s.ALLOWED_URI_REGEXP)?s.ALLOWED_URI_REGEXP:os,et=typeof s.NAMESPACE=="string"?s.NAMESPACE:Ee,fn=qn(s,"MATHML_TEXT_INTEGRATION_POINTS",()=>D({},rr)),pn=qn(s,"HTML_INTEGRATION_POINTS",()=>D({},ar));let c=qn(s,"CUSTOM_ELEMENT_HANDLING",()=>lt(null));if(_=lt(null),ue(c,"tagNameCheck")&&sr(c.tagNameCheck)&&(_.tagNameCheck=c.tagNameCheck),ue(c,"attributeNameCheck")&&sr(c.attributeNameCheck)&&(_.attributeNameCheck=c.attributeNameCheck),ue(c,"allowCustomizedBuiltInElements")&&typeof c.allowCustomizedBuiltInElements=="boolean"&&(_.allowCustomizedBuiltInElements=c.allowCustomizedBuiltInElements),te(_),g&&(ve=!1),Lt&&(Le=!0),Je&&(z=D({},as),B=lt(null),Je.html===!0&&(D(z,rs),D(B,ss)),Je.svg===!0&&(D(z,jn),D(B,Wn),D(B,tn)),Je.svgFilters===!0&&(D(z,$n),D(B,Wn),D(B,tn)),Je.mathMl===!0&&(D(z,Gn),D(B,is),D(B,tn))),L.tagCheck=null,L.attributeCheck=null,ue(s,"ADD_TAGS")&&(typeof s.ADD_TAGS=="function"?L.tagCheck=s.ADD_TAGS:ut(s.ADD_TAGS)&&(z===oe&&(z=fe(z)),D(z,s.ADD_TAGS,Y))),ue(s,"ADD_ATTR")&&(typeof s.ADD_ATTR=="function"?L.attributeCheck=s.ADD_ATTR:ut(s.ADD_ATTR)&&(B===Be&&(B=fe(B)),D(B,s.ADD_ATTR,Y))),ue(s,"ADD_FORBID_CONTENTS")&&ut(s.ADD_FORBID_CONTENTS)&&(Qe===Jn&&(Qe=fe(Qe)),D(Qe,s.ADD_FORBID_CONTENTS,Y)),ln&&(z["#text"]=!0),T&&D(z,["html","head","body"]),z.table&&(D(z,["tbody"]),delete Oe.tbody),s.TRUSTED_TYPES_POLICY){if(typeof s.TRUSTED_TYPES_POLICY.createHTML!="function")throw De('TRUSTED_TYPES_POLICY configuration option must provide a "createHTML" hook.');if(typeof s.TRUSTED_TYPES_POLICY.createScriptURL!="function")throw De('TRUSTED_TYPES_POLICY configuration option must provide a "createScriptURL" hook.');let d=J;J=s.TRUSTED_TYPES_POLICY;try{ge=xe("")}catch(p){throw J=d,p}}else s.TRUSTED_TYPES_POLICY===null?(J=void 0,ge=""):(J===void 0&&(J=v()),J&&typeof ge=="string"&&(ge=xe("")));Q&&Q(s),tt=s},ir=D({},[...jn,...$n,...tc]),or=D({},[...Gn,...nc]),Ms=function(s,c,d){return c.namespaceURI===Ee?s==="svg":c.namespaceURI===Mt?s==="svg"&&(d==="annotation-xml"||fn[d]):!!ir[s]},Is=function(s,c,d){return c.namespaceURI===Ee?s==="math":c.namespaceURI===It?s==="math"&&pn[d]:!!or[s]},Ds=function(s,c,d){return c.namespaceURI===It&&!pn[d]||c.namespaceURI===Mt&&!fn[d]?!1:!or[s]&&(Rs[s]||!ir[s])},Ps=function(s){let c=G(s);(!c||!c.tagName)&&(c={namespaceURI:et,tagName:"template"});let d=wt(s.tagName),p=wt(c.tagName);return hn[s.namespaceURI]?s.namespaceURI===It?Ms(d,c,p):s.namespaceURI===Mt?Is(d,c,p):s.namespaceURI===Ee?Ds(d,c,p):!!(ht==="application/xhtml+xml"&&hn[s.namespaceURI]):!1},Ce=function(s){xt(e.removed,{element:s});try{G(s).removeChild(s)}catch{if(O(s),!G(s))throw De("a node selected for removal could not be detached from its tree and cannot be safely returned; refusing to sanitize in place")}},cr=function(s,c,d){try{j(s,c)}catch{try{s.removeAttribute(d)}catch{}}},Dt=function(s){Pt(s);let c=$(s);if(c){let p=[];qe(c,x=>{xt(p,x)}),qe(p,x=>{try{O(x)}catch{}})}let d=W(s);if(d)for(let p=d.length-1;p>=0;--p){let x=d[p],N=x&&x.name;typeof N=="string"&&cr(s,x,N)}},Fe=function(s,c,d){if(!d)try{d=c.getAttributeNode(s)}catch{d=null}xt(e.removed,{attribute:d||null,from:c});try{d?j(c,d):c.removeAttribute(s)}catch{try{c.removeAttribute(s)}catch{}}if(s==="is")if(Le||Lt)try{Ce(c)}catch{}else try{c.setAttribute(s,"")}catch{}},Us=function(s){let c=W(s);if(c)for(let d=c.length-1;d>=0;--d){let p=c[d],x=p&&p.name;typeof x!="string"||B[Y(x)]||cr(s,p,x)}},Pt=function(s){let c=[s];for(;c.length>0;){let d=c.pop();pe(d)===he.element&&Us(d);let p=$(d);if(p)for(let x=p.length-1;x>=0;--x)c.push(p[x])}},lr=function(s,c){return y?s==="patchsrc"?!0:s==="for"&&c!=="label"&&c!=="output":!1},zs=function(s){if(!y)return;let c=[s];for(;c.length>0;){let d=c.pop(),p=pe(d);if(p===he.processingInstruction||p===he.comment&&ne(ls,d.data)){try{O(d)}catch{}continue}if(p===he.element){let N=d,C=Y(re(d));try{N.hasAttribute&&N.hasAttribute("patchsrc")&&N.removeAttribute("patchsrc"),N.hasAttribute&&N.hasAttribute("for")&&lr("for",C)&&N.removeAttribute("for")}catch{}}let x=$(d);if(x)for(let N=x.length-1;N>=0;--N)c.push(x[N])}},ur=function(s){let c=null,d=null;if(dt)s="<remove></remove>"+s;else{let N=Qa(s,/^[\r\n\t ]+/);d=N&&N[0]}ht==="application/xhtml+xml"&&et===Ee&&(s='<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>'+s+"</body></html>");let p=J?xe(s):s;if(et===Ee)try{c=new m().parseFromString(p,ht)}catch{}if(!c||!c.documentElement){c=k.createDocument(et,"template",null);try{c.documentElement.innerHTML=dn?ge:p}catch{}}let x=c.body||c.documentElement;return s&&d&&x.insertBefore(n.createTextNode(d),x.childNodes[0]||null),et===Ee?ie.call(c,T?"html":"body")[0]:T?c.documentElement:x},dr=function(s){let c=K?K(s):s.ownerDocument;return U.call(c||s,s,u.SHOW_ELEMENT|u.SHOW_COMMENT|u.SHOW_TEXT|u.SHOW_PROCESSING_INSTRUCTION|u.SHOW_CDATA_SECTION,null)},Ut=function(s){return s=Et(s,me," "),s=Et(s,kt," "),s=Et(s,Nt," "),s},mn=function(s){var c;s.normalize();let d=K?K(s):s.ownerDocument,p=U.call(d||s,s,u.SHOW_TEXT|u.SHOW_COMMENT|u.SHOW_CDATA_SECTION|u.SHOW_PROCESSING_INSTRUCTION,null),x=p.nextNode();for(;x;)x.data=Ut(x.data),x=p.nextNode();let N=(c=s.querySelectorAll)===null||c===void 0?void 0:c.call(s,"template");N&&qe(N,C=>{nt(C.content)&&mn(C.content)})},zt=function(s){let c=F?F(s):null;return typeof c!="string"||Y(c)!=="form"?!1:typeof s.nodeName!="string"||typeof s.textContent!="string"||typeof s.removeChild!="function"||s.attributes!==W(s)||typeof s.removeAttribute!="function"||typeof s.removeAttributeNode!="function"||typeof s.getAttributeNode!="function"||typeof s.setAttribute!="function"||typeof s.namespaceURI!="string"||typeof s.insertBefore!="function"||typeof s.hasChildNodes!="function"||s.nodeType!==M(s)||s.childNodes!==$(s)},nt=function(s){if(!M||typeof s!="object"||s===null)return!1;try{return M(s)===he.documentFragment}catch{return!1}},ft=function(s){if(!M||typeof s!="object"||s===null)return!1;try{return typeof M(s)=="number"}catch{return!1}};function Te(f,s,c){f.length!==0&&qe(f,d=>{d.call(e,s,c,tt)})}let Bs=function(s,c){return!!(y&&s.hasChildNodes()&&!ft(s.firstElementChild)&&ne(cs,s.textContent)&&ne(cs,s.innerHTML)||y&&s.namespaceURI===Ee&&pc[c]&&(ft(s.firstElementChild)||typeof s.textContent=="string"&&ne(gc[c],s.textContent))||s.nodeType===he.processingInstruction||y&&s.nodeType===he.comment&&ne(ls,s.data))},Bt=function(s,c){if(s instanceof RegExp)return ne(s,c);if(s instanceof Function){for(var d=arguments.length,p=new Array(d>2?d-2:0),x=2;x<d;x++)p[x-2]=arguments[x];return!!s(c,...p)}return!1},Hs=function(s,c,d){if(!Oe[c]&&gr(c)&&Bt(_.tagNameCheck,c))return!1;if(ln&&!Qe[c]){let p=G(s),x=$(s);if(x&&p){let N=x.length;for(let C=N-1;C>=0;--C){let q=s===d?R(x[C],!0):x[C];p.insertBefore(q,H(s))}}}return Ce(s),!0},hr=function(s,c,d,p){return s.length===0?c:c===d||c===p?fe(c):c},rt=function(s,c){return s===c||G(s)!==null?!1:(un&&Pt(s),!0)},fr=function(s,c){if(Te(S.beforeSanitizeElements,s,null),rt(s,c))return!0;if(zt(s))return Ce(s),!0;let d=Y(re(s));if(z=hr(S.uponSanitizeElement,z,oe,V),Te(S.uponSanitizeElement,s,{tagName:d,allowedTags:z}),rt(s,c))return!0;if(Bs(s,d))return Ce(s),!0;if(Oe[d]||!(L.tagCheck instanceof Function&&L.tagCheck(d))&&!z[d]){let p=Hs(s,d,c);return p===!1&&(Te(S.afterSanitizeElements,s,null),rt(s,c))?!0:p}if(pe(s)===he.element&&!Ps(s)||(d==="noscript"||d==="noembed"||d==="noframes")&&ne(hc,s.innerHTML))return Ce(s),!0;if(g&&s.nodeType===he.text){let p=Ut(s.textContent);s.textContent!==p&&(xt(e.removed,{element:s.cloneNode()}),s.textContent=p)}return Te(S.afterSanitizeElements,s,null),rt(s,c)},pr=function(s,c,d){if(X[c]||lr(c,s)||Yn&&(c==="id"||c==="name")&&(d in n||d in Cs))return!1;let p=B[c]||L.attributeCheck instanceof Function&&L.attributeCheck(c,s);return ve&&ne(Rt,c)||He&&ne(sn,c)?!0:p?tr[c]||ne(ze,Et(d,Ot,""))||(c==="src"||c==="xlink:href"||c==="href")&&s!=="script"&&es(d,"data:")===0&&Qn[s]||Xe&&!ne(on,Et(d,Ot,""))?!0:!d:gr(s)&&Bt(_.tagNameCheck,s)&&Bt(_.attributeNameCheck,c,s)||c==="is"&&_.allowCustomizedBuiltInElements&&Bt(_.tagNameCheck,d)},Fs=D({},["annotation-xml","color-profile","font-face","font-face-format","font-face-name","font-face-src","font-face-uri","missing-glyph"]),gr=function(s){return!Fs[wt(s)]&&ne(cn,s)},js=function(s,c,d,p){if(J&&typeof b=="object"&&typeof b.getAttributeType=="function"&&!d)switch(b.getAttributeType(s,c)){case"TrustedHTML":return xe(p);case"TrustedScriptURL":return h(p)}return p},$s=function(s,c,d,p){try{return d?s.setAttributeNS(d,c,p):s.setAttribute(c,p),zt(s)?(Ce(s),!1):!0}catch{return Fe(c,s),!1}},mr=function(s,c){if(Te(S.beforeSanitizeAttributes,s,null),rt(s,c))return;let d=s.attributes;if(!d||zt(s))return;B=hr(S.uponSanitizeAttribute,B,Be,ce);let p={attrName:"",attrValue:"",keepAttr:!0,allowedAttributes:B,forceKeepAttr:void 0},x=d.length,N=Y(s.nodeName);for(;x--;){let C=d[x],q=C.name,be=C.namespaceURI,de=C.value,at=Y(q),yn=de,ae=q==="value"?yn:Vo(yn),br=!1;if(p.attrName=at,p.attrValue=ae,p.keepAttr=!0,p.forceKeepAttr=void 0,Te(S.uponSanitizeAttribute,s,p),ae=p.attrValue,Xn&&(at==="id"||at==="name")&&es(ae,Zn)!==0&&(Fe(q,s,C),ae=Zn+ae,br=!0),y&&ne(/((--!?|])>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,ae)){Fe(q,s,C);continue}if(at==="attributename"&&Qa(ae,"href")){Fe(q,s,C);continue}if(!p.forceKeepAttr){if(!p.keepAttr){Fe(q,s,C);continue}if(!Ze&&ne(fc,ae)){Fe(q,s,C);continue}if(g&&(ae=Ut(ae)),!pr(N,at,ae)){Fe(q,s,C);continue}ae=js(N,at,be,ae),ae!==yn&&$s(s,q,be,ae)&&br&&Ja(e.removed)}}Te(S.afterSanitizeAttributes,s,null),rt(s,c)},Ht=function(s){let c=null,d=dr(s);for(Te(S.beforeSanitizeShadowDOM,s,null);c=d.nextNode();)if(Te(S.uponSanitizeShadowNode,c,null),fr(c,s),mr(c,s),nt(c.content)&&Ht(c.content),pe(c)===he.element){let p=P(c);nt(p)&&(bn(p),Ht(p))}Te(S.afterSanitizeShadowDOM,s,null)},bn=function(s){let c=[{node:s,shadow:null}];for(;c.length>0;){let d=c.pop();if(d.shadow){Ht(d.shadow);continue}let p=d.node,x=pe(p)===he.element,N=$(p);if(N)for(let C=N.length-1;C>=0;--C)c.push({node:N[C],shadow:null});if(x){let C=F?F(p):null;if(typeof C=="string"&&Y(C)==="template"){let q=p.content;nt(q)&&c.push({node:q,shadow:null})}}if(x){let C=P(p);nt(C)&&c.push({node:null,shadow:C},{node:C,shadow:null})}}};return e.sanitize=function(f){let s=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},c=null,d=null,p=null,x=null;if(dn=!f,dn&&(f="<!-->"),typeof f!="string"&&!ft(f)&&(f=Qo(f),typeof f!="string"))throw De("dirty is not a string, aborting");if(!e.isSupported)return f;I?(z=V,B=ce):gn(s),(S.uponSanitizeElement.length>0||S.uponSanitizeAttribute.length>0)&&(z=fe(z)),S.uponSanitizeAttribute.length>0&&(B=fe(B)),e.removed=[];let N=un&&typeof f!="string"&&ft(f);if(N){zs(f);let be=re(f);if(typeof be=="string"){let de=Y(be);if(!z[de]||Oe[de])throw Dt(f),De("root node is forbidden and cannot be sanitized in-place")}if(zt(f))throw Dt(f),De("root node is clobbered and cannot be sanitized in-place");try{bn(f)}catch(de){throw Dt(f),de}}else if(ft(f))c=ur("<!---->"),d=c.ownerDocument.importNode(f,!0),d.nodeType===he.element&&d.nodeName==="BODY"||d.nodeName==="HTML"?c=d:c.appendChild(d),bn(c);else{if(!Le&&!g&&!T&&f.indexOf("<")===-1)return J&&Ct?xe(f):f;if(c=ur(f),!c)return Le?null:Ct?ge:""}c&&dt&&Ce(c.firstChild);let C=N?f:c;try{let be=dr(C);for(;p=be.nextNode();)fr(p,C),mr(p,C),nt(p.content)&&Ht(p.content)}catch(be){throw N&&(Dt(f),qe(e.removed,de=>{de.element&&Pt(de.element)})),be}if(N){let be=!1;if(qe(e.removed,de=>{de.element&&(de.element===f&&(be=!0),Pt(de.element))}),be)throw De("a node selected for removal could not be safely returned; refusing to sanitize in place");return g&&mn(f),f}if(Le){if(g&&mn(c),Lt)for(x=ee.call(c.ownerDocument);c.firstChild;)x.appendChild(c.firstChild);else x=c;return(B.shadowroot||B.shadowrootmode)&&(x=Ne.call(r,x,!0)),x}let q=T?c.outerHTML:c.innerHTML;return T&&z["!doctype"]&&c.ownerDocument&&c.ownerDocument.doctype&&c.ownerDocument.doctype.name&&ne(uc,c.ownerDocument.doctype.name)&&(q="<!DOCTYPE "+c.ownerDocument.doctype.name+`>
`+q),g&&(q=Ut(q)),J&&Ct?xe(q):q},e.setConfig=function(){let f=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};gn(f),I=!0,V=z,ce=B},e.clearConfig=function(){tt=null,I=!1,V=null,ce=null,J=Ue,ge=""},e.isValidAttribute=function(f,s,c){tt||gn({});let d=Y(f),p=Y(s);return pr(d,p,c)},e.addHook=function(f,s){typeof s=="function"&&ue(S,f)&&xt(S[f],s)},e.removeHook=function(f,s){if(ue(S,f)){if(s!==void 0){let c=qo(S[f],s);return c===-1?void 0:Ko(S[f],c,1)[0]}return Ja(S[f])}},e.removeHooks=function(f){ue(S,f)&&(S[f]=[])},e.removeAllHooks=function(){S=us()},e}var At=ps();var gs="vitrine",yc=Object.freeze(["a","abbr","b","blockquote","br","caption","code","col","colgroup","dd","del","details","div","dl","dt","em","figcaption","figure","h1","h2","h3","h4","h5","h6","hr","i","img","input","ins","kbd","li","mark","ol","p","pre","q","s","samp","small","span","strong","sub","summary","sup","table","tbody","td","tfoot","th","thead","tr","u","ul","var"]),ms=Object.freeze(["align","alt","checked","class","colspan","dir","disabled","height","href","lang","open","rowspan","span","src","start","title","type","width"]),vc=/^language-[\w#+.-]{1,40}$/,St;function nn(){if(St!==void 0)return St;St=null;let t=globalThis.trustedTypes;if(t&&typeof t.createPolicy=="function")try{St=t.createPolicy(gs,{createHTML:e=>e,createScriptURL:e=>e})}catch{console.warn(`[vitrine] Could not create the "${gs}" Trusted Types policy. Add it to your CSP "trusted-types" directive.`)}return St??null}function bs(t){let e=document.createDocumentFragment();return e.append(document.createTextNode(String(t))),e}var Ke;function ys(){if(Ke!==void 0)return Ke;Ke=!1;try{if(!At.isSupported)return!1;let t=At.sanitize('<img src="x" onerror="1"><script>1<\/script><a href="javascript:1">a</a>',{RETURN_DOM_FRAGMENT:!0,...nn()?{TRUSTED_TYPES_POLICY:nn()}:{}}),e=t.querySelector("img");Ke=t instanceof DocumentFragment&&e!==null&&!e.hasAttribute("onerror")&&t.querySelector("script")===null&&!t.querySelector("a")?.hasAttribute("href")}catch{Ke=!1}return Ke||console.warn("[vitrine] HTML sanitizer unavailable: rich content is shown as plain text."),Ke}function hu(t,e={}){if(!ys())return bs(t);let n=nn(),r={ALLOWED_TAGS:[...yc],ALLOWED_ATTR:e.lineMarkers?[...ms,"data-vt-line"]:[...ms],ALLOW_DATA_ATTR:!1,ALLOW_ARIA_ATTR:!1,ALLOW_UNKNOWN_PROTOCOLS:!1,SAFE_FOR_TEMPLATES:!1,WHOLE_DOCUMENT:!1,RETURN_DOM_FRAGMENT:!0,KEEP_CONTENT:!0};n&&(r.TRUSTED_TYPES_POLICY=n);let a=At.sanitize(String(t),r);return xc(a,e),a}var _c=/^(?:hljs-[\w-]{1,40}|[a-z]{1,20}_{1,2})$/;function vs(t){if(!ys())return bs(t);let e=nn(),n={ALLOWED_TAGS:["span"],ALLOWED_ATTR:["class"],ALLOW_DATA_ATTR:!1,ALLOW_ARIA_ATTR:!1,RETURN_DOM_FRAGMENT:!0,KEEP_CONTENT:!0};e&&(n.TRUSTED_TYPES_POLICY=e);let r=At.sanitize(String(t),n);for(let a of Array.from(r.querySelectorAll("[class]"))){let i=Array.from(a.classList).filter(o=>_c.test(o));i.length?a.setAttribute("class",i.join(" ")):a.removeAttribute("class")}return r}function xc(t,e){let n=e.images??"allow",r=(e.externalLinks??"new-tab")==="new-tab",a=e.baseUrl;for(let i of Array.from(t.querySelectorAll("[data-vt-line]"))){let o=/^(\d{1,9}):(.+)$/.exec(i.getAttribute("data-vt-line")??"");o&&e.lineMarkers&&o[2]===e.lineMarkers&&i.localName==="span"&&!i.hasChildNodes()?i.setAttribute("data-vt-line",o[1]):i.removeAttribute("data-vt-line")}for(let i of Array.from(t.querySelectorAll("[class]"))){let o=Array.from(i.classList).filter(l=>i.localName==="code"&&vc.test(l));o.length?i.setAttribute("class",o.join(" ")):i.removeAttribute("class")}for(let i of Array.from(t.querySelectorAll("a")))Ec(i,r,a);for(let i of Array.from(t.querySelectorAll("img")))Tc(i,n,a);for(let i of Array.from(t.querySelectorAll("input")))i.getAttribute("type")!=="checkbox"?i.remove():i.setAttribute("disabled","")}function _s(t,e){if(!e||t.startsWith("#")||/^[a-z][a-z0-9+.-]*:/i.test(t.trim()))return t;try{return new URL(t,e).href}catch{return t}}function Ec(t,e,n){let r=t.getAttribute("href");if(r===null)return;if(!pt(r)){t.removeAttribute("href");return}let a=_s(r,n);a!==r&&t.setAttribute("href",a),!a.startsWith("#")&&(gt(a)||(t.setAttribute("rel","noopener noreferrer nofollow"),e&&/^https?:/i.test(a.trim())&&t.setAttribute("target","_blank")))}function Tc(t,e,n){let r=t.getAttribute("src")??"",a=pt(r,{allowDataImage:!0})?_s(r,n):r;if(a!==r&&t.setAttribute("src",a),!(e==="allow"?pt(a,{allowDataImage:!0}):e==="same-origin"&&pt(a)&&gt(a))||!a){let o=t.ownerDocument.createElement("span");o.className="vt-blocked-image",o.textContent=t.getAttribute("alt")||"",o.title=a.length>200?a.slice(0,200)+"\u2026":a,t.replaceWith(o);return}t.setAttribute("loading","lazy"),t.setAttribute("decoding","async"),t.setAttribute("referrerpolicy","no-referrer")}var wc={bash:Pa,diff:Ua,javascript:ja,json:$a,markdown:Ga,plaintext:Wa,python:qa,shell:Ka,xml:Va,yaml:Ya};for(let[t,e]of Object.entries(wc))Ie.registerLanguage(t,e);Ie.configure({ignoreUnescapedHTML:!0,throwUnescapedHTML:!1});var Ac=4e3,Ve=null,xs=new Map;function Ru(t){if(typeof t!="string")return null;let e=t.trim().toLowerCase();if(!e||e.length>40)return null;if(Object.prototype.hasOwnProperty.call(Qt,e))return e;if(!Ve){Ve=new Map;for(let[n,r]of Object.entries(Qt))for(let a of r.split(" "))a&&!Ve.has(a)&&Ve.set(a,n);Ve.set("text","plaintext"),Ve.set("plain","plaintext")}return Ve.get(e)??null}function Es(t){return!!Ie.getLanguage(t)}function Ou(t){if(Es(t))return Promise.resolve(!0);if(!Object.prototype.hasOwnProperty.call(Qt,t))return Promise.resolve(!1);let e=xs.get(t);if(e)return e;let n=Sc(t);return xs.set(t,n),n}async function Sc(t){let e=le().languagesUrl||Pr();if(!e)return!1;try{let n=new URL(`${t}.js`,new URL(e.endsWith("/")?e:`${e}/`,document.baseURI));if(n.protocol!=="https:"&&n.protocol!=="http:")return!1;let r=await import(n.href);return typeof r.default!="function"?!1:(Ie.registerLanguage(t,r.default),!0)}catch(n){return console.warn(`[vitrine] Could not load the "${t}" language.`,n),!1}}function Lu(t){let e=Ie.listLanguages().filter(r=>r!=="plaintext"),n=Ie.highlightAuto(t.slice(0,Ac),e);return n.language&&n.relevance>=3?n.language:"plaintext"}function Ts(t,e){if(e==="plaintext"||!Es(e)){let r=document.createDocumentFragment();return r.append(document.createTextNode(t)),r}let n=Ie.highlight(t,{language:e,ignoreIllegals:!0});return vs(n.value)}function ws(t){let e=[],n=[],r=document.createDocumentFragment(),a=r,i=()=>{e.push(r),r=document.createDocumentFragment(),a=r;for(let l of n){let u=l.cloneNode(!1);a.appendChild(u),a=u}},o=l=>{if(l.nodeType===Node.TEXT_NODE){(l.nodeValue??"").split(`
`).forEach((b,A)=>{A>0&&i(),b&&a.appendChild(document.createTextNode(b))});return}if(l.nodeType!==Node.ELEMENT_NODE)return;let u=l;a.appendChild(u.cloneNode(!1)),a=a.lastChild,n.push(u);for(let m of Array.from(u.childNodes))o(m);n.pop(),a=a.parentNode};for(let l of Array.from(t.childNodes))o(l);return e.push(r),e}function Mu(t){return t.split(`
`).map(e=>{let n=document.createDocumentFragment();return e&&n.appendChild(document.createTextNode(e)),n})}var kc=1e3,As=200;function Nc(t){let e=[],n=[];for(let r of t)r.startsWith("@@")?(e.push("hunk"),n.push(r)):/^(?:\+\+\+|---)(?: |$)|^diff |^index /.test(r)?(e.push("meta"),n.push(r)):r.startsWith("+")?(e.push("added"),n.push(r.slice(1))):r.startsWith("-")?(e.push("removed"),n.push(r.slice(1))):(e.push("context"),n.push(r.startsWith(" ")?r.slice(1):r));return{kinds:e,code:n}}function Ss(t,e){let r=(t.endsWith(`
`)&&!e.trailingNewline?t.slice(0,-1):t).split(`
`),a=null;if(e.diff){let P=Nc(r);a=P.kinds,r=P.code}let i=r.join(`
`),o=i.length>e.highlightLimit,l=o||e.language==="plaintext",u=l?null:ws(Ts(i,e.language)),m=l?i.split(`
`):null,b=u?u.length:m.length,A=e.startLine+b-1,R=Math.max(String(e.startLine).length,String(A).length),O=w("pre",{class:"code",part:"code"});O.style.setProperty("--_digits",String(R));let j=P=>{let W=e.startLine+P,M=a?.[P],F=w("span",{class:"line",part:"line",attrs:{"data-line":W}});if(e.highlightRanges.length&&Gr(W,e.highlightRanges)&&(F.classList.add("highlighted"),F.setAttribute("part","line line-highlighted")),M&&M!=="context"&&F.classList.add(M),e.lineNumbers&&F.append(w("span",{class:"gutter",part:"gutter line-number",attrs:{"aria-hidden":"true","data-n":W}})),a){let pe=M==="added"?e.diffLabels?.added:M==="removed"?e.diffLabels?.removed:"";F.append(w("span",{class:"sign"},pe?w("span",{class:"sr-only",text:`${pe}: `}):null))}let K=w("span",{class:"content"});return u?K.append(u[P]):m?.[P]&&K.append(m[P]),P<b-1&&K.append(`
`),F.append(K),F},H=(P,W,M)=>{let F=document.createDocumentFragment();for(let K=W;K<M;K+=1)F.appendChild(j(K));P.appendChild(F)},$=document.createDocumentFragment();if(e.chunk!==!1&&b>kc)for(let P=0;P<b;P+=As){let W=Math.min(b,P+As),M=w("span",{class:"chunk",attrs:{"data-first":e.startLine+P,"data-count":W-P}});M.style.setProperty("--_chunk-lines",String(W-P)),$.append(M),P===0?H(M,P,W):(M.setAttribute("data-pending",""),na(M,()=>{M.removeAttribute("data-pending"),H(M,P,W)}))}else H($,0,b);return O.append($),{element:w("div",{class:"code-view"},O),code:O,lineCount:b,highlightSkipped:o}}function Hu(t){t&&(t.closest(".chunk")?.classList.add("revealed"),t.scrollIntoView({block:"nearest",inline:"nearest"}))}var rn=class{constructor(e){this.steps=[{value:e,start:0,end:0}],this.index=0,this.lastKind="",this.lastTime=0,this.listeners=new Set}get canUndo(){return this.index>0}get canRedo(){return this.index<this.steps.length-1}get current(){return this.steps[this.index]}record(e,n){if(e.value===this.current.value)return;let r=Date.now(),i=(n==="insertText"||n.startsWith("delete"))&&n===this.lastKind&&r-this.lastTime<600&&!this.canRedo;this.steps.length=this.index+1,i&&this.index>0?this.steps[this.index]=e:(this.steps.push(e),this.index+=1),this.lastKind=n,this.lastTime=r,this.trim(),this.notify()}undo(){return this.canUndo?(this.index-=1,this.lastKind="",this.notify(),this.current):null}redo(){return this.canRedo?(this.index+=1,this.lastKind="",this.notify(),this.current):null}trim(){let e=this.steps.reduce((n,r)=>n+r.value.length,0);for(;this.steps.length>1&&(this.steps.length>300||e>2e7)&&this.index>0;)e-=this.steps.shift().value.length,this.index-=1}subscribe(e){return this.listeners.add(e),()=>this.listeners.delete(e)}notify(){for(let e of this.listeners)e()}};var Rc=6e4,Oc=250,an="  ",ks=class{constructor(e){this.options=e,this.text=e.text,this.tabReleased=!1,this.changedSinceFocus=!1,this.timer=void 0,this.textarea=w("textarea",{class:"editor-input",part:"editor",attrs:{"aria-label":e.label,placeholder:e.placeholder??null,spellcheck:"false",autocapitalize:"off",autocomplete:"off",autocorrect:"off",wrap:e.wrap?"soft":"off","data-focus-key":"editor"}}),this.textarea.value=e.text,this.history=e.history&&e.history.current.value===e.text?e.history:new rn(e.text),this.layer=this.buildLayer(e.text),this.element=w("div",{class:e.wrap?"editor wrap":"editor"},this.layer,this.textarea),this.textarea.addEventListener("input",n=>this.onInput(n.inputType||"other")),this.textarea.addEventListener("beforeinput",n=>{(n.inputType==="historyUndo"||n.inputType==="historyRedo")&&(n.preventDefault(),n.inputType==="historyUndo"?this.undo():this.redo())}),this.textarea.addEventListener("keydown",n=>this.onKeyDown(n)),this.textarea.addEventListener("focus",()=>{this.changedSinceFocus=!1}),this.textarea.addEventListener("blur",()=>{this.changedSinceFocus&&e.onChange?.(this.text)})}buildLayer(e){let n=Ss(e,{language:this.options.language,lineNumbers:this.options.lineNumbers,startLine:1,highlightRanges:this.options.highlightRanges??[],diff:!1,highlightLimit:this.options.highlightLimit,trailingNewline:!0,chunk:!1});return n.element.classList.add("editor-layer"),n.element.setAttribute("aria-hidden","true"),n.element}refresh(){clearTimeout(this.timer);let e=this.buildLayer(this.text);this.layer.replaceWith(e),this.layer=e,this.element.classList.remove("pending"),this.align()}align(){let e=this.layer.querySelector(".gutter"),n=e?e.getBoundingClientRect().width:0;this.element.style.setProperty("--_editor-gutter",`${n}px`)}setHighlightRanges(e){this.options.highlightRanges=e,this.refresh()}onInput(e){this.text=this.textarea.value.replace(/\r\n?/g,`
`),this.changedSinceFocus=!0,this.history.record({value:this.text,start:this.textarea.selectionStart,end:this.textarea.selectionEnd},e),this.text.length<=Rc?this.refresh():(this.element.classList.add("pending"),clearTimeout(this.timer),this.timer=setTimeout(()=>this.refresh(),Oc)),this.options.onInput(this.text)}onKeyDown(e){let n=e.ctrlKey||e.metaKey,r=e.key.toLowerCase();if(n&&!e.altKey&&(r==="z"||r==="y")){e.preventDefault(),r==="y"||e.shiftKey?this.redo():this.undo();return}if(e.key==="Escape"){this.tabReleased=!0;return}if(e.key==="Tab"&&!this.tabReleased&&!e.ctrlKey&&!e.metaKey&&!e.altKey){e.preventDefault(),e.shiftKey?this.outdent():this.indent();return}if(e.key!=="Tab"&&(this.tabReleased=!1),e.key==="Enter"&&!e.shiftKey&&!e.ctrlKey&&!e.metaKey&&!e.isComposing){let{value:a,selectionStart:i}=this.textarea,o=a.lastIndexOf(`
`,i-1)+1,l=/^[ \t]*/.exec(a.slice(o,i))?.[0]??"";l&&(e.preventDefault(),this.insert(`
${l}`))}}indent(){let{value:e,selectionStart:n,selectionEnd:r}=this.textarea;if(n===r||!e.slice(n,r).includes(`
`)){this.insert(an);return}let a=e.lastIndexOf(`
`,n-1)+1,i=e.slice(a,r),o=i.replace(/^/gm,an);this.replaceRange(a,r,o),this.textarea.setSelectionRange(n+an.length,r+(o.length-i.length))}outdent(){let{value:e,selectionStart:n,selectionEnd:r}=this.textarea,a=e.lastIndexOf(`
`,n-1)+1,i=e.slice(a,r),o=new RegExp(`^(?:\\t| {1,${an.length}})`,"gm"),l=(/^(?:\t| {1,2})/.exec(i)?.[0]??"").length,u=i.replace(o,"");u!==i&&(this.replaceRange(a,r,u),this.textarea.setSelectionRange(Math.max(a,n-l),r-(i.length-u.length)))}insert(e){this.textarea.focus(),document.execCommand?.("insertText",!1,e)||(this.textarea.setRangeText(e,this.textarea.selectionStart,this.textarea.selectionEnd,"end"),this.onInput("insertText"))}replaceRange(e,n,r){this.textarea.setSelectionRange(e,n),this.insert(r)}undo(){this.restore(this.history.undo())}redo(){this.restore(this.history.redo())}restore(e){e&&(this.textarea.value=e.value,this.textarea.focus(),this.textarea.setSelectionRange(e.start,e.end),this.text=e.value,this.changedSinceFocus=!0,this.refresh(),this.options.onInput(this.text))}destroy(){clearTimeout(this.timer)}};export{$r as a,dl as b,it as c,hl as d,Ln as e,fl as f,pl as g,le as h,Qs as i,w as j,Yr as k,se as l,Ai as m,$t as n,Jr as o,ea as p,we as q,Re as r,ni as s,Tr as t,hi as u,pi as v,gi as w,Sn as x,Kc as y,mi as z,$e as A,El as B,Li as C,aa as D,Al as E,_e as F,Ol as G,oa as H,ca as I,Ll as J,la as K,pa as L,Ie as M,hu as N,Ru as O,Es as P,Ou as Q,Lu as R,Ts as S,ws as T,Mu as U,Ss as V,Hu as W,ks as X,tl as Y};
/*! Bundled license information:

dompurify/dist/purify.es.mjs:
  (*! @license DOMPurify 3.4.16 | (c) Cure53 and other contributors | Released under the Apache license 2.0 and Mozilla Public License 2.0 | github.com/cure53/DOMPurify/blob/3.4.16/LICENSE *)
  (*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/babel/babel/blob/main/packages/babel-helpers/LICENSE *)
*/
