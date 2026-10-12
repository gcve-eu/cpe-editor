/*! Vitrine v0.0.0 | MIT License | https://github.com/ecrou-exact/vitrine
 * Includes: highlight.js 11.12.0 (BSD-3-Clause), marked 18.1.0 (MIT), DOMPurify 3.4.16 (Apache-2.0 OR MPL-2.0), Lucide 1.52.0 (ISC; icons derived from Feather: MIT).
 * Full license texts: THIRD_PARTY_NOTICES.md */
var Ge=Object.create;var W=Object.defineProperty;var $e=Object.getOwnPropertyDescriptor;var Ye=Object.getOwnPropertyNames;var Qe=Object.getPrototypeOf,Je=Object.prototype.hasOwnProperty;var jt=(t,e)=>()=>{try{return e||t((e={exports:{}}).exports,e),e.exports}catch(a){throw e=0,a}};var We=(t,e,a,r)=>{if(e&&typeof e=="object"||typeof e=="function")for(let n of Ye(e))!Je.call(t,n)&&n!==a&&W(t,n,{get:()=>e[n],enumerable:!(r=$e(e,n))||r.enumerable});return t};var Ot=(t,e,a)=>(a=t!=null?Ge(Qe(t)):{},We(e||!t||!t.__esModule?W(a,"default",{value:t,enumerable:!0}):a,t));var X="",K="",Z="";function ee(t){X=t}function Pt(){return X}function te(t){Z=t}function zt(){return Z}function O(t){K=t}function ae(){return K}function Ht(t){ee(new URL("languages/",t).href),O(new URL("syntax-themes/",t).href),te(new URL("vendor/",t).href)}var I=Object.freeze({theme:"auto",lightTheme:"light",darkTheme:"dark",lang:"en",maxSize:2097152,highlightLimit:3e5,maxDepth:512,fetchTimeout:15e3,languagesUrl:"",syntaxTheme:"",syntaxThemeDark:"",syntaxThemesUrl:"",vendorUrl:""}),Xe=Object.freeze({maxSize:50*1024*1024,highlightLimit:5*1024*1024,maxDepth:1e4,fetchTimeout:12e4}),x={...I},P=new Set;function u(){return Object.freeze({...x})}function qt(t){if(!t||typeof t!="object")return u();let e={...x};for(let[r,n]of Object.entries(t))Ke(r,n);let a=new Set(Object.keys(x).filter(r=>x[r]!==e[r]));if(a.size)for(let r of P)r(a);return u()}function Ke(t,e){if(!Object.prototype.hasOwnProperty.call(I,t)){console.warn(`[vitrine] Unknown configuration option "${t}".`);return}let a=t;if(typeof I[a]==="number"){let n=Xe[a];if(typeof e!="number"||!Number.isFinite(e)||e<=0){console.warn(`[vitrine] Option "${t}" must be a positive number.`);return}x[a]=Math.min(Math.floor(e),n??e);return}if(typeof e!="string"||e.length>2048){console.warn(`[vitrine] Option "${t}" must be a string.`);return}x[a]=e.trim()}function re(t){return P.add(t),()=>P.delete(t)}var g=Object.freeze({READY:"vt-ready",COPY:"vt-copy",SEARCH:"vt-search",TAB_CHANGE:"vt-tab-change",INPUT:"vt-input",CHANGE:"vt-change",MODE_CHANGE:"vt-mode-change",TAG_ADD:"vt-tag-add",TAG_REMOVE:"vt-tag-remove",TAG_CREATE:"vt-tag-create",TAG_CLICK:"vt-tag-click",SORT:"vt-sort",FULLSCREEN_CHANGE:"vt-fullscreen-change",LAYOUT_CHANGE:"vt-layout-change",SELECT:"vt-select",TOGGLE:"vt-toggle",FILTER_CHANGE:"vt-filter-change",TYPING_END:"vt-typing-end",CHANGE_NAVIGATE:"vt-change-navigate",ERROR:"vt-error"});function m(t,e,a){return t.dispatchEvent(new CustomEvent(e,{detail:a,bubbles:!0,composed:!0,cancelable:!0}))}var F=Object.freeze({copy:"Copy",copyCode:"Copy code",copied:"Copied",copyFailed:"Copy failed",copySource:"Copy source",download:"Download",search:"Search",searchPlaceholder:"Search\u2026",searchNext:"Next match",searchPrevious:"Previous match",searchClose:"Close search",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"No matches",searchResults:"{total} matches",wrap:"Toggle line wrap",showMore:"Show all {count} lines",preview:"Preview",source:"Source",split:"Split",swapPanes:"Swap panes",stackPanes:"Stack panes",syncScroll:"Sync scrolling",tabs:"View",actions:"Actions",toc:"Table of contents",anchor:"Link to this section",table:"Table",tree:"Tree",raw:"Raw",expandAll:"Expand all",collapseAll:"Collapse all",copyPath:"Copy path",copyValue:"Copy value",items:"{count} items",item:"1 item",keys:"{count} keys",key:"1 key",showMoreItems:"Show {count} more",showFullString:"Show full string ({count} characters)",truncated:"Partially expanded: too many nodes.",loading:"Loading\u2026",errorTitle:"Unable to display content",invalidJson:"Invalid JSON at line {line}, column {column}: {message}.",invalidJsonRaw:"Invalid JSON at line {line}, column {column} \u2014 showing raw text.",empty:"Nothing to display",tooLarge:"Content is too large ({size} characters, limit {limit}).",tooDeep:"Nesting is too deep (limit {limit}).",tooComplex:"This document is nested too deeply to display.",unserializable:"This value cannot be converted to JSON (circular reference or BigInt).",highlightSkipped:"Content is large: syntax highlighting is disabled.",loadFailed:'Could not load "{url}": {reason}',remoteBlocked:'Cross-origin URL blocked. Add the "allow-remote" attribute to allow it.',unsafeUrl:"URL blocked: only http(s) URLs can be loaded.",timeout:"Request timed out.",added:"Added",removed:"Removed",code:"Code",edit:"Edit",splitView:"Side by side",unifiedView:"Unified",diffStats:"+{added} \u2212{removed}",diffSimplified:"Many changes: the comparison is simplified to removed and added blocks.",noDifferences:"No differences",previousChange:"Previous change",nextChange:"Next change",changePosition:"{current} of {total}",changeTotal:"{count} changes",terminal:"Terminal",command:"Command",copyCommand:"Copy command",copyCommands:"Copy commands",replay:"Replay",showMoreLines:"Show {count} more lines",files:"Files",copyTree:"Copy tree",treeStats:"{folders} folders, {files} files",invalidTree:"This tree could not be read: {message}",treeTruncated:"Only the first {limit} entries are shown.",status_added:"added",status_removed:"removed",status_modified:"modified",status_highlighted:"highlighted",httpExchange:"Exchange",httpRequest:"Request",httpResponse:"Response",httpBody:"Body",httpHeaders:"Headers",httpQuery:"Query",httpNone:"None",httpNoBody:"No body",copyUrl:"Copy URL",codeLanguage:"Language",showSecrets:"Show secrets",hideSecrets:"Hide secrets",secretsShown:"Secrets shown",secretsHidden:"Secrets hidden",secretsInCode:"Credentials are masked in this code. Replace them with your own.",invalidHttp:"This HTTP message could not be read: {message}",log:"Log",followLog:"Follow new lines",levelToggle:"Show or hide {level} entries",logNoMatch:"No entry matches the filters.",chartView:"Chart",legend:"Legend",seriesToggle:"Show or hide {name}",copyData:"Copy data",chartSummary:"{type} with {series} series and {points} points.",chartRange:"{name} from {min} to {max}",chart_line:"Line chart",chart_area:"Area chart",chart_bar:"Bar chart",chart_pie:"Donut chart",chartError:"This data could not be charted: {message}",chartTruncated:"Only the first 5,000 points of each series are shown.",chartLoadFailed:"The chart library could not be loaded: {message}",openapiInvalid:"This API description could not be read: {message}",openapiYamlFailed:"The YAML reader could not be loaded: {message}",openapiTruncated:"Only the first 2,000 endpoints are shown.",openapiServers:"Servers",openapiAuth:"Authentication",openapiEndpoints:"Endpoints",openapiTags:"Tags",openapiAllTags:"All",openapiNoMatch:"No endpoint matches.",openapiDeprecated:"deprecated",openapiParameters:"Parameters",openapiName:"Name",openapiIn:"In",openapiType:"Type",openapiDescription:"Description",openapiRequired:"required",openapiRequestBody:"Request body",openapiResponses:"Responses",openapiExample:"Example",openapiExampleValue:"Example",unchangedLines:"Show {count} unchanged lines",copyPatch:"Copy patch",changes:"Changes",original:"Original",modified:"Modified",patch:"Patch",tags:"Tags",noTags:"No tags",addTag:"Add a tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:'Create "{tag}"',removeTag:"Remove {tag}",tagAdded:"{tag} added",tagRemoved:"{tag} removed",pressAgainToRemove:"Press Backspace again to remove {tag}",tagDuplicate:"{tag} is already selected.",tagDisabled:"{tag} cannot be selected.",tagLimit:"You can select up to {max} tags.",tagNotAllowed:"{tag} is not in the list.",tagTooLong:"{tag} is too long.",tagInvalid:"{tag} is not a valid tag.",tagRefused:"{tag} was refused.",tagsRequired:"Select at least one tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Browse all tags",otherTags:"Other",clearTags:"Remove all tags",filterTags:"Filter tags",tagsFound:"{count} tags",invalidTags:'The tags must be a JSON array, or an object with "value" and "options".',rowsRange:"Rows {from}\u2013{to} of {total}",noRows:"No rows",firstPage:"First page",previousPage:"Previous page",nextPage:"Next page",lastPage:"Last page",sortBy:"Sort by {name}",column:"Column {n}",rowNumber:"Row",csvStatus:"{rows} rows \xD7 {columns} columns",csvUnclosed:"Unclosed quote starting at line {line}.",tooManyColumns:"Only the first {limit} columns are shown.",matchingRows:"{count} matching rows",undo:"Undo",redo:"Redo",fullscreen:"Full screen",exitFullscreen:"Exit full screen",stopEditing:"Stop editing",editor:"Editor",validJson:"Valid JSON"}),Ze=Object.freeze({copy:"Copier",copyCode:"Copier le code",copied:"Copi\xE9",copyFailed:"\xC9chec de la copie",copySource:"Copier la source",download:"T\xE9l\xE9charger",search:"Rechercher",searchPlaceholder:"Rechercher\u2026",searchNext:"R\xE9sultat suivant",searchPrevious:"R\xE9sultat pr\xE9c\xE9dent",searchClose:"Fermer la recherche",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"Aucun r\xE9sultat",searchResults:"{total} r\xE9sultats",wrap:"Activer/d\xE9sactiver le retour \xE0 la ligne",showMore:"Afficher les {count} lignes",preview:"Aper\xE7u",source:"Source",split:"C\xF4te \xE0 c\xF4te",swapPanes:"Inverser les panneaux",stackPanes:"Empiler les panneaux",syncScroll:"Synchroniser le d\xE9filement",tabs:"Affichage",actions:"Actions",toc:"Table des mati\xE8res",anchor:"Lien vers cette section",table:"Tableau",tree:"Arbre",raw:"Brut",expandAll:"Tout d\xE9plier",collapseAll:"Tout replier",copyPath:"Copier le chemin",copyValue:"Copier la valeur",items:"{count} \xE9l\xE9ments",item:"1 \xE9l\xE9ment",keys:"{count} cl\xE9s",key:"1 cl\xE9",showMoreItems:"Afficher {count} de plus",showFullString:"Afficher toute la cha\xEEne ({count} caract\xE8res)",truncated:"D\xE9pliage partiel : trop de n\u0153uds.",loading:"Chargement\u2026",errorTitle:"Impossible d\u2019afficher le contenu",invalidJson:"JSON invalide \xE0 la ligne {line}, colonne {column} : {message}.",invalidJsonRaw:"JSON invalide \xE0 la ligne {line}, colonne {column} \u2014 affichage du texte brut.",empty:"Rien \xE0 afficher",tooLarge:"Contenu trop volumineux ({size} caract\xE8res, limite {limit}).",tooDeep:"Imbrication trop profonde (limite {limit}).",tooComplex:"Ce document est trop imbriqu\xE9 pour \xEAtre affich\xE9.",unserializable:"Cette valeur ne peut pas \xEAtre convertie en JSON (r\xE9f\xE9rence circulaire ou BigInt).",highlightSkipped:"Contenu volumineux : coloration syntaxique d\xE9sactiv\xE9e.",loadFailed:"Impossible de charger \xAB {url} \xBB : {reason}",remoteBlocked:"URL d\u2019une autre origine bloqu\xE9e. Ajoutez l\u2019attribut \xAB allow-remote \xBB pour l\u2019autoriser.",unsafeUrl:"URL bloqu\xE9e : seules les URL http(s) peuvent \xEAtre charg\xE9es.",timeout:"D\xE9lai de la requ\xEAte d\xE9pass\xE9.",added:"Ajout\xE9",removed:"Supprim\xE9",code:"Code",edit:"Modifier",splitView:"C\xF4te \xE0 c\xF4te",unifiedView:"Unifi\xE9",diffStats:"+{added} \u2212{removed}",diffSimplified:"Beaucoup de changements : la comparaison est simplifi\xE9e en blocs retir\xE9s et ajout\xE9s.",noDifferences:"Aucune diff\xE9rence",previousChange:"Modification pr\xE9c\xE9dente",nextChange:"Modification suivante",changePosition:"{current} sur {total}",changeTotal:"Modifications : {count}",terminal:"Terminal",command:"Commande",copyCommand:"Copier la commande",copyCommands:"Copier les commandes",replay:"Rejouer",showMoreLines:"Afficher {count} lignes de plus",files:"Fichiers",copyTree:"Copier l'arborescence",treeStats:"{folders} dossiers, {files} fichiers",invalidTree:"Impossible de lire cette arborescence : {message}",treeTruncated:"Seules les {limit} premi\xE8res entr\xE9es sont affich\xE9es.",status_added:"ajout\xE9",status_removed:"supprim\xE9",status_modified:"modifi\xE9",status_highlighted:"mis en \xE9vidence",httpExchange:"\xC9change",httpRequest:"Requ\xEAte",httpResponse:"R\xE9ponse",httpBody:"Corps",httpHeaders:"En-t\xEAtes",httpQuery:"Param\xE8tres",httpNone:"Aucun",httpNoBody:"Pas de corps",copyUrl:"Copier l'URL",codeLanguage:"Langage",showSecrets:"Afficher les secrets",hideSecrets:"Masquer les secrets",secretsShown:"Secrets affich\xE9s",secretsHidden:"Secrets masqu\xE9s",secretsInCode:"Les identifiants sont masqu\xE9s dans ce code. Remplacez-les par les v\xF4tres.",invalidHttp:"Impossible de lire ce message HTTP : {message}",log:"Journal",followLog:"Suivre les nouvelles lignes",levelToggle:"Afficher ou masquer les entr\xE9es {level}",logNoMatch:"Aucune entr\xE9e ne correspond aux filtres.",chartView:"Graphique",legend:"L\xE9gende",seriesToggle:"Afficher ou masquer {name}",copyData:"Copier les donn\xE9es",chartSummary:"{type} avec {series} s\xE9ries et {points} points.",chartRange:"{name} de {min} \xE0 {max}",chart_line:"Graphique en courbes",chart_area:"Graphique en aires",chart_bar:"Graphique en barres",chart_pie:"Graphique en anneau",chartError:"Impossible de tracer ces donn\xE9es : {message}",chartTruncated:"Seuls les 5 000 premiers points de chaque s\xE9rie sont affich\xE9s.",chartLoadFailed:"Impossible de charger la biblioth\xE8que de graphiques : {message}",openapiInvalid:"Impossible de lire cette description d\u2019API : {message}",openapiYamlFailed:"Impossible de charger le lecteur YAML : {message}",openapiTruncated:"Seuls les 2 000 premiers points d\u2019acc\xE8s sont affich\xE9s.",openapiServers:"Serveurs",openapiAuth:"Authentification",openapiEndpoints:"Points d\u2019acc\xE8s",openapiTags:"Tags",openapiAllTags:"Tous",openapiNoMatch:"Aucun point d\u2019acc\xE8s ne correspond.",openapiDeprecated:"obsol\xE8te",openapiParameters:"Param\xE8tres",openapiName:"Nom",openapiIn:"Emplacement",openapiType:"Type",openapiDescription:"Description",openapiRequired:"requis",openapiRequestBody:"Corps de la requ\xEAte",openapiResponses:"R\xE9ponses",openapiExample:"Exemple",openapiExampleValue:"Exemple",unchangedLines:"Afficher {count} lignes inchang\xE9es",copyPatch:"Copier le patch",changes:"Modifications",original:"Original",modified:"Modifi\xE9",patch:"Patch",tags:"Tags",noTags:"Aucun tag",addTag:"Ajouter un tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:"Cr\xE9er \xAB {tag} \xBB",removeTag:"Retirer {tag}",tagAdded:"{tag} ajout\xE9",tagRemoved:"{tag} retir\xE9",pressAgainToRemove:"Appuyez de nouveau sur Retour arri\xE8re pour retirer {tag}",tagDuplicate:"{tag} est d\xE9j\xE0 s\xE9lectionn\xE9.",tagDisabled:"{tag} ne peut pas \xEAtre s\xE9lectionn\xE9.",tagLimit:"Vous pouvez s\xE9lectionner jusqu\u2019\xE0 {max} tags.",tagNotAllowed:"{tag} n\u2019est pas dans la liste.",tagTooLong:"{tag} est trop long.",tagInvalid:"{tag} n\u2019est pas un tag valide.",tagRefused:"{tag} a \xE9t\xE9 refus\xE9.",tagsRequired:"S\xE9lectionnez au moins un tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Parcourir tous les tags",otherTags:"Autres",clearTags:"Retirer tous les tags",filterTags:"Filtrer les tags",tagsFound:"{count} tags",invalidTags:"Les tags doivent \xEAtre un tableau JSON, ou un objet avec \xAB value \xBB et \xAB options \xBB.",rowsRange:"Lignes {from}\u2013{to} sur {total}",noRows:"Aucune ligne",firstPage:"Premi\xE8re page",previousPage:"Page pr\xE9c\xE9dente",nextPage:"Page suivante",lastPage:"Derni\xE8re page",sortBy:"Trier par {name}",column:"Colonne {n}",rowNumber:"Ligne",csvStatus:"{rows} lignes \xD7 {columns} colonnes",csvUnclosed:"Guillemet non ferm\xE9 \xE0 partir de la ligne {line}.",tooManyColumns:"Seules les {limit} premi\xE8res colonnes sont affich\xE9es.",matchingRows:"{count} lignes correspondantes",undo:"Annuler",redo:"R\xE9tablir",fullscreen:"Plein \xE9cran",exitFullscreen:"Quitter le plein \xE9cran",stopEditing:"Terminer la modification",editor:"\xC9diteur",validJson:"JSON valide"}),E=new Map([["en",F],["fr",Ze]]);function Gt(t,e){if(typeof t!="string"||!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(t))throw new TypeError(`[vitrine] Invalid locale code "${t}".`);let a={};for(let[r,n]of Object.entries(e??{}))Object.prototype.hasOwnProperty.call(F,r)&&typeof n=="string"&&(a[r]=n.slice(0,500));E.set(t,Object.freeze({...E.get(t)??{},...a}));for(let r of z)r()}var z=new Set;function ne(t){return z.add(t),()=>z.delete(t)}function U(t){let e=E.get(t),a=E.get(String(t).split("-")[0]);return(r,n)=>{let s=e?.[r]??a?.[r]??F[r]??String(r);return n?s.replace(/\{(\w+)\}/g,(o,i)=>Object.prototype.hasOwnProperty.call(n,i)?String(n[i]):o):s}}function se(t,e){try{return new Intl.NumberFormat(e).format(t)}catch{return String(t)}}var oe=`/* Vitrine Light \u2014 default light theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
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
`;var ie=`/* Vitrine Dark \u2014 default dark theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
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
`;var le=`/* Vitrine Dim \u2014 softer, blue-grey dark theme for long reading sessions. */
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
`;var ce=`/* Vitrine Paper \u2014 warm, low-glare light theme. */
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
`;var de=`/* Vitrine High Contrast \u2014 maximum legibility (WCAG AAA text contrast). */
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
`;var st=Object.freeze(["bg","surface","surface-sunken","surface-raised","border","border-strong","fg","fg-muted","accent","accent-fg","on-accent","accent-soft","highlight","highlight-current","line-highlight","success","warning","danger","info","diff-added","diff-removed","shadow","syntax-keyword","syntax-string","syntax-number","syntax-function","syntax-type","syntax-comment","syntax-attr","syntax-tag","syntax-meta"]),f=new Map,v=new CSSStyleSheet,ot=/^[a-z][a-z0-9-]{0,39}$/,it=new Set(["auto"]);function lt(t){let e=/\[data-theme='([a-z0-9-]+)'\]/.exec(t)?.[1];if(!e)throw new Error("[vitrine] Theme file without a [data-theme] selector.");let a=/color-scheme:\s*(light|dark)\s*;/.exec(t)?.[1]==="dark"?"dark":"light",r={};for(let[,n,s]of t.matchAll(/--vt-([a-z0-9-]+)\s*:\s*([^;]+);/g))r[n]=s.trim();return{name:e,definition:{colorScheme:a,tokens:r}}}for(let t of[oe,ie,le,ce,de]){let{name:e,definition:a}=lt(t);f.set(e,a)}var na=Object.freeze([...f.keys()]);function ct(t){return typeof t!="string"||t.length===0||t.length>200||/[;{}<>\\]/.test(t)?!1:!/(?:url|image|image-set|cross-fade|element|src)\s*\(|@import|expression/i.test(t)}function sa(t,e={}){if(typeof t!="string"||!ot.test(t)||it.has(t))throw new TypeError(`[vitrine] Invalid theme name "${t}". Use lowercase letters, digits, "-".`);let a=e.colorScheme==="dark"?"dark":e.colorScheme==="light"?"light":void 0,r=e.extends??(a==="dark"?"dark":"light"),n=f.get(r);if(!n)throw new TypeError(`[vitrine] Unknown base theme "${r}".`);let s={...n.tokens};for(let[o,i]of Object.entries(e.tokens??{})){let l=o.replace(/^--vt-/,"");st.includes(l)?ct(i)?s[l]=i.trim():console.warn(`[vitrine] Unsafe or invalid value for theme token "${o}" ignored.`):console.warn(`[vitrine] Unknown theme token "${o}" ignored.`)}return f.set(t,{colorScheme:a??n.colorScheme,tokens:s}),ue(),pe(),t}function oa(){return[...f.keys()]}function he(t){let e=f.get(t);return e?{colorScheme:e.colorScheme,tokens:{...e.tokens}}:void 0}function ue(){for(;v.cssRules.length;)v.deleteRule(0);for(let[t,e]of f){let a=v.insertRule(`.vt[data-theme="${t}"] {}`,v.cssRules.length),r=v.cssRules[a].style;r.setProperty("color-scheme",e.colorScheme);for(let[n,s]of Object.entries(e.tokens))r.setProperty(`--_${n}`,`var(--vt-${n}, ${s})`)}}ue();var H=typeof matchMedia=="function"?matchMedia("(prefers-color-scheme: dark)"):null,D=new Set;function pe(){for(let t of D)t()}H?.addEventListener?.("change",pe);function fe(t){return D.add(t),()=>D.delete(t)}function ge(t){let e=u(),a=t?.trim().toLowerCase()||e.theme;if(a!=="auto"&&!f.has(a)&&(a=f.has(e.theme)?e.theme:"auto"),a!=="auto")return a;let r=H?.matches?e.darkTheme:e.lightTheme;return f.has(r)?r:H?.matches?"dark":"light"}var q=Object.freeze({"1c-light":0,"a11y-dark":1,"a11y-light":0,agate:1,"an-old-hope":1,androidstudio:1,"arduino-light":0,arta:1,ascetic:0,"atom-one-dark":1,"atom-one-dark-reasonable":1,"atom-one-light":0,"base16-3024":1,"base16-apathy":1,"base16-apprentice":1,"base16-ashes":1,"base16-atelier-cave":1,"base16-atelier-cave-light":0,"base16-atelier-dune":1,"base16-atelier-dune-light":0,"base16-atelier-estuary":1,"base16-atelier-estuary-light":0,"base16-atelier-forest":1,"base16-atelier-forest-light":0,"base16-atelier-heath":1,"base16-atelier-heath-light":0,"base16-atelier-lakeside":1,"base16-atelier-lakeside-light":0,"base16-atelier-plateau":1,"base16-atelier-plateau-light":0,"base16-atelier-savanna":1,"base16-atelier-savanna-light":0,"base16-atelier-seaside":1,"base16-atelier-seaside-light":0,"base16-atelier-sulphurpool":1,"base16-atelier-sulphurpool-light":0,"base16-atlas":1,"base16-bespin":1,"base16-black-metal":1,"base16-black-metal-bathory":1,"base16-black-metal-burzum":1,"base16-black-metal-dark-funeral":1,"base16-black-metal-gorgoroth":1,"base16-black-metal-immortal":1,"base16-black-metal-khold":1,"base16-black-metal-marduk":1,"base16-black-metal-mayhem":1,"base16-black-metal-nile":1,"base16-black-metal-venom":1,"base16-brewer":1,"base16-bright":1,"base16-brogrammer":1,"base16-brush-trees":0,"base16-brush-trees-dark":1,"base16-chalk":1,"base16-circus":1,"base16-classic-dark":1,"base16-classic-light":0,"base16-codeschool":1,"base16-colors":1,"base16-cupcake":0,"base16-cupertino":0,"base16-danqing":1,"base16-darcula":1,"base16-dark-violet":1,"base16-darkmoss":1,"base16-darktooth":1,"base16-decaf":1,"base16-default-dark":1,"base16-default-light":0,"base16-dirtysea":0,"base16-dracula":1,"base16-edge-dark":1,"base16-edge-light":0,"base16-eighties":1,"base16-embers":1,"base16-equilibrium-dark":1,"base16-equilibrium-gray-dark":1,"base16-equilibrium-gray-light":0,"base16-equilibrium-light":0,"base16-espresso":1,"base16-eva":1,"base16-eva-dim":1,"base16-flat":1,"base16-framer":1,"base16-fruit-soda":0,"base16-gigavolt":1,"base16-github":0,"base16-google-dark":1,"base16-google-light":0,"base16-grayscale-dark":1,"base16-grayscale-light":0,"base16-green-screen":1,"base16-gruvbox-dark-hard":1,"base16-gruvbox-dark-medium":1,"base16-gruvbox-dark-pale":1,"base16-gruvbox-dark-soft":1,"base16-gruvbox-light-hard":0,"base16-gruvbox-light-medium":0,"base16-gruvbox-light-soft":0,"base16-hardcore":1,"base16-harmonic16-dark":1,"base16-harmonic16-light":0,"base16-heetch-dark":1,"base16-heetch-light":0,"base16-helios":1,"base16-hopscotch":1,"base16-horizon-dark":1,"base16-horizon-light":0,"base16-humanoid-dark":1,"base16-humanoid-light":0,"base16-ia-dark":1,"base16-ia-light":0,"base16-icy-dark":1,"base16-ir-black":1,"base16-isotope":1,"base16-kimber":1,"base16-london-tube":1,"base16-macintosh":1,"base16-marrakesh":1,"base16-materia":1,"base16-material":1,"base16-material-darker":1,"base16-material-lighter":0,"base16-material-palenight":1,"base16-material-vivid":1,"base16-mellow-purple":1,"base16-mexico-light":0,"base16-mocha":1,"base16-monokai":1,"base16-nebula":1,"base16-nord":1,"base16-nova":1,"base16-ocean":1,"base16-oceanicnext":1,"base16-one-light":0,"base16-onedark":1,"base16-outrun-dark":1,"base16-papercolor-dark":1,"base16-papercolor-light":0,"base16-paraiso":1,"base16-pasque":1,"base16-phd":1,"base16-pico":1,"base16-pop":1,"base16-porple":1,"base16-qualia":1,"base16-railscasts":1,"base16-rebecca":1,"base16-ros-pine":1,"base16-ros-pine-dawn":0,"base16-ros-pine-moon":1,"base16-sagelight":0,"base16-sandcastle":1,"base16-seti-ui":1,"base16-shapeshifter":0,"base16-silk-dark":1,"base16-silk-light":0,"base16-snazzy":1,"base16-solar-flare":1,"base16-solar-flare-light":0,"base16-solarized-dark":1,"base16-solarized-light":0,"base16-spacemacs":1,"base16-summercamp":1,"base16-summerfruit-dark":1,"base16-summerfruit-light":0,"base16-synth-midnight-terminal-dark":1,"base16-synth-midnight-terminal-light":0,"base16-tango":1,"base16-tender":1,"base16-tomorrow":0,"base16-tomorrow-night":1,"base16-twilight":1,"base16-unikitty-dark":1,"base16-unikitty-light":0,"base16-vulcan":1,"base16-windows-10":1,"base16-windows-10-light":0,"base16-windows-95":1,"base16-windows-95-light":0,"base16-windows-high-contrast":1,"base16-windows-high-contrast-light":0,"base16-windows-nt":1,"base16-windows-nt-light":0,"base16-woodland":1,"base16-xcode-dusk":1,"base16-zenburn":1,"brown-paper":0,"codepen-embed":1,"color-brewer":0,"cybertopia-cherry":0,"cybertopia-dimmer":0,"cybertopia-icecap":0,"cybertopia-saturated":0,dark:1,default:0,devibeans:1,docco:0,equinox:0,far:1,felipec:1,foundation:0,github:0,"github-dark":1,"github-dark-dimmed":1,gml:1,googlecode:0,"gradient-dark":1,"gradient-light":0,grayscale:0,hybrid:1,idea:0,"intellij-light":0,"ir-black":1,"isbl-editor-dark":1,"isbl-editor-light":0,"kimbie-dark":1,"kimbie-light":0,lightfair:0,lioshi:1,magula:0,"mono-blue":0,monokai:1,"monokai-sublime":1,"night-owl":1,"nnfx-dark":1,"nnfx-light":0,nord:1,obsidian:1,"panda-syntax-dark":1,"panda-syntax-light":0,"paraiso-dark":1,"paraiso-light":0,pojoaque:0,purebasic:0,"qtcreator-dark":1,"qtcreator-light":0,rainbow:1,"rose-pine":1,"rose-pine-dawn":0,"rose-pine-moon":1,routeros:0,"school-book":0,"shades-of-purple":1,srcery:1,"stackoverflow-dark":1,"stackoverflow-light":0,sunburst:1,"tokyo-night-dark":1,"tokyo-night-light":0,"tomorrow-night-blue":1,"tomorrow-night-bright":1,vs:0,"vs-dark":1,vs2015:1,xcode:0,xt256:1});var B=new Map,me=new Map;function be(t){if(typeof t!="string")return null;let e=t.trim().toLowerCase().replace(/\//g,"-");return!e||e.length>60?null:Object.prototype.hasOwnProperty.call(q,e)?e:null}function ua(){return Object.keys(q)}function ve(t){return me.get(t)}function ye(t){let e=B.get(t);if(e)return e;let a=dt(t);return B.set(t,a),a}async function dt(t){let e=u().syntaxThemesUrl||ae();if(!e)return null;try{let a=new URL(`${t}.css`,new URL(e.endsWith("/")?e:`${e}/`,document.baseURI));if(a.protocol!=="https:"&&a.protocol!=="http:")return null;let r=await fetch(a.href,{credentials:"same-origin"});if(!r.ok)throw new Error(`HTTP ${r.status}`);let n=await r.text(),s=new CSSStyleSheet;return s.replaceSync(n),me.set(t,s),s}catch(a){return console.warn(`[vitrine] Could not load the "${t}" syntax theme.`,a),B.delete(t),null}}var xe=`/*
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
`;function w(t){if(t===null)return null;let e=t.trim().toLowerCase();return!(e==="false"||e==="off"||e==="no"||e==="0")}function ga(t,{min:e,max:a,fallback:r}){if(t===null||t.length>32)return r;let n=t.trim();if(!/^[+-]?\d+$/.test(n))return r;let s=Number(n);return Number.isSafeInteger(s)?Math.min(a,Math.max(e,s)):r}function V(t,e,a){if(t===null)return a;let r=t.trim().toLowerCase();return e.includes(r)?r:a}function ma(t,e){if(t===null||t.length>1e3)return null;let a=[];for(let r of t.split(",")){let n=r.trim().toLowerCase();e.includes(n)&&!a.includes(n)&&a.push(n)}return a.length?a:null}var ut=500;function ba(t){if(!t||t.length>1e3*10)return[];let e=[];for(let r of t.split(",")){if(e.length>=ut)break;let n=/^\s*(\d{1,9})\s*(?:-\s*(\d{1,9})\s*)?$/.exec(r);if(!n)continue;let s=Number(n[1]),o=n[2]===void 0?s:Number(n[2]);e.push([Math.min(s,o),Math.max(s,o)])}e.sort((r,n)=>r[0]-n[0]);let a=[];for(let r of e){let n=a[a.length-1];n&&r[0]<=n[1]+1?n[1]=Math.max(n[1],r[1]):a.push([r[0],r[1]])}return a}function va(t,e){let a=0,r=e.length-1;for(;a<=r;){let n=a+r>>1,[s,o]=e[n];if(t<s)r=n-1;else if(t>o)a=n+1;else return!0}return!1}function we(t){if(t===null)return null;let e=t.trim().toLowerCase();return/^\d{1,6}(?:\.\d{1,4})?(?:px|em|rem|vh|svh|lvh|dvh|%|ch|lh)$/.test(e)?e:null}function ke(t,e=200){if(!t)return"";let r=t.slice(0,e*4).replace(/[\u0000-\u001f\u007f-\u009f]/g,"").replace(/\s+/g," ").trim();return r.length>e?r.slice(0,e-1)+"\u2026":r}function _e(t,e){let a=(t??"").split(/[\\/]/).pop()??"",r=/[\u0000-\u001f\u007f<>:"|?*]/g;return a.replace(r,"").replace(/^[.\s]+/,"").trim().slice(0,120)||e}function c(t,e={},...a){let r=document.createElement(t);if(e.class&&(r.className=e.class),e.part&&r.setAttribute("part",e.part),e.attrs)for(let[n,s]of Object.entries(e.attrs))s===!1||s===null||s===void 0||r.setAttribute(n,s===!0?"":String(s));if(e.text!==void 0&&(r.textContent=e.text),e.on)for(let[n,s]of Object.entries(e.on))r.addEventListener(n,s);return pt(r,a),r}function pt(t,e){for(let a of e)a==null||a===!1||t.append(typeof a=="string"?document.createTextNode(a):a)}var Te=0;function Se(t){return Te+=1,`vt-${t}-${Te}`}function A(t){let e=t.replace(/\r\n?/g,`
`).split(`
`);for(;e.length&&e[0].trim()==="";)e.shift();for(;e.length&&e[e.length-1].trim()==="";)e.pop();let a=1/0;for(let r of e){if(r.trim()==="")continue;let n=/^[ \t]*/.exec(r);if(a=Math.min(a,n?n[0].length:0),a===0)break}return!Number.isFinite(a)||a===0?e.join(`
`):e.map(r=>r.slice(a)).join(`
`)}function Ce(t,e){let a,r=(...n)=>{clearTimeout(a),a=setTimeout(()=>t(...n),e)};return r.cancel=()=>clearTimeout(a),r}var ft=new Set(["http:","https:","mailto:","tel:"]),gt=/^data:image\/(?:png|gif|jpe?g|webp|avif);base64,[a-z0-9+/]+=*$/i;function wa(t,e={}){if(typeof t!="string")return!1;let a=t.replace(/^[\u0000- ]+|[\u0000- ]+$/g,"").replace(/[\t\n\r]/g,"");if(a===""||e.allowDataImage&&gt.test(a))return!0;let r=/^([a-z][a-z0-9+.-]*):/i.exec(a);return r?ft.has(r[1].toLowerCase()+":"):!0}function Ee(t){try{return new URL(t,document.baseURI).origin===location.origin}catch{return!1}}var h=class extends Error{constructor(e,a={},r){super(e,r===void 0?void 0:{cause:r}),this.name="VitrineError",this.code=e,this.params=a}},mt=new Set(["text/plain","text/markdown","text/x-markdown","application/json","text/json"]);function Ae(t){for(let r of Array.from(t.children)){let n=bt(r);if(n!==null)return n}let e="";for(let r of Array.from(t.childNodes))r.nodeType===Node.TEXT_NODE||r.nodeType===Node.CDATA_SECTION_NODE?e+=r.nodeValue??"":r.nodeType===Node.ELEMENT_NODE&&(e+=r.textContent??"");let a=A(e);return a===""?null:a}function bt(t){if(t instanceof HTMLTemplateElement){let e=t.content.children.length>0;return A(e?t.innerHTML:t.content.textContent??"")}return t instanceof HTMLScriptElement&&mt.has(t.type.trim().toLowerCase())?A(t.textContent??""):null}function M(t,e){if(t.length>e)throw new h("tooLarge",{size:t.length,limit:e})}async function Me(t,e){let a=vt(t),r=Ee(a.href);if(!r&&!e.allowRemote)throw new h("remoteBlocked");let n=new AbortController,s=setTimeout(()=>n.abort(new h("timeout")),e.timeout),o=()=>n.abort(e.signal?.reason);e.signal?.addEventListener("abort",o,{once:!0}),e.signal?.aborted&&o();try{let i=await fetch(a.href,{mode:r?"same-origin":"cors",credentials:"same-origin",redirect:"follow",referrerPolicy:"strict-origin-when-cross-origin",signal:n.signal});if(!i.ok)throw new h("loadFailed",{url:Re(a),reason:`HTTP ${i.status}`});let l=Number(i.headers.get("content-length"));if(Number.isFinite(l)&&l>e.maxSize*4)throw new h("tooLarge",{size:l,limit:e.maxSize});return await yt(i,e.maxSize,n)}catch(i){throw xt(i,n.signal,a)}finally{clearTimeout(s),e.signal?.removeEventListener("abort",o)}}function vt(t){let e;try{e=new URL(t.trim(),document.baseURI)}catch{throw new h("unsafeUrl")}if(e.protocol!=="http:"&&e.protocol!=="https:")throw new h("unsafeUrl");return e}async function yt(t,e,a){if(!t.body){let o=await t.text();return M(o,e),o}let r=t.body.getReader(),n=new TextDecoder,s="";for(;;){let{done:o,value:i}=await r.read();if(o)break;if(s+=n.decode(i,{stream:!0}),s.length>e)throw a.abort(),new h("tooLarge",{size:`> ${e}`,limit:e})}return s+=n.decode(),M(s,e),s}function xt(t,e,a){if(t instanceof h)return t;if(e.aborted&&e.reason instanceof h)return e.reason;if(t instanceof DOMException&&t.name==="AbortError")return t;let r=t instanceof Error?t.message:String(t);return new h("loadFailed",{url:Re(a),reason:r},t)}function Re(t){let e=t.origin===location.origin?t.pathname+t.search:t.href;return e.length>120?e.slice(0,119)+"\u2026":e}function Le(t){return t instanceof DOMException&&t.name==="AbortError"}var Ne="http://www.w3.org/2000/svg";var _=["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"}],T=["path",{d:"M14 2v4a2 2 0 0 0 2 2h4"}],wt={copy:[["rect",{width:"14",height:"14",x:"8",y:"8",rx:"2",ry:"2"}],["path",{d:"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}]],check:[["path",{d:"M20 6 9 17l-5-5"}]],search:[["path",{d:"m21 21-4.34-4.34"}],["circle",{cx:"11",cy:"11",r:"8"}]],"chevron-up":[["path",{d:"m18 15-6-6-6 6"}]],"chevron-down":[["path",{d:"m6 9 6 6 6-6"}]],"chevron-right":[["path",{d:"m9 18 6-6-6-6"}]],wrap:[["path",{d:"m16 16-3 3 3 3"}],["path",{d:"M3 12h14.5a1 1 0 0 1 0 7H13"}],["path",{d:"M3 19h6"}],["path",{d:"M3 5h18"}]],download:[["path",{d:"M12 15V3"}],["path",{d:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"}],["path",{d:"m7 10 5 5 5-5"}]],"expand-all":[["path",{d:"m7 15 5 5 5-5"}],["path",{d:"m7 9 5-5 5 5"}]],"collapse-all":[["path",{d:"m7 20 5-5 5 5"}],["path",{d:"m7 4 5 5 5-5"}]],link:[["path",{d:"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"}],["path",{d:"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"}]],eye:[["path",{d:"M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"}],["circle",{cx:"12",cy:"12",r:"3"}]],code:[["path",{d:"m16 18 6-6-6-6"}],["path",{d:"m8 6-6 6 6 6"}]],columns:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M12 3v18"}]],list:[["path",{d:"M3 5h.01"}],["path",{d:"M3 12h.01"}],["path",{d:"M3 19h.01"}],["path",{d:"M8 5h13"}],["path",{d:"M8 12h13"}],["path",{d:"M8 19h13"}]],pencil:[["path",{d:"M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"}],["path",{d:"m15 5 4 4"}]],"chevron-left":[["path",{d:"m15 18-6-6 6-6"}]],"chevrons-left":[["path",{d:"m11 17-5-5 5-5"}],["path",{d:"m18 17-5-5 5-5"}]],"chevrons-right":[["path",{d:"m6 17 5-5-5-5"}],["path",{d:"m13 17 5-5-5-5"}]],sort:[["path",{d:"m21 16-4 4-4-4"}],["path",{d:"M17 20V4"}],["path",{d:"m3 8 4-4 4 4"}],["path",{d:"M7 4v16"}]],"sort-up":[["path",{d:"m5 12 7-7 7 7"}],["path",{d:"M12 19V5"}]],"sort-down":[["path",{d:"M12 5v14"}],["path",{d:"m19 12-7 7-7-7"}]],table:[["path",{d:"M12 3v18"}],["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 9h18"}],["path",{d:"M3 15h18"}]],undo:[["path",{d:"M9 14 4 9l5-5"}],["path",{d:"M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11"}]],redo:[["path",{d:"m15 14 5-5-5-5"}],["path",{d:"M20 9H9.5A5.5 5.5 0 0 0 4 14.5A5.5 5.5 0 0 0 9.5 20H13"}]],maximize:[["path",{d:"M15 3h6v6"}],["path",{d:"m21 3-7 7"}],["path",{d:"m3 21 7-7"}],["path",{d:"M9 21H3v-6"}]],minimize:[["path",{d:"m14 10 7-7"}],["path",{d:"M20 10h-6V4"}],["path",{d:"m3 21 7-7"}],["path",{d:"M4 14h6v6"}]],swap:[["path",{d:"M8 3 4 7l4 4"}],["path",{d:"M4 7h16"}],["path",{d:"m16 21 4-4-4-4"}],["path",{d:"M20 17H4"}]],rows:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 12h18"}]],"sync-scroll":[["path",{d:"M9 17H7A5 5 0 0 1 7 7h2"}],["path",{d:"M15 7h2a5 5 0 1 1 0 10h-2"}],["line",{x1:"8",x2:"16",y1:"12",y2:"12"}]],alert:[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}],["path",{d:"M12 9v4"}],["path",{d:"M12 17h.01"}]],close:[["path",{d:"M18 6 6 18"}],["path",{d:"m6 6 12 12"}]],replay:[["path",{d:"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"}],["path",{d:"M3 3v5h5"}]],chart:[["path",{d:"M3 3v16a2 2 0 0 0 2 2h16"}],["path",{d:"m19 9-5 5-4-4-3 3"}]],follow:[["path",{d:"M12 17V3"}],["path",{d:"m6 11 6 6 6-6"}],["path",{d:"M19 21H5"}]],terminal:[["path",{d:"M12 19h8"}],["path",{d:"m4 17 6-6-6-6"}]],folder:[["path",{d:"M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"}]],"folder-open":[["path",{d:"m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"}]],file:[_,T],"file-code":[_,T,["path",{d:"m10 13-2 2 2 2"}],["path",{d:"m14 17 2-2-2-2"}]],"file-text":[_,T,["path",{d:"M10 9H8"}],["path",{d:"M16 13H8"}],["path",{d:"M16 17H8"}]],"file-image":[_,T,["circle",{cx:"10",cy:"12",r:"2"}],["path",{d:"m20 17-1.296-1.296a2.41 2.41 0 0 0-3.408 0L9 22"}]],"file-data":[_,T,["path",{d:"M10 12a1 1 0 0 0-1 1v1a1 1 0 0 1-1 1 1 1 0 0 1 1 1v1a1 1 0 0 0 1 1"}],["path",{d:"M14 18a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1 1 1 0 0 1-1-1v-1a1 1 0 0 0-1-1"}]],lock:[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2"}],["path",{d:"M7 11V7a5 5 0 0 1 10 0v4"}]],"eye-off":[["path",{d:"M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"}],["path",{d:"M14.084 14.158a3 3 0 0 1-4.242-4.242"}],["path",{d:"M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"}],["path",{d:"m2 2 20 20"}]]};function y(t){let e=document.createElementNS(Ne,"svg");e.setAttribute("viewBox","0 0 24 24"),e.setAttribute("fill","none"),e.setAttribute("stroke","currentColor"),e.setAttribute("stroke-width","2.1"),e.setAttribute("stroke-linecap","round"),e.setAttribute("stroke-linejoin","round"),e.setAttribute("aria-hidden","true"),e.setAttribute("focusable","false"),e.setAttribute("class","icon");for(let[a,r]of wt[t]??[]){let n=document.createElementNS(Ne,a);for(let[s,o]of Object.entries(r))n.setAttribute(s,o);e.append(n)}return e}var G=new WeakMap,S=null;function kt(){return S||typeof IntersectionObserver>"u"||(S=new IntersectionObserver(t=>{for(let e of t)e.isIntersecting&&R(e.target)},{rootMargin:"600px 0px"})),S}function Ea(t,e){G.set(t,e);let a=kt();a?a.observe(t):R(t)}function R(t){let e=G.get(t);e&&(G.delete(t),S?.unobserve(t),e())}function je(t){for(let e of Array.from(t.querySelectorAll(".chunk[data-pending]")))R(e)}function Aa(t,e){for(let a of Array.from(t.querySelectorAll(".chunk[data-pending]"))){let r=Number(a.getAttribute("data-first")),n=Number(a.getAttribute("data-count"));if(e>=r&&e<r+n){R(a);break}}return t.querySelector(`.line[data-line="${e}"]`)}var _t=5e3,L=200;function Tt(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}function St(t,e,a=_t){let r=[];if(!e)return{starts:r,capped:!1};let n=new RegExp(Tt(e),"gi"),s;for(;(s=n.exec(t))!==null;){if(r.length===a)return{starts:r,capped:!0};r.push(s.index),s[0].length===0&&(n.lastIndex+=1)}return{starts:r,capped:!1}}var Oe=class{constructor(e,a={}){this.root=e,this.skip=a.skip??"",this.matches=[],this.current=-1}run(e){this.clear();let a=e.slice(0,L);if(!a)return{total:0,capped:!1};je(this.root);let{nodes:r,starts:n,text:s}=this.collectText(),{starts:o,capped:i}=St(s,a),l=o.map(()=>[]);for(let d=o.length-1;d>=0;d-=1){let k=o[d],Y=k+a.length,b=Ct(n,Y-1);for(;b>=0&&n[b]+(r[b].nodeValue??"").length>k;){let C=n[b],Q=Math.max(k,C)-C,J=Math.min(Y,C+(r[b].nodeValue??"").length)-C;J>Q&&l[d].unshift(Et(r[b],Q,J,d)),b-=1}}return this.matches=l,{total:l.length,capped:i}}collectText(){let e=this.skip,a=document.createTreeWalker(this.root,NodeFilter.SHOW_TEXT,{acceptNode(i){let l=i.parentElement;return e&&l&&l.closest(e)?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT}}),r=[],n=[],s=[],o=0;for(let i=a.nextNode();i;i=a.nextNode()){let l=i.nodeValue??"";l&&(r.push(i),n.push(o),s.push(l),o+=l.length)}return{nodes:r,starts:n,text:s.join("")}}go(e){if(!this.matches.length)return null;let a=this.matches.length,r=(e%a+a)%a;for(let n of this.matches[this.current]??[])n.classList.remove("current");this.current=r;for(let n of this.matches[r])n.classList.add("current");return this.matches[r][0]??null}unsetCurrent(){for(let e of this.matches[this.current]??[])e.classList.remove("current");this.current=-1}clear(){let e=new Set;for(let a of this.matches)for(let r of a){let n=r.parentNode;n&&(r.replaceWith(...Array.from(r.childNodes)),e.add(n))}for(let a of e)a.normalize();this.matches=[],this.current=-1}};function Ct(t,e){let a=0,r=t.length-1;for(;a<r;){let n=a+r+1>>1;t[n]<=e?a=n:r=n-1}return a}function Et(t,e,a,r){let n=t.splitText(e);n.splitText(a-e);let s=document.createElement("mark");return s.className="match",s.setAttribute("part","match"),s.dataset.match=String(r),n.replaceWith(s),s.appendChild(n),s}function La(t,e){let a=[];return{run(r){let n=!1;return a=t.map(s=>{let o=s.run(r);return n||=o.capped,o.total}),{total:a.reduce((s,o)=>s+o,0),capped:n}},go(r){let n=r;for(let s=0;s<t.length;s+=1){if(n<a[s]){for(let i of t)i!==t[s]&&i.unsetCurrent();let o=t[s].go(n);o&&e(o);return}n-=a[s]}},clear(){for(let r of t)r.clear()}}}function p(t){let e=c("button",{class:"btn",part:`button${t.part?` ${t.part}`:""}`,attrs:{type:"button","aria-label":t.label,title:t.label,"aria-pressed":t.pressed===void 0?null:String(t.pressed),"data-focus-key":t.key},on:{click:t.onClick}});return e.append(y(t.icon)),e}function Pe(t,e,a){let r=t.querySelector("svg");r&&(r.replaceWith(y(a?"check":"alert")),t.classList.toggle("done",a),setTimeout(()=>{t.querySelector("svg")?.replaceWith(y(e)),t.classList.remove("done")},1500))}var N=class{constructor(e,a,r=""){this.t=e,this.handlers=a,this.total=0,this.capped=!1,this.index=-1;let n=Se("search");this.input=c("input",{class:"search-input",part:"search-input",attrs:{id:n,type:"search",placeholder:e("searchPlaceholder"),"aria-label":e("search"),maxlength:L,autocomplete:"off",spellcheck:"false",enterkeyhint:"search","data-focus-key":"search-input"}}),this.input.value=r.slice(0,L),this.count=c("span",{class:"search-count",part:"search-count",attrs:{"aria-hidden":"true"}});let s=p({icon:"chevron-up",label:e("searchPrevious"),onClick:()=>this.step(-1),key:"search-prev"}),o=p({icon:"chevron-down",label:e("searchNext"),onClick:()=>this.step(1),key:"search-next"}),i=p({icon:"close",label:e("searchClose"),onClick:()=>a.onClose(),key:"search-close"});this.element=c("div",{class:"search",part:"search",attrs:{role:"search"}},this.input,this.count,s,o,i);let l=Ce(()=>this.run(),150);this.input.addEventListener("input",l),this.input.addEventListener("keydown",d=>{d.key==="Enter"?(d.preventDefault(),l.cancel(),this.input.value!==this.lastQuery?this.run():this.step(d.shiftKey?-1:1)):d.key==="Escape"&&(d.preventDefault(),d.stopPropagation(),this.input.value?(this.input.value="",this.run()):a.onClose())}),this.lastQuery=void 0}run(){let e=this.input.value;this.lastQuery=e;let{total:a,capped:r}=this.handlers.run(e);this.total=a,this.capped=r,this.index=-1,a>0?this.step(1):this.updateCount(),this.handlers.onResult?.(e,a,r)}step(e){this.total&&(this.index=((this.index+e)%this.total+this.total)%this.total,this.handlers.go(this.index),this.updateCount())}updateCount(){if(!this.input.value)this.count.textContent="";else if(!this.total)this.count.textContent=this.t("searchNone");else{let e=this.capped?"searchCountCapped":"searchCount";this.count.textContent=this.t(e,{current:this.index+1,total:this.total})}}focus(){this.input.focus(),this.input.select()}};function Pa({tabs:t,selected:e,label:a,onSelect:r,panelId:n}){let s=c("div",{class:"tabs",part:"tabs",attrs:{role:"tablist","aria-label":a}}),o=t.map(i=>{let l=i.id===e;return c("button",{class:"tab",part:l?"tab tab-active":"tab",attrs:{type:"button",role:"tab","aria-selected":String(l),"aria-controls":n,tabindex:l?"0":"-1","data-tab":i.id,"data-focus-key":`tab-${i.id}`},on:{click:()=>r(i.id)}},i.icon?y(i.icon):null,i.label)});return s.append(...o),s.addEventListener("keydown",i=>{let l=o.findIndex(k=>k===i.target);if(l<0)return;let d=-1;i.key==="ArrowRight"?d=(l+1)%o.length:i.key==="ArrowLeft"?d=(l-1+o.length)%o.length:i.key==="Home"?d=0:i.key==="End"&&(d=o.length-1),!(d<0)&&(i.preventDefault(),r(t[d].id))}),s}function ze(t){return c("div",{class:"loader",part:"loading",attrs:{role:"status"}},At(),c("span",{class:"loader-label",text:t("loading")}))}var Ie="http://www.w3.org/2000/svg";function At(){let t=document.createElementNS(Ie,"svg");t.setAttribute("viewBox","0 0 120 120"),t.setAttribute("class","loader-mark"),t.setAttribute("aria-hidden","true"),t.setAttribute("focusable","false");let e=[["rect",{class:"loader-frame",x:"12",y:"16",width:"96",height:"88",rx:"18"}],["path",{class:"loader-frame",d:"M12 42 L108 42"}],["circle",{class:"loader-dot",cx:"29",cy:"29",r:"5"}],["path",{class:"loader-v",d:"M42 60 L60 86 L78 60",pathLength:"100"}]];for(let[a,r]of e){let n=document.createElementNS(Ie,a);for(let[s,o]of Object.entries(r))n.setAttribute(s,o);t.append(n)}return t}function Fe(t,e){return c("div",{class:"message",part:"error",attrs:{role:"alert"}},y("alert"),c("div",{},c("p",{class:"message-title",text:t}),e?c("p",{class:"message-detail",text:e}):null))}function za(t){return c("div",{class:"notice",part:"notice",attrs:{role:"note"}},y("alert"),c("span",{text:t}))}function Ue(t){return c("div",{class:"empty",part:"empty",text:t("empty")})}var He=`/*
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
`;var De=`/*
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
`;async function $(t,e=document){if(navigator.clipboard&&window.isSecureContext)try{return await navigator.clipboard.writeText(t),!0}catch{}return Lt(t,e)}function Lt(t,e){let a=document.createElement("textarea");a.value=t,a.setAttribute("readonly",""),a.setAttribute("aria-hidden","true"),a.style.position="fixed",a.style.opacity="0",a.style.pointerEvents="none",(e instanceof Document?e.body:e).appendChild(a);try{return a.select(),document.execCommand("copy")}catch{return!1}finally{a.remove()}}function qe(t,e,a="text/plain"){let r=new Blob([t],{type:`${a};charset=utf-8`}),n=URL.createObjectURL(r),s=document.createElement("a");s.href=n,s.download=e,s.rel="noopener",s.style.display="none",document.body.appendChild(s),s.click(),s.remove(),setTimeout(()=>URL.revokeObjectURL(n),1e3)}var Be=new Map;function j(t){let e=Be.get(t);return e||(e=new CSSStyleSheet,e.replaceSync(t),Be.set(t,e)),e}var Nt=Object.freeze(["variant","theme","src","allow-remote","max-height","copy","search","download","header","dot","title","label","lang-ui","mode","edit-toggle","placeholder","syntax-theme","syntax-theme-dark","badge","history","fullscreen","status"]),Ve=class extends HTMLElement{static type="base";static componentAttributes=[];static presets={simple:{},full:{}};static allowEmpty=!1;static keepCarriageReturns=!1;static upgradeProperties=["content"];static styles=[];static get observedAttributes(){return[...Nt,...this.componentAttributes]}constructor(){super(),this.root=this.attachShadow({mode:"open"}),this.frame=c("div",{class:"vt",part:"container"}),this.syntaxTheme=null,this.updateSheets(null),this.live=c("div",{class:"sr-only",attrs:{"aria-live":"polite","aria-atomic":"true"}}),this.root.append(this.frame,this.live),this._content=void 0,this.text=null,this.error=null,this.loading=!1,this.searchOpen=!1,this.searchQuery="",this.searchBar=null,this.t=U("en"),this._loadToken=0,this._abort=null,this._renderQueued=!1,this._readyPending=!1,this._cleanups=[],this._observer=null,this._connected=!1,this.modeState=null,this.editHistory=null,this._historyCleanup=null,this._escapeFullscreen=null}get content(){return this.text??""}set content(e){let a=e==null?void 0:String(e);a!==void 0&&a===this._content&&a===this.text||(this._content=a,this._connected&&this.reload())}upgradeProperty(e){if(Object.prototype.hasOwnProperty.call(this,e)){let a=this[e];delete this[e],this[e]=a}}connectedCallback(){for(let a of this.constructor.upgradeProperties)this.upgradeProperty(a);this._cleanups.push(re(a=>a.has("maxSize")?this.reload():this.requestRender()),fe(()=>this.applyTheme()),ne(()=>this.requestRender())),this._observer=new MutationObserver(()=>{this._content===void 0&&!this.hasAttribute("src")&&this.reload()}),this._observer.observe(this,{childList:!0,characterData:!0,subtree:!0});let e=()=>{document.fullscreenElement===this?this.setFullscreen("native"):this.frame.dataset.fullscreen==="native"&&this.setFullscreen(null)};document.addEventListener("fullscreenchange",e),this._cleanups.push(()=>document.removeEventListener("fullscreenchange",e)),this._connected=!0,this.reload()}disconnectedCallback(){this._connected=!1;for(let e of this._cleanups.splice(0))e();this._observer?.disconnect(),this._observer=null,this._abort?.abort(),this._abort=null}attributeChangedCallback(e,a,r){a===r||!this.isConnected||(e==="mode"&&(this.modeState=null),e==="src"||e==="allow-remote"?this.reload():e==="theme"?this.applyTheme():this.requestRender())}reload(){let e=++this._loadToken;this._abort?.abort(),this._abort=null;let a=u(),r=this.getAttribute("src");if(this._content!==void 0)this.setText(this._content);else if(r!==null&&r.trim()!==""){this.loading=!0,this.error=null,this.requestRender();let n=new AbortController;this._abort=n,Me(r,{allowRemote:w(this.getAttribute("allow-remote"))===!0,maxSize:a.maxSize,timeout:a.fetchTimeout,signal:n.signal}).then(s=>e===this._loadToken&&this.setText(s),s=>e===this._loadToken&&!Le(s)&&this.setError(s))}else this.setText(this.readInline()??"")}setText(e){this.loading=!1,this.editHistory=null;try{M(e,u().maxSize)}catch(r){this.setError(r);return}let a=this.constructor;this.text=e.replace(a.keepCarriageReturns?/\r\n/g:/\r\n?/g,`
`),this.error=null,this.contentChanged(),this._readyPending=!0,this.requestRender()}setError(e){this.loading=!1,this._readyPending=!1,this.error=e,this.text=null,this.contentChanged(),this.requestRender();let{title:a,detail:r}=this.describeError(e);m(this,g.ERROR,{message:r||a,cause:e})}describeError(e){let a=this.t;if(e instanceof h){let r={...e.params};for(let n of["size","limit"])typeof r[n]=="number"&&(r[n]=se(Number(r[n]),this.locale));return{title:a("errorTitle"),detail:a(e.code,r)}}return{title:a("errorTitle"),detail:e instanceof Error?e.message:String(e)}}get editing(){return(this.modeState??V(this.getAttribute("mode"),["view","edit"],"view"))==="edit"}edited(e){this.text=e,this._content=e,this.contentEdited(e),m(this,g.INPUT,{value:e})}contentEdited(e){}historyButtons(e){if(this.editHistory=e.history,w(this.getAttribute("history"))===!1)return[];let a=p({icon:"undo",label:this.t("undo"),key:"undo",part:"undo-button",onClick:()=>e.undo()}),r=p({icon:"redo",label:this.t("redo"),key:"redo",part:"redo-button",onClick:()=>e.redo()}),n=()=>{a.disabled=!e.history.canUndo,r.disabled=!e.history.canRedo};return n(),this._historyCleanup?.(),this._historyCleanup=e.history.subscribe(n),[a,r]}fullscreenButton(){if(!this.feature("fullscreen"))return null;let e=!!this.frame.dataset.fullscreen;return p({icon:e?"minimize":"maximize",label:this.t(e?"exitFullscreen":"fullscreen"),key:"fullscreen",part:"fullscreen-button",pressed:e,onClick:()=>this.toggleFullscreen()})}async toggleFullscreen(){let e=this.frame.dataset.fullscreen;if(e==="native"){await document.exitFullscreen?.().catch(()=>{});return}if(e==="window"){this.setFullscreen(null);return}if(document.fullscreenEnabled&&this.requestFullscreen)try{await this.requestFullscreen({navigationUI:"hide"});return}catch{}this.setFullscreen("window")}setFullscreen(e){e?this.frame.dataset.fullscreen=e:delete this.frame.dataset.fullscreen,e==="window"?(this._escapeFullscreen=a=>{a.key==="Escape"&&!a.defaultPrevented&&this.setFullscreen(null)},this.frame.addEventListener("keydown",this._escapeFullscreen)):this._escapeFullscreen&&(this.frame.removeEventListener("keydown",this._escapeFullscreen),this._escapeFullscreen=null),this.render(),this.root.querySelector('[data-focus-key="fullscreen"]')?.focus(),m(this,g.FULLSCREEN_CHANGE,{fullscreen:!!e})}editToggleButton(){return this.feature("edit-toggle")?p({icon:this.editing?"eye":"pencil",label:this.t(this.editing?"stopEditing":"edit"),key:"edit-toggle",part:"edit-button",pressed:this.editing,onClick:()=>{this.modeState=this.editing?"view":"edit",this.render(),m(this,g.MODE_CHANGE,{mode:this.modeState}),this.modeState==="edit"&&this.root.querySelector(".editor-input")?.focus()}}):null}readInline(){return Ae(this)}contentChanged(){}get variant(){return V(this.getAttribute("variant"),["simple","full"],"simple")}feature(e){let a=w(this.getAttribute(e));return a!==null?a:this.constructor.presets[this.variant][e]??!1}get locale(){let e=this.getAttribute("lang-ui")?.trim();return e&&/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(e)?e:u().lang}get heading(){return ke(this.getAttribute("label")??this.getAttribute("title"))}requestRender(){this._renderQueued||(this._renderQueued=!0,queueMicrotask(()=>{this._renderQueued=!1,this.isConnected&&this.render()}))}applyTheme(){let e=ge(this.getAttribute("theme"));this.frame.dataset.theme=e,this.applySyntaxTheme(he(e)?.colorScheme==="dark")}applySyntaxTheme(e){let a=u(),r=e&&this.getAttribute("syntax-theme-dark")||this.getAttribute("syntax-theme")||e&&a.syntaxThemeDark||a.syntaxTheme,n=be(r);if(this.syntaxTheme=n,!n){this.updateSheets(null);return}let s=ve(n);if(s){this.updateSheets(s);return}ye(n).then(o=>{o&&this.syntaxTheme===n&&this.updateSheets(o)})}updateSheets(e){let r=this.constructor.styles.map(j),n=[j(He),v,j(De),...r];this.frame.toggleAttribute("data-syntax-theme",!!e),this.root.adoptedStyleSheets=e?[...n.filter(s=>s!==j(xe)),e]:n}render(){let e=this.activeFocusKey(),a=this.root.activeElement,r=a instanceof HTMLTextAreaElement||a instanceof HTMLInputElement?[a.selectionStart,a.selectionEnd]:null;this.t=U(this.locale),this.applyTheme();let n=we(this.getAttribute("max-height"));if(n?this.frame.style.setProperty("--_max-height",n):this.frame.style.removeProperty("--_max-height"),this.searchBar=null,this.frame.replaceChildren(),this.loading){this.frame.append(...this.chrome(null),c("div",{class:"body",part:"body"},ze(this.t))),this.frame.setAttribute("aria-busy","true");return}if(this.frame.removeAttribute("aria-busy"),this.error){let{title:o,detail:i}=this.describeError(this.error);this.frame.append(...this.chrome(null),Fe(o,i));return}if(!this.text&&!this.editing&&!this.constructor.allowEmpty)this.frame.append(...this.chrome(null),Ue(this.t));else{this.renderContent(this.frame);let o=this.searchBar;this.searchOpen&&this.searchQuery&&o?.run()}this.restoreFocus(e);let s=this.root.activeElement;if(r&&(s instanceof HTMLTextAreaElement||s instanceof HTMLInputElement)&&r[0]!==null)try{s.setSelectionRange(r[0],r[1])}catch{}this._readyPending&&(this._readyPending=!1,m(this,g.READY,{type:this.constructor.type}))}renderContent(e){throw new Error("renderContent() must be implemented.")}chrome(e){let a=(e?.actions??[]).filter(o=>o!==null),r=a.length?c("div",{class:"toolbar",part:"toolbar",attrs:{role:"toolbar","aria-label":this.t("actions")}},...a):null;if(!this.feature("header"))return r?.classList.add("floating"),[r,e?.tabs??null,this.searchBar?.element??null].filter(o=>o!==null);let n=this.heading,s=c("div",{class:"header",part:"header"},this.feature("dot")?c("span",{class:"dot",part:"status-dot",attrs:{"aria-hidden":"true"}}):null,n?c("span",{class:"title",part:"title",text:n,attrs:{title:n}}):null,e?.tabs??null,n?null:c("span",{class:"spacer"}),e?.badge&&w(this.getAttribute("badge"))!==!1?c("span",{class:"badge",part:"badge",text:e.badge}):null);return r&&s.append(r),this.searchBar?[s,this.searchBar.element]:[s]}copyButton(e,a=this.t("copy"),r="copy"){let n=p({icon:"copy",label:a,key:r,part:"copy-button",onClick:async()=>{let s=e(),o=await $(s,this.root);Pe(n,"copy",o),this.announce(this.t(o?"copied":"copyFailed")),o&&m(this,g.COPY,{text:s})}});return n}copyTextButton(e,a,r){let n=c("button",{class:"text-btn",part:"copy-button",text:a,attrs:{type:"button","data-focus-key":r},on:{click:async()=>{let s=e(),o=await $(s,this.root);n.textContent=this.t(o?"copied":"copyFailed"),n.classList.toggle("done",o),setTimeout(()=>{n.textContent=a,n.classList.remove("done")},1500),this.announce(this.t(o?"copied":"copyFailed")),o&&m(this,g.COPY,{text:s})}}});return n}downloadName(e){let a=this.getAttribute("download"),r=a&&w(a)!==!1&&!/^(?:true|on|yes)$/i.test(a.trim())?a:null,n=/\.[a-z0-9]{1,10}$/i.test(this.heading)?this.heading:null;return _e(r??n,e)}downloadButton(e,a,r){return p({icon:"download",label:this.t("download"),key:"download",part:"download-button",onClick:()=>qe(e(),a,r)})}searchButton(e){return this.feature("search")?(this.searchOpen&&(this.searchBar=new N(this.t,{run:a=>(this.searchQuery=a,e.run(a)),go:a=>e.go(a),onResult:(a,r,n)=>{a&&this.announce(r?this.t("searchResults",{total:n?`${r}+`:r}):this.t("searchNone")),m(this,g.SEARCH,{query:a,matches:r})},onClose:()=>{e.clear(),this.searchOpen=!1,this.searchQuery="",this.render(),this.root.querySelector('[data-focus-key="search"]')?.focus()}},this.searchQuery)),p({icon:"search",label:this.t("search"),key:"search",part:"search-button",pressed:this.searchOpen,onClick:()=>{this.searchOpen=!this.searchOpen,this.searchOpen||(this.searchQuery=""),this.render(),this.searchOpen&&this.searchBar?.focus()}})):null}announce(e){this.live.textContent="",setTimeout(()=>{this.live.textContent=e},50)}activeFocusKey(){let e=this.root.activeElement;return e instanceof HTMLElement?e.dataset.focusKey??null:null}restoreFocus(e){if(!e)return;let a=this.root.querySelector(`[data-focus-key="${CSS.escape(e)}"]`);a instanceof HTMLElement&&a.focus({preventScroll:!0})}};export{jt as a,Ot as b,Pt as c,zt as d,Ht as e,xe as f,w as g,ga as h,V as i,ma as j,ba as k,va as l,u as m,qt as n,c as o,pt as p,Se as q,wa as r,Ee as s,h as t,bt as u,M as v,Me as w,Le as x,g as y,m as z,Gt as A,se as B,na as C,sa as D,oa as E,he as F,ua as G,y as H,Ea as I,Aa as J,_t as K,L,Oe as M,La as N,p as O,Pa as P,ze as Q,Fe as R,za as S,Ue as T,Ve as U};
