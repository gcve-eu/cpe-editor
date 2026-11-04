/*! Vitrine | MIT | https://github.com/ecrou-exact/vitrine
 * Source: e7db1ebd587b27f41988a0da9785310eaa6f2f08. Standalone vt-table bundle.
 * Includes highlight.js (BSD-3-Clause), DOMPurify (Apache-2.0 OR MPL-2.0),
 * and Lucide icons (ISC). See LICENSE and THIRD_PARTY_NOTICES.md. */
var ge=Object.freeze({copy:"Copy",copyCode:"Copy code",copied:"Copied",copyFailed:"Copy failed",copySource:"Copy source",download:"Download",search:"Search",searchPlaceholder:"Search\u2026",searchNext:"Next match",searchPrevious:"Previous match",searchClose:"Close search",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"No matches",searchResults:"{total} matches",wrap:"Toggle line wrap",showMore:"Show all {count} lines",preview:"Preview",source:"Source",split:"Split",swapPanes:"Swap panes",stackPanes:"Stack panes",syncScroll:"Sync scrolling",tabs:"View",actions:"Actions",toc:"Table of contents",anchor:"Link to this section",table:"Table",tree:"Tree",raw:"Raw",expandAll:"Expand all",collapseAll:"Collapse all",copyPath:"Copy path",copyValue:"Copy value",items:"{count} items",item:"1 item",keys:"{count} keys",key:"1 key",showMoreItems:"Show {count} more",showFullString:"Show full string ({count} characters)",truncated:"Partially expanded: too many nodes.",loading:"Loading\u2026",errorTitle:"Unable to display content",invalidJson:"Invalid JSON at line {line}, column {column}: {message}.",invalidJsonRaw:"Invalid JSON at line {line}, column {column} \u2014 showing raw text.",empty:"Nothing to display",tooLarge:"Content is too large ({size} characters, limit {limit}).",tooDeep:"Nesting is too deep (limit {limit}).",tooComplex:"This document is nested too deeply to display.",unserializable:"This value cannot be converted to JSON (circular reference or BigInt).",highlightSkipped:"Content is large: syntax highlighting is disabled.",loadFailed:'Could not load "{url}": {reason}',remoteBlocked:'Cross-origin URL blocked. Add the "allow-remote" attribute to allow it.',unsafeUrl:"URL blocked: only http(s) URLs can be loaded.",timeout:"Request timed out.",added:"Added",removed:"Removed",code:"Code",edit:"Edit",splitView:"Side by side",unifiedView:"Unified",diffStats:"+{added} \u2212{removed}",diffSimplified:"Many changes: the comparison is simplified to removed and added blocks.",noDifferences:"No differences",previousChange:"Previous change",nextChange:"Next change",changePosition:"{current} of {total}",changeTotal:"{count} changes",terminal:"Terminal",command:"Command",copyCommand:"Copy command",copyCommands:"Copy commands",replay:"Replay",showMoreLines:"Show {count} more lines",files:"Files",copyTree:"Copy tree",treeStats:"{folders} folders, {files} files",invalidTree:"This tree could not be read: {message}",treeTruncated:"Only the first {limit} entries are shown.",status_added:"added",status_removed:"removed",status_modified:"modified",status_highlighted:"highlighted",httpExchange:"Exchange",httpRequest:"Request",httpResponse:"Response",httpBody:"Body",httpHeaders:"Headers",httpQuery:"Query",httpNone:"None",httpNoBody:"No body",copyUrl:"Copy URL",codeLanguage:"Language",showSecrets:"Show secrets",hideSecrets:"Hide secrets",secretsShown:"Secrets shown",secretsHidden:"Secrets hidden",secretsInCode:"Credentials are masked in this code. Replace them with your own.",invalidHttp:"This HTTP message could not be read: {message}",log:"Log",followLog:"Follow new lines",levelToggle:"Show or hide {level} entries",logNoMatch:"No entry matches the filters.",chartView:"Chart",legend:"Legend",seriesToggle:"Show or hide {name}",copyData:"Copy data",chartSummary:"{type} with {series} series and {points} points.",chartRange:"{name} from {min} to {max}",chart_line:"Line chart",chart_area:"Area chart",chart_bar:"Bar chart",chart_pie:"Donut chart",chartError:"This data could not be charted: {message}",chartTruncated:"Only the first 5,000 points of each series are shown.",chartLoadFailed:"The chart library could not be loaded: {message}",openapiInvalid:"This API description could not be read: {message}",openapiYamlFailed:"The YAML reader could not be loaded: {message}",openapiTruncated:"Only the first 2,000 endpoints are shown.",openapiServers:"Servers",openapiAuth:"Authentication",openapiEndpoints:"Endpoints",openapiTags:"Tags",openapiAllTags:"All",openapiNoMatch:"No endpoint matches.",openapiDeprecated:"deprecated",openapiParameters:"Parameters",openapiName:"Name",openapiIn:"In",openapiType:"Type",openapiDescription:"Description",openapiRequired:"required",openapiRequestBody:"Request body",openapiResponses:"Responses",openapiExample:"Example",openapiExampleValue:"Example",unchangedLines:"Show {count} unchanged lines",copyPatch:"Copy patch",changes:"Changes",original:"Original",modified:"Modified",patch:"Patch",tags:"Tags",noTags:"No tags",addTag:"Add a tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:'Create "{tag}"',removeTag:"Remove {tag}",tagAdded:"{tag} added",tagRemoved:"{tag} removed",pressAgainToRemove:"Press Backspace again to remove {tag}",tagDuplicate:"{tag} is already selected.",tagDisabled:"{tag} cannot be selected.",tagLimit:"You can select up to {max} tags.",tagNotAllowed:"{tag} is not in the list.",tagTooLong:"{tag} is too long.",tagInvalid:"{tag} is not a valid tag.",tagRefused:"{tag} was refused.",tagsRequired:"Select at least one tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Browse all tags",otherTags:"Other",clearTags:"Remove all tags",filterTags:"Filter tags",tagsFound:"{count} tags",invalidTags:'The tags must be a JSON array, or an object with "value" and "options".',rowsRange:"Rows {from}\u2013{to} of {total}",noRows:"No rows",firstPage:"First page",previousPage:"Previous page",nextPage:"Next page",lastPage:"Last page",sortBy:"Sort by {name}",column:"Column {n}",rowNumber:"Row",csvStatus:"{rows} rows \xD7 {columns} columns",csvUnclosed:"Unclosed quote starting at line {line}.",tooManyColumns:"Only the first {limit} columns are shown.",matchingRows:"{count} matching rows",undo:"Undo",redo:"Redo",fullscreen:"Full screen",exitFullscreen:"Exit full screen",stopEditing:"Stop editing",editor:"Editor",validJson:"Valid JSON"}),Xt=Object.freeze({copy:"Copier",copyCode:"Copier le code",copied:"Copi\xE9",copyFailed:"\xC9chec de la copie",copySource:"Copier la source",download:"T\xE9l\xE9charger",search:"Rechercher",searchPlaceholder:"Rechercher\u2026",searchNext:"R\xE9sultat suivant",searchPrevious:"R\xE9sultat pr\xE9c\xE9dent",searchClose:"Fermer la recherche",searchCount:"{current} / {total}",searchCountCapped:"{current} / {total}+",searchNone:"Aucun r\xE9sultat",searchResults:"{total} r\xE9sultats",wrap:"Activer/d\xE9sactiver le retour \xE0 la ligne",showMore:"Afficher les {count} lignes",preview:"Aper\xE7u",source:"Source",split:"C\xF4te \xE0 c\xF4te",swapPanes:"Inverser les panneaux",stackPanes:"Empiler les panneaux",syncScroll:"Synchroniser le d\xE9filement",tabs:"Affichage",actions:"Actions",toc:"Table des mati\xE8res",anchor:"Lien vers cette section",table:"Tableau",tree:"Arbre",raw:"Brut",expandAll:"Tout d\xE9plier",collapseAll:"Tout replier",copyPath:"Copier le chemin",copyValue:"Copier la valeur",items:"{count} \xE9l\xE9ments",item:"1 \xE9l\xE9ment",keys:"{count} cl\xE9s",key:"1 cl\xE9",showMoreItems:"Afficher {count} de plus",showFullString:"Afficher toute la cha\xEEne ({count} caract\xE8res)",truncated:"D\xE9pliage partiel : trop de n\u0153uds.",loading:"Chargement\u2026",errorTitle:"Impossible d\u2019afficher le contenu",invalidJson:"JSON invalide \xE0 la ligne {line}, colonne {column} : {message}.",invalidJsonRaw:"JSON invalide \xE0 la ligne {line}, colonne {column} \u2014 affichage du texte brut.",empty:"Rien \xE0 afficher",tooLarge:"Contenu trop volumineux ({size} caract\xE8res, limite {limit}).",tooDeep:"Imbrication trop profonde (limite {limit}).",tooComplex:"Ce document est trop imbriqu\xE9 pour \xEAtre affich\xE9.",unserializable:"Cette valeur ne peut pas \xEAtre convertie en JSON (r\xE9f\xE9rence circulaire ou BigInt).",highlightSkipped:"Contenu volumineux : coloration syntaxique d\xE9sactiv\xE9e.",loadFailed:"Impossible de charger \xAB {url} \xBB : {reason}",remoteBlocked:"URL d\u2019une autre origine bloqu\xE9e. Ajoutez l\u2019attribut \xAB allow-remote \xBB pour l\u2019autoriser.",unsafeUrl:"URL bloqu\xE9e : seules les URL http(s) peuvent \xEAtre charg\xE9es.",timeout:"D\xE9lai de la requ\xEAte d\xE9pass\xE9.",added:"Ajout\xE9",removed:"Supprim\xE9",code:"Code",edit:"Modifier",splitView:"C\xF4te \xE0 c\xF4te",unifiedView:"Unifi\xE9",diffStats:"+{added} \u2212{removed}",diffSimplified:"Beaucoup de changements : la comparaison est simplifi\xE9e en blocs retir\xE9s et ajout\xE9s.",noDifferences:"Aucune diff\xE9rence",previousChange:"Modification pr\xE9c\xE9dente",nextChange:"Modification suivante",changePosition:"{current} sur {total}",changeTotal:"Modifications : {count}",terminal:"Terminal",command:"Commande",copyCommand:"Copier la commande",copyCommands:"Copier les commandes",replay:"Rejouer",showMoreLines:"Afficher {count} lignes de plus",files:"Fichiers",copyTree:"Copier l'arborescence",treeStats:"{folders} dossiers, {files} fichiers",invalidTree:"Impossible de lire cette arborescence : {message}",treeTruncated:"Seules les {limit} premi\xE8res entr\xE9es sont affich\xE9es.",status_added:"ajout\xE9",status_removed:"supprim\xE9",status_modified:"modifi\xE9",status_highlighted:"mis en \xE9vidence",httpExchange:"\xC9change",httpRequest:"Requ\xEAte",httpResponse:"R\xE9ponse",httpBody:"Corps",httpHeaders:"En-t\xEAtes",httpQuery:"Param\xE8tres",httpNone:"Aucun",httpNoBody:"Pas de corps",copyUrl:"Copier l'URL",codeLanguage:"Langage",showSecrets:"Afficher les secrets",hideSecrets:"Masquer les secrets",secretsShown:"Secrets affich\xE9s",secretsHidden:"Secrets masqu\xE9s",secretsInCode:"Les identifiants sont masqu\xE9s dans ce code. Remplacez-les par les v\xF4tres.",invalidHttp:"Impossible de lire ce message HTTP : {message}",log:"Journal",followLog:"Suivre les nouvelles lignes",levelToggle:"Afficher ou masquer les entr\xE9es {level}",logNoMatch:"Aucune entr\xE9e ne correspond aux filtres.",chartView:"Graphique",legend:"L\xE9gende",seriesToggle:"Afficher ou masquer {name}",copyData:"Copier les donn\xE9es",chartSummary:"{type} avec {series} s\xE9ries et {points} points.",chartRange:"{name} de {min} \xE0 {max}",chart_line:"Graphique en courbes",chart_area:"Graphique en aires",chart_bar:"Graphique en barres",chart_pie:"Graphique en anneau",chartError:"Impossible de tracer ces donn\xE9es : {message}",chartTruncated:"Seuls les 5 000 premiers points de chaque s\xE9rie sont affich\xE9s.",chartLoadFailed:"Impossible de charger la biblioth\xE8que de graphiques : {message}",openapiInvalid:"Impossible de lire cette description d\u2019API : {message}",openapiYamlFailed:"Impossible de charger le lecteur YAML : {message}",openapiTruncated:"Seuls les 2 000 premiers points d\u2019acc\xE8s sont affich\xE9s.",openapiServers:"Serveurs",openapiAuth:"Authentification",openapiEndpoints:"Points d\u2019acc\xE8s",openapiTags:"Tags",openapiAllTags:"Tous",openapiNoMatch:"Aucun point d\u2019acc\xE8s ne correspond.",openapiDeprecated:"obsol\xE8te",openapiParameters:"Param\xE8tres",openapiName:"Nom",openapiIn:"Emplacement",openapiType:"Type",openapiDescription:"Description",openapiRequired:"requis",openapiRequestBody:"Corps de la requ\xEAte",openapiResponses:"R\xE9ponses",openapiExample:"Exemple",openapiExampleValue:"Exemple",unchangedLines:"Afficher {count} lignes inchang\xE9es",copyPatch:"Copier le patch",changes:"Modifications",original:"Original",modified:"Modifi\xE9",patch:"Patch",tags:"Tags",noTags:"Aucun tag",addTag:"Ajouter un tag",tagPlaceholder:"tag",suggestions:"Suggestions",createTag:"Cr\xE9er \xAB {tag} \xBB",removeTag:"Retirer {tag}",tagAdded:"{tag} ajout\xE9",tagRemoved:"{tag} retir\xE9",pressAgainToRemove:"Appuyez de nouveau sur Retour arri\xE8re pour retirer {tag}",tagDuplicate:"{tag} est d\xE9j\xE0 s\xE9lectionn\xE9.",tagDisabled:"{tag} ne peut pas \xEAtre s\xE9lectionn\xE9.",tagLimit:"Vous pouvez s\xE9lectionner jusqu\u2019\xE0 {max} tags.",tagNotAllowed:"{tag} n\u2019est pas dans la liste.",tagTooLong:"{tag} est trop long.",tagInvalid:"{tag} n\u2019est pas un tag valide.",tagRefused:"{tag} a \xE9t\xE9 refus\xE9.",tagsRequired:"S\xE9lectionnez au moins un tag.",tagCount:"{count} tags",tagCountOne:"1 tag",tagCountMax:"{count} / {max} tags",browseTags:"Parcourir tous les tags",otherTags:"Autres",clearTags:"Retirer tous les tags",filterTags:"Filtrer les tags",tagsFound:"{count} tags",invalidTags:"Les tags doivent \xEAtre un tableau JSON, ou un objet avec \xAB value \xBB et \xAB options \xBB.",rowsRange:"Lignes {from}\u2013{to} sur {total}",noRows:"Aucune ligne",firstPage:"Premi\xE8re page",previousPage:"Page pr\xE9c\xE9dente",nextPage:"Page suivante",lastPage:"Derni\xE8re page",sortBy:"Trier par {name}",column:"Colonne {n}",rowNumber:"Ligne",csvStatus:"{rows} lignes \xD7 {columns} colonnes",csvUnclosed:"Guillemet non ferm\xE9 \xE0 partir de la ligne {line}.",tooManyColumns:"Seules les {limit} premi\xE8res colonnes sont affich\xE9es.",matchingRows:"{count} lignes correspondantes",undo:"Annuler",redo:"R\xE9tablir",fullscreen:"Plein \xE9cran",exitFullscreen:"Quitter le plein \xE9cran",stopEditing:"Terminer la modification",editor:"\xC9diteur",validJson:"JSON valide"}),be={},X=new Map;function Pe(n){for(let[e,t]of Object.entries(n))e==="en"?Object.assign(be,t):X.set(e,{...X.get(e)??{},...t});for(let e of ee)e()}var Z=new Map([["en",ge],["fr",Xt]]);function Zt(n,e){if(typeof n!="string"||!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(n))throw new TypeError(`[vitrine] Invalid locale code "${n}".`);let t={};for(let[a,r]of Object.entries(e??{}))(Object.prototype.hasOwnProperty.call(ge,a)||Object.prototype.hasOwnProperty.call(be,a))&&typeof r=="string"&&(t[a]=r.slice(0,500));Z.set(n,Object.freeze({...Z.get(n)??{},...t}));for(let a of ee)a()}var ee=new Set;function Fe(n){return ee.add(n),()=>ee.delete(n)}function me(n){let e=Z.get(n),t=Z.get(String(n).split("-")[0]);return(a,r)=>{let s=String(n).split("-")[0],i=e?.[a]??t?.[a]??X.get(n)?.[a]??X.get(s)?.[a]??ge[a]??be[a]??String(a);return r?i.replace(/\{(\w+)\}/g,(o,l)=>Object.prototype.hasOwnProperty.call(r,l)?String(r[l]):o):i}}function E(n,e){try{return new Intl.NumberFormat(e).format(n)}catch{return String(n)}}var je=Object.freeze({tableYes:"Yes",tableNo:"No",tableAll:"All",tableEmpty:"(empty)",tableRows:"{count} rows",tableRowCount:"{count} rows",tableFiltered:"filtered from {total}",tableNoMatch:"No row matches the filters.",tableInvalid:"The data could not be read: {message}",tableTruncated:"The table was cut to its first rows or columns.",tableSelected:"{count} selected",tableSelect:"Select",tableSelectAll:"Select all",tableSelectRow:"Select row {n}",tableSelectGroup:"Select the group",tableSelectAllMatching:"Select all {count}",tableSelectionActions:"Actions on the selection",tableClearSelection:"Clear the selection",tableCopyRows:"Copy rows",tableDetails:"Details",tableExpandRow:"Show details",tableCollapseRow:"Hide details",tableShowFilters:"Show filters",tableHideFilters:"Hide filters",tableFilter:"Filter",tableFilterBy:"Filter {name}",tableFilterText:"Filter\u2026",tableFilterRange:">10, 1..5\u2026",tableRemoveFilter:"Remove the filter on {name}",tableClearAll:"Clear all",tableColumns:"Columns",tableColumnMenu:"{name} column options",tableShowAll:"Show all",tableResetLayout:"Reset layout",tableMoveUp:"Move {name} up",tableMoveDown:"Move {name} down",tableMoveLeft:"Move left",tableMoveRight:"Move right",tableMoved:"{name} moved to position {position}",tablePin:"Pin up to this column",tableUnpin:"Unpin",tableAutoFit:"Fit width to content",tableHideColumn:"Hide column",tableResize:"Drag to resize, double-click to fit",tableGroupBy:"Group by this column",tableGroupedBy:"Grouped by {name}",tableUngroup:"Ungroup",tableSortAsc:"Sort ascending",tableSortDesc:"Sort descending",tableClearSort:"Clear sort",tableSortField:"Sort by",tableNoSort:"No sort",tableSortedBy:"Sorted by {names}",tableSortedAnnounce:"Sorted by {name}, {direction}",tableAscending:"ascending",tableDescending:"descending",tableUnsorted:"Original order",tableFooter:"Footer",tableAgg_count:"Count",tableAgg_sum:"Sum",tableAgg_avg:"Avg",tableAgg_min:"Min",tableAgg_max:"Max",tableAggName_none:"Nothing",tableAggName_count:"Count of values",tableAggName_sum:"Sum",tableAggName_avg:"Average",tableAggName_min:"Minimum",tableAggName_max:"Maximum",tableDensity:"Density: {density}",tableDensity_compact:"compact",tableDensity_normal:"normal",tableDensity_comfortable:"comfortable",tablePageSize:"Rows per page",tablePerPage:"Per page",tablePage:"{page} / {pages}",tableEditCell:"Edit {name}",tableShortcuts:"Keyboard shortcuts",tableKeyMove:"Move between cells",tableKeyRowEnds:"First or last cell of the row",tableKeyTableEnds:"First or last row",tableKeyPage:"One screen up or down",tableKeySelect:"Select the row (on a header: sort)",tableKeyRange:"Extend the selection",tableKeySelectAll:"Select every matching row",tableKeyClear:"Clear the selection, close a menu",tableKeyEnter:"Edit, open details or a group, sort a header",tableKeyEdit:"Edit the cell",tableKeyExpand:"Open or close details and groups",tableKeyCopy:"Copy the selection or the cell",tableKeyMultiSort:"On a header: add to the sort",tableKeyMoveColumn:"On a header: move the column",tableKeyResize:"On a header: resize the column",tableKeySearch:"Search",tableMouseHint:"Shift+click a header to sort on several columns. Ctrl+click or Shift+click rows to select. Drag headers to reorder, their edge to resize.",tableSelectMenu:"Selection options",tableSelectPage:"Select this page",tableSelectMatching:"Select all matching rows",tableSelectEverything:"Select every row (ignore filters)",tableInvertPage:"Invert the page selection",tableUnselectPage:"Unselect this page",tableShowing:"Showing {shown} of {total}",tablePageAnnounce:"Page {page} of {pages}",tableShowMore:"Show {count} more",tableGoToPage:"Page {page}",tableJump:"Go to page",tableJumpShort:"Page\u2026",tablePagination:"Pagination",tableContains:"contains \u201C{text}\u201D",tableIsEmpty:"is empty",tableNot:"not",tableAnd:"AND",tableOr:"OR",tableToggleJoin:"Switch between AND and OR",tableEditCondition:"Edit this condition",tableRemoveCondition:"Remove {name}",tableQueryLabel:"Filter rows",tableQueryMore:"Add a condition\u2026",tableQueryPlaceholder:"Filter: team:Core, score:>50, -status:closed, or any text\u2026",tableOpHint:"compare",tableRangeHint:"range",tableFilterColumn:"filter this column",tableMatchAll:"Match all",tableMatchAny:"Match any",tableClearConditions:"Clear the conditions",tableType_text:"text",tableType_number:"number",tableType_date:"date",tableType_boolean:"yes / no",tableType_url:"link",tableSeeAll:"See all",tableShowLess:"Show less"}),Ie={tableYes:"Oui",tableNo:"Non",tableAll:"Tout",tableEmpty:"(vide)",tableRows:"{count} lignes",tableRowCount:"{count} lignes",tableFiltered:"filtr\xE9es sur {total}",tableNoMatch:"Aucune ligne ne correspond aux filtres.",tableInvalid:"Les donn\xE9es n\u2019ont pas pu \xEAtre lues : {message}",tableTruncated:"Le tableau a \xE9t\xE9 limit\xE9 \xE0 ses premi\xE8res lignes ou colonnes.",tableSelected:"{count} s\xE9lectionn\xE9es",tableSelect:"S\xE9lection",tableSelectAll:"Tout s\xE9lectionner",tableSelectRow:"S\xE9lectionner la ligne {n}",tableSelectGroup:"S\xE9lectionner le groupe",tableSelectAllMatching:"S\xE9lectionner les {count}",tableSelectionActions:"Actions sur la s\xE9lection",tableClearSelection:"Vider la s\xE9lection",tableCopyRows:"Copier les lignes",tableDetails:"D\xE9tails",tableExpandRow:"Afficher les d\xE9tails",tableCollapseRow:"Masquer les d\xE9tails",tableShowFilters:"Afficher les filtres",tableHideFilters:"Masquer les filtres",tableFilter:"Filtrer",tableFilterBy:"Filtrer {name}",tableFilterText:"Filtrer\u2026",tableRemoveFilter:"Retirer le filtre sur {name}",tableClearAll:"Tout effacer",tableColumns:"Colonnes",tableColumnMenu:"Options de la colonne {name}",tableShowAll:"Tout afficher",tableResetLayout:"R\xE9initialiser",tableMoveUp:"Monter {name}",tableMoveDown:"Descendre {name}",tableMoveLeft:"D\xE9placer \xE0 gauche",tableMoveRight:"D\xE9placer \xE0 droite",tableMoved:"{name} d\xE9plac\xE9e en position {position}",tablePin:"Figer jusqu\u2019\xE0 cette colonne",tableUnpin:"Lib\xE9rer",tableAutoFit:"Ajuster au contenu",tableHideColumn:"Masquer la colonne",tableResize:"Glisser pour redimensionner, double-clic pour ajuster",tableGroupBy:"Grouper par cette colonne",tableGroupedBy:"Group\xE9 par {name}",tableUngroup:"D\xE9grouper",tableSortAsc:"Tri croissant",tableSortDesc:"Tri d\xE9croissant",tableClearSort:"Retirer le tri",tableSortField:"Trier par",tableNoSort:"Sans tri",tableSortedBy:"Tri\xE9 par {names}",tableSortedAnnounce:"Tri\xE9 par {name}, {direction}",tableAscending:"croissant",tableDescending:"d\xE9croissant",tableUnsorted:"Ordre d\u2019origine",tableFooter:"Pied de tableau",tableAgg_count:"Nombre",tableAgg_sum:"Somme",tableAgg_avg:"Moy.",tableAgg_min:"Min",tableAgg_max:"Max",tableAggName_none:"Rien",tableAggName_count:"Nombre de valeurs",tableAggName_sum:"Somme",tableAggName_avg:"Moyenne",tableAggName_min:"Minimum",tableAggName_max:"Maximum",tableDensity:"Densit\xE9 : {density}",tableDensity_compact:"compacte",tableDensity_normal:"normale",tableDensity_comfortable:"a\xE9r\xE9e",tablePageSize:"Lignes par page",tablePerPage:"Par page",tableEditCell:"Modifier {name}",tableShortcuts:"Raccourcis clavier",tableKeyMove:"Se d\xE9placer entre les cellules",tableKeyRowEnds:"Premi\xE8re ou derni\xE8re cellule de la ligne",tableKeyTableEnds:"Premi\xE8re ou derni\xE8re ligne",tableKeyPage:"Un \xE9cran plus haut ou plus bas",tableKeySelect:"S\xE9lectionner la ligne (sur un en-t\xEAte : trier)",tableKeyRange:"\xC9tendre la s\xE9lection",tableKeySelectAll:"S\xE9lectionner toutes les lignes filtr\xE9es",tableKeyClear:"Vider la s\xE9lection, fermer un menu",tableKeyEnter:"Modifier, ouvrir les d\xE9tails ou un groupe, trier un en-t\xEAte",tableKeyEdit:"Modifier la cellule",tableKeyExpand:"Ouvrir ou fermer d\xE9tails et groupes",tableKeyCopy:"Copier la s\xE9lection ou la cellule",tableKeyMultiSort:"Sur un en-t\xEAte : ajouter au tri",tableKeyMoveColumn:"Sur un en-t\xEAte : d\xE9placer la colonne",tableKeyResize:"Sur un en-t\xEAte : redimensionner la colonne",tableKeySearch:"Rechercher",tableMouseHint:"Maj+clic sur un en-t\xEAte pour trier sur plusieurs colonnes. Ctrl+clic ou Maj+clic sur les lignes pour s\xE9lectionner. Glissez les en-t\xEAtes pour les r\xE9ordonner, leur bord pour redimensionner.",tableSelectMenu:"Options de s\xE9lection",tableSelectPage:"S\xE9lectionner cette page",tableSelectMatching:"S\xE9lectionner toutes les lignes filtr\xE9es",tableSelectEverything:"S\xE9lectionner tout (sans filtres)",tableInvertPage:"Inverser la s\xE9lection de la page",tableUnselectPage:"D\xE9s\xE9lectionner cette page",tableShowing:"{shown} affich\xE9es sur {total}",tablePageAnnounce:"Page {page} sur {pages}",tableShowMore:"Afficher {count} de plus",tableGoToPage:"Page {page}",tableJump:"Aller \xE0 la page",tableJumpShort:"Page\u2026",tablePagination:"Pagination",tableContains:"contient \xAB {text} \xBB",tableIsEmpty:"est vide",tableNot:"pas",tableAnd:"ET",tableOr:"OU",tableToggleJoin:"Basculer entre ET et OU",tableEditCondition:"Modifier cette condition",tableRemoveCondition:"Retirer {name}",tableQueryLabel:"Filtrer les lignes",tableQueryMore:"Ajouter une condition\u2026",tableQueryPlaceholder:"Filtrer : team:Core, score:>50, -status:closed, ou du texte\u2026",tableOpHint:"comparer",tableRangeHint:"intervalle",tableFilterColumn:"filtrer cette colonne",tableMatchAll:"Toutes les conditions",tableMatchAny:"Au moins une",tableClearConditions:"Effacer les conditions",tableType_text:"texte",tableType_number:"nombre",tableType_date:"date",tableType_boolean:"oui / non",tableType_url:"lien",tableSeeAll:"Voir tout",tableShowLess:"R\xE9duire"};var qe=`/*
 * Data table: sticky header and pinned columns, filters, selection bar, groups,
 * details, menus, pager, and a card layout on narrow screens.
 */
.vt {
  --_row-h: 37px;
  --_cell-x: var(--_space-3);
}

.vt[data-density='compact'] {
  --_row-h: 30px;
  --_cell-x: var(--_space-2);
}

.vt[data-density='comfortable'] {
  --_row-h: 46px;
  --_cell-x: var(--_space-4);
}

.tb {
  position: relative;
  display: flex;
  flex-direction: column;
  min-height: 0;
  font-family: var(--_font-ui);
  font-size: var(--_font-size-ui);
}

.tb-body {
  background: var(--_surface);
}

/* Without max-height the page scrolls; paging off (virtual) needs its own height. */
.tb-body:has(> .tb-grid) {
  max-height: var(--_max-height, none);
}

.tb-body.virtual {
  height: var(--_max-height, min(70vh, 560px));
  max-height: none;
}

.vt[data-fullscreen] .tb-body.virtual {
  height: auto;
}

/* ---------- Grid ---------- */

.tb-grid {
  table-layout: fixed;
  border-collapse: separate;
  border-spacing: 0;
  font-variant-numeric: tabular-nums;
}

.tb-grid th,
.tb-grid td {
  height: var(--_row-h);
  padding: 0 var(--_cell-x);
  border-bottom: 1px solid var(--_border);
  overflow: hidden;
  background: var(--_surface);
  text-align: start;
  text-overflow: ellipsis;
  white-space: nowrap;
  box-sizing: border-box;
}

.vt[data-wrap] .tb-grid td {
  height: auto;
  padding-block: 6px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.tb-grid thead th {
  position: sticky;
  top: 0;
  z-index: 3;
  background: var(--_surface-sunken);
  color: var(--_fg);
  font-weight: 600;
}

.tb-grid thead .tb-filters th {
  top: var(--_row-h);
  height: auto;
  padding-block: 4px;
  font-weight: 400;
}

.tb-grid tfoot td {
  position: sticky;
  bottom: 0;
  z-index: 3;
  border-top: 1px solid var(--_border-strong);
  border-bottom: 0;
  background: var(--_surface-sunken);
  color: var(--_fg-muted);
}

.tb-grid tfoot strong {
  color: var(--_fg);
  font-weight: 600;
}

.tb-agg {
  font-size: var(--_font-size-small);
}

.tb-grid .pinned {
  position: sticky;
  z-index: 2;
}

.tb-grid thead .pinned,
.tb-grid tfoot .pinned {
  z-index: 4;
}

.tb-grid .pin-edge {
  box-shadow: 1px 0 0 var(--_border-strong);
}

.tb-grid .type-number,
.tb-grid .align-end {
  text-align: end;
}

.tb-grid .align-center {
  text-align: center;
}

.tb-grid tbody .tb-row:hover > * {
  background: color-mix(in srgb, var(--_accent-soft) 55%, var(--_surface));
}

.tb-grid tbody .tb-row.selected > * {
  background: color-mix(in srgb, var(--_accent-soft) 100%, var(--_surface));
}

.tb-grid tbody .tb-row.current > * {
  box-shadow:
    inset 0 1px 0 var(--_warning),
    inset 0 -1px 0 var(--_warning);
}

.tb-grid [data-c]:focus-visible {
  outline: 2px solid var(--_accent);
  outline-offset: -2px;
}

.tb-grid .editable {
  cursor: text;
}

.tb-ctl {
  padding: 0 !important;
  color: var(--_fg-muted);
  text-align: center !important;
}

.tb-ctl-number {
  padding-inline: var(--_space-2) !important;
  text-align: end !important;
  font-size: var(--_font-size-small);
}

.tb-check {
  width: 16px;
  height: 16px;
  margin: 0;
  accent-color: var(--_accent);
  vertical-align: middle;
  cursor: pointer;
}

.tb-expand {
  display: inline-grid;
  place-items: center;
  width: 24px;
  height: 24px;
  padding: 0;
  border: 0;
  border-radius: var(--_radius-sm);
  background: none;
  color: var(--_fg-muted);
  cursor: pointer;
}

.tb-expand:hover {
  background: var(--_accent-soft);
  color: var(--_fg);
}

/* ---------- Header cells ---------- */

.tb-head {
  position: relative;
  cursor: pointer;
  user-select: none;
}

.tb-head-inner {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.tb-head.type-number .tb-head-inner,
.tb-head.align-end .tb-head-inner {
  flex-direction: row-reverse;
}

.tb-label {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}

.tb-head .icon {
  flex: none;
  width: 14px;
  height: 14px;
  color: var(--_accent-fg);
}

.tb-sort-hint {
  display: inline-flex;
  opacity: 0;
  transition: opacity var(--_duration-fast) var(--_easing);
}

.tb-sort-hint .icon {
  color: var(--_fg-muted);
}

.tb-head:hover .tb-sort-hint,
.tb-head:focus-visible .tb-sort-hint {
  opacity: 1;
}

.tb-sort-rank {
  min-width: 14px;
  padding: 0 3px;
  border-radius: var(--_radius-full);
  background: var(--_accent-soft);
  color: var(--_accent-fg);
  font-size: 10px;
  line-height: 14px;
  text-align: center;
}

.tb-menu-btn {
  display: inline-grid;
  place-items: center;
  flex: none;
  width: 22px;
  height: 22px;
  margin-inline-start: auto;
  padding: 0;
  border: 0;
  border-radius: var(--_radius-sm);
  background: none;
  color: var(--_fg-muted);
  cursor: pointer;
  opacity: 0;
}

.tb-head.type-number .tb-menu-btn,
.tb-head.align-end .tb-menu-btn {
  margin-inline: 0 auto;
}

.tb-head:hover .tb-menu-btn,
.tb-head:focus-within .tb-menu-btn,
.tb-menu-btn[aria-expanded='true'] {
  opacity: 1;
}

.tb-menu-btn:hover {
  background: var(--_accent-soft);
  color: var(--_fg);
}

.tb-menu-btn .icon {
  color: inherit;
}

@media (hover: none) {
  .tb-menu-btn,
  .tb-sort-hint {
    opacity: 1;
  }
}

.tb-resizer {
  position: absolute;
  top: 0;
  inset-inline-end: -4px;
  z-index: 1;
  width: 9px;
  height: 100%;
  cursor: col-resize;
  touch-action: none;
}

.tb-resizer::after {
  content: '';
  position: absolute;
  top: 25%;
  bottom: 25%;
  left: 4px;
  width: 1px;
  background: var(--_border-strong);
}

.tb-resizer:hover::after,
.tb-resizer.active::after {
  top: 0;
  bottom: 0;
  width: 2px;
  background: var(--_accent);
}

.tb-head.dragging {
  opacity: 0.5;
}

.tb-head.drop-before {
  box-shadow: inset 3px 0 0 var(--_accent);
}

.tb-head.drop-after {
  box-shadow: inset -3px 0 0 var(--_accent);
}

.tb-filter,
.tb-size,
.tb-edit {
  box-sizing: border-box;
  width: 100%;
  min-height: 26px;
  padding: 2px 6px;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-sm);
  background: var(--_surface);
  color: var(--_fg);
  font: inherit;
  font-size: var(--_font-size-small);
}

.tb-edit {
  min-height: calc(var(--_row-h) - 8px);
  font-size: inherit;
}

.tb-size {
  width: auto;
}

/* ---------- Cells ---------- */

.tb-text {
  white-space: inherit;
}

.tb-link {
  color: var(--_accent-fg);
}

.tb-bool {
  display: inline-flex;
  vertical-align: middle;
}

.tb-bool.yes {
  color: var(--_success);
}

.tb-bool.no {
  color: var(--_fg-muted);
}

.tb-empty {
  height: auto !important;
  padding: var(--_space-6) var(--_space-4) !important;
  color: var(--_fg-muted);
  text-align: center !important;
  white-space: normal !important;
}

.tb-spacer td {
  height: auto;
  padding: 0;
  border: 0;
}

/* ---------- Groups and details ---------- */

.tb-group-cell,
.tb-detail > td {
  overflow: visible !important;
}

.tb-group-cell {
  background: var(--_surface-sunken) !important;
  cursor: pointer;
}

.tb-group-inner {
  display: inline-flex;
  align-items: center;
  gap: var(--_space-2);
  position: sticky;
  left: var(--_space-3);
}

.tb-chevron {
  display: inline-flex;
  color: var(--_fg-muted);
}

.tb-group-name {
  color: var(--_fg-muted);
}

.tb-count {
  padding: 0 7px;
  border-radius: var(--_radius-full);
  background: var(--_accent-soft);
  color: var(--_accent-fg);
  font-size: var(--_font-size-small);
  line-height: 18px;
}

.tb-detail > td {
  height: auto !important;
  padding: var(--_space-3) var(--_space-5) !important;
  background: var(--_surface-sunken) !important;
  white-space: normal !important;
}

.tb-detail-list,
.tb-card-fields {
  display: grid;
  grid-template-columns: minmax(90px, max-content) 1fr;
  gap: 4px var(--_space-4);
  margin: 0;
}

.tb-detail-list {
  position: sticky;
  left: var(--_space-5);
  max-width: min(900px, 90cqw);
}

.tb-detail-list dt,
.tb-card-fields dt {
  color: var(--_fg-muted);
}

.tb-detail-list dd,
.tb-card-fields dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}

/* ---------- Bars ---------- */

.tb-bulk,
.tb-state {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--_space-2);
  padding: var(--_space-2) var(--_space-3);
  border-bottom: 1px solid var(--_border);
}

.tb-bulk {
  background: color-mix(in srgb, var(--_accent-soft) 70%, var(--_surface));
}

.tb-bulk .spacer {
  flex: 1;
}

.tb-bulk-count {
  font-weight: 600;
}

.tb-bulk .text-btn,
.tb-state .text-btn {
  min-height: 26px;
  font-size: var(--_font-size-small);
}

.tb-bulk .text-btn .icon {
  width: 14px;
  height: 14px;
}

.tb-bulk .text-btn.danger {
  border-color: var(--_danger);
  color: var(--_danger);
}

.tb-state {
  background: var(--_surface);
}

.tb-chip {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  max-width: 320px;
  padding: 0 2px 0 8px;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-full);
  font-size: var(--_font-size-small);
  line-height: 22px;
}

.tb-chip > span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tb-chip-x {
  display: inline-grid;
  place-items: center;
  width: 18px;
  height: 18px;
  padding: 0;
  border: 0;
  border-radius: var(--_radius-full);
  background: none;
  color: var(--_fg-muted);
  cursor: pointer;
}

.tb-chip-x:hover {
  background: var(--_accent-soft);
  color: var(--_fg);
}

.tb-chip-x .icon {
  width: 12px;
  height: 12px;
}

.pager {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--_space-2) var(--_space-3);
  min-height: 40px;
  padding: 0 var(--_space-2) 0 var(--_space-3);
  border-top: 1px solid var(--_border);
  background: var(--_surface);
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
}

.tb-pager .toolbar {
  display: flex;
  align-items: center;
  gap: 2px;
}

.tb-size-label {
  display: inline-flex;
  align-items: center;
  gap: var(--_space-2);
  margin-inline-end: var(--_space-2);
}

.tb-page {
  padding: 0 var(--_space-2);
  color: var(--_fg);
}

/* ---------- Popovers ---------- */

.tb-popover {
  position: absolute;
  top: var(--_space-2);
  right: var(--_space-2);
  z-index: 20;
  min-width: 220px;
  max-width: min(360px, calc(100% - 16px));
  max-height: min(70vh, 460px);
  padding: var(--_space-1);
  overflow: auto;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius);
  background: var(--_surface);
  box-shadow: 0 10px 30px rgb(0 0 0 / 18%);
  color: var(--_fg);
  overscroll-behavior: contain;
}

.tb-popover hr {
  margin: var(--_space-1) 0;
  border: 0;
  border-top: 1px solid var(--_border);
}

.tb-menu-title {
  padding: var(--_space-2) var(--_space-2) var(--_space-1);
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  font-weight: 600;
}

.tb-menu-item {
  display: flex;
  align-items: center;
  gap: var(--_space-2);
  width: 100%;
  min-height: 30px;
  padding: 0 var(--_space-2);
  border: 0;
  border-radius: var(--_radius-sm);
  background: none;
  color: inherit;
  font: inherit;
  text-align: start;
  cursor: pointer;
}

.tb-menu-item:hover:not(:disabled),
.tb-menu-item:focus-visible {
  background: var(--_accent-soft);
}

.tb-menu-item:disabled {
  opacity: 0.45;
  cursor: default;
}

.tb-menu-item .icon {
  width: 15px;
  height: 15px;
  color: var(--_fg-muted);
}

.tb-menu-item[aria-checked='true'] .icon {
  color: var(--_accent-fg);
}

.tb-col-list {
  margin: 0;
  padding: 0;
  list-style: none;
}

.tb-col-item {
  display: flex;
  align-items: center;
  gap: 2px;
  padding-inline-start: var(--_space-2);
  border-radius: var(--_radius-sm);
}

.tb-col-item:hover {
  background: color-mix(in srgb, var(--_accent-soft) 50%, transparent);
}

.tb-col-item label {
  display: flex;
  flex: 1;
  align-items: center;
  gap: var(--_space-2);
  min-width: 0;
  min-height: 30px;
  cursor: pointer;
}

.tb-col-item label span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tb-col-item input {
  accent-color: var(--_accent);
}

.tb-col-actions {
  display: flex;
  gap: var(--_space-2);
  padding: var(--_space-2);
  border-top: 1px solid var(--_border);
}

.tb-help {
  min-width: min(380px, calc(100% - 16px));
  padding: var(--_space-2) var(--_space-3);
}

.tb-popover-close {
  float: right;
}

.tb-keys {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px var(--_space-3);
  margin: var(--_space-2) 0;
}

.tb-keys dt {
  white-space: nowrap;
}

.tb-keys dd {
  margin: 0;
}

.tb-keys kbd {
  padding: 1px 5px;
  border: 1px solid var(--_border-strong);
  border-bottom-width: 2px;
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
  font-family: var(--_font-mono);
  font-size: var(--_font-size-small);
}

.tb-hint {
  margin: var(--_space-2) 0 0;
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
}

/* ---------- Cards ---------- */

.tb-cards-wrap {
  padding: var(--_space-3);
}

.tb-card-tools {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--_space-2);
  margin-bottom: var(--_space-3);
}

.tb-card-tools .tb-filter {
  width: auto;
  min-width: 140px;
}

.tb-card-all {
  display: inline-flex;
  align-items: center;
  gap: var(--_space-2);
  margin-inline-end: auto;
}

.tb-cards {
  display: grid;
  gap: var(--_space-2);
}

.tb-card {
  padding: var(--_space-3);
  border: 1px solid var(--_border);
  border-radius: var(--_radius);
  background: var(--_surface);
}

.tb-card.selected {
  border-color: var(--_accent);
  background: color-mix(in srgb, var(--_accent-soft) 60%, var(--_surface));
}

.tb-card-top {
  display: flex;
  align-items: center;
  gap: var(--_space-2);
  margin-bottom: var(--_space-2);
}

.tb-card-title {
  min-width: 0;
  overflow-wrap: anywhere;
}

.tb-card-fields {
  font-size: var(--_font-size-small);
}

.tb-card-group {
  display: flex;
  align-items: center;
  gap: var(--_space-2);
  width: 100%;
  min-height: 36px;
  padding: 0 var(--_space-2);
  border: 0;
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
  color: var(--_fg);
  font: inherit;
  cursor: pointer;
}

@media (pointer: coarse) {
  .tb-check {
    width: 20px;
    height: 20px;
  }

  .tb-resizer {
    width: 16px;
    inset-inline-end: -8px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .tb-sort-hint {
    transition: none;
  }
}

/* ---------- Sticky header: the table scrolls in a box, its header stays on top ---------- */

.vt[data-sticky] .tb-body:has(> .tb-grid) {
  max-height: var(--_max-height, min(78vh, 760px));
}

/* ---------- Chevrons turn instead of changing ---------- */

.tb-chevron .icon,
.tb-expand .icon,
.tb-card-group .icon {
  transition: transform var(--_duration) var(--_easing);
}

.tb-group[aria-expanded='true'] .tb-chevron .icon,
.tb-expand[aria-expanded='true'] .icon,
.tb-card-group[aria-expanded='true'] .icon {
  transform: rotate(90deg);
}

.tb-expand[aria-expanded='true'] {
  background: var(--_accent-soft);
  color: var(--_accent-fg);
}

.tb-row:has(.tb-expand[aria-expanded='true']) > * {
  border-bottom-color: transparent;
}

/* ---------- Groups ---------- */

.tb-group-cell {
  border-top: 1px solid var(--_border);
  background: color-mix(in srgb, var(--_accent-soft) 35%, var(--_surface-sunken)) !important;
}

.tb-group-cell:hover {
  background: color-mix(in srgb, var(--_accent-soft) 70%, var(--_surface-sunken)) !important;
}

.tb-group-inner {
  flex-wrap: wrap;
  row-gap: 2px;
}

.tb-group-agg {
  display: inline-flex;
  align-items: baseline;
  gap: 6px;
  margin-inline-start: var(--_space-3);
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
}

.tb-group-agg strong {
  color: var(--_fg);
  font-weight: 600;
}

/* ---------- Details ---------- */

.tb-detail > td {
  padding: 0 !important;
  border-bottom: 1px solid var(--_border) !important;
  background: color-mix(in srgb, var(--_accent-soft) 25%, var(--_surface)) !important;
}

.tb-detail-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(240px, 100%), 1fr));
  gap: var(--_space-2);
  margin: var(--_space-2) var(--_space-3) var(--_space-3);
  padding: var(--_space-3);
  border-inline-start: 3px solid var(--_accent);
  border-radius: var(--_radius);
  background: var(--_surface);
  box-shadow: 0 1px 2px rgb(0 0 0 / 6%);
  animation: tb-open var(--_duration) var(--_easing);
}

.tb-field {
  min-width: 0;
  padding: var(--_space-1) var(--_space-2);
  border-radius: var(--_radius-sm);
}

.tb-field:hover {
  background: var(--_surface-sunken);
}

.tb-field dt {
  margin-bottom: 2px;
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  font-weight: 500;
}

.tb-field dd {
  margin: 0;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}

.tb-field.hidden-col dt::after {
  content: ' \xB7';
  color: var(--_border-strong);
}

@keyframes tb-open {
  from {
    opacity: 0;
    transform: translateY(-4px);
  }
}

/* ---------- Cell displays ---------- */

.vt {
  --_tone-gray: #6b7280;
  --_tone-red: #dc2626;
  --_tone-orange: #ea580c;
  --_tone-yellow: #ca8a04;
  --_tone-green: #16a34a;
  --_tone-teal: #0d9488;
  --_tone-blue: #2563eb;
  --_tone-purple: #9333ea;
  --_tone-pink: #db2777;
}

.tone-gray {
  --_tone: var(--_tone-gray);
}
.tone-red {
  --_tone: var(--_tone-red);
}
.tone-orange {
  --_tone: var(--_tone-orange);
}
.tone-yellow {
  --_tone: var(--_tone-yellow);
}
.tone-green {
  --_tone: var(--_tone-green);
}
.tone-teal {
  --_tone: var(--_tone-teal);
}
.tone-blue {
  --_tone: var(--_tone-blue);
}
.tone-purple {
  --_tone: var(--_tone-purple);
}
.tone-pink {
  --_tone: var(--_tone-pink);
}

.tb-badges {
  display: inline-flex;
  flex-wrap: nowrap;
  align-items: center;
  gap: 4px;
  max-width: 100%;
  overflow: hidden;
  vertical-align: middle;
}

.vt[data-wrap] .tb-badges,
.tb-field .tb-badges,
.tb-card .tb-badges,
.tb-cell.open .tb-badges {
  flex-wrap: wrap;
}

.tb-badge {
  display: inline-flex;
  flex: none;
  align-items: center;
  gap: 5px;
  max-width: 220px;
  padding: 0 8px;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--_tone) 30%, transparent);
  border-radius: var(--_radius-full);
  background: color-mix(in srgb, var(--_tone) 13%, var(--_surface));
  color: color-mix(in srgb, var(--_tone) 72%, var(--_fg));
  font-size: var(--_font-size-small);
  font-weight: 500;
  line-height: 20px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tb-badge > span:last-child {
  overflow: hidden;
  text-overflow: ellipsis;
}

.tb-badge.status {
  border-color: transparent;
  background: transparent;
  padding-inline-start: 0;
  color: var(--_fg);
}

.tb-dot {
  flex: none;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--_tone);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--_tone) 18%, transparent);
}

.tb-more {
  flex: none;
  margin-inline-start: 4px;
  padding: 0 6px;
  border: 0;
  border-radius: var(--_radius-sm);
  background: var(--_accent-soft);
  color: var(--_accent-fg);
  font: inherit;
  font-size: var(--_font-size-small);
  font-weight: 600;
  line-height: 20px;
  cursor: pointer;
  white-space: nowrap;
}

.tb-more:hover {
  background: color-mix(in srgb, var(--_accent) 22%, var(--_surface));
}

.tb-more-wrap {
  display: inline-flex;
  align-items: baseline;
  max-width: 100%;
  min-width: 0;
}

.tb-more-wrap > :first-child {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* An opened cell grows: the row takes the height of its text. */
.tb-grid td:has(.tb-more-wrap.open),
.tb-grid td:has(.tb-badges .tb-more[aria-expanded='true']) {
  height: auto;
  padding-block: 6px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.tb-more-wrap.open {
  display: inline;
}

.tb-more-wrap.open .tb-more {
  vertical-align: baseline;
}

.tb-clamp {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: var(--_lines, 2);
  white-space: normal;
}

.tb-code {
  padding: 1px 5px;
  border-radius: var(--_radius-sm);
  background: var(--_surface-sunken);
  font-family: var(--_font-mono);
  font-size: 0.92em;
}

.tb-json {
  color: var(--_fg-muted);
}

.tb-progress-wrap {
  display: inline-flex;
  align-items: center;
  gap: var(--_space-2);
  width: 100%;
  vertical-align: middle;
}

.tb-progress {
  position: relative;
  flex: 1;
  min-width: 40px;
  height: 6px;
  overflow: hidden;
  border-radius: var(--_radius-full);
  background: color-mix(in srgb, var(--_tone) 15%, var(--_surface-sunken));
}

.tb-progress-fill {
  position: absolute;
  inset: 0 auto 0 0;
  border-radius: inherit;
  background: var(--_tone);
}

.tb-progress-text {
  flex: none;
  min-width: 3.2em;
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  text-align: end;
}

.tb-rating {
  letter-spacing: 1px;
  white-space: nowrap;
}

.tb-star {
  color: var(--_border-strong);
}

.tb-star.on {
  color: #f59e0b;
}

.tb-star.half {
  background: linear-gradient(90deg, #f59e0b 50%, var(--_border-strong) 50%);
  background-clip: text;
  color: transparent;
}

.tb-image {
  width: var(--_img, 28px);
  height: var(--_img, 28px);
  border-radius: var(--_radius-sm);
  object-fit: cover;
  vertical-align: middle;
}

.tb-person {
  display: inline-flex;
  align-items: center;
  gap: var(--_space-2);
  max-width: 100%;
  min-width: 0;
  vertical-align: middle;
}

.tb-avatar {
  display: inline-grid;
  flex: none;
  place-items: center;
  width: 26px;
  height: 26px;
  overflow: hidden;
  border-radius: 50%;
  background: color-mix(in srgb, var(--_tone) 22%, var(--_surface));
  color: color-mix(in srgb, var(--_tone) 80%, var(--_fg));
  font-size: 11px;
  font-weight: 700;
}

.vt[data-density='compact'] .tb-avatar {
  width: 22px;
  height: 22px;
  font-size: 10px;
}

.tb-avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.tb-person-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
  line-height: 1.2;
}

.tb-person-text > * {
  overflow: hidden;
  text-overflow: ellipsis;
}

.tb-sub {
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
}

.tb-color {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.tb-swatch {
  width: 14px;
  height: 14px;
  border: 1px solid var(--_border-strong);
  border-radius: 4px;
}

.tb-blank {
  color: var(--_fg-muted);
}

/* ---------- Query bar ---------- */

.tb-query {
  display: flex;
  align-items: flex-start;
  gap: var(--_space-2);
  padding: var(--_space-2) var(--_space-3);
  border-bottom: 1px solid var(--_border);
  background: var(--_surface);
}

.tb-query-icon {
  display: inline-flex;
  padding-top: 6px;
  color: var(--_fg-muted);
}

.tb-query-field {
  display: flex;
  flex: 1;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px;
  min-width: 0;
  min-height: 30px;
  padding: 2px 4px;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius);
  background: var(--_surface);
}

.tb-query-field:focus-within {
  border-color: var(--_accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--_accent) 18%, transparent);
}

.tb-cond {
  display: inline-flex;
  align-items: center;
  max-width: 100%;
  border: 1px solid color-mix(in srgb, var(--_accent) 35%, transparent);
  border-radius: var(--_radius-full);
  background: var(--_accent-soft);
  color: var(--_accent-fg);
  font-size: var(--_font-size-small);
  line-height: 22px;
}

.tb-cond.not {
  border-color: color-mix(in srgb, var(--_danger) 40%, transparent);
  background: color-mix(in srgb, var(--_danger) 10%, var(--_surface));
  color: var(--_danger);
}

.tb-cond.text {
  border-style: dashed;
}

.tb-cond-label {
  max-width: 280px;
  padding: 0 4px 0 9px;
  overflow: hidden;
  border: 0;
  background: none;
  color: inherit;
  font: inherit;
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: pointer;
}

.tb-join {
  padding: 0 6px;
  border: 0;
  border-radius: var(--_radius-sm);
  background: none;
  color: var(--_fg-muted);
  font: inherit;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.06em;
  line-height: 20px;
  cursor: pointer;
}

.tb-join.or {
  color: var(--_warning);
}

.tb-join:hover {
  background: var(--_surface-sunken);
}

.tb-query-box {
  position: relative;
  flex: 1;
  min-width: 160px;
}

.tb-query-input {
  box-sizing: border-box;
  width: 100%;
  min-height: 24px;
  padding: 0 4px;
  border: 0;
  outline: none;
  background: transparent;
  color: var(--_fg);
  font: inherit;
}

.tb-suggest {
  position: absolute;
  top: calc(100% + 6px);
  left: -4px;
  z-index: 30;
  min-width: min(320px, 90vw);
  max-height: 300px;
  margin: 0;
  padding: var(--_space-1);
  overflow: auto;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius);
  background: var(--_surface);
  box-shadow: 0 10px 30px rgb(0 0 0 / 18%);
  list-style: none;
}

.tb-option {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--_space-3);
  min-height: 30px;
  padding: 0 var(--_space-2);
  border-radius: var(--_radius-sm);
  cursor: pointer;
}

.tb-option > span:first-child {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tb-option.active,
.tb-option:hover {
  background: var(--_accent-soft);
}

.tb-option-hint {
  flex: none;
  color: var(--_fg-muted);
  font-size: var(--_font-size-small);
  font-variant-numeric: tabular-nums;
}

.tb-match {
  flex: none;
  min-height: 30px;
  padding: 0 var(--_space-2);
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-sm);
  background: var(--_surface);
  color: var(--_fg);
  font: inherit;
  font-size: var(--_font-size-small);
  cursor: pointer;
}

/* ---------- Selection header ---------- */

.tb-ctl-select {
  white-space: nowrap;
}

.tb-select-more {
  display: inline-grid;
  place-items: center;
  width: 14px;
  height: 22px;
  margin-inline-start: 1px;
  padding: 0;
  border: 0;
  border-radius: var(--_radius-sm);
  background: none;
  color: var(--_fg-muted);
  vertical-align: middle;
  cursor: pointer;
}

.tb-select-more:hover,
.tb-select-more[aria-expanded='true'] {
  background: var(--_accent-soft);
  color: var(--_fg);
}

.tb-select-more .icon {
  width: 12px;
  height: 12px;
}

.tb-select-menu .tb-menu-item {
  justify-content: space-between;
}

.tb-row.selected > :first-child {
  box-shadow: inset 3px 0 0 var(--_accent);
}

:host([select-on-click]) .tb-row {
  cursor: pointer;
}

/* ---------- Pager ---------- */

.tb-pager {
  padding-block: 4px;
}

.tb-pager.top {
  border-top: 0;
  border-bottom: 1px solid var(--_border);
}

.tb-pager-end {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--_space-2);
}

.tb-pages {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 2px;
}

.tb-page-btn {
  min-width: 28px;
  height: 28px;
  padding: 0 6px;
  border: 0;
  border-radius: var(--_radius-sm);
  background: none;
  color: var(--_fg);
  font: inherit;
  font-variant-numeric: tabular-nums;
  cursor: pointer;
}

.tb-page-btn:hover {
  background: var(--_accent-soft);
}

.tb-page-btn.current {
  background: var(--_accent);
  color: var(--_on-accent);
  font-weight: 600;
}

.tb-gap {
  padding: 0 4px;
  color: var(--_fg-muted);
}

.tb-jump {
  box-sizing: border-box;
  width: 72px;
  min-height: 28px;
  margin-inline-start: var(--_space-2);
  padding: 0 6px;
  border: 1px solid var(--_border-strong);
  border-radius: var(--_radius-sm);
  background: var(--_surface);
  color: var(--_fg);
  font: inherit;
}

.tb-pager .text-btn {
  min-height: 28px;
  font-size: var(--_font-size-small);
}

/* ---------- Phones ---------- */

.tb-card dd {
  min-width: 0;
}

.tb-card .tb-more-wrap {
  display: inline;
}

.tb-card .tb-more-wrap > :first-child {
  white-space: pre-wrap;
}

@container (max-width: 520px) {
  .tb-query {
    padding-inline: var(--_space-2);
  }

  .tb-query-icon {
    display: none;
  }

  .tb-pager {
    justify-content: center;
    padding-inline: var(--_space-2);
  }

  .tb-pager-end {
    justify-content: center;
  }

  .tb-size-label > span,
  .tb-jump {
    display: none;
  }

  .tb-bulk {
    padding-inline: var(--_space-2);
  }

  .tb-bulk .text-btn > span:not(:only-child) {
    display: none;
  }
}

.tb {
  container-type: inline-size;
}

@media (prefers-reduced-motion: reduce) {
  .tb-detail-list {
    animation: none;
  }

  .tb-chevron .icon,
  .tb-expand .icon,
  .tb-card-group .icon {
    transition: none;
  }
}

/* Row states are layered on the surface: translucent accents must not show what scrolls under pinned columns. */
.tb-grid tbody .tb-row:hover > * {
  --_row-tint: color-mix(in srgb, var(--_accent-soft) 60%, transparent);
  background: linear-gradient(var(--_row-tint), var(--_row-tint)), var(--_surface);
}

.tb-grid tbody .tb-row.selected > * {
  --_row-tint: var(--_accent-soft);
  background: linear-gradient(var(--_row-tint), var(--_row-tint)), var(--_surface);
}

.tb-grid tbody .tb-row.selected:hover > * {
  --_row-tint: color-mix(in srgb, var(--_accent) 20%, transparent);
}

.tb-grid .tb-group-cell {
  --_row-tint: color-mix(in srgb, var(--_accent-soft) 45%, transparent);
  background:
    linear-gradient(var(--_row-tint), var(--_row-tint)), var(--_surface-sunken) !important;
}

.tb-grid .tb-group-cell:hover {
  --_row-tint: var(--_accent-soft);
}

.tb-grid .tb-detail > td {
  --_row-tint: color-mix(in srgb, var(--_accent-soft) 40%, transparent);
  background: linear-gradient(var(--_row-tint), var(--_row-tint)), var(--_surface) !important;
}

.tb-detail-list {
  position: sticky;
  left: var(--_space-3);
  max-width: min(1100px, calc(100cqw - 2 * var(--_space-3)));
}

/* Small screens: keep the essential header buttons. */
@media (max-width: 560px) {
  .header [data-focus-key='help'],
  .header [data-focus-key='density'],
  .header [data-focus-key='expand-all'],
  .header [data-focus-key='collapse-all'],
  .header [data-focus-key='fullscreen'] {
    display: none;
  }
}
`;function j(n){if(n===null)return null;let e=n.trim().toLowerCase();return!(e==="false"||e==="off"||e==="no"||e==="0")}function te(n,{min:e,max:t,fallback:a}){if(n===null||n.length>32)return a;let r=n.trim();if(!/^[+-]?\d+$/.test(r))return a;let s=Number(r);return Number.isSafeInteger(s)?Math.min(t,Math.max(e,s)):a}function O(n,e,t){if(n===null)return t;let a=n.trim().toLowerCase();return e.includes(a)?a:t}function Ke(n){if(n===null)return null;let e=n.trim().toLowerCase();return/^\d{1,6}(?:\.\d{1,4})?(?:px|em|rem|vh|svh|lvh|dvh|%|ch|lh)$/.test(e)?e:null}function Be(n,e=200){if(!n)return"";let a=n.slice(0,e*4).replace(/[\u0000-\u001f\u007f-\u009f]/g,"").replace(/\s+/g," ").trim();return a.length>e?a.slice(0,e-1)+"\u2026":a}function He(n,e){let t=(n??"").split(/[\\/]/).pop()??"",a=/[\u0000-\u001f\u007f<>:"|?*]/g;return t.replace(a,"").replace(/^[.\s]+/,"").trim().slice(0,120)||e}async function B(n,e=document){if(navigator.clipboard&&window.isSecureContext)try{return await navigator.clipboard.writeText(n),!0}catch{}return ta(n,e)}function ta(n,e){let t=document.createElement("textarea");t.value=n,t.setAttribute("readonly",""),t.setAttribute("aria-hidden","true"),t.style.position="fixed",t.style.opacity="0",t.style.pointerEvents="none",(e instanceof Document?e.body:e).appendChild(t);try{return t.select(),document.execCommand("copy")}catch{return!1}finally{t.remove()}}function V(n,e,t="text/plain"){let a=new Blob([n],{type:`${t};charset=utf-8`}),r=URL.createObjectURL(a),s=document.createElement("a");s.href=r,s.download=e,s.rel="noopener",s.style.display="none",document.body.appendChild(s),s.click(),s.remove(),setTimeout(()=>URL.revokeObjectURL(r),1e3)}var Ue=`/*
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
`;var Ge=`/*
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
`;var Ve=`/*
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
`;var ye=Object.freeze({theme:"auto",lightTheme:"light",darkTheme:"dark",lang:"en",maxSize:2097152,highlightLimit:3e5,maxDepth:512,fetchTimeout:15e3,languagesUrl:"",syntaxTheme:"",syntaxThemeDark:"",syntaxThemesUrl:"",vendorUrl:""}),na=Object.freeze({maxSize:50*1024*1024,highlightLimit:5*1024*1024,maxDepth:1e4,fetchTimeout:12e4}),H={...ye},ve=new Set;function R(){return Object.freeze({...H})}function ia(n){if(!n||typeof n!="object")return R();let e={...H};for(let[a,r]of Object.entries(n))oa(a,r);let t=new Set(Object.keys(H).filter(a=>H[a]!==e[a]));if(t.size)for(let a of ve)a(t);return R()}function oa(n,e){if(!Object.prototype.hasOwnProperty.call(ye,n)){console.warn(`[vitrine] Unknown configuration option "${n}".`);return}let t=n;if(typeof ye[t]==="number"){let r=na[t];if(typeof e!="number"||!Number.isFinite(e)||e<=0){console.warn(`[vitrine] Option "${n}" must be a positive number.`);return}H[t]=Math.min(Math.floor(e),r??e);return}if(typeof e!="string"||e.length>2048){console.warn(`[vitrine] Option "${n}" must be a string.`);return}H[t]=e.trim()}function We(n){return ve.add(n),()=>ve.delete(n)}function d(n,e={},...t){let a=document.createElement(n);if(e.class&&(a.className=e.class),e.part&&a.setAttribute("part",e.part),e.attrs)for(let[r,s]of Object.entries(e.attrs))s===!1||s===null||s===void 0||a.setAttribute(r,s===!0?"":String(s));if(e.text!==void 0&&(a.textContent=e.text),e.on)for(let[r,s]of Object.entries(e.on))a.addEventListener(r,s);return ae(a,t),a}function ae(n,e){for(let t of e)t==null||t===!1||n.append(typeof t=="string"?document.createTextNode(t):t)}var Qe=0;function re(n){return Qe+=1,`vt-${n}-${Qe}`}function se(n){let e=n.replace(/\r\n?/g,`
`).split(`
`);for(;e.length&&e[0].trim()==="";)e.shift();for(;e.length&&e[e.length-1].trim()==="";)e.pop();let t=1/0;for(let a of e){if(a.trim()==="")continue;let r=/^[ \t]*/.exec(a);if(t=Math.min(t,r?r[0].length:0),t===0)break}return!Number.isFinite(t)||t===0?e.join(`
`):e.map(a=>a.slice(t)).join(`
`)}function Je(n,e){let t,a=(...r)=>{clearTimeout(t),t=setTimeout(()=>n(...r),e)};return a.cancel=()=>clearTimeout(t),a}function Ye(n){try{return new URL(n,document.baseURI).origin===location.origin}catch{return!1}}var M=class extends Error{constructor(e,t={},a){super(e,a===void 0?void 0:{cause:a}),this.name="VitrineError",this.code=e,this.params=t}},la=new Set(["text/plain","text/markdown","text/x-markdown","application/json","text/json","application/xml","text/xml"]);function Xe(n){for(let a of Array.from(n.children)){let r=ca(a);if(r!==null)return r}let e="";for(let a of Array.from(n.childNodes))a.nodeType===Node.TEXT_NODE||a.nodeType===Node.CDATA_SECTION_NODE?e+=a.nodeValue??"":a.nodeType===Node.ELEMENT_NODE&&(e+=a.textContent??"");let t=se(e);return t===""?null:t}function ca(n){if(n instanceof HTMLTemplateElement){let e=n.content.children.length>0;return se(e?n.innerHTML:n.content.textContent??"")}return n instanceof HTMLScriptElement&&la.has(n.type.trim().toLowerCase())?se(n.textContent??""):null}function ne(n,e){if(n.length>e)throw new M("tooLarge",{size:n.length,limit:e})}async function Ze(n,e){let t=da(n),a=Ye(t.href);if(!a&&!e.allowRemote)throw new M("remoteBlocked");let r=new AbortController,s=setTimeout(()=>r.abort(new M("timeout")),e.timeout),i=()=>r.abort(e.signal?.reason);e.signal?.addEventListener("abort",i,{once:!0}),e.signal?.aborted&&i();try{let o=await fetch(t.href,{mode:a?"same-origin":"cors",credentials:"same-origin",redirect:"follow",referrerPolicy:"strict-origin-when-cross-origin",signal:r.signal});if(!o.ok)throw new M("loadFailed",{url:et(t),reason:`HTTP ${o.status}`});let l=Number(o.headers.get("content-length"));if(Number.isFinite(l)&&l>e.maxSize*4)throw new M("tooLarge",{size:l,limit:e.maxSize});return await ha(o,e.maxSize,r)}catch(o){throw ua(o,r.signal,t)}finally{clearTimeout(s),e.signal?.removeEventListener("abort",i)}}function da(n){let e;try{e=new URL(n.trim(),document.baseURI)}catch{throw new M("unsafeUrl")}if(e.protocol!=="http:"&&e.protocol!=="https:")throw new M("unsafeUrl");return e}async function ha(n,e,t){if(!n.body){let i=await n.text();return ne(i,e),i}let a=n.body.getReader(),r=new TextDecoder,s="";for(;;){let{done:i,value:o}=await a.read();if(i)break;if(s+=r.decode(o,{stream:!0}),s.length>e)throw t.abort(),new M("tooLarge",{size:`> ${e}`,limit:e})}return s+=r.decode(),ne(s,e),s}function ua(n,e,t){if(n instanceof M)return n;if(e.aborted&&e.reason instanceof M)return e.reason;if(n instanceof DOMException&&n.name==="AbortError")return n;let a=n instanceof Error?n.message:String(n);return new M("loadFailed",{url:et(t),reason:a},n)}function et(n){let e=n.origin===location.origin?n.pathname+n.search:n.href;return e.length>120?e.slice(0,119)+"\u2026":e}function tt(n){return n instanceof DOMException&&n.name==="AbortError"}var _=Object.freeze({READY:"vt-ready",COPY:"vt-copy",SEARCH:"vt-search",TAB_CHANGE:"vt-tab-change",INPUT:"vt-input",CHANGE:"vt-change",MODE_CHANGE:"vt-mode-change",TAG_ADD:"vt-tag-add",TAG_REMOVE:"vt-tag-remove",TAG_CREATE:"vt-tag-create",TAG_CLICK:"vt-tag-click",SORT:"vt-sort",FULLSCREEN_CHANGE:"vt-fullscreen-change",LAYOUT_CHANGE:"vt-layout-change",SELECT:"vt-select",TOGGLE:"vt-toggle",FILTER_CHANGE:"vt-filter-change",TYPING_END:"vt-typing-end",CHANGE_NAVIGATE:"vt-change-navigate",STEP_TOGGLE:"vt-step-toggle",JOB_CHANGE:"vt-job-change",MATCH:"vt-match",BULK_ACTION:"vt-bulk-action",CELL_EDIT:"vt-cell-edit",COLUMN_CHANGE:"vt-column-change",ROW_ACTIVATE:"vt-row-activate",ERROR:"vt-error"});function C(n,e,t){return n.dispatchEvent(new CustomEvent(e,{detail:t,bubbles:!0,composed:!0,cancelable:!0}))}var at=`/* Vitrine Light \u2014 default light theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
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
`;var rt=`/* Vitrine Dark \u2014 default dark theme. Values: docs/DESIGN_SYSTEM.md \xA72. */
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
`;var st=`/* Vitrine Dim \u2014 softer, blue-grey dark theme for long reading sessions. */
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
`;var nt=`/* Vitrine Paper \u2014 warm, low-glare light theme. */
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
`;var it=`/* Vitrine High Contrast \u2014 maximum legibility (WCAG AAA text contrast). */
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
`;var ya=Object.freeze(["bg","surface","surface-sunken","surface-raised","border","border-strong","fg","fg-muted","accent","accent-fg","on-accent","accent-soft","highlight","highlight-current","line-highlight","success","warning","danger","info","diff-added","diff-removed","shadow","syntax-keyword","syntax-string","syntax-number","syntax-function","syntax-type","syntax-comment","syntax-attr","syntax-tag","syntax-meta"]),$=new Map,I=new CSSStyleSheet,va=/^[a-z][a-z0-9-]{0,39}$/,xa=new Set(["auto"]);function wa(n){let e=/\[data-theme='([a-z0-9-]+)'\]/.exec(n)?.[1];if(!e)throw new Error("[vitrine] Theme file without a [data-theme] selector.");let t=/color-scheme:\s*(light|dark)\s*;/.exec(n)?.[1]==="dark"?"dark":"light",a={};for(let[,r,s]of n.matchAll(/--vt-([a-z0-9-]+)\s*:\s*([^;]+);/g))a[r]=s.trim();return{name:e,definition:{colorScheme:t,tokens:a}}}for(let n of[at,rt,st,nt,it]){let{name:e,definition:t}=wa(n);$.set(e,t)}var ka=Object.freeze([...$.keys()]);function _a(n){return typeof n!="string"||n.length===0||n.length>200||/[;{}<>\\]/.test(n)?!1:!/(?:url|image|image-set|cross-fade|element|src)\s*\(|@import|expression/i.test(n)}function Sa(n,e={}){if(typeof n!="string"||!va.test(n)||xa.has(n))throw new TypeError(`[vitrine] Invalid theme name "${n}". Use lowercase letters, digits, "-".`);let t=e.colorScheme==="dark"?"dark":e.colorScheme==="light"?"light":void 0,a=e.extends??(t==="dark"?"dark":"light"),r=$.get(a);if(!r)throw new TypeError(`[vitrine] Unknown base theme "${a}".`);let s={...r.tokens};for(let[i,o]of Object.entries(e.tokens??{})){let l=i.replace(/^--vt-/,"");ya.includes(l)?_a(o)?s[l]=o.trim():console.warn(`[vitrine] Unsafe or invalid value for theme token "${i}" ignored.`):console.warn(`[vitrine] Unknown theme token "${i}" ignored.`)}return $.set(n,{colorScheme:t??r.colorScheme,tokens:s}),ot(),lt(),n}function Ca(){return[...$.keys()]}function ke(n){let e=$.get(n);return e?{colorScheme:e.colorScheme,tokens:{...e.tokens}}:void 0}function ot(){for(;I.cssRules.length;)I.deleteRule(0);for(let[n,e]of $){let t=I.insertRule(`.vt[data-theme="${n}"] {}`,I.cssRules.length),a=I.cssRules[t].style;a.setProperty("color-scheme",e.colorScheme);for(let[r,s]of Object.entries(e.tokens))a.setProperty(`--_${r}`,`var(--vt-${r}, ${s})`)}}ot();var xe=typeof matchMedia=="function"?matchMedia("(prefers-color-scheme: dark)"):null,we=new Set;function lt(){for(let n of we)n()}xe?.addEventListener?.("change",lt);function ct(n){return we.add(n),()=>we.delete(n)}function dt(n){let e=R(),t=n?.trim().toLowerCase()||e.theme;if(t!=="auto"&&!$.has(t)&&(t=$.has(e.theme)?e.theme:"auto"),t!=="auto")return t;let a=xe?.matches?e.darkTheme:e.lightTheme;return $.has(a)?a:xe?.matches?"dark":"light"}var Aa="",ht="",Ta="";function ut(n){Aa=n}function pt(n){Ta=n}function _e(n){ht=n}function ft(){return ht}var Se=Object.freeze({"1c-light":0,"a11y-dark":1,"a11y-light":0,agate:1,"an-old-hope":1,androidstudio:1,"arduino-light":0,arta:1,ascetic:0,"atom-one-dark":1,"atom-one-dark-reasonable":1,"atom-one-light":0,"base16-3024":1,"base16-apathy":1,"base16-apprentice":1,"base16-ashes":1,"base16-atelier-cave":1,"base16-atelier-cave-light":0,"base16-atelier-dune":1,"base16-atelier-dune-light":0,"base16-atelier-estuary":1,"base16-atelier-estuary-light":0,"base16-atelier-forest":1,"base16-atelier-forest-light":0,"base16-atelier-heath":1,"base16-atelier-heath-light":0,"base16-atelier-lakeside":1,"base16-atelier-lakeside-light":0,"base16-atelier-plateau":1,"base16-atelier-plateau-light":0,"base16-atelier-savanna":1,"base16-atelier-savanna-light":0,"base16-atelier-seaside":1,"base16-atelier-seaside-light":0,"base16-atelier-sulphurpool":1,"base16-atelier-sulphurpool-light":0,"base16-atlas":1,"base16-bespin":1,"base16-black-metal":1,"base16-black-metal-bathory":1,"base16-black-metal-burzum":1,"base16-black-metal-dark-funeral":1,"base16-black-metal-gorgoroth":1,"base16-black-metal-immortal":1,"base16-black-metal-khold":1,"base16-black-metal-marduk":1,"base16-black-metal-mayhem":1,"base16-black-metal-nile":1,"base16-black-metal-venom":1,"base16-brewer":1,"base16-bright":1,"base16-brogrammer":1,"base16-brush-trees":0,"base16-brush-trees-dark":1,"base16-chalk":1,"base16-circus":1,"base16-classic-dark":1,"base16-classic-light":0,"base16-codeschool":1,"base16-colors":1,"base16-cupcake":0,"base16-cupertino":0,"base16-danqing":1,"base16-darcula":1,"base16-dark-violet":1,"base16-darkmoss":1,"base16-darktooth":1,"base16-decaf":1,"base16-default-dark":1,"base16-default-light":0,"base16-dirtysea":0,"base16-dracula":1,"base16-edge-dark":1,"base16-edge-light":0,"base16-eighties":1,"base16-embers":1,"base16-equilibrium-dark":1,"base16-equilibrium-gray-dark":1,"base16-equilibrium-gray-light":0,"base16-equilibrium-light":0,"base16-espresso":1,"base16-eva":1,"base16-eva-dim":1,"base16-flat":1,"base16-framer":1,"base16-fruit-soda":0,"base16-gigavolt":1,"base16-github":0,"base16-google-dark":1,"base16-google-light":0,"base16-grayscale-dark":1,"base16-grayscale-light":0,"base16-green-screen":1,"base16-gruvbox-dark-hard":1,"base16-gruvbox-dark-medium":1,"base16-gruvbox-dark-pale":1,"base16-gruvbox-dark-soft":1,"base16-gruvbox-light-hard":0,"base16-gruvbox-light-medium":0,"base16-gruvbox-light-soft":0,"base16-hardcore":1,"base16-harmonic16-dark":1,"base16-harmonic16-light":0,"base16-heetch-dark":1,"base16-heetch-light":0,"base16-helios":1,"base16-hopscotch":1,"base16-horizon-dark":1,"base16-horizon-light":0,"base16-humanoid-dark":1,"base16-humanoid-light":0,"base16-ia-dark":1,"base16-ia-light":0,"base16-icy-dark":1,"base16-ir-black":1,"base16-isotope":1,"base16-kimber":1,"base16-london-tube":1,"base16-macintosh":1,"base16-marrakesh":1,"base16-materia":1,"base16-material":1,"base16-material-darker":1,"base16-material-lighter":0,"base16-material-palenight":1,"base16-material-vivid":1,"base16-mellow-purple":1,"base16-mexico-light":0,"base16-mocha":1,"base16-monokai":1,"base16-nebula":1,"base16-nord":1,"base16-nova":1,"base16-ocean":1,"base16-oceanicnext":1,"base16-one-light":0,"base16-onedark":1,"base16-outrun-dark":1,"base16-papercolor-dark":1,"base16-papercolor-light":0,"base16-paraiso":1,"base16-pasque":1,"base16-phd":1,"base16-pico":1,"base16-pop":1,"base16-porple":1,"base16-qualia":1,"base16-railscasts":1,"base16-rebecca":1,"base16-ros-pine":1,"base16-ros-pine-dawn":0,"base16-ros-pine-moon":1,"base16-sagelight":0,"base16-sandcastle":1,"base16-seti-ui":1,"base16-shapeshifter":0,"base16-silk-dark":1,"base16-silk-light":0,"base16-snazzy":1,"base16-solar-flare":1,"base16-solar-flare-light":0,"base16-solarized-dark":1,"base16-solarized-light":0,"base16-spacemacs":1,"base16-summercamp":1,"base16-summerfruit-dark":1,"base16-summerfruit-light":0,"base16-synth-midnight-terminal-dark":1,"base16-synth-midnight-terminal-light":0,"base16-tango":1,"base16-tender":1,"base16-tomorrow":0,"base16-tomorrow-night":1,"base16-twilight":1,"base16-unikitty-dark":1,"base16-unikitty-light":0,"base16-vulcan":1,"base16-windows-10":1,"base16-windows-10-light":0,"base16-windows-95":1,"base16-windows-95-light":0,"base16-windows-high-contrast":1,"base16-windows-high-contrast-light":0,"base16-windows-nt":1,"base16-windows-nt-light":0,"base16-woodland":1,"base16-xcode-dusk":1,"base16-zenburn":1,"brown-paper":0,"codepen-embed":1,"color-brewer":0,"cybertopia-cherry":0,"cybertopia-dimmer":0,"cybertopia-icecap":0,"cybertopia-saturated":0,dark:1,default:0,devibeans:1,docco:0,equinox:0,far:1,felipec:1,foundation:0,github:0,"github-dark":1,"github-dark-dimmed":1,gml:1,googlecode:0,"gradient-dark":1,"gradient-light":0,grayscale:0,hybrid:1,idea:0,"intellij-light":0,"ir-black":1,"isbl-editor-dark":1,"isbl-editor-light":0,"kimbie-dark":1,"kimbie-light":0,lightfair:0,lioshi:1,magula:0,"mono-blue":0,monokai:1,"monokai-sublime":1,"night-owl":1,"nnfx-dark":1,"nnfx-light":0,nord:1,obsidian:1,"panda-syntax-dark":1,"panda-syntax-light":0,"paraiso-dark":1,"paraiso-light":0,pojoaque:0,purebasic:0,"qtcreator-dark":1,"qtcreator-light":0,rainbow:1,"rose-pine":1,"rose-pine-dawn":0,"rose-pine-moon":1,routeros:0,"school-book":0,"shades-of-purple":1,srcery:1,"stackoverflow-dark":1,"stackoverflow-light":0,sunburst:1,"tokyo-night-dark":1,"tokyo-night-light":0,"tomorrow-night-blue":1,"tomorrow-night-bright":1,vs:0,"vs-dark":1,vs2015:1,xcode:0,xt256:1});var Ce=new Map,gt=new Map;function bt(n){if(typeof n!="string")return null;let e=n.trim().toLowerCase().replace(/\//g,"-");return!e||e.length>60?null:Object.prototype.hasOwnProperty.call(Se,e)?e:null}function Ea(){return Object.keys(Se)}function mt(n){return gt.get(n)}function yt(n){let e=Ce.get(n);if(e)return e;let t=Ma(n);return Ce.set(n,t),t}async function Ma(n){let e=R().syntaxThemesUrl||ft();if(!e)return null;try{let t=new URL(`${n}.css`,new URL(e.endsWith("/")?e:`${e}/`,document.baseURI));if(t.protocol!=="https:"&&t.protocol!=="http:")return null;let a=await fetch(t.href,{credentials:"same-origin"});if(!a.ok)throw new Error(`HTTP ${a.status}`);let r=await a.text(),s=new CSSStyleSheet;return s.replaceSync(r),gt.set(n,s),s}catch(t){return console.warn(`[vitrine] Could not load the "${n}" syntax theme.`,t),Ce.delete(n),null}}var vt="http://www.w3.org/2000/svg";var W=["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"}],Q=["path",{d:"M14 2v4a2 2 0 0 0 2 2h4"}],Na={copy:[["rect",{width:"14",height:"14",x:"8",y:"8",rx:"2",ry:"2"}],["path",{d:"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}]],check:[["path",{d:"M20 6 9 17l-5-5"}]],search:[["path",{d:"m21 21-4.34-4.34"}],["circle",{cx:"11",cy:"11",r:"8"}]],"chevron-up":[["path",{d:"m18 15-6-6-6 6"}]],"chevron-down":[["path",{d:"m6 9 6 6 6-6"}]],"chevron-right":[["path",{d:"m9 18 6-6-6-6"}]],wrap:[["path",{d:"m16 16-3 3 3 3"}],["path",{d:"M3 12h14.5a1 1 0 0 1 0 7H13"}],["path",{d:"M3 19h6"}],["path",{d:"M3 5h18"}]],download:[["path",{d:"M12 15V3"}],["path",{d:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"}],["path",{d:"m7 10 5 5 5-5"}]],"expand-all":[["path",{d:"m7 15 5 5 5-5"}],["path",{d:"m7 9 5-5 5 5"}]],"collapse-all":[["path",{d:"m7 20 5-5 5 5"}],["path",{d:"m7 4 5 5 5-5"}]],link:[["path",{d:"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"}],["path",{d:"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"}]],eye:[["path",{d:"M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"}],["circle",{cx:"12",cy:"12",r:"3"}]],code:[["path",{d:"m16 18 6-6-6-6"}],["path",{d:"m8 6-6 6 6 6"}]],columns:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M12 3v18"}]],list:[["path",{d:"M3 5h.01"}],["path",{d:"M3 12h.01"}],["path",{d:"M3 19h.01"}],["path",{d:"M8 5h13"}],["path",{d:"M8 12h13"}],["path",{d:"M8 19h13"}]],pencil:[["path",{d:"M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"}],["path",{d:"m15 5 4 4"}]],"chevron-left":[["path",{d:"m15 18-6-6 6-6"}]],"chevrons-left":[["path",{d:"m11 17-5-5 5-5"}],["path",{d:"m18 17-5-5 5-5"}]],"chevrons-right":[["path",{d:"m6 17 5-5-5-5"}],["path",{d:"m13 17 5-5-5-5"}]],sort:[["path",{d:"m21 16-4 4-4-4"}],["path",{d:"M17 20V4"}],["path",{d:"m3 8 4-4 4 4"}],["path",{d:"M7 4v16"}]],"sort-up":[["path",{d:"m5 12 7-7 7 7"}],["path",{d:"M12 19V5"}]],"sort-down":[["path",{d:"M12 5v14"}],["path",{d:"m19 12-7 7-7-7"}]],table:[["path",{d:"M12 3v18"}],["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 9h18"}],["path",{d:"M3 15h18"}]],undo:[["path",{d:"M9 14 4 9l5-5"}],["path",{d:"M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11"}]],redo:[["path",{d:"m15 14 5-5-5-5"}],["path",{d:"M20 9H9.5A5.5 5.5 0 0 0 4 14.5A5.5 5.5 0 0 0 9.5 20H13"}]],maximize:[["path",{d:"M15 3h6v6"}],["path",{d:"m21 3-7 7"}],["path",{d:"m3 21 7-7"}],["path",{d:"M9 21H3v-6"}]],minimize:[["path",{d:"m14 10 7-7"}],["path",{d:"M20 10h-6V4"}],["path",{d:"m3 21 7-7"}],["path",{d:"M4 14h6v6"}]],swap:[["path",{d:"M8 3 4 7l4 4"}],["path",{d:"M4 7h16"}],["path",{d:"m16 21 4-4-4-4"}],["path",{d:"M20 17H4"}]],filter:[["path",{d:"M22 3H2l8 9.46V19l4 2v-8.54L22 3z"}]],keyboard:[["rect",{width:"20",height:"16",x:"2",y:"4",rx:"2"}],["path",{d:"M6 8h.01M10 8h.01M14 8h.01M18 8h.01M8 12h.01M12 12h.01M16 12h.01M7 16h10"}]],rows:[["rect",{width:"18",height:"18",x:"3",y:"3",rx:"2"}],["path",{d:"M3 12h18"}]],"sync-scroll":[["path",{d:"M9 17H7A5 5 0 0 1 7 7h2"}],["path",{d:"M15 7h2a5 5 0 1 1 0 10h-2"}],["line",{x1:"8",x2:"16",y1:"12",y2:"12"}]],alert:[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}],["path",{d:"M12 9v4"}],["path",{d:"M12 17h.01"}]],close:[["path",{d:"M18 6 6 18"}],["path",{d:"m6 6 12 12"}]],replay:[["path",{d:"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"}],["path",{d:"M3 3v5h5"}]],chart:[["path",{d:"M3 3v16a2 2 0 0 0 2 2h16"}],["path",{d:"m19 9-5 5-4-4-3 3"}]],follow:[["path",{d:"M12 17V3"}],["path",{d:"m6 11 6 6 6-6"}],["path",{d:"M19 21H5"}]],terminal:[["path",{d:"M12 19h8"}],["path",{d:"m4 17 6-6-6-6"}]],folder:[["path",{d:"M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"}]],"folder-open":[["path",{d:"m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"}]],file:[W,Q],"file-code":[W,Q,["path",{d:"m10 13-2 2 2 2"}],["path",{d:"m14 17 2-2-2-2"}]],"file-text":[W,Q,["path",{d:"M10 9H8"}],["path",{d:"M16 13H8"}],["path",{d:"M16 17H8"}]],"file-image":[W,Q,["circle",{cx:"10",cy:"12",r:"2"}],["path",{d:"m20 17-1.296-1.296a2.41 2.41 0 0 0-3.408 0L9 22"}]],"file-data":[W,Q,["path",{d:"M10 12a1 1 0 0 0-1 1v1a1 1 0 0 1-1 1 1 1 0 0 1 1 1v1a1 1 0 0 0 1 1"}],["path",{d:"M14 18a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1 1 1 0 0 1-1-1v-1a1 1 0 0 0-1-1"}]],lock:[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2"}],["path",{d:"M7 11V7a5 5 0 0 1 10 0v4"}]],"eye-off":[["path",{d:"M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"}],["path",{d:"M14.084 14.158a3 3 0 0 1-4.242-4.242"}],["path",{d:"M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"}],["path",{d:"m2 2 20 20"}]],"status-circle":[["circle",{cx:"12",cy:"12",r:"9"}]],"status-running":[["path",{d:"M21 12a9 9 0 1 1-6.22-8.56"}]],"status-skipped":[["circle",{cx:"12",cy:"12",r:"9"}],["path",{d:"m5.7 5.7 12.6 12.6"}]],"status-success":[["circle",{cx:"12",cy:"12",r:"9"}],["path",{d:"m8.5 12 2.5 2.5 4.5-5"}]],"status-failure":[["circle",{cx:"12",cy:"12",r:"9"}],["path",{d:"m15 9-6 6"}],["path",{d:"m9 9 6 6"}]]};function S(n){let e=document.createElementNS(vt,"svg");e.setAttribute("viewBox","0 0 24 24"),e.setAttribute("fill","none"),e.setAttribute("stroke","currentColor"),e.setAttribute("stroke-width","2.1"),e.setAttribute("stroke-linecap","round"),e.setAttribute("stroke-linejoin","round"),e.setAttribute("aria-hidden","true"),e.setAttribute("focusable","false"),e.setAttribute("class","icon");for(let[t,a]of Na[n]??[]){let r=document.createElementNS(vt,t);for(let[s,i]of Object.entries(a))r.setAttribute(s,i);e.append(r)}return e}var xt=new WeakMap,La=null;function Ra(n){let e=xt.get(n);e&&(xt.delete(n),La?.unobserve(n),e())}function wt(n){for(let e of Array.from(n.querySelectorAll(".chunk[data-pending]")))Ra(e)}var za=5e3,oe=200;function Da(n){return n.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}function $a(n,e,t=za){let a=[];if(!e)return{starts:a,capped:!1};let r=new RegExp(Da(e),"gi"),s;for(;(s=r.exec(n))!==null;){if(a.length===t)return{starts:a,capped:!0};a.push(s.index),s[0].length===0&&(r.lastIndex+=1)}return{starts:a,capped:!1}}var ie=class{constructor(e,t={}){this.root=e,this.skip=t.skip??"",this.matches=[],this.current=-1}run(e){this.clear();let t=e.slice(0,oe);if(!t)return{total:0,capped:!1};wt(this.root);let{nodes:a,starts:r,text:s}=this.collectText(),{starts:i,capped:o}=$a(s,t),l=i.map(()=>[]);for(let c=i.length-1;c>=0;c-=1){let h=i[c],f=h+t.length,u=Oa(r,f-1);for(;u>=0&&r[u]+(a[u].nodeValue??"").length>h;){let p=r[u],g=Math.max(h,p)-p,b=Math.min(f,p+(a[u].nodeValue??"").length)-p;b>g&&l[c].unshift(Pa(a[u],g,b,c)),u-=1}}return this.matches=l,{total:l.length,capped:o}}collectText(){let e=this.skip,t=document.createTreeWalker(this.root,NodeFilter.SHOW_TEXT,{acceptNode(o){let l=o.parentElement;return e&&l&&l.closest(e)?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT}}),a=[],r=[],s=[],i=0;for(let o=t.nextNode();o;o=t.nextNode()){let l=o.nodeValue??"";l&&(a.push(o),r.push(i),s.push(l),i+=l.length)}return{nodes:a,starts:r,text:s.join("")}}go(e){if(!this.matches.length)return null;let t=this.matches.length,a=(e%t+t)%t;for(let r of this.matches[this.current]??[])r.classList.remove("current");this.current=a;for(let r of this.matches[a])r.classList.add("current");return this.matches[a][0]??null}unsetCurrent(){for(let e of this.matches[this.current]??[])e.classList.remove("current");this.current=-1}clear(){let e=new Set;for(let t of this.matches)for(let a of t){let r=a.parentNode;r&&(a.replaceWith(...Array.from(a.childNodes)),e.add(r))}for(let t of e)t.normalize();this.matches=[],this.current=-1}};function Oa(n,e){let t=0,a=n.length-1;for(;t<a;){let r=t+a+1>>1;n[r]<=e?t=r:a=r-1}return t}function Pa(n,e,t,a){let r=n.splitText(e);r.splitText(t-e);let s=document.createElement("mark");return s.className="match",s.setAttribute("part","match"),s.dataset.match=String(a),r.replaceWith(s),s.appendChild(r),s}function w(n){let e=d("button",{class:"btn",part:`button${n.part?` ${n.part}`:""}`,attrs:{type:"button","aria-label":n.label,title:n.label,"aria-pressed":n.pressed===void 0?null:String(n.pressed),"data-focus-key":n.key},on:{click:n.onClick}});return e.append(S(n.icon)),e}function _t(n,e,t){let a=n.querySelector("svg");a&&(a.replaceWith(S(t?"check":"alert")),n.classList.toggle("done",t),setTimeout(()=>{n.querySelector("svg")?.replaceWith(S(e)),n.classList.remove("done")},1500))}var le=class{constructor(e,t,a=""){this.t=e,this.handlers=t,this.total=0,this.capped=!1,this.index=-1;let r=re("search");this.input=d("input",{class:"search-input",part:"search-input",attrs:{id:r,type:"search",placeholder:e("searchPlaceholder"),"aria-label":e("search"),maxlength:oe,autocomplete:"off",spellcheck:"false",enterkeyhint:"search","data-focus-key":"search-input"}}),this.input.value=a.slice(0,oe),this.count=d("span",{class:"search-count",part:"search-count",attrs:{"aria-hidden":"true"}});let s=w({icon:"chevron-up",label:e("searchPrevious"),onClick:()=>this.step(-1),key:"search-prev"}),i=w({icon:"chevron-down",label:e("searchNext"),onClick:()=>this.step(1),key:"search-next"}),o=w({icon:"close",label:e("searchClose"),onClick:()=>t.onClose(),key:"search-close"});this.element=d("div",{class:"search",part:"search",attrs:{role:"search"}},this.input,this.count,s,i,o);let l=Je(()=>this.run(),150);this.input.addEventListener("input",l),this.input.addEventListener("keydown",c=>{c.key==="Enter"?(c.preventDefault(),l.cancel(),this.input.value!==this.lastQuery?this.run():this.step(c.shiftKey?-1:1)):c.key==="Escape"&&(c.preventDefault(),c.stopPropagation(),this.input.value?(this.input.value="",this.run()):t.onClose())}),this.lastQuery=void 0}run(){let e=this.input.value;this.lastQuery=e;let{total:t,capped:a}=this.handlers.run(e);this.total=t,this.capped=a,this.index=-1,t>0?this.step(1):this.updateCount(),this.handlers.onResult?.(e,t,a)}step(e){this.total&&(this.index=((this.index+e)%this.total+this.total)%this.total,this.handlers.go(this.index),this.updateCount())}updateCount(){if(!this.input.value)this.count.textContent="";else if(!this.total)this.count.textContent=this.t("searchNone");else{let e=this.capped?"searchCountCapped":"searchCount";this.count.textContent=this.t(e,{current:this.index+1,total:this.total})}}focus(){this.input.focus(),this.input.select()}};function St(n){return d("div",{class:"loader",part:"loading",attrs:{role:"status"}},Fa(),d("span",{class:"loader-label",text:n("loading")}))}var kt="http://www.w3.org/2000/svg";function Fa(){let n=document.createElementNS(kt,"svg");n.setAttribute("viewBox","0 0 120 120"),n.setAttribute("class","loader-mark"),n.setAttribute("aria-hidden","true"),n.setAttribute("focusable","false");let e=[["rect",{class:"loader-frame",x:"12",y:"16",width:"96",height:"88",rx:"18"}],["path",{class:"loader-frame",d:"M12 42 L108 42"}],["circle",{class:"loader-dot",cx:"29",cy:"29",r:"5"}],["path",{class:"loader-v",d:"M42 60 L60 86 L78 60",pathLength:"100"}]];for(let[t,a]of e){let r=document.createElementNS(kt,t);for(let[s,i]of Object.entries(a))r.setAttribute(s,i);n.append(r)}return n}function Ct(n,e){return d("div",{class:"message",part:"error",attrs:{role:"alert"}},S("alert"),d("div",{},d("p",{class:"message-title",text:n}),e?d("p",{class:"message-detail",text:e}):null))}function Ae(n){return d("div",{class:"notice",part:"notice",attrs:{role:"note"}},S("alert"),d("span",{text:n}))}function At(n){return d("div",{class:"empty",part:"empty",text:n("empty")})}var Tt=new Map;function ce(n){let e=Tt.get(n);return e||(e=new CSSStyleSheet,e.replaceSync(n),Tt.set(n,e)),e}var ja=Object.freeze(["variant","theme","src","allow-remote","max-height","copy","search","download","header","dot","title","label","lang-ui","mode","edit-toggle","placeholder","syntax-theme","syntax-theme-dark","badge","history","fullscreen","status"]),de=class extends HTMLElement{static type="base";static componentAttributes=[];static presets={simple:{},full:{}};static allowEmpty=!1;static keepCarriageReturns=!1;static upgradeProperties=["content"];static styles=[];static get observedAttributes(){return[...ja,...this.componentAttributes]}constructor(){super(),this.root=this.attachShadow({mode:"open"}),this.frame=d("div",{class:"vt",part:"container"}),this.syntaxTheme=null,this.updateSheets(null),this.live=d("div",{class:"sr-only",attrs:{"aria-live":"polite","aria-atomic":"true"}}),this.root.append(this.frame,this.live),this._content=void 0,this.text=null,this.error=null,this.loading=!1,this.searchOpen=!1,this.searchQuery="",this.searchBar=null,this.t=me("en"),this._loadToken=0,this._abort=null,this._renderQueued=!1,this._readyPending=!1,this._cleanups=[],this._observer=null,this._connected=!1,this.modeState=null,this.editHistory=null,this._historyCleanup=null,this._escapeFullscreen=null}get content(){return this.text??""}set content(e){let t=e==null?void 0:String(e);t!==void 0&&t===this._content&&t===this.text||(this._content=t,this._connected&&this.reload())}upgradeProperty(e){if(Object.prototype.hasOwnProperty.call(this,e)){let t=this[e];delete this[e],this[e]=t}}connectedCallback(){for(let t of this.constructor.upgradeProperties)this.upgradeProperty(t);this._cleanups.push(We(t=>t.has("maxSize")?this.reload():this.requestRender()),ct(()=>this.applyTheme()),Fe(()=>this.requestRender())),this._observer=new MutationObserver(()=>{this._content===void 0&&!this.hasAttribute("src")&&this.reload()}),this._observer.observe(this,{childList:!0,characterData:!0,subtree:!0});let e=()=>{document.fullscreenElement===this?this.setFullscreen("native"):this.frame.dataset.fullscreen==="native"&&this.setFullscreen(null)};document.addEventListener("fullscreenchange",e),this._cleanups.push(()=>document.removeEventListener("fullscreenchange",e)),this._connected=!0,this.reload()}disconnectedCallback(){this._connected=!1;for(let e of this._cleanups.splice(0))e();this._observer?.disconnect(),this._observer=null,this._abort?.abort(),this._abort=null}attributeChangedCallback(e,t,a){t===a||!this.isConnected||(e==="mode"&&(this.modeState=null),e==="src"||e==="allow-remote"?this.reload():e==="theme"?this.applyTheme():this.requestRender())}reload(){let e=++this._loadToken;this._abort?.abort(),this._abort=null;let t=R(),a=this.getAttribute("src");if(this._content!==void 0)this.setText(this._content);else if(a!==null&&a.trim()!==""){this.loading=!0,this.error=null,this.requestRender();let r=new AbortController;this._abort=r,Ze(a,{allowRemote:j(this.getAttribute("allow-remote"))===!0,maxSize:t.maxSize,timeout:t.fetchTimeout,signal:r.signal}).then(s=>e===this._loadToken&&this.setText(s),s=>e===this._loadToken&&!tt(s)&&this.setError(s))}else this.setText(this.readInline()??"")}setText(e){this.loading=!1,this.editHistory=null;try{ne(e,R().maxSize)}catch(a){this.setError(a);return}let t=this.constructor;this.text=e.replace(t.keepCarriageReturns?/\r\n/g:/\r\n?/g,`
`),this.error=null,this.contentChanged(),this._readyPending=!0,this.requestRender()}setError(e){this.loading=!1,this._readyPending=!1,this.error=e,this.text=null,this.contentChanged(),this.requestRender();let{title:t,detail:a}=this.describeError(e);C(this,_.ERROR,{message:a||t,cause:e})}describeError(e){let t=this.t;if(e instanceof M){let a={...e.params};for(let r of["size","limit"])typeof a[r]=="number"&&(a[r]=E(Number(a[r]),this.locale));return{title:t("errorTitle"),detail:t(e.code,a)}}return{title:t("errorTitle"),detail:e instanceof Error?e.message:String(e)}}get editing(){return(this.modeState??O(this.getAttribute("mode"),["view","edit"],"view"))==="edit"}edited(e){this.text=e,this._content=e,this.contentEdited(e),C(this,_.INPUT,{value:e})}contentEdited(e){}historyButtons(e){if(this.editHistory=e.history,j(this.getAttribute("history"))===!1)return[];let t=w({icon:"undo",label:this.t("undo"),key:"undo",part:"undo-button",onClick:()=>e.undo()}),a=w({icon:"redo",label:this.t("redo"),key:"redo",part:"redo-button",onClick:()=>e.redo()}),r=()=>{t.disabled=!e.history.canUndo,a.disabled=!e.history.canRedo};return r(),this._historyCleanup?.(),this._historyCleanup=e.history.subscribe(r),[t,a]}fullscreenButton(){if(!this.feature("fullscreen"))return null;let e=!!this.frame.dataset.fullscreen;return w({icon:e?"minimize":"maximize",label:this.t(e?"exitFullscreen":"fullscreen"),key:"fullscreen",part:"fullscreen-button",pressed:e,onClick:()=>this.toggleFullscreen()})}async toggleFullscreen(){let e=this.frame.dataset.fullscreen;if(e==="native"){await document.exitFullscreen?.().catch(()=>{});return}if(e==="window"){this.setFullscreen(null);return}if(document.fullscreenEnabled&&this.requestFullscreen)try{await this.requestFullscreen({navigationUI:"hide"});return}catch{}this.setFullscreen("window")}setFullscreen(e){e?this.frame.dataset.fullscreen=e:delete this.frame.dataset.fullscreen,e==="window"?(this._escapeFullscreen=t=>{t.key==="Escape"&&!t.defaultPrevented&&this.setFullscreen(null)},this.frame.addEventListener("keydown",this._escapeFullscreen)):this._escapeFullscreen&&(this.frame.removeEventListener("keydown",this._escapeFullscreen),this._escapeFullscreen=null),this.render(),this.root.querySelector('[data-focus-key="fullscreen"]')?.focus(),C(this,_.FULLSCREEN_CHANGE,{fullscreen:!!e})}editToggleButton(){return this.feature("edit-toggle")?w({icon:this.editing?"eye":"pencil",label:this.t(this.editing?"stopEditing":"edit"),key:"edit-toggle",part:"edit-button",pressed:this.editing,onClick:()=>{this.modeState=this.editing?"view":"edit",this.render(),C(this,_.MODE_CHANGE,{mode:this.modeState}),this.modeState==="edit"&&this.root.querySelector(".editor-input")?.focus()}}):null}readInline(){return Xe(this)}contentChanged(){}get variant(){return O(this.getAttribute("variant"),["simple","full"],"simple")}feature(e){let t=j(this.getAttribute(e));return t!==null?t:this.constructor.presets[this.variant][e]??!1}get locale(){let e=this.getAttribute("lang-ui")?.trim();return e&&/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(e)?e:R().lang}get heading(){return Be(this.getAttribute("label")??this.getAttribute("title"))}requestRender(){this._renderQueued||(this._renderQueued=!0,queueMicrotask(()=>{this._renderQueued=!1,this.isConnected&&this.render()}))}applyTheme(){let e=dt(this.getAttribute("theme"));this.frame.dataset.theme=e,this.applySyntaxTheme(ke(e)?.colorScheme==="dark")}applySyntaxTheme(e){let t=R(),a=e&&this.getAttribute("syntax-theme-dark")||this.getAttribute("syntax-theme")||e&&t.syntaxThemeDark||t.syntaxTheme,r=bt(a);if(this.syntaxTheme=r,!r){this.updateSheets(null);return}let s=mt(r);if(s){this.updateSheets(s);return}yt(r).then(i=>{i&&this.syntaxTheme===r&&this.updateSheets(i)})}updateSheets(e){let a=this.constructor.styles.map(ce),r=[ce(Ue),I,ce(Ge),...a];this.frame.toggleAttribute("data-syntax-theme",!!e),this.root.adoptedStyleSheets=e?[...r.filter(s=>s!==ce(Ve)),e]:r}render(){let e=this.activeFocusKey(),t=this.root.activeElement,a=t instanceof HTMLTextAreaElement||t instanceof HTMLInputElement?[t.selectionStart,t.selectionEnd]:null;this.t=me(this.locale),this.applyTheme();let r=Ke(this.getAttribute("max-height"));if(r?this.frame.style.setProperty("--_max-height",r):this.frame.style.removeProperty("--_max-height"),this.searchBar=null,this.frame.replaceChildren(),this.loading){this.frame.append(...this.chrome(null),d("div",{class:"body",part:"body"},St(this.t))),this.frame.setAttribute("aria-busy","true");return}if(this.frame.removeAttribute("aria-busy"),this.error){let{title:i,detail:o}=this.describeError(this.error);this.frame.append(...this.chrome(null),Ct(i,o));return}if(!this.text&&!this.editing&&!this.constructor.allowEmpty)this.frame.append(...this.chrome(null),At(this.t));else{this.renderContent(this.frame);let i=this.searchBar;this.searchOpen&&this.searchQuery&&i?.run()}this.restoreFocus(e);let s=this.root.activeElement;if(a&&(s instanceof HTMLTextAreaElement||s instanceof HTMLInputElement)&&a[0]!==null)try{s.setSelectionRange(a[0],a[1])}catch{}this._readyPending&&(this._readyPending=!1,C(this,_.READY,{type:this.constructor.type}))}renderContent(e){throw new Error("renderContent() must be implemented.")}chrome(e){let t=(e?.actions??[]).filter(i=>i!==null),a=t.length?d("div",{class:"toolbar",part:"toolbar",attrs:{role:"toolbar","aria-label":this.t("actions")}},...t):null;if(!this.feature("header"))return a?.classList.add("floating"),[a,e?.tabs??null,this.searchBar?.element??null].filter(i=>i!==null);let r=this.heading,s=d("div",{class:"header",part:"header"},this.feature("dot")?d("span",{class:"dot",part:"status-dot",attrs:{"aria-hidden":"true"}}):null,r?d("span",{class:"title",part:"title",text:r,attrs:{title:r}}):null,e?.tabs??null,r?null:d("span",{class:"spacer"}),e?.badge&&j(this.getAttribute("badge"))!==!1?d("span",{class:"badge",part:"badge",text:e.badge}):null);return a&&s.append(a),this.searchBar?[s,this.searchBar.element]:[s]}copyButton(e,t=this.t("copy"),a="copy"){let r=w({icon:"copy",label:t,key:a,part:"copy-button",onClick:async()=>{let s=e(),i=await B(s,this.root);_t(r,"copy",i),this.announce(this.t(i?"copied":"copyFailed")),i&&C(this,_.COPY,{text:s})}});return r}copyTextButton(e,t,a){let r=d("button",{class:"text-btn",part:"copy-button",text:t,attrs:{type:"button","data-focus-key":a},on:{click:async()=>{let s=e(),i=await B(s,this.root);r.textContent=this.t(i?"copied":"copyFailed"),r.classList.toggle("done",i),setTimeout(()=>{r.textContent=t,r.classList.remove("done")},1500),this.announce(this.t(i?"copied":"copyFailed")),i&&C(this,_.COPY,{text:s})}}});return r}downloadName(e){let t=this.getAttribute("download"),a=t&&j(t)!==!1&&!/^(?:true|on|yes)$/i.test(t.trim())?t:null,r=/\.[a-z0-9]{1,10}$/i.test(this.heading)?this.heading:null;return He(a??r,e)}downloadButton(e,t,a){return w({icon:"download",label:this.t("download"),key:"download",part:"download-button",onClick:()=>V(e(),t,a)})}searchButton(e){return this.feature("search")?(this.searchOpen&&(this.searchBar=new le(this.t,{run:t=>(this.searchQuery=t,e.run(t)),go:t=>e.go(t),onResult:(t,a,r)=>{t&&this.announce(a?this.t("searchResults",{total:r?`${a}+`:a}):this.t("searchNone")),C(this,_.SEARCH,{query:t,matches:a})},onClose:()=>{e.clear(),this.searchOpen=!1,this.searchQuery="",this.render(),this.root.querySelector('[data-focus-key="search"]')?.focus()}},this.searchQuery)),w({icon:"search",label:this.t("search"),key:"search",part:"search-button",pressed:this.searchOpen,onClick:()=>{this.searchOpen=!this.searchOpen,this.searchOpen||(this.searchQuery=""),this.render(),this.searchOpen&&this.searchBar?.focus()}})):null}announce(e){this.live.textContent="",setTimeout(()=>{this.live.textContent=e},50)}activeFocusKey(){let e=this.root.activeElement;return e instanceof HTMLElement?e.dataset.focusKey??null:null}restoreFocus(e){if(!e)return;let t=this.root.querySelector(`[data-focus-key="${CSS.escape(e)}"]`);t instanceof HTMLElement&&t.focus({preventScroll:!0})}};var Ia=Object.freeze([",",";","	","|"]);function qa(n){let e=n.slice(0,2e4).split(/\r?\n/).slice(0,20).filter(r=>r.trim()),t=",",a=0;for(let r of Ia){let s=e.map(l=>Ka(l,r));if(!s.length||s[0]===0)continue;let o=s.filter(l=>l===s[0]).length/s.length*10+Math.min(s[0],10);o>a&&(t=r,a=o)}return t}function Ka(n,e){let t=0,a=!1;for(let r of n)r==='"'?a=!a:r===e&&!a&&(t+=1);return t}function Et(n,e={}){let t=n.charCodeAt(0)===65279?n.slice(1):n,a=e.delimiter??qa(t),r=[],s=[],i="",o=!1,l=0,c=1,h=0,f=!1,u=0,p=t.length,g=()=>{s.length<1e3?s.push(i):f=!0,i=""},b=()=>{g(),h=Math.max(h,s.length),r.push(s),s=[]};for(;u<p;){let m=t[u];if(o){if(m==='"'){if(t[u+1]==='"'){i+='"',u+=2;continue}o=!1,u+=1;continue}let A=t.indexOf('"',u),T=A===-1?p:A,L=t.slice(u,T);c+=Ba(L),i+=L,u=T;continue}m==='"'&&i===""?(o=!0,l=c,u+=1):m===a?(g(),u+=1):m===`
`||m==="\r"?(b(),u+=m==="\r"&&t[u+1]===`
`?2:1,c+=1):(i+=m,u+=1)}return(i!==""||s.length)&&b(),{rows:r,delimiter:a,columns:h,truncatedColumns:f,error:o?{message:"Unclosed quoted field",line:l}:null}}function Ba(n){let e=0;for(let t=n.indexOf(`
`);t!==-1;t=n.indexOf(`
`,t+1))e+=1;return e}function Mt(n,e){let t=a=>a.includes('"')||a.includes("\r")||a.includes(`
`)||a.includes(e);return n.map(a=>a.map(r=>t(r)?`"${r.replace(/"/g,'""')}"`:r).join(e)).join(`
`)}var Ha=["text","number","date","boolean","url"],he=["none","count","sum","avg","min","max"],Nt=500,Lt=2e5,Rt=/^[-+]?(?:\d{1,3}(?:[ ,]\d{3})+|\d+)?(?:\.\d+)?(?:e[-+]?\d+)?%?$/i,Ua=/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/,Ga=/^(?:true|false|yes|no)$/i,Va=/^https?:\/\/[^\s]+$/i;function zt(n,e="auto"){let t=n.trim();if(!t)return{columns:[],rows:[]};if(e==="json"||e==="auto"&&/^[[{]/.test(t)){let h;try{h=JSON.parse(t)}catch(f){return{columns:[],rows:[],error:f instanceof Error?f.message:String(f)}}return ue(h)}let r=Et(n),[s=[],...i]=r.rows,o=$t(s.map((h,f)=>h.trim()||`column${f+1}`)),l=i.map(h=>Object.fromEntries(o.map((f,u)=>[f,h[u]??""]))),c=Dt(o.map(h=>({key:h})),l);return r.error&&(c.error=`Unclosed quote from line ${r.error.line}.`),c}function ue(n,e=null){let t=[],a=e;if(Array.isArray(n))t=n;else if(n&&typeof n=="object"){let s=n;Array.isArray(s.rows)?t=s.rows:Array.isArray(s.data)&&(t=s.data),!a&&Array.isArray(s.columns)&&(a=s.columns.map(i=>typeof i=="string"?{key:i}:i))}if(t.length&&Array.isArray(t[0])){let s=t.filter(Array.isArray),i=a?a.map(l=>l.key):$t(s[0].map((l,c)=>String(l??"")||`column${c+1}`));t=(a?s:s.slice(1)).map(l=>Object.fromEntries(i.map((c,h)=>[c,l[h]]))),a||(a=i.map(l=>({key:l})))}let r=t.filter(s=>s!==null&&typeof s=="object"&&!Array.isArray(s));return Dt(a,r)}function Dt(n,e){let t=e.length>Lt,a=t?e.slice(0,Lt):e,r=n?n.filter(i=>i&&typeof i.key=="string"&&i.key):[];if(!r.length){let i=new Set;for(let o=0;o<a.length&&o<1e3;o+=1)for(let l of Object.keys(a[o]))i.add(l);r=[...i].map(o=>({key:o}))}return{columns:r.slice(0,Nt).map(i=>{let o=Ha.includes(i.type)?i.type:Qa(a,i.key);return{...i,label:i.label??Wa(i.key),type:o,hidden:!!i.hidden,sortable:i.sortable!==!1,filterable:i.filterable!==!1,editable:!!i.editable,resizable:i.resizable!==!1,aggregate:he.includes(i.aggregate)?i.aggregate:"none"}}),rows:a,truncated:t||r.length>Nt}}function $t(n){let e=new Map;return n.map(t=>{let a=e.get(t)??0;return e.set(t,a+1),a?`${t}_${a+1}`:t})}function Wa(n){let e=n.replace(/([a-z\d])([A-Z])/g,"$1 $2").replace(/[_-]+/g," ").trim().toLowerCase();return e?e[0].toUpperCase()+e.slice(1):n}function Qa(n,e){let t=0,a={number:0,date:0,boolean:0,url:0};for(let r=0;r<n.length&&t<500;r+=1){let s=n[r][e];if(!(s==null||s==="")){if(t+=1,typeof s=="number")a.number+=1;else if(typeof s=="boolean")a.boolean+=1;else if(s instanceof Date)a.date+=1;else if(typeof s=="string"){let i=s.trim();Rt.test(i)&&/\d/.test(i)?a.number+=1:Ua.test(i)?a.date+=1:Ga.test(i)?a.boolean+=1:Va.test(i)&&(a.url+=1)}}}if(!t)return"text";for(let r of["number","date","boolean","url"])if(a[r]===t)return r;return"text"}function z(n){return n==null||n===""||typeof n=="number"&&Number.isNaN(n)}function N(n){if(typeof n=="number")return n;if(typeof n=="boolean")return n?1:0;if(n instanceof Date)return n.getTime();if(typeof n!="string")return Number.NaN;let e=n.trim();return e?Number(e.replace(/[ ,%]/g,"")):Number.NaN}function K(n){return n instanceof Date?n.getTime():typeof n=="number"?n:typeof n=="string"&&n.trim()?Date.parse(n.trim()):Number.NaN}function q(n){if(typeof n=="boolean")return n;if(typeof n=="number")return n!==0;if(typeof n!="string")return null;let e=n.trim().toLowerCase();return e==="true"||e==="yes"||e==="1"?!0:e==="false"||e==="no"||e==="0"?!1:null}function v(n){if(n==null)return"";if(typeof n=="string")return n;if(n instanceof Date)return Number.isNaN(n.getTime())?"":n.toISOString();if(typeof n=="object")try{return JSON.stringify(n)}catch{return String(n)}return String(n)}function Ot(n,e){let{key:t,type:a}=e;return n.map(r=>{let s=r[t];if(z(s))return null;if(a==="number"){let i=N(s);return Number.isNaN(i)?null:i}if(a==="date"){let i=K(s);return Number.isNaN(i)?null:i}if(a==="boolean"){let i=q(s);return i===null?null:Number(i)}return v(s)})}function Pt(n,e,t){return e.length?[...n].sort((a,r)=>{for(let{keys:s,direction:i}of e){let o=s[a],l=s[r];if(o===l)continue;if(o===null)return 1;if(l===null)return-1;let c=typeof o=="number"&&typeof l=="number"?o-l:t.compare(String(o),String(l));if(c)return i==="ascending"?c:-c}return a-r}):n}function Te(n,e){let t=n.trim();if(!t)return null;let a=t.toLowerCase();if(a==="empty")return s=>z(s);if(a==="!empty")return s=>!z(s);if(e==="boolean"){let s=q(t);if(s!==null)return i=>q(i)===s}if(e==="number"||e==="date"){let s=e==="number"?N:K,i=/^(.+?)\s*\.\.\s*(.+)$/.exec(t);if(i){let l=s(i[1]),c=s(i[2]);if(!Number.isNaN(l)&&!Number.isNaN(c))return h=>{let f=s(h);return f>=Math.min(l,c)&&f<=Math.max(l,c)}}let o=/^(>=|<=|!=|>|<|=)\s*(.+)$/.exec(t);if(o){let l=s(o[2]);if(!Number.isNaN(l)){let c={">":h=>h>l,">=":h=>h>=l,"<":h=>h<l,"<=":h=>h<=l,"=":h=>h===l,"!=":h=>h!==l}[o[1]];return h=>{let f=s(h);return!Number.isNaN(f)&&c(f)}}}}if(t.startsWith("=")){let s=a.slice(1);return i=>v(i).toLowerCase()===s}if(t.startsWith("!")&&t.length>1){let s=a.slice(1);return i=>!v(i).toLowerCase().includes(s)}let r=a.split(/\s+/);return s=>{let i=v(s).toLowerCase();return r.every(o=>i.includes(o))}}function Ee(n,e,t,a){if(a==="none")return null;if(a==="count"){let c=0;for(let h of e)z(n[h][t.key])||(c+=1);return c}let r=t.type==="date"?K:N,s=0,i=0,o=1/0,l=-1/0;for(let c of e){let h=r(n[c][t.key]);Number.isNaN(h)||(s+=h,i+=1,h<o&&(o=h),h>l&&(l=h))}return i?a==="sum"?s:a==="avg"?s/i:a==="min"?o:l:null}function Ft(n,e,t){let a=new Map;for(let r of e){let s=v(n[r][t]),i=a.get(s);i?i.push(r):a.set(s,[r])}return[...a].map(([r,s])=>({value:r,indexes:s}))}function jt(n,e,t){if(t==="json"){let i=n.map(o=>Object.fromEntries(e.map(l=>[l.key,o[l.key]??null])));return JSON.stringify(i,null,2)}let a=e.map(i=>i.label),r=n.map(i=>e.map(o=>v(i[o.key])));if(t==="tsv")return[a,...r].map(i=>i.map(o=>o.replace(/[\t\r\n]+/g," ")).join("	")).join(`
`);let s=r.map(i=>i.map(o=>/^[=+\-@\t\r]/.test(o)&&!Rt.test(o)?`'${o}`:o));return Mt([a,...s],",")}function It(n,e,t){if(typeof t=="string"||t===void 0||t===null){if(e.type==="number"&&typeof t!="string"&&n.trim()!==""){let a=N(n);return Number.isNaN(a)?n:a}return n}if(typeof t=="number"){if(!n.trim())return null;let a=N(n);return Number.isNaN(a)?n:a}return typeof t=="boolean"?q(n)??n:n}var Ja=["text","number","badge","status","tags","progress","rating","link","email","image","avatar","code","date","relative","currency","percent","bytes","color","json","boolean"],Me=["gray","red","orange","yellow","green","teal","blue","purple","pink"];function J(n){let e=n.display;return Ja.includes(e)?e:n.type==="url"?"link":n.type==="boolean"?"boolean":n.type==="number"?"number":n.type==="date"?"date":"text"}function ze(n,e,t,a){if(z(e))return"";let r=J(n),s=l=>`${n.prefix??""}${l}${n.suffix??""}`,i=typeof n.decimals=="number"?Math.max(0,Math.min(10,n.decimals)):void 0,o=(l={})=>{let c=N(e);if(Number.isNaN(c))return v(e);try{return new Intl.NumberFormat(t,{minimumFractionDigits:i,maximumFractionDigits:i??2,...l}).format(c)}catch{return String(c)}};switch(r){case"number":return typeof e!="number"&&!n.decimals&&!n.prefix&&!n.suffix?v(e):s(n.grouping===!1?String(N(e)):o({useGrouping:n.grouping!==!1}));case"currency":return o({style:"currency",currency:/^[A-Z]{3}$/.test(n.currency??"")?n.currency:"EUR"});case"percent":{let l=N(e);return Number.isNaN(l)?v(e):s(new Intl.NumberFormat(t,{style:"percent",maximumFractionDigits:i??1}).format(n.ratio?l:l/100))}case"bytes":return rr(N(e),t);case"date":{let l=K(e);return Number.isNaN(l)?v(e):typeof e=="string"&&!n.dateStyle?e:Gt(l,t,n.dateStyle)}case"relative":{let l=K(e);return Number.isNaN(l)?v(e):nr(l,t)}case"boolean":{let l=q(e);return l===null?v(e):l?n.trueLabel??a("tableYes"):n.falseLabel??a("tableNo")}case"rating":{let l=N(e);return Number.isNaN(l)?v(e):`${l}/${n.max??5}`}case"progress":{let l=N(e);return Number.isNaN(l)?v(e):`${Math.round(l/(n.max||100)*100)}%`}case"tags":return Le(e).join(", ");case"json":return v(e);default:return s(v(e))}}function Kt(n,e,t,a,r){if(z(e)&&J(n)!=="avatar")return d("span",{class:"tb-blank",text:n.emptyText??""});switch(J(n)){case"badge":case"status":return qt(n,Le(e),r,J(n)==="status");case"tags":return qt(n,Le(e),r,!1,n.maxItems??3);case"progress":return Ya(n,e,a);case"rating":return Xa(n,e,a);case"link":case"email":return Za(n,e,t,a);case"image":return er(n,e,t,a);case"avatar":return tr(n,e,t,a);case"code":return Ne(n,a,r,"tb-code");case"json":return Ne(n,a,r,"tb-code tb-json",80);case"color":return ar(a);case"relative":return d("time",{class:"tb-text",text:a,attrs:{title:sr(e,r.locale)}});case"boolean":{let s=q(e);return s===null?d("span",{class:"tb-text",text:a}):n.trueLabel||n.falseLabel?d("span",{class:`tb-badge tone-${s?"green":"gray"}`,text:a}):d("span",{class:`tb-bool ${s?"yes":"no"}`},S(s?"check":"close"),d("span",{class:"sr-only",text:a}))}default:return Ne(n,a,r,"tb-text")}}function Ne(n,e,t,a,r){let s=n.maxLength??r??0,i=n.lines??0,o=s>0&&e.length>s||i>0&&(e.split(`
`).length>i||e.length>i*70);if(t.expanded&&!t.onToggle)return d("span",{class:a,text:e});if(!o||!t.onToggle){let f=o&&s>0?`${e.slice(0,s).trimEnd()}\u2026`:e;return d("span",{class:a,text:f,attrs:{title:e.length>24?e.slice(0,500):null}})}let l=d("span",{class:`tb-more-wrap${t.expanded?" open":""}`}),c=t.expanded||s<=0?e:`${e.slice(0,s).trimEnd()}\u2026`,h=d("span",{class:`${a}${i&&!t.expanded?" tb-clamp":""}`,text:c});return i&&!t.expanded&&h.style.setProperty("--_lines",String(i)),l.append(h,Bt(t)),l}function Bt(n,e){return d("button",{class:"tb-more",text:e??n.t(n.expanded?"tableShowLess":"tableSeeAll"),attrs:{type:"button",tabindex:"-1","aria-expanded":String(n.expanded)},on:{click:t=>{t.stopPropagation(),n.onToggle?.()}}})}function qt(n,e,t,a,r=1/0){let s=d("span",{class:"tb-badges"}),i=t.expanded||!t.onToggle?1/0:r;return e.slice(0,i).forEach(o=>{let l=Ht(n,o);s.append(d("span",{class:`tb-badge tone-${l}${a?" status":""}`,attrs:{title:o}},a?d("span",{class:"tb-dot",attrs:{"aria-hidden":"true"}}):null,d("span",{text:n.labels?.[o]??o})))}),e.length>r&&t.onToggle&&s.append(Bt(t,t.expanded?t.t("tableShowLess"):`+${e.length-r}`)),s}function Ht(n,e){let t=n.colors?.[e]??n.colors?.[e.toLowerCase()];if(t&&Me.includes(t))return t;if(n.colors&&!n.autoColors)return"gray";let a=0;for(let r of e.toLowerCase())a=a*31+r.charCodeAt(0)|0;return Me[1+Math.abs(a)%(Me.length-1)]}function Ya(n,e,t){let a=N(e),r=n.max||100,s=Number.isNaN(a)?0:Math.max(0,Math.min(1,a/r)),i=n.thresholds??[.34,.67],o=n.colors?"teal":s<i[0]?"red":s<i[1]?"orange":"green",l=d("span",{class:`tb-progress tone-${n.tone??o}`,attrs:{role:"img","aria-label":t}}),c=d("span",{class:"tb-progress-fill"});return c.style.width=`${s*100}%`,l.append(c),d("span",{class:"tb-progress-wrap"},l,d("span",{class:"tb-progress-text",text:t,attrs:{"aria-hidden":"true"}}))}function Xa(n,e,t){let a=N(e),r=Math.max(1,Math.min(10,n.max??5)),s=d("span",{class:"tb-rating",attrs:{role:"img","aria-label":t,title:t}});for(let i=1;i<=r;i+=1){let o=d("span",{class:`tb-star${a>=i?" on":a>=i-.5?" half":""}`,text:"\u2605",attrs:{"aria-hidden":"true"}});s.append(o)}return s}function Za(n,e,t,a){let r=n.href?U(n.href,t,!0):v(e),s=J(n)==="email"&&!n.href?Re(`mailto:${r}`):Re(r),i=n.linkText?U(n.linkText,t):a;if(!s)return d("span",{class:"tb-text",text:i});let o=/^https?:/i.test(s);return d("a",{class:"tb-link",text:i,attrs:{href:s,target:o?"_blank":null,rel:o?"noopener noreferrer nofollow":null,tabindex:"-1",title:i.length>24?i:null}})}function er(n,e,t,a){let r=Ut(n.src?U(n.src,t,!0):v(e));if(!r)return d("span",{class:"tb-text",text:a});let s=d("img",{class:"tb-image",attrs:{src:r,alt:n.alt?U(n.alt,t):"",loading:"lazy",decoding:"async",referrerpolicy:"no-referrer"}});return n.size&&s.style.setProperty("--_img",`${Math.max(12,Math.min(200,n.size))}px`),s}function tr(n,e,t,a){let r=n.src?Ut(U(n.src,t,!0)):null,s=a.split(/[\s._-]+/).filter(Boolean).slice(0,2).map(l=>l[0]?.toUpperCase()??"").join(""),i=d("span",{class:`tb-avatar tone-${Ht({...n,colors:void 0},a||"?")}`,attrs:{"aria-hidden":"true"}});if(r){let l=d("img",{attrs:{src:r,alt:"",loading:"lazy",decoding:"async",referrerpolicy:"no-referrer"}});l.addEventListener("error",()=>l.replaceWith(document.createTextNode(s))),i.append(l)}else i.textContent=s||"?";let o=n.subtitle?U(n.subtitle,t):"";return d("span",{class:"tb-person"},i,d("span",{class:"tb-person-text"},d("span",{class:"tb-text",text:a}),o?d("span",{class:"tb-sub",text:o}):null))}function ar(n){let e=n.trim(),t=/^#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(e)||/^(?:rgb|hsl|oklch)a?\([\d\s.,%/+-]+\)$/i.test(e),a=d("span",{class:"tb-swatch",attrs:{"aria-hidden":"true"}});return t&&(a.style.background=e),d("span",{class:"tb-color"},a,d("span",{class:"tb-code",text:e}))}function Le(n){return Array.isArray(n)?n.filter(e=>!z(e)).map(v):z(n)?[]:v(n).split(/\s*[,;|]\s*/).filter(Boolean)}function U(n,e,t=!1){return n.replace(/\{([\w.-]+)\}/g,(a,r)=>{let s=v(e[r]);return t?encodeURIComponent(s):s})}function Re(n){let e=n.trim();if(!e||/[\u0000-\u001f]/.test(e))return null;if(/^(?:\/(?!\/)|\.{1,2}\/|#|\?)/.test(e)||!/^[a-z][a-z\d+.-]*:/i.test(e))return/^\/\//.test(e)?null:e;try{let t=new URL(e);return["http:","https:","mailto:","tel:"].includes(t.protocol)?t.href:null}catch{return null}}function Ut(n){let e=Re(n);return e&&!/^(?:mailto|tel):/i.test(e)?e:null}function rr(n,e){if(Number.isNaN(n))return"";let t=["B","KB","MB","GB","TB","PB"],a=0,r=Math.abs(n);for(;r>=1024&&a<t.length-1;)r/=1024,a+=1;let s=new Intl.NumberFormat(e,{maximumFractionDigits:r<10&&a?1:0}).format(r);return`${n<0?"-":""}${s} ${t[a]}`}function Gt(n,e,t){let a=new Date(n);try{return t==="datetime"?a.toLocaleString(e,{dateStyle:"medium",timeStyle:"short"}):t==="time"?a.toLocaleTimeString(e,{timeStyle:"short"}):a.toLocaleDateString(e,{dateStyle:t||"medium"})}catch{return a.toISOString()}}function sr(n,e){let t=K(n);return Number.isNaN(t)?null:Gt(t,e,"datetime")}function nr(n,e,t=Date.now()){let a=(n-t)/1e3,r=[["year",31536e3],["month",2592e3],["week",604800],["day",86400],["hour",3600],["minute",60],["second",1]],s=new Intl.RelativeTimeFormat(e,{numeric:"auto"});for(let[i,o]of r)if(Math.abs(a)>=o||i==="second")return s.format(Math.round(a/o),i);return""}Pe({en:je,fr:Ie});var Y=["compact","normal","comfortable"],De={compact:30,normal:37,comfortable:46},ir=["auto","table","cards"],or=["none","single","multiple"],lr=["auto","json","csv"],Vt=[10,25,50,100,250,500,0],cr=["pages","simple","more","none"],Wt=8,dr=56,hr=1200,ur=200,fe=class extends de{static type="table";static allowEmpty=!0;static upgradeProperties=["content","data","columns","bulkActions","state"];static componentAttributes=Object.freeze(["format","sortable","filters","selectable","column-menu","resizable","reorderable","group-by","expandable","editable","footer","density","layout","card-breakpoint","page-size","pinned","row-numbers","wrap","row-key","persist","columns","pagination","pager-position","page-sizes","select-all","select-menu","select-on-click","bulk-bar","query-bar","sticky-header"]);static presets={simple:{sortable:!0,resizable:!0,"bulk-bar":!0,"select-menu":!0,"sticky-header":!0},full:{header:!0,dot:!0,copy:!0,search:!0,download:!0,fullscreen:!0,sortable:!0,filters:!0,"column-menu":!0,resizable:!0,reorderable:!0,expandable:!0,"row-numbers":!0,"bulk-bar":!0,"select-menu":!0,"query-bar":!0,"sticky-header":!0}};static styles=[qe];constructor(){super(),this._data=null,this._columnDefs=null,this._bulkActions=[],this.cache=null,this.cacheText=null,this.keyCache=new Map,this.textCache=new Map,this.viewCache=null,this.order=null,this.hiddenKeys=new Set,this.shown=new Set,this.widths=new Map,this.aggregates=new Map,this.sortState=null,this.filterValues=new Map,this.filtersOpen=null,this.groupState=void 0,this.collapsed=new Set,this.expanded=new Set,this.openCells=new Set,this.selected=new Set,this.anchor=null,this.densityState=null,this.pageSizeState=null,this.pinnedState=null,this.page=0,this.query="",this.conditions=[],this.matchAll=!0,this.valueCache=new Map,this.focusQuery=!1,this.focusPos={r:-1,c:0},this.editingCell=null,this.panel=null,this.detailHeights=new Map,this.host=null,this.scroller=null,this.table=null,this.tbody=null,this.resizeObserver=null,this.narrow=!1,this.restored=!1,this.scrollFrame=0,this.dragKey=null,this.filterTimer=void 0,this.tableId=re("table"),this.pinOffsets={},this.windowRange=null,this.resizing=!1,this.onOutside=e=>{!this.panel||e.composedPath().some(a=>a instanceof Element&&a.matches?.(".tb-popover, [data-popover-anchor]"))||this.closePanel(!1)}}connectedCallback(){super.connectedCallback(),this.restoreState(),this.root.addEventListener("pointerdown",this.onOutside),typeof ResizeObserver<"u"&&(this.resizeObserver=new ResizeObserver(([e])=>{let t=e.contentRect.width>0&&e.contentRect.width<this.cardBreakpoint;t!==this.narrow&&(this.narrow=t,this.layoutAttr==="auto"&&this.requestRender())}),this.resizeObserver.observe(this))}disconnectedCallback(){this.root.removeEventListener("pointerdown",this.onOutside),this.resizeObserver?.disconnect(),this.resizeObserver=null,cancelAnimationFrame(this.scrollFrame),clearTimeout(this.filterTimer),super.disconnectedCallback()}attributeChangedCallback(e,t,a){e==="group-by"&&(this.groupState=void 0),e==="density"&&(this.densityState=null),e==="page-size"&&(this.pageSizeState=null),e==="pinned"&&(this.pinnedState=null),e==="format"||e==="row-key"||e==="columns"?this.invalidateData():this.invalidateView(),super.attributeChangedCallback(e,t,a)}contentChanged(){this._data||this.invalidateData()}get data(){return this.getDataset().rows}set data(e){this._data=Array.isArray(e)?e:null,this.invalidateData(),this.requestRender()}get columns(){return this.allColumns().map(({format:e,render:t,...a})=>({...a,format:e,render:t}))}set columns(e){this._columnDefs=Array.isArray(e)?e:null,this.order=null,this.invalidateData(),this.requestRender()}get bulkActions(){return this._bulkActions}set bulkActions(e){this._bulkActions=Array.isArray(e)?e.filter(t=>t&&typeof t.id=="string"&&typeof t.label=="string"):[],this.requestRender()}get selection(){let e=this.getDataset().rows,t=[];return e.forEach((a,r)=>{this.selected.has(this.rowKey(r))&&t.push(a)}),t}get selectedKeys(){return[...this.selected]}select(e,t={}){t.add||this.selected.clear();for(let a of e)this.selected.add(String(a));this.selectionChanged()}clearSelection(){this.selected.size&&(this.selected.clear(),this.selectionChanged())}selectAll(){if(this.selectionMode==="multiple"){for(let e of this.view().order)this.selected.add(this.rowKey(e));this.selectionChanged()}}getRows(e={}){let t=this.getDataset().rows;return(e.filtered===!1?t.map((r,s)=>s):this.view().order).filter(r=>!e.selected||this.selected.has(this.rowKey(r))).map(r=>t[r])}exportData(e="csv",t={}){return jt(this.getRows(t),this.visibleColumns(),e)}updateRow(e,t){let a=this.indexOfKey(String(e));return a<0?!1:(Object.assign(this.getDataset().rows[a],t),this.invalidateValues(),this.renderGrid(),!0)}addRows(e){this.getDataset().rows.push(...e.filter(a=>a&&typeof a=="object")),this.invalidateValues(),this.renderGrid()}removeRows(e){let t=new Set([...e].map(String)),a=this.getDataset(),r=a.rows.filter((i,o)=>!t.has(this.rowKey(o))),s=a.rows.map((i,o)=>this.rowKey(o)).filter(i=>!t.has(i));if(a.rows.splice(0,a.rows.length,...r),this.hasAttribute("row-key"))for(let i of t)this.selected.delete(i);else{let i=new Set;s.forEach((o,l)=>this.selected.has(o)&&i.add(this.rowKey(l))),this.selected=i}this.expanded.clear(),this.invalidateValues(),this.renderGrid(),this.selectionChanged()}expandAll(){if(this.groupKey)this.collapsed.clear();else if(this.feature("expandable"))for(let e of this.view().order.slice(0,1e3))this.expanded.add(e);this.invalidateView(),this.renderGrid()}collapseAll(){if(this.groupKey)for(let e of this.view().items)e.kind==="group"&&this.collapsed.add(e.value);else this.expanded.clear();this.invalidateView(),this.renderGrid()}resetLayout(){this.order=null,this.hiddenKeys.clear(),this.shown.clear(),this.widths.clear(),this.aggregates.clear(),this.pinnedState=null,this.columnsChanged()}get state(){return{columns:this.allColumns().map(e=>({key:e.key,hidden:this.isHidden(e),width:this.widths.get(e.key),aggregate:this.aggregates.get(e.key)})),sort:this.sortSpecs.map(e=>({...e})),filters:Object.fromEntries([...this.filterValues].filter(([,e])=>e.trim())),conditions:this.conditions.map(e=>({...e})),match:this.matchAll?"all":"any",groupBy:this.groupKey,density:this.density,pageSize:this.pageSize,pinned:this.pinned}}set state(e){!e||typeof e!="object"||(this.applyState(e),this.invalidateView(),this.requestRender())}get selectionMode(){let e=this.getAttribute("selectable");if(e===null)return this.variant==="full"?"multiple":"none";let t=e.trim().toLowerCase();return t===""||t==="true"?"multiple":t==="false"?"none":O(t,or,"none")}get density(){return this.densityState??O(this.getAttribute("density"),Y,"normal")}get pageSize(){if(this.pageSizeState!==null)return this.pageSizeState;let e=this.getAttribute("page-size");return e!==null&&e.trim()==="0"?0:te(e,{min:5,max:1e3,fallback:50})}get pinned(){return this.pinnedState??te(this.getAttribute("pinned"),{min:0,max:20,fallback:0})}get layoutAttr(){return O(this.getAttribute("layout"),ir,"auto")}get cardBreakpoint(){return te(this.getAttribute("card-breakpoint"),{min:0,max:4e3,fallback:560})}get cards(){return this.layoutAttr==="cards"||this.layoutAttr==="auto"&&this.narrow}get groupKey(){let e=this.groupState===void 0?this.getAttribute("group-by"):this.groupState;return e&&this.allColumns().some(t=>t.key===e)?e:null}get sortSpecs(){return(this.sortState??[]).filter(e=>this.allColumns().some(t=>t.key===e.key))}get showFilters(){return this.filtersOpen??this.feature("filters")}get virtual(){return(this.pageSize===0||this.paginationAttr==="none")&&!this.cards&&!this.feature("wrap")}get paginationAttr(){return O(this.getAttribute("pagination"),cr,"pages")}get paginationMode(){let e=this.paginationAttr;return(e==="none"||this.pageSize===0)&&!this.virtual?"more":this.pageSize===0?"none":e}get effectivePageSize(){return this.virtual?1/0:this.pageSize||ur}pageWindow(e){let{items:t,base:a}=this.view(),r=this.effectivePageSize,s=(u,p)=>{let g=0;for(let b=u;b<p;b+=1)t[b].kind==="row"&&(g+=1);return g};if(!Number.isFinite(r))return{from:0,to:t.length,pages:1,size:r,rowFrom:0,rowTo:s(0,t.length)};let i=Math.max(1,Math.ceil(a.length/r));this.page=Math.max(0,Math.min(this.page,i-1));let o=this.paginationMode==="more"?0:this.page*r,l=Math.min(a.length,(this.page+1)*r),c=a[o]??t.length,h=l<a.length?a[l]:t.length,f=s(0,c);return{from:c,to:h,pages:i,size:r,rowFrom:f,rowTo:f+s(c,h)}}get columnDefs(){if(this._columnDefs)return this._columnDefs;let e=this.getAttribute("columns");if(!e)return null;try{let t=JSON.parse(e);if(Array.isArray(t))return t.map(a=>typeof a=="string"?{key:a}:a)}catch{return e.split(",").map(t=>({key:t.trim()})).filter(t=>t.key)}return null}getDataset(){if(this._data)return(!this.cache||this.cacheText!==null)&&(this.cache=ue(this._data,this.columnDefs),this.cache.rows=this._data,this.cacheText=null),this.cache;let e=this.text??"";if(!this.cache||this.cacheText!==e){let t=O(this.getAttribute("format"),lr,"auto"),a=zt(e,t);this.cache=this.columnDefs?{...ue(a.rows,this.columnDefs),error:a.error}:a,this.cacheText=e}return this.cache}invalidateData(){this.cache=null,this.cacheText=null,this.selected.clear(),this.expanded.clear(),this.collapsed.clear(),this.detailHeights.clear(),this.page=0,this.invalidateValues()}invalidateValues(){this.keyCache.clear(),this.textCache.clear(),this.valueCache.clear(),this.invalidateView()}invalidateView(){this.viewCache=null}allColumns(){let{columns:e}=this.getDataset(),t=new Map(e.map(r=>[r.key,r])),a=(this.order??[]).filter(r=>t.has(r));for(let r of e)a.includes(r.key)||a.push(r.key);return a.map(r=>{let s=t.get(r),i=this.widths.get(r),o=this.aggregates.get(r);return{...s,width:i??s.width,aggregate:o??s.aggregate}})}isHidden(e){return this.hiddenKeys.has(e.key)?!0:this.shown.has(e.key)?!1:e.hidden}visibleColumns(){return this.allColumns().filter(e=>!this.isHidden(e))}rowKey(e){let t=this.getAttribute("row-key"),a=this.getDataset().rows[e];return t&&a&&!z(a[t])?v(a[t]):String(e)}indexOfKey(e){let t=this.getDataset().rows;for(let a=0;a<t.length;a+=1)if(this.rowKey(a)===e)return a;return-1}keysOf(e){let t=this.keyCache.get(e.key);return t||(t=Ot(this.getDataset().rows,e),this.keyCache.set(e.key,t)),t}textOf(e){let t=this.textCache.get(e.key);return t||(t=this.getDataset().rows.map(r=>this.displayText(e,r).toLowerCase()),this.textCache.set(e.key,t)),t}get collator(){return new Intl.Collator(this.locale,{numeric:!0,sensitivity:"base"})}view(){let e=this.allColumns(),t=JSON.stringify([this.sortSpecs,[...this.filterValues],this.query,this.conditions,this.matchAll,this.groupKey,[...this.collapsed],[...this.expanded],e.map(p=>[p.key,p.type,this.isHidden(p)])]);if(this.viewCache?.key===t)return this.viewCache;let{rows:a}=this.getDataset(),r=a.map((p,g)=>g);for(let p of e){let g=this.filterValues.get(p.key)??"",b=Te(g,p.type);b&&(r=r.filter(y=>b(a[y][p.key])))}let s=this.conditions.map(p=>this.compileCondition(p,e)).filter(p=>p!==null);if(s.length){let p=this.matchAll;r=r.filter(g=>p?s.every(b=>b(g)):s.some(b=>b(g)))}let i=this.query.trim().toLowerCase();if(i){let p=e.filter(g=>!this.isHidden(g)).map(g=>this.textOf(g));r=r.filter(g=>p.some(b=>b[g].includes(i)))}let o=this.sortSpecs.map(p=>{let g=e.find(b=>b.key===p.key);return g?{keys:this.keysOf(g),direction:p.direction}:null}).filter(p=>p!==null);r=Pt(r,o,this.collator);let l=[],c=this.feature("expandable"),h=p=>{l.push({kind:"row",index:p}),c&&this.expanded.has(p)&&l.push({kind:"detail",index:p})},f=this.groupKey;if(f)for(let p of Ft(a,r,f))l.push({kind:"group",value:p.value,indexes:p.indexes}),this.collapsed.has(p.value)||p.indexes.forEach(h);else r.forEach(h);let u=[];return l.forEach((p,g)=>p.kind!=="detail"&&u.push(g)),this.viewCache={items:l,order:r,base:u,key:t},this.viewCache}displayText(e,t){let a=t[e.key];if(e.format)try{return String(e.format(a,t)??"")}catch{return v(a)}return Jt(e.key)&&e.grouping===void 0&&!e.display?v(a):a instanceof Date&&!Number.isNaN(a.getTime())&&!e.display?a.toLocaleString(this.locale):ze(e,a,this.locale,this.t)}applyState(e){Array.isArray(e.columns)&&(this.order=e.columns.map(t=>t.key),this.hiddenKeys=new Set(e.columns.filter(t=>t.hidden).map(t=>t.key)),this.shown=new Set(e.columns.filter(t=>!t.hidden).map(t=>t.key)),this.widths=new Map(e.columns.filter(t=>typeof t.width=="number"&&t.width>0).map(t=>[t.key,$e(t.width)])),this.aggregates=new Map(e.columns.filter(t=>t.aggregate&&he.includes(t.aggregate)).map(t=>[t.key,t.aggregate]))),Array.isArray(e.sort)&&(this.sortState=e.sort.filter(t=>t&&typeof t.key=="string").map(t=>({key:t.key,direction:t.direction==="descending"?"descending":"ascending"}))),e.filters&&typeof e.filters=="object"&&(this.filterValues=new Map(Object.entries(e.filters).map(([t,a])=>[t,String(a)]))),Array.isArray(e.conditions)&&(this.conditions=e.conditions.filter(t=>t&&typeof t.value=="string").map(t=>({key:typeof t.key=="string"?t.key:null,value:t.value,not:!!t.not}))),e.match&&(this.matchAll=e.match!=="any"),e.groupBy!==void 0&&(this.groupState=e.groupBy||null),e.density&&Y.includes(e.density)&&(this.densityState=e.density),typeof e.pageSize=="number"&&(this.pageSizeState=Vt.includes(e.pageSize)?e.pageSize:null),typeof e.pinned=="number"&&(this.pinnedState=Math.max(0,Math.min(20,e.pinned)))}restoreState(){let e=this.storageKey;if(!(!e||this.restored)){this.restored=!0;try{let t=localStorage.getItem(e);t&&this.applyState(JSON.parse(t))}catch{}}}saveState(){let e=this.storageKey;if(!e)return;let{filters:t,...a}=this.state;try{localStorage.setItem(e,JSON.stringify(a))}catch{}}get storageKey(){let e=this.getAttribute("persist")?.trim();return e?`vitrine-table:${e.slice(0,100)}`:null}columnsChanged(){this.invalidateView(),this.saveState(),this.render(),C(this,_.COLUMN_CHANGE,{columns:this.state.columns})}selectionChanged(){let e=[...this.selected];this.renderGrid(),this.announce(this.t("tableSelected",{count:E(e.length,this.locale)})),C(this,_.SELECT,{keys:e,rows:this.selection,count:e.length})}renderContent(e){let t=this.t,a=this.getDataset();this.frame.dataset.density=this.density,this.frame.toggleAttribute("data-sticky",this.feature("sticky-header")),this.frame.toggleAttribute("data-wrap",this.feature("wrap"));let r=this.feature("expandable")||!!this.groupKey,s=[this.searchButton({run:o=>this.search(o),go:o=>this.goToResult(o),clear:()=>this.search("")}),this.feature("column-menu")||this.feature("filters")?w({icon:"filter",label:t(this.showFilters?"tableHideFilters":"tableShowFilters"),key:"filters",pressed:this.showFilters,onClick:()=>{this.filtersOpen=!this.showFilters,this.render()}}):null,this.feature("column-menu")?w({icon:"columns",label:t("tableColumns"),key:"columns",pressed:this.panel==="columns",onClick:()=>this.togglePanel("columns")}):null,w({icon:"rows",label:t("tableDensity",{density:t(`tableDensity_${this.density}`)}),key:"density",onClick:()=>this.cycleDensity()}),r?w({icon:"expand-all",label:t("expandAll"),key:"expand-all",onClick:()=>this.expandAll()}):null,r?w({icon:"collapse-all",label:t("collapseAll"),key:"collapse-all",onClick:()=>this.collapseAll()}):null,w({icon:"keyboard",label:t("tableShortcuts"),key:"help",pressed:this.panel==="help",onClick:()=>this.togglePanel("help")}),this.fullscreenButton(),this.feature("download")?this.downloadButton(()=>this.exportData("csv"),this.downloadName("table.csv"),"text/csv"):null,this.feature("copy")?this.copyButton(()=>this.exportData("tsv"),t("tableCopyRows")):null];for(let o of s)o?.setAttribute("data-popover-anchor","");let i=[];a.error&&i.push(Ae(t("tableInvalid",{message:a.error}))),a.truncated&&i.push(Ae(t("tableTruncated"))),this.host=d("div",{class:"tb",part:"table-host"}),e.append(...this.chrome({badge:this.cards?"":t("table"),actions:s}),...i,this.host),this.scroller=null,this.renderGrid()}renderGrid(){if(!this.host)return;let e=this.scroller?.scrollTop??0,t=this.scroller?.scrollLeft??0,a=this.activeFocusKey(),r=this.root.activeElement?.closest?.(".tb-grid, .tb-cards")!==null&&this.root.activeElement!==null,{order:s,items:i}=this.view(),o=this.pageWindow(i.length),l=d("div",{class:`body tb-body${this.virtual?" virtual":""}`,part:"body",attrs:{tabindex:this.cards?"0":null,role:this.cards?"region":null,"aria-label":this.heading||this.t("table")}});this.scroller=l,this.virtual&&l.addEventListener("scroll",()=>this.onScroll(),{passive:!0}),this.cards?l.append(this.renderCards(i)):l.append(this.renderTable());let c=this.getAttribute("pager-position");this.host.replaceChildren(...[this.queryBar(),this.bulkBar(s),this.stateBar(),c==="top"||c==="both"?this.pager(i.length,s.length,o,"top"):null,l,c==="top"?null:this.pager(i.length,s.length,o,"bottom"),this.renderPanel()].filter(h=>h!==null)),l.scrollTop=e,l.scrollLeft=t,this.virtual&&this.renderBody(),a?this.restoreFocus(a):r&&this.focusCell(this.focusPos.r,this.focusPos.c,!1)}renderTable(){let e=this.t,t=this.visibleColumns(),a=this.controlColumns(),r=t.map(c=>this.widthOf(c)),s=a.reduce((c,h)=>c+h.width,0)+r.reduce((c,h)=>c+h,0),i=d("table",{class:"tb-grid",part:"table",attrs:{id:this.tableId,role:"grid","aria-label":this.heading||e("table"),"aria-rowcount":this.view().order.length+1,"aria-colcount":t.length,"aria-multiselectable":this.selectionMode==="multiple"?"true":null},on:{keydown:c=>this.onGridKey(c),click:c=>this.onGridClick(c),dblclick:c=>this.onGridDoubleClick(c),focusin:c=>this.onGridFocus(c)}});i.style.width=`max(100%, ${s}px)`;let o=d("colgroup");for(let c of a)o.append(pe(d("col",{class:`tb-col-${c.id}`}),"width",c.width));t.forEach((c,h)=>o.append(pe(d("col",{attrs:{"data-key":c.key}}),"width",r[h]))),this.table=i,this.tbody=d("tbody"),i.append(o,this.renderHead(t,a),this.tbody);let l=this.renderFoot(t,a);return l&&i.append(l),this.applyPinning(i,t,a,r),this.virtual||this.renderBody(),i}controlColumns(){let e=[];if(this.selectionMode!=="none"&&e.push({id:"select",width:40}),this.feature("expandable")&&e.push({id:"expand",width:34}),this.feature("row-numbers")){let t=String(this.getDataset().rows.length).length;e.push({id:"number",width:Math.max(44,t*8+24)})}return e}widthOf(e){if(e.width)return $e(e.width);let t=this.getDataset().rows,a=e.label.length+7,r=Math.max(1,Math.floor(t.length/200));for(let i=0;i<t.length;i+=r){let o=this.displayText(e,t[i]).length;o>a&&(a=o)}let s=Math.round(a*7.6+34);return Math.max(e.type==="boolean"?72:90,Math.min(e.type==="text"?340:220,s))}applyPinning(e,t,a,r){let s=0,i={};for(let l of a)i[`ctl-${l.id}`]=s,s+=l.width;let o=Math.min(this.pinned,t.length);for(let l=0;l<o;l+=1)i[`col-${l}`]=s,s+=r[l];e.style.setProperty("--_pin-edge",`${s}px`),this.pinOffsets=i}pin(e,t){let a=this.pinOffsets?.[t];if(a===void 0)return;e.classList.add("pinned"),e.style.left=`${a}px`;let r=this.visibleColumns(),s=this.pinned>0?`col-${Math.min(this.pinned,r.length)-1}`:null;t===s&&e.classList.add("pin-edge")}renderHead(e,t){let a=this.t,r=d("tr",{attrs:{role:"row","aria-rowindex":1}}),{order:s}=this.view();for(let c of t){let h=d("th",{class:`tb-ctl tb-ctl-${c.id}`,attrs:{role:"columnheader",scope:"col"}});c.id==="select"?this.selectionMode==="multiple"?(h.append(this.headerCheckbox(s)),this.feature("select-menu")&&h.append(d("button",{class:"tb-select-more",attrs:{type:"button",tabindex:"-1","aria-haspopup":"menu","aria-expanded":String(this.panel==="select"),"aria-label":a("tableSelectMenu"),"data-popover-anchor":"","data-focus-key":"select-menu"},on:{click:f=>(f.stopPropagation(),this.togglePanel("select"))}},S("chevron-down")))):h.append(d("span",{class:"sr-only",text:a("tableSelect")})):c.id==="expand"?h.append(d("span",{class:"sr-only",text:a("tableDetails")})):h.append(d("span",{class:"sr-only",text:a("rowNumber")})),this.pin(h,`ctl-${c.id}`),r.append(h)}let i=this.feature("sortable"),o=this.sortSpecs;e.forEach((c,h)=>{let f=o.findIndex(b=>b.key===c.key),u=f>=0?o[f].direction:null,p=d("th",{class:`tb-head type-${c.type}${c.align?` align-${c.align}`:""}`,part:"header-cell",attrs:{role:"columnheader",scope:"col","aria-colindex":h+1,"aria-sort":i&&c.sortable?u??"none":null,"data-r":-1,"data-c":h,"data-key":c.key,tabindex:"-1",draggable:this.feature("reorderable")?"true":null,title:c.label}}),g=d("div",{class:"tb-head-inner"});g.append(d("span",{class:"tb-label",text:c.label})),u?(g.append(S(u==="ascending"?"sort-up":"sort-down")),o.length>1&&g.append(d("span",{class:"tb-sort-rank",text:String(f+1),attrs:{"aria-hidden":"true"}}))):i&&c.sortable&&g.append(d("span",{class:"tb-sort-hint"},S("sort"))),this.feature("column-menu")&&g.append(d("button",{class:"tb-menu-btn",attrs:{type:"button",tabindex:"-1","aria-haspopup":"menu","aria-label":a("tableColumnMenu",{name:c.label}),"data-popover-anchor":"","data-focus-key":`menu-${c.key}`},on:{click:b=>{b.stopPropagation(),this.togglePanel({column:c.key})}}},S("chevron-down"))),p.append(g),this.feature("resizable")&&c.resizable&&p.append(this.resizer(c)),this.feature("reorderable")&&this.makeDraggable(p,c.key),this.pin(p,`col-${h}`),r.append(p)});let l=d("thead",{},r);return this.showFilters&&l.append(this.filterRow(e,t)),l}headerCheckbox(e){let t=this.t,a=this.getAttribute("select-all")==="all",r=a?e.map(l=>this.rowKey(l)):this.pageKeys(),s=r.filter(l=>this.selected.has(l)).length,i=t(a?"tableSelectAll":"tableSelectPage"),o=d("input",{class:"tb-check",attrs:{type:"checkbox","aria-label":i,title:i,"data-focus-key":"select-all",tabindex:"-1"},on:{change:()=>{if(s===r.length&&s){for(let l of r)this.selected.delete(l);this.selectionChanged()}else this.select(r,{add:!0})}}});return o.checked=s>0&&s===r.length,o.indeterminate=s>0&&s<r.length,o}filterRow(e,t){let a=this.t,r=d("tr",{class:"tb-filters"});for(let s of t){let i=d("th",{class:`tb-ctl tb-ctl-${s.id}`});this.pin(i,`ctl-${s.id}`),r.append(i)}return e.forEach((s,i)=>{let o=d("th");if(this.pin(o,`col-${i}`),!s.filterable){r.append(o);return}let l=this.filterValues.get(s.key)??"",c=a("tableFilterBy",{name:s.label}),h;s.type==="boolean"?(h=d("select",{class:"tb-filter",part:"filter",attrs:{"aria-label":c,"data-focus-key":`filter-${s.key}`}},d("option",{attrs:{value:""},text:a("tableAll")}),d("option",{attrs:{value:"true"},text:a("tableYes")}),d("option",{attrs:{value:"false"},text:a("tableNo")}),d("option",{attrs:{value:"empty"},text:a("tableEmpty")})),h.value=l,h.addEventListener("change",()=>this.setFilter(s.key,h.value,!0))):(h=d("input",{class:"tb-filter",part:"filter",attrs:{type:"search","aria-label":c,placeholder:a(s.type==="number"||s.type==="date"?"tableFilterRange":"tableFilterText"),autocomplete:"off",spellcheck:"false",maxlength:200,"data-focus-key":`filter-${s.key}`}}),h.value=l,h.addEventListener("input",()=>this.setFilter(s.key,h.value,!1)),h.addEventListener("keydown",f=>{f.key==="Escape"&&h.value?(f.stopPropagation(),h.value="",this.setFilter(s.key,"",!0)):f.key==="ArrowDown"&&(f.preventDefault(),this.focusCell(this.firstRowItem(),i))})),o.append(h),r.append(o)}),r}renderFoot(e,t){let a=this.feature("footer"),r=e.map(l=>l.aggregate!=="none"?l.aggregate:a&&l.type==="number"&&!Jt(l.key)&&!["rating","progress","percent"].includes(l.display??"")?"sum":"none");if(!a&&r.every(l=>l==="none"))return null;let{rows:s}=this.getDataset(),{order:i}=this.view(),o=d("tr",{class:"tb-foot"});return t.forEach((l,c)=>{let h=d("td",{class:`tb-ctl tb-ctl-${l.id}`,text:c===0?E(i.length,this.locale):"",attrs:{title:c===0?this.t("tableRowCount",{count:i.length}):null}});this.pin(h,`ctl-${l.id}`),o.append(h)}),e.forEach((l,c)=>{let h=r[c],f=Ee(s,i,l,h),u=d("td",{class:`type-${l.type}${l.align?` align-${l.align}`:""}`});if(f!==null){let p=l.type==="date"&&h!=="count"?new Date(f).toLocaleDateString(this.locale):E(Math.round(f*100)/100,this.locale);u.append(d("span",{class:"tb-agg",text:this.t(`tableAgg_${h}`)})," ",d("strong",{text:p}))}else c===0&&!t.length&&(u.textContent=this.t("tableRowCount",{count:E(i.length,this.locale)}));this.pin(u,`col-${c}`),o.append(u)}),d("tfoot",{},o)}renderBody(){let e=this.tbody;if(!e)return;let{items:t}=this.view(),a=this.visibleColumns(),r=this.controlColumns(),s=a.length+r.length,i=[],o,l,c=0,h=0;if(this.virtual&&this.scroller){let f=De[this.density],u=t.map(A=>Qt(A,f,this.detailHeights)),p=this.table?.tHead??null,g=Math.max(0,this.scroller.scrollTop-(p?.offsetHeight??0)),b=this.scroller.clientHeight||480,y=0;for(o=0;o<t.length&&y+u[o]<g;)y+=u[o++];o=Math.max(0,o-Wt),c=u.slice(0,o).reduce((A,T)=>A+T,0);let m=0;for(l=o;l<t.length&&m<b+Wt*2*f;)m+=u[l++];h=u.slice(l).reduce((A,T)=>A+T,0),this.windowRange=[o,l]}else({from:o,to:l}=this.pageWindow(t.length));c&&i.push(d("tr",{class:"tb-spacer",attrs:{"aria-hidden":"true"}},pe(d("td",{attrs:{colspan:s}}),"height",c)));for(let f=o;f<l;f+=1)i.push(this.renderItem(t[f],f,a,r));if(h&&i.push(d("tr",{class:"tb-spacer",attrs:{"aria-hidden":"true"}},pe(d("td",{attrs:{colspan:s}}),"height",h))),t.length||i.push(d("tr",{},d("td",{class:"tb-empty",attrs:{colspan:s},text:this.getDataset().rows.length?this.t("tableNoMatch"):this.t("noRows")}))),e.replaceChildren(...i),this.query&&this.highlight(e),this.virtual){let f=!1;for(let u of e.querySelectorAll("tr.tb-detail")){let p=Number(u.getAttribute("data-index")),g=u.offsetHeight;g&&this.detailHeights.get(p)!==g&&(this.detailHeights.set(p,g),f=!0)}f&&requestAnimationFrame(()=>this.renderBody())}this.syncTabStop()}onScroll(){cancelAnimationFrame(this.scrollFrame),this.scrollFrame=requestAnimationFrame(()=>{let e=this.root.activeElement,t=e instanceof HTMLElement&&this.tbody?.contains(e);this.renderBody(),t&&this.focusCell(this.focusPos.r,this.focusPos.c,!1)})}renderItem(e,t,a,r){let s=this.t,i=a.length+r.length;if(e.kind==="group"){let u=!this.collapsed.has(e.value),p=this.allColumns().find(m=>m.key===this.groupKey),g=e.value===""?s("tableEmpty"):p?this.displayText(p,{[p.key]:this.getDataset().rows[e.indexes[0]][p.key]}):e.value,b=e.indexes.filter(m=>this.selected.has(this.rowKey(m))).length,y=d("td",{class:"tb-group-cell",attrs:{colspan:i,"data-r":t,"data-c":0,tabindex:"-1",role:"gridcell"}},d("span",{class:"tb-group-inner"},d("span",{class:"tb-chevron"},S("chevron-right")),this.selectionMode==="multiple"?this.groupCheckbox(e.indexes,b):null,d("span",{class:"tb-group-name",text:p?`${p.label}: `:""}),d("strong",{text:g}),d("span",{class:"tb-count",text:E(e.indexes.length,this.locale)}),...this.groupAggregates(e.indexes,a)));return d("tr",{class:"tb-group",part:"group-row",attrs:{role:"row","aria-expanded":String(u),"data-group":e.value,"data-r":t}},y)}let{rows:o}=this.getDataset(),l=o[e.index],c=this.rowKey(e.index);if(e.kind==="detail"){let u=d("dl",{class:"tb-detail-list"});for(let p of this.allColumns())u.append(d("div",{class:`tb-field${this.isHidden(p)?" hidden-col":""}`},d("dt",{text:p.label}),d("dd",{},this.cellContent(p,l,!0))));return d("tr",{class:"tb-detail",attrs:{"data-index":e.index,role:"row"}},d("td",{attrs:{colspan:i,role:"gridcell"}},u))}let h=this.selected.has(c),f=d("tr",{class:`tb-row${h?" selected":""}`,part:"row",attrs:{role:"row","aria-rowindex":t+2,"aria-selected":this.selectionMode!=="none"?String(h):null,"data-r":t,"data-key":c}});for(let u of r){let p=d("td",{class:`tb-ctl tb-ctl-${u.id}`});if(u.id==="select")p.append(d("input",{class:"tb-check",attrs:{type:"checkbox",tabindex:"-1","aria-label":s("tableSelectRow",{n:e.index+1})},on:{click:g=>{g.stopPropagation(),g.shiftKey&&this.anchor!==null?this.selectRange(this.anchor,t):this.toggleRow(t)}}})),p.firstChild.checked=h;else if(u.id==="expand"){let g=this.expanded.has(e.index);p.append(d("button",{class:"tb-expand",attrs:{type:"button",tabindex:"-1","aria-expanded":String(g),"aria-label":s(g?"tableCollapseRow":"tableExpandRow")},on:{click:b=>(b.stopPropagation(),this.toggleDetail(e.index))}},S("chevron-right")))}else p.textContent=E(e.index+1,this.locale);this.pin(p,`ctl-${u.id}`),f.append(p)}return a.forEach((u,p)=>{let g=d("td",{class:`tb-cell type-${u.type}${u.align?` align-${u.align}`:""}${this.canEdit(u)?" editable":""}`,part:"cell",attrs:{role:"gridcell","data-r":t,"data-c":p,tabindex:"-1","aria-colindex":p+1}});this.editingCell?.r===t&&this.editingCell.c===p?g.append(this.editor(u,l,t,p)):g.append(this.cellContent(u,l)),this.pin(g,`col-${p}`),f.append(g)}),f}groupAggregates(e,t){let{rows:a}=this.getDataset();return t.filter(r=>r.aggregate!=="none").slice(0,4).map(r=>{let s=Ee(a,e,r,r.aggregate);if(s===null)return null;let i=r.type==="date"&&r.aggregate!=="count"?new Date(s).toLocaleDateString(this.locale):r.aggregate==="count"?E(s,this.locale):ze({...r,display:r.display==="progress"||r.display==="rating"?"number":r.display},Math.round(s*100)/100,this.locale,this.t);return d("span",{class:"tb-group-agg"},d("span",{text:`${r.label} \xB7 ${this.t(`tableAgg_${r.aggregate}`)}`}),d("strong",{text:i}))}).filter(r=>r!==null)}groupCheckbox(e,t){let a=d("input",{class:"tb-check",attrs:{type:"checkbox",tabindex:"-1","aria-label":this.t("tableSelectGroup")},on:{click:r=>{r.stopPropagation();let s=t===e.length;for(let i of e){let o=this.rowKey(i);s?this.selected.delete(o):this.selected.add(o)}this.selectionChanged()}}});return a.checked=t>0&&t===e.length,a.indeterminate=t>0&&t<e.length,a}cellContent(e,t,a=!1){let r=t[e.key];if(e.render)try{let l=e.render(r,t);return l instanceof Node?l:document.createTextNode(String(l??""))}catch{}let s=this.displayText(e,t),i=this.getDataset().rows.indexOf(t),o=`${this.rowKey(i)}\0${e.key}`;return Kt(e,r,t,s,{t:this.t,locale:this.locale,expanded:a||this.openCells.has(o),onToggle:a?null:()=>{if(this.virtual&&this.feature("expandable")){this.toggleDetail(i);return}this.openCells.has(o)?this.openCells.delete(o):this.openCells.add(o),this.cards?this.renderGrid():this.renderBody()}})}renderCards(e){let t=this.t,a=this.visibleColumns(),r=this.pageWindow(e.length),s=d("div",{class:"tb-cards",attrs:{role:"list","aria-label":this.heading||t("table")}}),i=this.feature("sortable"),o=this.sortSpecs[0],l=d("div",{class:"tb-card-tools"});if(this.selectionMode==="multiple"){let{order:f}=this.view(),u=f.filter(g=>this.selected.has(this.rowKey(g))).length,p=d("input",{class:"tb-check",attrs:{type:"checkbox","aria-label":t("tableSelectAll")},on:{change:()=>u===f.length&&u?this.clearSelection():this.selectAll()}});p.checked=u>0&&u===f.length,p.indeterminate=u>0&&u<f.length,l.append(d("label",{class:"tb-card-all"},p,d("span",{text:t("tableSelectAll")})))}if(i){let f=d("select",{class:"tb-filter",attrs:{"aria-label":t("tableSortField"),"data-focus-key":"card-sort"}},d("option",{attrs:{value:""},text:t("tableNoSort")}),...a.filter(u=>u.sortable).map(u=>d("option",{attrs:{value:u.key},text:u.label})));f.value=o?.key??"",f.addEventListener("change",()=>this.setSort(f.value?[{key:f.value,direction:o?.direction??"ascending"}]:[])),l.append(f),o&&l.append(w({icon:o.direction==="ascending"?"sort-up":"sort-down",label:t(o.direction==="ascending"?"tableSortAsc":"tableSortDesc"),key:"card-direction",onClick:()=>this.setSort([{key:o.key,direction:o.direction==="ascending"?"descending":"ascending"}])}))}let c=d("div",{class:"tb-cards-wrap"},l,s),{rows:h}=this.getDataset();for(let f=r.from;f<r.to;f+=1){let u=e[f];if(u.kind==="detail")continue;if(u.kind==="group"){let x=!this.collapsed.has(u.value);s.append(d("button",{class:"tb-card-group",part:"group-row",attrs:{type:"button","aria-expanded":String(x),role:"listitem"},on:{click:()=>this.toggleGroup(u.value)}},S("chevron-right"),d("strong",{text:u.value||t("tableEmpty")}),d("span",{class:"tb-count",text:E(u.indexes.length,this.locale)})));continue}let p=h[u.index],g=this.rowKey(u.index),b=this.selected.has(g),y=d("article",{class:`tb-card${b?" selected":""}`,part:"card",attrs:{role:"listitem","data-key":g}}),[m,...A]=a,T=d("div",{class:"tb-card-top"});if(this.selectionMode!=="none"){let x=d("input",{class:"tb-check",attrs:{type:"checkbox","aria-label":t("tableSelectRow",{n:u.index+1})},on:{change:()=>this.toggleRow(f)}});x.checked=b,T.append(x)}m&&T.append(d("strong",{class:"tb-card-title"},this.cellContent(m,p))),y.append(T);let L=d("dl",{class:"tb-card-fields"});for(let x of A)L.append(d("dt",{text:x.label}),d("dd",{},this.cellContent(x,p)));y.append(L),s.append(y)}return e.length||s.append(d("p",{class:"tb-empty",text:h.length?t("tableNoMatch"):t("noRows")})),this.query&&this.highlight(s),c}bulkBar(e){if(!this.selected.size||this.selectionMode==="none"||!this.feature("bulk-bar"))return null;let t=this.t,a=this.selected.size,r=d("div",{class:"tb-bulk",part:"bulk-bar",attrs:{role:"toolbar","aria-label":t("tableSelectionActions")}});r.append(d("span",{class:"tb-bulk-count",text:t("tableSelected",{count:E(a,this.locale)})}));let s=e.filter(i=>this.selected.has(this.rowKey(i))).length;this.selectionMode==="multiple"&&s<e.length&&r.append(this.textButton(t("tableSelectAllMatching",{count:E(e.length,this.locale)}),"bulk-all",()=>this.selectAll())),r.append(d("span",{class:"spacer"})),r.append(this.textButton(t("copy"),"bulk-copy",async i=>{let o=await B(this.exportData("tsv",{selected:!0}),this.root);i.classList.toggle("done",o),this.announce(t(o?"copied":"copyFailed"))},"copy"),this.textButton("CSV","bulk-csv",()=>V(this.exportData("csv",{selected:!0}),this.downloadName("selection.csv"),"text/csv"),"download"),this.textButton("JSON","bulk-json",()=>V(this.exportData("json",{selected:!0}),"selection.json","application/json"),"download"));for(let i of this._bulkActions){let o=this.textButton(i.label,`bulk-${i.id}`,()=>{C(this,_.BULK_ACTION,{action:i.id,keys:[...this.selected],rows:this.selection})},i.icon);i.danger&&o.classList.add("danger"),r.append(o)}return r.append(w({icon:"close",label:t("tableClearSelection"),key:"bulk-clear",onClick:()=>this.clearSelection()})),r}stateBar(){let e=this.t,t=[],a=this.allColumns(),r=o=>a.find(l=>l.key===o)?.label??o;for(let[o,l]of this.filterValues)l.trim()&&t.push(this.chip(`${r(o)}: ${l}`,e("tableRemoveFilter",{name:r(o)}),()=>this.setFilter(o,"",!0)));let s=this.groupKey;s&&t.push(this.chip(e("tableGroupedBy",{name:r(s)}),e("tableUngroup"),()=>this.setGroup(null)));let i=this.sortSpecs;return i.length>1&&t.push(this.chip(e("tableSortedBy",{names:i.map(o=>r(o.key)).join(", ")}),e("tableClearSort"),()=>this.setSort([]))),t.length?d("div",{class:"tb-state"},...t,t.length>1?this.textButton(e("tableClearAll"),"clear-all",()=>this.clearQuery()):null):null}chip(e,t,a){return d("span",{class:"tb-chip"},d("span",{text:e}),d("button",{class:"tb-chip-x",attrs:{type:"button","aria-label":t,title:t},on:{click:a}},S("close")))}textButton(e,t,a,r){let s=d("button",{class:"text-btn",attrs:{type:"button","data-focus-key":t}});return r&&s.append(S(r)),s.append(d("span",{text:e})),s.addEventListener("click",()=>a(s)),s}pager(e,t,a,r){let s=this.t,i=this.paginationMode,o=this.getDataset().rows.length,{pages:l}=a,c=b=>E(b,this.locale),h;l>1&&i!=="more"?h=s("rowsRange",{from:c(t?a.rowFrom+1:0),to:c(a.rowTo),total:c(t)}):i==="more"&&a.to<e?h=s("tableShowing",{shown:c(a.rowTo),total:c(t)}):h=s("tableRows",{count:c(t)}),t!==o&&(h+=` \xB7 ${s("tableFiltered",{total:c(o)})}`),this.selected.size&&!this.feature("bulk-bar")&&(h+=` \xB7 ${s("tableSelected",{count:c(this.selected.size)})}`);let f=b=>{this.page=Math.max(0,Math.min(l-1,b)),this.renderGrid(),i!=="more"&&this.scroller?.scrollTo({top:0}),this.root.querySelector(`.tb-pager.${r} [data-focus-key="${r}-page-${this.page}"], .tb-pager.${r} .tb-page-btn[aria-current]`)?.focus(),this.announce(s("tablePageAnnounce",{page:c(this.page+1),pages:c(l)}))},u=(b,y,m,A)=>{let T=w({icon:b,label:s(y),key:`${r}-${y}`,onClick:()=>f(m)});return T.disabled=A,T},p=d("div",{class:"toolbar tb-pages"});if(i==="more"){if(a.to<e){let b=Math.min(a.size,t-a.rowTo);p.append(this.textButton(s("tableShowMore",{count:c(b)}),`${r}-more`,()=>f(this.page+1)),this.textButton(s("tableShowAll"),`${r}-more-all`,()=>f(l-1)))}}else if(l>1&&i!=="none"){if(ae(p,[i==="pages"?u("chevrons-left","firstPage",0,this.page===0):null,u("chevron-left","previousPage",this.page-1,this.page===0)]),i==="pages")for(let b of pr(this.page,l)){if(b<0){p.append(d("span",{class:"tb-gap",text:"\u2026",attrs:{"aria-hidden":"true"}}));continue}let y=b===this.page;p.append(d("button",{class:`tb-page-btn${y?" current":""}`,text:c(b+1),attrs:{type:"button","aria-current":y?"page":null,"aria-label":s("tableGoToPage",{page:c(b+1)}),"data-focus-key":`${r}-page-${b}`},on:{click:()=>f(b)}}))}else p.append(d("span",{class:"tb-page",text:s("tablePage",{page:c(this.page+1),pages:c(l)})}));if(ae(p,[u("chevron-right","nextPage",this.page+1,this.page>=l-1),i==="pages"?u("chevrons-right","lastPage",l-1,this.page>=l-1):null]),i==="pages"&&l>7){let b=d("input",{class:"tb-jump",attrs:{type:"number",min:1,max:l,inputmode:"numeric","aria-label":s("tableJump"),placeholder:s("tableJumpShort"),"data-focus-key":`${r}-jump`}});b.addEventListener("keydown",y=>{if(y.key!=="Enter")return;let m=Number(b.value);Number.isFinite(m)&&m>=1&&f(Math.round(m)-1)}),p.append(b)}}let g=d("select",{class:"tb-size",attrs:{"aria-label":s("tablePageSize"),"data-focus-key":`${r}-page-size`}},...[...new Set([...Vt.filter(b=>b),this.pageSize,0])].sort((b,y)=>(b||1/0)-(y||1/0)).map(b=>d("option",{attrs:{value:b},text:b?c(b):s("tableAll")})));return g.value=String(this.pageSize),g.addEventListener("change",()=>{this.pageSizeState=Number(g.value),this.page=0,this.saveState(),this.render()}),d("div",{class:`pager tb-pager ${r}`,part:"pager",attrs:{role:"navigation","aria-label":s("tablePagination")}},d("span",{class:"pager-info",attrs:{"aria-live":r==="bottom"?"polite":null},text:h}),d("div",{class:"tb-pager-end"},j(this.getAttribute("page-sizes"))!==!1?d("label",{class:"tb-size-label"},d("span",{text:s("tablePerPage")}),g):null,p))}compileCondition(e,t){let{rows:a}=this.getDataset(),r=e.value.trim();if(!r)return null;let s;if(e.key===null){let o=r.toLowerCase(),l=t.filter(c=>!this.isHidden(c)).map(c=>this.textOf(c));s=c=>l.some(h=>h[c].includes(o))}else{let o=t.find(c=>c.key===e.key);if(!o)return null;let l=/^[=!]?[^<>=!.]*,/.test(r)&&!/\.\./.test(r)?r.replace(/^=/,"").split(","):null;if(l){let c=this.textOf(o),h=l.map(u=>u.trim().toLowerCase()).filter(Boolean),f=a.map(u=>v(u[o.key]).toLowerCase());s=u=>h.some(p=>c[u]===p||f[u]===p)}else{let c=Te(r,o.type);if(!c)return null;let h=r.startsWith("=")?r.slice(1).trim().toLowerCase():null,f=h!==null?this.textOf(o):null;s=u=>f&&f[u]===h||c(a[u][o.key])}}let i=s;return e.not?o=>!i(o):i}valuesOf(e){let t=this.valueCache.get(e.key);if(!t){let a=new Map,r=this.getDataset().rows,s=Math.max(1,Math.floor(r.length/2e4));for(let i=0;i<r.length;i+=s){let o=r[i][e.key],l=Array.isArray(o)?o.map(v):[this.displayText(e,r[i])];for(let c of l)c&&c.length<=80&&a.set(c,(a.get(c)??0)+1)}t=[...a].sort((i,o)=>o[1]-i[1]||i[0].localeCompare(o[0])).slice(0,500),this.valueCache.set(e.key,t)}return t}parseCondition(e){let t=e.trim();if(!t)return null;let a=!1;t.startsWith("-")&&t.includes(":")&&(a=!0,t=t.slice(1));let r=t.indexOf(":");if(r>0){let s=t.slice(0,r).trim().toLowerCase(),i=this.allColumns().find(l=>l.key.toLowerCase()===s||l.label.toLowerCase()===s),o=t.slice(r+1).trim();if(i&&o)return o.startsWith("!")&&!o.startsWith("!=")&&o!=="!empty"?{key:i.key,value:o.slice(1),not:!a}:{key:i.key,value:o,not:a}}return{key:null,value:t,not:!1}}conditionLabel(e){let t=this.t;if(e.key===null)return t("tableContains",{text:e.value});let r=this.allColumns().find(l=>l.key===e.key)?.label??e.key,s=e.value,i,o=/^(>=|<=|!=|>|<|=)\s*(.*)$/.exec(s);return/\.\./.test(s)?i=`${r} ${s.replace(/\s*\.\.\s*/," \u2013 ")}`:o?i=`${r} ${o[1]==="="?"=":o[1].replace(">=","\u2265").replace("<=","\u2264").replace("!=","\u2260")} ${o[2]}`:s.includes(",")?i=`${r} \u2208 ${s.split(",").map(l=>l.trim()).filter(Boolean).join(" | ")}`:s.toLowerCase()==="empty"?i=`${r} ${t("tableIsEmpty")}`:i=`${r} ~ ${s}`,e.not?`${t("tableNot")} ${i}`:i}setConditions(e){this.conditions=e,this.page=0,this.invalidateView(),this.focusQuery=!0,this.refreshRows(),this.filterChanged()}restoreQueryFocus(){this.focusQuery&&(this.focusQuery=!1,this.root.querySelector(".tb-query-input")?.focus())}queryBar(){if(!this.feature("query-bar"))return null;let e=this.t,t=d("div",{class:"tb-query",part:"query-bar"}),a=d("div",{class:"tb-query-field"});t.append(d("span",{class:"tb-query-icon",attrs:{"aria-hidden":"true"}},S("filter"))),this.conditions.forEach((g,b)=>{b&&a.append(d("button",{class:`tb-join ${this.matchAll?"and":"or"}`,text:e(this.matchAll?"tableAnd":"tableOr"),attrs:{type:"button",title:e("tableToggleJoin"),"data-focus-key":`join-${b}`},on:{click:()=>{this.matchAll=!this.matchAll,this.setConditions(this.conditions),this.restoreFocus(`join-${b}`)}}}));let y=d("span",{class:`tb-cond${g.not?" not":""}${g.key===null?" text":""}`},d("button",{class:"tb-cond-label",text:this.conditionLabel(g),attrs:{type:"button",title:e("tableEditCondition"),"data-focus-key":`cond-${b}`},on:{click:()=>{let m=this.conditions.filter((x,k)=>k!==b),A=this.allColumns().find(x=>x.key===g.key),T=g.key===null?g.value:`${g.not?"-":""}${A?.key??g.key}:${g.value}`;this.setConditions(m);let L=this.root.querySelector(".tb-query-input");L&&(L.value=T,L.focus(),L.dispatchEvent(new Event("input")))}}}),d("button",{class:"tb-chip-x",attrs:{type:"button","aria-label":e("tableRemoveCondition",{name:this.conditionLabel(g)})},on:{click:()=>this.setConditions(this.conditions.filter((m,A)=>A!==b))}},S("close")));a.append(y)});let r=`${this.tableId}-suggest`,s=d("input",{class:"tb-query-input",attrs:{type:"text",role:"combobox","aria-expanded":"false","aria-controls":r,"aria-autocomplete":"list","aria-label":e("tableQueryLabel"),placeholder:this.conditions.length?e("tableQueryMore"):e("tableQueryPlaceholder"),autocomplete:"off",spellcheck:"false",maxlength:300,"data-focus-key":"query-input"}}),i=d("ul",{class:"tb-suggest",attrs:{id:r,role:"listbox",hidden:!0}}),o=[],l=-1,c=()=>{i.hidden=!0,s.setAttribute("aria-expanded","false"),s.removeAttribute("aria-activedescendant"),l=-1},h=()=>{i.replaceChildren(...o.map((g,b)=>d("li",{class:`tb-option${b===l?" active":""}`,attrs:{id:`${r}-${b}`,role:"option","aria-selected":String(b===l)},on:{pointerdown:y=>{y.preventDefault(),g.apply()}}},d("span",{text:g.label}),g.hint?d("span",{class:"tb-option-hint",text:g.hint}):null))),i.hidden=!o.length,s.setAttribute("aria-expanded",String(o.length>0)),l>=0?s.setAttribute("aria-activedescendant",`${r}-${l}`):s.removeAttribute("aria-activedescendant")},f=g=>{let b=this.parseCondition(g);b&&(s.value="",c(),this.setConditions([...this.conditions,b]))},u=()=>{let g=s.value,b=g.trim(),y=b.startsWith("-")?"-":"",m=y?b.slice(1):b,A=m.indexOf(":"),T=this.allColumns().filter(x=>x.filterable),L=x=>E(x,this.locale);if(o=[],A>0){let x=m.slice(0,A).toLowerCase(),k=T.find(P=>P.key.toLowerCase()===x||P.label.toLowerCase()===x),D=m.slice(A+1);if(k){let P=D.replace(/^[=!~]/,"").toLowerCase();if(k.type==="number"||k.type==="date"){let F=k.type==="number"?"100":"2024-01-01";for(let G of[">","<",">=","<="])D&&!G.startsWith(D[0])||o.push({label:`${k.label} ${G} \u2026`,hint:e("tableOpHint"),apply:()=>p(`${y}${k.key}:${G}`)});D||o.push({label:`${k.label} ${F}..`,hint:e("tableRangeHint"),apply:()=>p(`${y}${k.key}:`)})}let Oe=this.valuesOf(k).filter(([F])=>!P||F.toLowerCase().includes(P)).slice(0,8);for(let[F,G]of Oe)o.push({label:`${k.label} = ${F}`,hint:L(G),apply:()=>f(`${y}${k.key}:=${F}`)});D&&!Oe.some(([F])=>F.toLowerCase()===P)&&o.unshift({label:this.conditionLabel({key:k.key,value:D,not:!!y}),hint:"\u21B5",apply:()=>f(g)})}}else if(m){o.push({label:e("tableContains",{text:m}),hint:"\u21B5",apply:()=>f(m)});let x=m.toLowerCase();for(let k of T)(k.label.toLowerCase().includes(x)||k.key.toLowerCase().includes(x))&&o.push({label:`${k.label}:`,hint:e("tableFilterColumn"),apply:()=>p(`${y}${k.key}:`)});for(let k of T){if(o.length>9)break;for(let[D,P]of this.valuesOf(k))if(D.toLowerCase().startsWith(x)){o.push({label:`${k.label} = ${D}`,hint:L(P),apply:()=>f(`${k.key}:=${D}`)});break}}}else for(let x of T.slice(0,10))o.push({label:`${x.label}:`,hint:e(`tableType_${x.type}`),apply:()=>p(`${x.key}:`)});o=o.slice(0,10),l=o.length&&m?0:-1,h()},p=g=>{s.value=g,s.focus(),u()};return s.addEventListener("input",u),s.addEventListener("focus",u),s.addEventListener("blur",()=>setTimeout(c,100)),s.addEventListener("keydown",g=>{if(g.key==="ArrowDown"||g.key==="ArrowUp"){if(!o.length)return;g.preventDefault(),l=(l+(g.key==="ArrowDown"?1:-1)+o.length)%o.length,h()}else g.key==="Enter"?(g.preventDefault(),l>=0&&o[l]?o[l].apply():f(s.value)):g.key==="Tab"&&l>=0&&!i.hidden&&s.value?(g.preventDefault(),o[l].apply()):g.key==="Escape"?i.hidden?s.value&&(g.stopPropagation(),s.value=""):(g.stopPropagation(),c()):g.key==="Backspace"&&!s.value&&this.conditions.length&&(g.preventDefault(),this.setConditions(this.conditions.slice(0,-1)))}),a.append(d("span",{class:"tb-query-box"},s,i)),t.append(a),this.conditions.length>1&&t.append(d("button",{class:"tb-match",attrs:{type:"button","data-focus-key":"match-mode",title:e("tableToggleJoin")},on:{click:()=>{this.matchAll=!this.matchAll,this.setConditions(this.conditions),this.restoreFocus("match-mode")}}},d("span",{text:e(this.matchAll?"tableMatchAll":"tableMatchAny")}))),this.conditions.length&&t.append(w({icon:"close",label:e("tableClearConditions"),key:"clear-conditions",onClick:()=>this.setConditions([])})),t}pageKeys(){let{items:e}=this.view(),{from:t,to:a}=this.virtual?{from:0,to:e.length}:this.pageWindow(e.length),r=[];for(let s=t;s<a;s+=1){let i=e[s];if(i.kind==="row")r.push(this.rowKey(i.index));else if(i.kind==="group"&&this.collapsed.has(i.value))for(let o of i.indexes)r.push(this.rowKey(o))}return r}selectMenu(e){let t=this.t;e.setAttribute("role","menu"),e.setAttribute("aria-label",t("tableSelectMenu")),e.classList.add("tb-select-menu");let a=l=>E(l,this.locale),{order:r}=this.view(),s=this.getDataset().rows.length,i=this.pageKeys(),o=(l,c,h,f=!1)=>{let u=d("button",{class:"tb-menu-item",attrs:{type:"button",role:"menuitem",disabled:f}},d("span",{text:l}),d("span",{class:"tb-option-hint",text:c}));return u.addEventListener("click",()=>{this.panel=null,h(),this.restoreFocus("select-all")}),u};e.append(o(t("tableSelectPage"),a(i.length),()=>this.select(i,{add:!0})),o(t("tableSelectMatching"),a(r.length),()=>this.selectAll())),r.length!==s&&e.append(o(t("tableSelectEverything"),a(s),()=>this.select(this.getDataset().rows.map((l,c)=>this.rowKey(c))))),e.append(d("hr"),o(t("tableInvertPage"),a(i.length),()=>{for(let l of i)this.selected.has(l)?this.selected.delete(l):this.selected.add(l);this.selectionChanged()}),o(t("tableUnselectPage"),"",()=>{for(let l of i)this.selected.delete(l);this.selectionChanged()},!i.some(l=>this.selected.has(l))),o(t("tableClearSelection"),a(this.selected.size),()=>this.clearSelection(),!this.selected.size)),e.querySelector("button:not([disabled])")?.setAttribute("data-autofocus","")}togglePanel(e){let t=typeof e=="string"?this.panel===e:typeof this.panel=="object"&&this.panel?.column===e.column;this.panel=t?null:e,this.renderGrid(),this.panel&&this.root.querySelector(".tb-popover [data-autofocus], .tb-popover button, .tb-popover input")?.focus()}closePanel(e=!0){let t=this.panel;if(!t||(this.panel=null,this.renderGrid(),!e))return;let a=typeof t=="string"?t==="select"?"select-menu":t:`menu-${t.column}`,r=this.root.querySelector(`[data-focus-key="${CSS.escape(a)}"]`);r?r.focus():typeof t=="object"&&this.focusHeader(t.column)}renderPanel(){let e=this.panel;if(!e)return null;let t=d("div",{class:"tb-popover",part:"menu",on:{keydown:a=>{let r=a;if(r.key==="Escape")r.stopPropagation(),this.closePanel();else if(r.key==="ArrowDown"||r.key==="ArrowUp"){if(r.altKey)return;let s=[...t.querySelectorAll('[role="menuitem"], [role="menuitemradio"], .tb-col-item input')],i=s.indexOf(this.root.activeElement);if(!s.length)return;r.preventDefault(),s[(i+(r.key==="ArrowDown"?1:-1)+s.length)%s.length].focus()}}}});return e==="help"?this.helpPanel(t):e==="columns"?this.columnsPanel(t):e==="select"?this.selectMenu(t):this.columnMenu(t,e.column),(typeof e=="object"||e==="select")&&queueMicrotask(()=>{let a=this.root.querySelector(typeof e=="object"?`th[data-key="${CSS.escape(e.column)}"]`:"th.tb-ctl-select"),r=this.host;if(!a||!r)return;let s=a.getBoundingClientRect(),i=r.getBoundingClientRect(),o=Math.max(4,Math.min(s.left-i.left,i.width-t.offsetWidth-4));t.style.left=`${o}px`,t.style.right="auto",t.style.top=`${s.bottom-i.top+2}px`}),t}columnMenu(e,t){let a=this.t,r=this.allColumns().find(u=>u.key===t);if(!r)return;e.setAttribute("role","menu"),e.setAttribute("aria-label",a("tableColumnMenu",{name:r.label}));let s=(u,p,g,b=!1)=>{let y=d("button",{class:"tb-menu-item",attrs:{type:"button",role:"menuitem",disabled:b}},S(p),d("span",{text:u}));return y.addEventListener("click",()=>{g()}),y},i=this.visibleColumns(),o=i.findIndex(u=>u.key===t),l=this.sortSpecs.find(u=>u.key===t);this.feature("sortable")&&r.sortable&&(e.append(s(a("tableSortAsc"),"sort-up",()=>this.menuDone(()=>this.setSort([{key:t,direction:"ascending"}]))),s(a("tableSortDesc"),"sort-down",()=>this.menuDone(()=>this.setSort([{key:t,direction:"descending"}])))),l&&e.append(s(a("tableClearSort"),"sort",()=>this.menuDone(()=>this.setSort(this.sortSpecs.filter(u=>u.key!==t))))),e.append(d("hr"))),r.filterable&&e.append(s(a("tableFilter"),"filter",()=>{this.filtersOpen=!0,this.panel=null,this.render(),this.root.querySelector(`[data-focus-key="filter-${CSS.escape(t)}"]`)?.focus()})),e.append(this.groupKey===t?s(a("tableUngroup"),"list",()=>this.menuDone(()=>this.setGroup(null))):s(a("tableGroupBy"),"list",()=>this.menuDone(()=>this.setGroup(t))),d("hr"),s(a("tableMoveLeft"),"chevron-left",()=>this.menuDone(()=>this.moveColumn(t,-1)),o<=0),s(a("tableMoveRight"),"chevron-right",()=>this.menuDone(()=>this.moveColumn(t,1)),o>=i.length-1),s(this.pinned>o?a("tableUnpin"):a("tablePin"),"lock",()=>this.menuDone(()=>this.setPinned(this.pinned>o?o:o+1))),s(a("tableAutoFit"),"columns",()=>this.menuDone(()=>this.autoFit(t))),s(a("tableHideColumn"),"eye-off",()=>this.menuDone(()=>this.setHidden(t,!0)),i.length<=1));let c=r.type==="number"||r.type==="date"?he:["none","count"];e.append(d("hr"),d("div",{class:"tb-menu-title",text:a("tableFooter")}));let h=r.aggregate;for(let u of c){if(r.type==="date"&&(u==="sum"||u==="avg"))continue;let p=d("button",{class:"tb-menu-item",attrs:{type:"button",role:"menuitemradio","aria-checked":String(h===u)}},S(h===u?"check":"status-circle"),d("span",{text:a(`tableAggName_${u}`)}));p.addEventListener("click",()=>this.menuDone(()=>{this.aggregates.set(t,u),this.columnsChanged()})),e.append(p)}e.querySelector("button:not([disabled])")?.setAttribute("data-autofocus","")}menuDone(e){let t=this.panel;this.panel=null,e(),this.renderGrid(),typeof t=="object"&&t&&this.focusHeader(t.column)}columnsPanel(e){let t=this.t;e.classList.add("tb-columns"),e.setAttribute("role","dialog"),e.setAttribute("aria-label",t("tableColumns")),e.append(d("div",{class:"tb-menu-title",text:t("tableColumns")}));let a=d("ul",{class:"tb-col-list"}),r=this.allColumns(),s=r.filter(i=>!this.isHidden(i)).length;r.forEach((i,o)=>{let l=!this.isHidden(i),c=d("input",{attrs:{type:"checkbox","data-focus-key":`col-${i.key}`,"aria-keyshortcuts":"Alt+ArrowUp Alt+ArrowDown"},on:{change:()=>this.setHidden(i.key,!c.checked,!0),keydown:f=>{let u=f;u.altKey&&(u.key==="ArrowUp"||u.key==="ArrowDown")&&(u.preventDefault(),this.moveColumn(i.key,u.key==="ArrowUp"?-1:1,!0))}}});c.checked=l,c.disabled=l&&s<=1;let h=(f,u,p,g)=>{let b=w({icon:u,label:p,key:`col-${i.key}-${f}`,onClick:()=>this.moveColumn(i.key,f,!0)});return b.disabled=g,b};a.append(d("li",{class:"tb-col-item"},d("label",{},c,d("span",{text:i.label})),h(-1,"chevron-up",t("tableMoveUp",{name:i.label}),o===0),h(1,"chevron-down",t("tableMoveDown",{name:i.label}),o===r.length-1)))}),e.append(a,d("div",{class:"tb-col-actions"},this.textButton(t("tableShowAll"),"show-all",()=>{this.hiddenKeys.clear();for(let i of r)this.shown.add(i.key);this.columnsChanged()}),this.textButton(t("tableResetLayout"),"reset-layout",()=>this.resetLayout())))}helpPanel(e){let t=this.t;e.classList.add("tb-help"),e.setAttribute("role","dialog"),e.setAttribute("aria-label",t("tableShortcuts"));let a=/Mac|iP(?:hone|ad)/.test(globalThis.navigator?.platform??"")?"\u2318":"Ctrl",r=[["\u2191 \u2193 \u2190 \u2192",t("tableKeyMove")],["Home / End",t("tableKeyRowEnds")],[`${a}+Home / End`,t("tableKeyTableEnds")],["PageUp / PageDown",t("tableKeyPage")],["Space",t("tableKeySelect")],["Shift+\u2191 \u2193",t("tableKeyRange")],[`${a}+A`,t("tableKeySelectAll")],["Esc",t("tableKeyClear")],["Enter",t("tableKeyEnter")],["F2",t("tableKeyEdit")],["+ / \u2212",t("tableKeyExpand")],[`${a}+C`,t("tableKeyCopy")],["Shift+Enter",t("tableKeyMultiSort")],["Alt+\u2190 \u2192",t("tableKeyMoveColumn")],["Alt+Shift+\u2190 \u2192",t("tableKeyResize")],["/",t("tableKeySearch")]];e.append(d("div",{class:"tb-menu-title",text:t("tableShortcuts")}));let s=d("dl",{class:"tb-keys"});for(let[o,l]of r)s.append(d("dt",{},d("kbd",{text:o})),d("dd",{text:l}));e.append(s,d("p",{class:"tb-hint",text:t("tableMouseHint")}));let i=w({icon:"close",label:t("searchClose"),key:"help-close",onClick:()=>this.closePanel()});i.classList.add("tb-popover-close"),i.setAttribute("data-autofocus",""),e.prepend(i)}setSort(e){this.sortState=e,this.page=0,this.invalidateView(),this.saveState(),this.renderGrid();let t=e[0],a=this.allColumns().find(r=>r.key===t?.key);this.announce(t?this.t("tableSortedAnnounce",{name:a?.label??t.key,direction:this.t(t.direction==="ascending"?"tableAscending":"tableDescending")}):this.t("tableUnsorted")),C(this,_.SORT,{column:t?.key??null,name:a?.label??null,direction:t?.direction??"none",sort:e.map(r=>({...r}))})}cycleSort(e,t){if(!this.allColumns().find(o=>o.key===e)?.sortable||!this.feature("sortable"))return;let r=this.sortSpecs,s=r.find(o=>o.key===e),i=s?s.direction==="ascending"?{key:e,direction:"descending"}:null:{key:e,direction:"ascending"};if(t){let o=r.filter(l=>l.key!==e);this.setSort(i?s?r.map(l=>l.key===e?i:l):[...o,i]:o)}else this.setSort(i?[i]:[]);this.focusHeader(e)}setFilter(e,t,a){this.filterValues.set(e,t),t||this.filterValues.delete(e),clearTimeout(this.filterTimer);let r=()=>{this.page=0,this.invalidateView();let s=this.activeFocusKey();a?this.renderGrid():this.refreshRows(),s&&this.restoreFocus(s),this.filterChanged()};a?r():this.filterTimer=setTimeout(r,140)}refreshRows(){if(!this.host||!this.table||this.cards){this.renderGrid();return}let{order:e,items:t}=this.view(),a=this.pageWindow(t.length);this.renderBody();let r=this.visibleColumns(),s=this.controlColumns(),i=this.renderFoot(r,s);this.table.tFoot&&this.table.tFoot.remove(),i&&this.table.append(i);let o=this.table.querySelector("thead .tb-check");o&&o.replaceWith(this.headerCheckbox(e));for(let u of this.host.querySelectorAll(":scope > .tb-bulk, :scope > .tb-state, :scope > .tb-pager, :scope > .tb-query"))u.remove();let l=this.bulkBar(e),c=this.stateBar(),h=this.queryBar(),f=this.getAttribute("pager-position");(f==="top"||f==="both")&&this.scroller?.before(this.pager(t.length,e.length,a,"top")),c&&this.host.prepend(c),l&&this.host.prepend(l),h&&this.host.prepend(h),f!=="top"&&this.scroller?.after(this.pager(t.length,e.length,a,"bottom")),this.restoreQueryFocus()}filterChanged(){let{order:e}=this.view();C(this,_.FILTER_CHANGE,{filters:Object.fromEntries(this.filterValues),query:this.query,shown:e.length})}clearQuery(){this.filterValues.clear(),this.groupState=null,this.sortState=[],this.page=0,this.invalidateView(),this.saveState(),this.renderGrid(),this.filterChanged()}setGroup(e){this.groupState=e,this.collapsed.clear(),this.page=0,this.invalidateView(),this.saveState(),this.render()}setHidden(e,t,a=!1){t?(this.hiddenKeys.add(e),this.shown.delete(e)):(this.hiddenKeys.delete(e),this.shown.add(e)),a||(this.panel=null),this.columnsChanged(),a&&this.restoreFocus(`col-${e}`)}moveColumn(e,t,a=!1){let r=this.allColumns().map(c=>c.key),s=this.visibleColumns().map(c=>c.key),i=r.indexOf(e),o;if(a)o=i+t;else{let c=s.indexOf(e)+t;if(c<0||c>=s.length)return;o=r.indexOf(s[c])}if(i<0||o<0||o>=r.length)return;r.splice(i,1),r.splice(o,0,e),this.order=r,this.columnsChanged(),a?this.restoreFocus(`col-${e}`):this.focusHeader(e);let l=this.allColumns().find(c=>c.key===e);this.announce(this.t("tableMoved",{name:l?.label??e,position:this.visibleColumns().findIndex(c=>c.key===e)+1}))}setPinned(e){this.pinnedState=e,this.columnsChanged()}setWidth(e,t,a=!0){let r=$e(t);this.widths.set(e,r);let s=this.table?.querySelector(`col[data-key="${CSS.escape(e)}"]`);if(s&&(s.style.width=`${r}px`),this.table){let i=0;for(let o of this.table.querySelectorAll("col"))i+=parseFloat(o.style.width)||0;this.table.style.width=`max(100%, ${i}px)`}a&&(this.pinned?this.columnsChanged():(this.saveState(),C(this,_.COLUMN_CHANGE,{columns:this.state.columns})))}autoFit(e){this.widths.delete(e);let t=this.allColumns().find(a=>a.key===e);t&&this.setWidth(e,this.widthOf({...t,width:void 0}))}cycleDensity(){let e=Y[(Y.indexOf(this.density)+1)%Y.length];this.densityState=e,this.saveState(),this.render(),this.announce(this.t("tableDensity",{density:this.t(`tableDensity_${e}`)}))}toggleGroup(e){let t=this.collapsed.has(e);t?this.collapsed.delete(e):this.collapsed.add(e),this.invalidateView(),this.renderGrid(),C(this,_.TOGGLE,{group:e,expanded:t})}toggleDetail(e){let t=!this.expanded.has(e);t?this.expanded.add(e):this.expanded.delete(e),this.invalidateView(),this.renderGrid(),C(this,_.TOGGLE,{key:this.rowKey(e),expanded:t})}toggleRow(e){let t=this.view().items[e];if(!t||t.kind!=="row"||this.selectionMode==="none")return;let a=this.rowKey(t.index);this.selected.has(a)?this.selected.delete(a):(this.selectionMode==="single"&&this.selected.clear(),this.selected.add(a)),this.anchor=e,this.selectionChanged()}selectRange(e,t){if(this.selectionMode!=="multiple"){this.toggleRow(t);return}let{items:a}=this.view();for(let r=Math.min(e,t);r<=Math.max(e,t);r+=1){let s=a[r];s?.kind==="row"&&this.selected.add(this.rowKey(s.index))}this.selectionChanged()}search(e){return this.query=e,this.page=0,this.invalidateView(),this.refreshRows(),this.filterChanged(),{total:e?this.view().order.length:0,capped:!1}}goToResult(e){let{items:t,order:a}=this.view(),r=a[e],s=t.findIndex(i=>i.kind==="row"&&i.index===r);s>=0&&this.revealItem(s,()=>{let i=this.root.querySelector(`tr[data-r="${s}"]`);for(let o of this.root.querySelectorAll("tr.current"))o.classList.remove("current");i?.classList.add("current"),i?.scrollIntoView({block:"nearest"})})}highlight(e){for(let t of e.querySelectorAll(".tb-text, .tb-link"))new ie(t).run(this.query)}canEdit(e){return!this.feature("editable")||e.render?!1:this.getDataset().columns.some(a=>a.editable)?e.editable:!0}editor(e,t,a,r){let s=t[e.key],i=d("input",{class:"tb-edit",attrs:{type:(e.type==="number","text"),inputmode:e.type==="number"?"decimal":null,"aria-label":this.t("tableEditCell",{name:e.label}),"data-focus-key":"cell-editor"}});i.value=s instanceof Date?s.toISOString():v(s);let o=!1,l=(c,h=0)=>{if(!o){if(o=!0,this.editingCell=null,c&&this.commitEdit(e,t,i.value),this.renderBody(),h){let f=this.nextEditable(a,r,h);if(f){this.startEdit(f.r,f.c);return}}this.focusCell(a,r)}};return i.addEventListener("keydown",c=>{c.stopPropagation(),c.key==="Enter"?(c.preventDefault(),l(!0)):c.key==="Escape"?(c.preventDefault(),l(!1)):c.key==="Tab"&&(c.preventDefault(),l(!0,c.shiftKey?-1:1))}),i.addEventListener("blur",()=>l(!0)),queueMicrotask(()=>{i.focus(),i.select()}),i}nextEditable(e,t,a){let r=this.visibleColumns(),{items:s}=this.view(),i=e,o=t+a;for(let l=0;l<1e4;l+=1){if(o>=r.length?(o=0,i+=1):o<0&&(o=r.length-1,i-=1),i<0||i>=s.length)return null;if(s[i].kind==="row"&&this.canEdit(r[o]))return{r:i,c:o};o+=a}return null}startEdit(e,t){let a=this.view().items[e],r=this.visibleColumns()[t];return!a||a.kind!=="row"||!r||!this.canEdit(r)?!1:(this.revealItem(e,()=>{this.editingCell={r:e,c:t},this.focusPos={r:e,c:t},this.renderBody()}),!0)}commitEdit(e,t,a){let r=t[e.key];if(v(r)===a)return;let s=It(a,e,r),i=this.getDataset().rows.indexOf(t);if(C(this,_.CELL_EDIT,{key:this.rowKey(i),column:e.key,value:s,previous:r,row:t})&&(t[e.key]=s,this.keyCache.delete(e.key),this.textCache.delete(e.key),this.invalidateView(),this.table?.tFoot)){let l=this.renderFoot(this.visibleColumns(),this.controlColumns());this.table.tFoot.remove(),l&&this.table.append(l)}}firstRowItem(){let{items:e}=this.view(),{from:t}=this.pageWindow(e.length);return e.length?Math.min(t,e.length-1):-1}revealItem(e,t){if(e<0){t();return}let a=this.effectivePageSize;if(Number.isFinite(a)){let r=Math.floor(Math.max(0,this.view().base.findIndex(i=>i>=e))/a),s=this.paginationMode==="more"?Math.max(r,this.page):r;s!==this.page&&(this.page=s,this.renderGrid())}else if(this.virtual&&this.scroller&&this.windowRange){let[r,s]=this.windowRange;if(e<r+1||e>=s-1){let i=De[this.density],{items:o}=this.view(),l=0;for(let u=0;u<e;u+=1)l+=Qt(o[u],i,this.detailHeights);let c=this.table?.tHead?.offsetHeight??0,h=this.scroller.clientHeight,f=this.scroller.scrollTop;l<f?this.scroller.scrollTop=l:l+i+c>f+h&&(this.scroller.scrollTop=l+i+c-h),this.renderBody()}}t()}focusCell(e,t,a=!0){let{items:r}=this.view(),s=this.visibleColumns();if(!s.length)return;let i=Math.max(-1,Math.min(r.length-1,e)),o=Math.max(0,Math.min(s.length-1,t));this.focusPos={r:i,c:o};let l=()=>{this.syncTabStop();let c=this.cellAt(i,o);c?.focus({preventScroll:!a}),a&&c?.scrollIntoView({block:"nearest",inline:"nearest"})};a?this.revealItem(i,l):l()}cellAt(e,t){return this.table?e===-1?this.table.querySelector(`th[data-r="-1"][data-c="${t}"]`):this.table.querySelector(`td[data-r="${e}"][data-c="${t}"]`)??this.table.querySelector(`td[data-r="${e}"][data-c="0"]`):null}syncTabStop(){if(!this.table)return;for(let r of this.table.querySelectorAll('[data-c][tabindex="0"]'))r.setAttribute("tabindex","-1");let{r:e,c:t}=this.focusPos;(this.cellAt(e,t)??this.cellAt(-1,0))?.setAttribute("tabindex","0")}focusHeader(e){let t=this.visibleColumns().findIndex(a=>a.key===e);t>=0&&this.focusCell(-1,t)}onGridFocus(e){let t=e.target.closest?.("[data-c]");if(!t)return;let a=Number(t.getAttribute("data-r")),r=Number(t.getAttribute("data-c"));(a!==this.focusPos.r||r!==this.focusPos.c)&&(this.focusPos={r:a,c:r},this.syncTabStop())}onGridClick(e){let t=e.target;if(t.closest("input, select, a, .tb-resizer"))return;let a=t.closest('th[data-r="-1"]');if(a){if(this.resizing)return;this.cycleSort(a.getAttribute("data-key"),e.shiftKey);return}let r=t.closest("tr.tb-group");if(r){this.toggleGroup(r.getAttribute("data-group")),this.focusCell(Number(r.getAttribute("data-r")),0,!1);return}let s=t.closest("td[data-c]");if(!s)return;let i=Number(s.getAttribute("data-r")),o=Number(s.getAttribute("data-c"));this.focusPos={r:i,c:o},this.selectionMode!=="none"&&(e.shiftKey&&this.anchor!==null?(e.preventDefault(),this.selectRange(this.anchor,i)):e.ctrlKey||e.metaKey||this.feature("select-on-click")?this.toggleRow(i):this.anchor=i),this.syncTabStop()}onGridDoubleClick(e){let t=e.target.closest("td[data-c]");if(!t||e.target.closest("input"))return;let a=Number(t.getAttribute("data-r")),r=Number(t.getAttribute("data-c"));this.startEdit(a,r)||this.activate(a)}activate(e){let t=this.view().items[e];t?.kind==="row"&&C(this,_.ROW_ACTIVATE,{key:this.rowKey(t.index),row:this.getDataset().rows[t.index]})}onGridKey(e){let t=e.target;if(t.matches("input, select, textarea"))return;let a=t.closest("[data-c]");if(!a)return;let{items:r}=this.view(),s=this.visibleColumns(),i=Number(a.getAttribute("data-r")),o=Number(a.getAttribute("data-c")),l=e.ctrlKey||e.metaKey,c=i>=0?r[i]:null,h=Math.max(5,Math.floor((this.scroller?.clientHeight??400)/De[this.density])-1),f=()=>{e.preventDefault(),e.stopPropagation()},u=(b,y)=>{let m=b+y;for(;m>=0&&m<r.length&&r[m].kind==="detail";)m+=y>0?1:-1;return m<-1&&(m=-1),m>=r.length&&(m=b),m},p=e.key;if(i===-1){let b=s[o];if(e.altKey&&(p==="ArrowLeft"||p==="ArrowRight")){f(),e.shiftKey?this.feature("resizable")&&this.setWidth(b.key,this.widthOf(b)+(p==="ArrowLeft"?-16:16)):this.feature("reorderable")&&this.moveColumn(b.key,p==="ArrowLeft"?-1:1);return}if(p==="Enter"||p===" "){f(),this.cycleSort(b.key,e.shiftKey);return}if(p==="ArrowDown"&&e.altKey||p==="ContextMenu"){f(),this.feature("column-menu")&&this.togglePanel({column:b.key});return}}switch(p){case"ArrowRight":f(),c?.kind==="group"&&this.collapsed.has(c.value)&&this.toggleGroup(c.value),this.focusCell(i,o+1);return;case"ArrowLeft":f(),c?.kind==="group"&&!this.collapsed.has(c.value)&&this.toggleGroup(c.value),this.focusCell(i,o-1);return;case"ArrowDown":{f();let b=u(i,1);e.shiftKey&&c&&this.selectionMode==="multiple"&&(this.anchor===null&&(this.anchor=i),this.focusPos={r:b,c:o},this.selectRange(this.anchor,b)),this.focusCell(b,o);return}case"ArrowUp":{f();let b=u(i,-1);e.shiftKey&&c&&b>=0&&this.selectionMode==="multiple"&&(this.anchor===null&&(this.anchor=i),this.focusPos={r:b,c:o},this.selectRange(this.anchor,b)),this.focusCell(b,o);return}case"Home":f(),this.focusCell(l?u(-1,1):i,0);return;case"End":f(),this.focusCell(l?r.length-1:i,s.length-1);return;case"PageDown":f(),this.focusCell(Math.min(r.length-1,Math.max(0,i)+h),o);return;case"PageUp":f(),this.focusCell(Math.max(0,i-h),o);return;default:}if(!c){p==="/"&&this.feature("search")?(f(),this.openSearch()):p==="?"&&(f(),this.togglePanel("help"));return}if(c.kind==="group"){(p==="Enter"||p===" "||p==="+"||p==="-")&&(f(),(p==="+"?this.collapsed.has(c.value):p!=="-"||!this.collapsed.has(c.value))&&this.toggleGroup(c.value),this.focusCell(i,0,!1));return}let g=c.index;if(p===" ")f(),e.shiftKey&&this.anchor!==null?this.selectRange(this.anchor,i):this.toggleRow(i),this.focusCell(i,o,!1);else if(p==="Enter")f(),this.startEdit(i,o)||(this.feature("expandable")?(this.toggleDetail(g),this.focusCell(i,o,!1)):this.activate(i));else if(p==="F2")f(),this.startEdit(i,o);else if(p==="+"||p==="-"){if(!this.feature("expandable"))return;f(),this.expanded.has(g)!==(p==="+")&&this.toggleDetail(g),this.focusCell(i,o,!1)}else if(l&&p.toLowerCase()==="a"){if(this.selectionMode!=="multiple")return;f(),this.selectAll(),this.focusCell(i,o,!1)}else if(l&&p.toLowerCase()==="c"){f();let b=this.selected.size?this.exportData("tsv",{selected:!0}):this.displayText(s[o],this.getDataset().rows[g]);B(b,this.root).then(y=>{this.announce(this.t(y?"copied":"copyFailed")),y&&C(this,_.COPY,{text:b})})}else if(p==="Escape"){if(!this.selected.size)return;f(),this.clearSelection(),this.focusCell(i,o,!1)}else p==="/"&&this.feature("search")?(f(),this.openSearch()):p==="?"&&(f(),this.togglePanel("help"))}openSearch(){this.searchOpen||(this.searchOpen=!0,this.render()),this.searchBar?.focus()}resizer(e){let t=d("span",{class:"tb-resizer",attrs:{"aria-hidden":"true",title:this.t("tableResize")}});return t.addEventListener("click",a=>a.stopPropagation()),t.addEventListener("dblclick",a=>{a.stopPropagation(),this.autoFit(e.key)}),t.addEventListener("pointerdown",a=>{a.preventDefault(),a.stopPropagation();let r=t.parentElement,s=a.clientX,i=r.getBoundingClientRect().width,o=getComputedStyle(this).direction==="rtl";this.resizing=!0,t.setPointerCapture?.(a.pointerId),t.classList.add("active");let l=h=>this.setWidth(e.key,i+(o?s-h.clientX:h.clientX-s),!1),c=()=>{t.removeEventListener("pointermove",l),t.removeEventListener("pointerup",c),t.removeEventListener("pointercancel",c),t.classList.remove("active"),this.setWidth(e.key,this.widths.get(e.key)??i),setTimeout(()=>this.resizing=!1,0)};t.addEventListener("pointermove",l),t.addEventListener("pointerup",c),t.addEventListener("pointercancel",c)}),t}makeDraggable(e,t){e.addEventListener("dragstart",a=>{if(this.resizing){a.preventDefault();return}this.dragKey=t,a.dataTransfer?.setData("text/plain",t),a.dataTransfer&&(a.dataTransfer.effectAllowed="move"),e.classList.add("dragging")}),e.addEventListener("dragend",()=>{this.dragKey=null,e.classList.remove("dragging");for(let a of this.root.querySelectorAll(".drop-before, .drop-after"))a.classList.remove("drop-before","drop-after")}),e.addEventListener("dragover",a=>{if(!this.dragKey||this.dragKey===t)return;a.preventDefault();let r=e.getBoundingClientRect(),s=a.clientX>r.left+r.width/2;e.classList.toggle("drop-after",s),e.classList.toggle("drop-before",!s)}),e.addEventListener("dragleave",()=>e.classList.remove("drop-before","drop-after")),e.addEventListener("drop",a=>{a.preventDefault();let r=this.dragKey;if(!r||r===t)return;let s=e.classList.contains("drop-after"),i=this.allColumns().map(o=>o.key).filter(o=>o!==r);i.splice(i.indexOf(t)+(s?1:0),0,r),this.order=i,this.dragKey=null,this.columnsChanged(),this.focusHeader(r)})}};function Qt(n,e,t){return n.kind==="detail"?t.get(n.index)??160:e}function Jt(n){return/^id$|[_-]id$|[a-z]Id$/i.test(n)&&!/[a-z]id$/.test(n.slice(-3))}function pe(n,e,t){return n.style[e]=`${t}px`,n}function pr(n,e){if(e<=7)return Array.from({length:e},(s,i)=>i);let t=new Set([0,e-1,n,n-1,n+1]);n<=3&&[1,2,3,4].forEach(s=>t.add(s)),n>=e-4&&[e-5,e-4,e-3,e-2].forEach(s=>t.add(s));let a=[...t].filter(s=>s>=0&&s<e).sort((s,i)=>s-i),r=[];return a.forEach((s,i)=>{i&&s-a[i-1]>1&&r.push(s-a[i-1]===2?s-1:-1),r.push(s)}),r}function $e(n){return Math.round(Math.max(dr,Math.min(hr,n)))}function Yt(n){ut(new URL("languages/",n).href),_e(new URL("syntax-themes/",n).href),pt(new URL("vendor/",n).href)}Yt(new URL("../",import.meta.url));customElements.get("vt-table")||customElements.define("vt-table",fe);export{ka as BUILT_IN_THEMES,_ as EVENTS,fe as VtTable,ia as configure,R as getConfig,ke as getTheme,Ea as listSyntaxThemes,Ca as listThemes,Zt as registerLocale,Sa as registerTheme};
