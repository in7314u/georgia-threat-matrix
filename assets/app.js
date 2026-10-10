(function () {
  "use strict";

  var D = window.GTM;
  var G = window.GTM_GLOBE;
  var KA = window.GTM_KA || { ui: {}, sectors: {}, actors: {}, timeline: {}, reports: {} };
  var app = document.getElementById("app");
  var actorById = {};
  var reportById = {};
  D.actors.forEach(function (a) { actorById[a.id] = a; });
  D.reports.forEach(function (r) { reportById[r.id] = r; });
  var timeline = D.timeline.slice().sort(function (a, b) { return a.sort < b.sort ? -1 : 1; });
  var firstYear = +timeline[0].sort.slice(0, 4);
  var lastYear = +timeline[timeline.length - 1].sort.slice(0, 4);

  /* ---------- language ---------- */

  var lang = "en";
  try { if (localStorage.getItem("gtm-lang") === "ka") lang = "ka"; } catch (e) { /* storage unavailable */ }

  // Interface text: the English string is the key.
  function t(s, vars) {
    var out = (lang === "ka" && KA.ui[s] != null) ? KA.ui[s] : s;
    if (vars) Object.keys(vars).forEach(function (k) { out = out.replace("{" + k + "}", vars[k]); });
    return out;
  }
  // Content from data.js, with a Georgian override where one exists.
  function loc(kind, id, field, fallback) {
    var o = lang === "ka" && KA[kind] && KA[kind][id];
    return (o && o[field] != null) ? o[field] : fallback;
  }
  function count(n, word) {
    return lang === "ka" ? n + " " + t(word) : n + " " + word + (n === 1 ? "" : "s");
  }
  function ev(e, field) { return loc("timeline", e.sort, field, e[field]); }
  function findingsOf(r) { return loc("reports", r.id, "findings", r.findings); }
  function isTranslated(r) { return lang === "ka" && KA.reports[r.id]; }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function highlight(text, q) {
    var safe = esc(text);
    if (!q) return safe;
    var re = new RegExp("(" + esc(q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "gi");
    return safe.replace(re, "<mark>$1</mark>");
  }
  function reportsFor(id) {
    return D.reports.filter(function (r) { return r.actors.indexOf(id) !== -1; });
  }
  function eventsFor(id) {
    return timeline.filter(function (e) { return e.actors.indexOf(id) !== -1; });
  }
  function actorPills(ids) {
    return ids.map(function (id) {
      return '<a class="pill" href="#/actor/' + id + '">' + esc(actorById[id].name) + "</a>";
    }).join("");
  }
  function mitreLink(a) {
    return '<a href="https://attack.mitre.org/groups/' + a.mitre + '/" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK ' + a.mitre + "</a>";
  }

  /* ---------- actor emblems ---------- */

  // Line drawings on a 64x64 grid, one per actor, each with a single red mark.
  // An actor without an entry here gets its initials instead.
  function red(x, y) { return '<circle cx="' + x + '" cy="' + y + '" r="3" fill="var(--red)" stroke="none"/>'; }
  var EMBLEMS = {
    // The Dukes: a crown
    "apt29": '<path d="M12 44 16 22 26 34 32 18 38 34 48 22 52 44Z"/><path d="M14 51H50"/>' + red(32, 12),
    // Pawn Storm: a chess pawn
    "apt28": '<circle cx="32" cy="19" r="7"/><path d="M24 31H40M27 31C27 39 24 43 21 48H43C40 43 37 39 37 31M17 54H47"/>' + red(32, 19),
    // Sandworm: a worm moving through dunes
    "sandworm": '<path d="M8 38C14 26 20 26 26 38S38 50 44 38 50 26 54 28"/><path d="M8 52H56" stroke-dasharray="1 6"/>' + red(55, 28),
    // MuddyWater: a drop over water
    "muddywater": '<path d="M32 9C24 21 18 27 18 35A14 14 0 0 0 46 35C46 27 40 21 32 9Z"/><path d="M11 55q5-4 10 0t10 0 10 0 10 0"/>' + red(32, 36),
    // Saint Bear: a bear's head under a halo
    "uac-0056": '<ellipse cx="32" cy="12" rx="12" ry="4"/><circle cx="32" cy="39" r="14"/><circle cx="20" cy="27" r="5"/><circle cx="44" cy="27" r="5"/>' + red(32, 42),
    // Lorec53: the lure document
    "lorec53": '<path d="M19 9H38L47 18V55H19Z"/><path d="M38 9V18H47M26 29H40M26 36H40M26 43H33"/>' + red(40, 46),
    // Georbot: a bot
    "georbot": '<rect x="15" y="23" width="34" height="27" rx="6"/><path d="M32 23V14M25 42H39"/><circle cx="25" cy="34" r="3"/><circle cx="39" cy="34" r="3"/>' + red(32, 11),
    // Winter Vivern: a snowflake
    "winter-vivern": '<path d="M32 9V55M12 20.5 52 43.5M12 43.5 52 20.5M27 14 32 19 37 14M27 50 32 45 37 50"/>' + red(32, 32),
    // Curly COMrades: curly braces
    "curly-comrades": '<path d="M26 11C20 11 20 15 20 21 20 27 18 32 13 32 18 32 20 37 20 43 20 49 20 53 26 53M38 11C44 11 44 15 44 21 44 27 46 32 51 32 46 32 44 37 44 43 44 49 44 53 38 53"/>' + red(32, 32)
  };
  function portrait(a, large) {
    var art = EMBLEMS[a.id]
      ? '<svg viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + EMBLEMS[a.id] + "</svg>"
      : '<span class="portrait-initials" aria-hidden="true">' + esc(a.name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase()) + "</span>";
    return '<div class="portrait' + (large ? " lg" : "") + '">' + art +
      (large ? '<span class="portrait-id">' + (a.mitre ? esc(a.mitre) : esc(t("No MITRE ID"))) + "</span>" : "") + "</div>";
  }

  /* ---------- shared fragments ---------- */

  function reportHtml(r, q, open) {
    var links = r.links.map(function (l) {
      return '<li><a href="' + esc(l.url) + '" target="_blank" rel="noopener noreferrer">' + esc(l.label) + "</a>" +
        (l.archived ? ' <span class="pill quiet" title="' + esc(t("A copy of this document is kept in the repository")) + '">' + esc(t("archived")) + "</span>" : "") + "</li>";
    }).join("");
    var list = findingsOf(r);
    var findings = "";
    if (list.length) {
      findings = "<details" + (open ? " open" : "") + "><summary>" + count(list.length, "finding") + " " + esc(t("on Georgia")) + "</summary>" +
        (lang === "ka" && !isTranslated(r) ? '<p class="label quote-note">' + esc(t("Quotations are shown in the original language.")) + "</p>" : "") +
        '<ul class="findings">' + list.map(function (f) { return "<li>" + highlight(f, q) + "</li>"; }).join("") + "</ul></details>";
    }
    return '<article class="report" id="r-' + r.id + '">' +
      '<h3><a href="' + esc(r.links[0].url) + '" target="_blank" rel="noopener noreferrer">' + highlight(r.title, q) + "</a></h3>" +
      '<div class="report-meta"><span class="label">' + highlight(r.publisher, q) + (r.year ? " · " + r.year : "") + "</span>" + actorPills(r.actors) +
      (r.general ? '<span class="pill quiet">' + esc(t("background")) + "</span>" : "") +
      (r.paraphrased ? '<span class="pill quiet" title="' + esc(t("Findings are summaries written for this site, not quotations")) + '">' + esc(t("summary")) + "</span>" : "") + "</div>" +
      '<ul class="links">' + links + "</ul>" + findings + "</article>";
  }

  function timelineHtml(events) {
    if (!events.length) return '<p class="empty">' + esc(t("No dated events recorded for this selection.")) + "</p>";
    return '<ol class="timeline">' + events.map(function (e) {
      var r = reportById[e.report];
      return "<li><time>" + esc(ev(e, "when")) + '</time><div><h3><a href="#/sources/' + r.id + '">' + esc(ev(e, "title")) + "</a></h3><p>" + esc(ev(e, "text")) + "</p>" +
        '<div class="row">' + actorPills(e.actors) +
        '<a class="src" href="#/sources/' + r.id + '">' + esc(t("Source:")) + " " + esc(r.publisher) + "</a></div></div></li>";
    }).join("") + "</ol>";
  }

  // One card per actor: emblem, name, origin, MITRE description, and where to read more.
  function actorCard(a, cls) {
    var events = eventsFor(a.id);
    var desc = loc("actors", a.id, "mitreDesc", a.mitreDesc) || loc("actors", a.id, "summary", a.summary);
    return '<a class="card ' + (cls || "") + '" href="#/actor/' + a.id + '">' +
      '<div class="card-top">' + portrait(a) + "<div><h3>" + esc(a.name) + '</h3><p class="label">' +
      (a.mitre ? "MITRE ATT&amp;CK " + a.mitre : esc(t("Not in MITRE ATT&CK"))) + "</p></div></div>" +
      '<div><span class="pill quiet">' + esc(t(a.origin)) + "</span></div>" +
      "<p>" + esc(desc) + "</p>" +
      '<div class="meta label"><span>' + count(reportsFor(a.id).length, "source") + "</span>" +
      (events.length ? "<span>" + esc(t("First seen")) + " " + events[0].sort.slice(0, 4) + "</span>" : "") +
      '<span class="go">' + esc(t("View profile →")) + "</span></div></a>";
  }

  function matrixHtml() {
    var head = D.sectors.map(function (s) {
      return '<th scope="col">' + esc(lang === "ka" && KA.sectors[s.id] || s.name) + "</th>";
    }).join("");
    var rows = D.actors.map(function (a) {
      var cells;
      if (a.sectorNote) {
        cells = '<td class="note" colspan="' + D.sectors.length + '">' + esc(loc("actors", a.id, "sectorNote", a.sectorNote)) + "</td>";
      } else {
        cells = D.sectors.map(function (s) {
          var level = a.sectors[s.id];
          if (!level) return "<td></td>";
          return '<td><span class="sq ' + level + '" role="img" aria-label="' + level + '"></span></td>';
        }).join("");
      }
      return '<tr><th scope="row"><a href="#/actor/' + a.id + '">' + esc(a.name) + "</a></th>" + cells + "</tr>";
    }).join("");
    return '<div class="scroll-x"><table class="matrix"><thead><tr><th scope="col"><span class="skip">Actor</span></th>' + head +
      "</tr></thead><tbody>" + rows + "</tbody></table></div>" +
      '<div class="legend label"><span><i class="sq"></i> ' + esc(t("Targeting documented in a source")) + "</span>" +
      '<span><i class="sq suggested"></i> ' + esc(t("Suggested by lure or decoy content")) + "</span></div>";
  }

  /* ---------- views ---------- */

  function viewHome() {
    app.innerHTML =
      '<section class="hero"><div class="wrap hero-in">' +
      "<h1>" + esc(t("Cyber threats against Georgia, in one place")) + "</h1>" +
      '<p class="lede">' + esc(t("Georgian Threat Matrix collects public reports on the state-backed hacking groups that have targeted Georgia. For each group you can see who they are, what they did here and when, with a link to every source.")) + "</p>" +
      '<div class="globe-wrap"><canvas id="globe" aria-label="Globe with Georgia marked in red" role="img"></canvas>' +
      '<div class="globe-pin" id="globe-pin"><i></i>' + esc(t("Georgia")) + "</div></div>" +
      '<div class="stats">' +
      '<a href="#/actors"><b>' + D.actors.length + "</b><span>" + esc(t("threat actors")) + "</span></a>" +
      '<a href="#/timeline"><b>' + timeline.length + "</b><span>" + esc(t("dated events")) + "</span></a>" +
      '<a href="#/sources"><b>' + D.reports.length + "</b><span>" + esc(t("sources")) + "</span></a>" +
      '<a href="#/timeline"><b>' + firstYear + "-" + lastYear + "</b><span>" + esc(t("years covered")) + "</span></a></div>" +
      "</div></section>" +

      '<section class="band"><div class="wrap section-head"><div><h2>' + esc(t("Threat actors")) + "</h2>" +
      '<p class="sub">' + esc(t("Who they are, according to MITRE ATT&CK. Open a profile for what each did in Georgia.")) + "</p></div>" +
      '<div class="rail-controls"><button type="button" data-rail="-1" aria-label="Previous">←</button><button type="button" data-rail="1" aria-label="Next">→</button></div></div>' +
      '<div class="rail" tabindex="0" aria-label="' + esc(t("Threat actors")) + '">' +
      D.actors.map(function (a) { return actorCard(a, "rail-card"); }).join("") + "</div>" +
      '<div class="wrap"><div class="rail-bar"><i></i></div></div></section>' +

      '<section class="band"><div class="wrap"><h2>' + esc(t("Where to go next")) + '</h2><div class="next">' +
      '<a href="#/timeline"><h3>' + esc(t("Timeline")) + "</h3><p>" + esc(t("Every dated event from {a} to {b}, oldest first, filterable by actor.", { a: firstYear, b: lastYear })) + '</p><span class="label">' + esc(t("Open timeline →")) + "</span></a>" +
      '<a href="#/sources"><h3>' + esc(t("Sources")) + "</h3><p>" + esc(t("Search all {n} reports, advisories and articles, and the passages that mention Georgia.", { n: D.reports.length })) + '</p><span class="label">' + esc(t("Search sources →")) + "</span></a>" +
      '<a href="#/about"><h3>' + esc(t("About and contributing")) + "</h3><p>" + esc(t("How the collection is put together, and how to send in a report that is missing.")) + '</p><span class="label">' + esc(t("Read more →")) + "</span></a>" +
      "</div></div></section>";
  }

  function pageHead(title, lede) {
    return '<div class="page-head"><h1>' + esc(title) + "</h1>" + (lede ? '<p class="lede">' + lede + "</p>" : "") + "</div>";
  }

  function viewActors() {
    app.innerHTML = '<div class="wrap page">' +
      pageHead(t("Threat actors"), esc(t("Groups that public reporting ties to activity against Georgian targets. Descriptions are summarised from MITRE ATT&CK where the group has an entry."))) +
      '<div class="cards">' + D.actors.map(function (a) { return actorCard(a); }).join("") + "</div>" +
      '<section class="section"><h2>' + esc(t("Who targeted what")) + '</h2><p class="sub">' + esc(t("Sectors each actor is reported to have targeted in Georgia.")) + "</p>" + matrixHtml() + "</section></div>";
  }

  function viewActor(id) {
    var a = actorById[id];
    if (!a) return viewMissing();
    var reports = reportsFor(id);
    var specific = reports.filter(function (r) { return !r.general; });
    var general = reports.filter(function (r) { return r.general; });
    var mitreDesc = loc("actors", id, "mitreDesc", a.mitreDesc);
    var note = loc("actors", id, "note", a.note);
    var facts =
      "<dt>" + esc(t("Origin")) + "</dt><dd>" + esc(t(a.origin)) + "</dd>" +
      (a.sponsor ? "<dt>" + esc(t("Attributed to")) + "</dt><dd>" + esc(t(a.sponsor)) + "</dd>" : "") +
      (a.aliases.length ? "<dt>" + esc(t("Also known as")) + '</dt><dd><div class="pills">' + a.aliases.map(function (x) { return '<span class="pill quiet">' + esc(x) + "</span>"; }).join("") + "</div></dd>" : "") +
      (a.related ? "<dt>" + esc(t("Tracked together with")) + '</dt><dd><div class="pills">' + actorPills(a.related) + "</div></dd>" : "") +
      (note ? "<dt>" + esc(t("Attribution note")) + "</dt><dd>" + esc(note) + "</dd>" : "");
    var mitre = mitreDesc
      ? '<div class="callout"><p class="label">' + esc(t("About this group")) + " · " + mitreLink(a) + "</p><p>" + esc(mitreDesc) + "</p></div>"
      : '<div class="callout"><p class="label">' + esc(t("About this group")) + "</p><p>" + esc(t("This group has no MITRE ATT&CK entry. What is known comes from the reports below.")) + "</p></div>";
    app.innerHTML = '<div class="wrap page">' +
      '<p class="crumb"><a href="#/actors">' + esc(t("← All threat actors")) + "</a></p>" +
      '<div class="page-head"><div class="profile">' + portrait(a, true) + "<div><h1>" + esc(a.name) + '</h1><div class="pills">' +
      '<span class="pill">' + esc(t(a.origin)) + "</span>" + (a.sponsor ? '<span class="pill quiet">' + esc(t(a.sponsor)) + "</span>" : "") +
      "</div></div></div>" + mitre +
      '<div class="callout red"><p class="label">' + esc(t("In Georgia")) + "</p><p>" + esc(loc("actors", id, "summary", a.summary)) + "</p></div>" +
      '<dl class="facts">' + facts + "</dl></div>" +
      '<section class="section" style="margin-top:0"><h2>' + esc(t("Activity against Georgia")) + "</h2>" + timelineHtml(eventsFor(id)) + "</section>" +
      '<section class="section"><h2>' + esc(t("Reports mentioning Georgia")) + "</h2>" +
      specific.map(function (r) { return reportHtml(r, "", true); }).join("") + "</section>" +
      (general.length ? '<section class="section"><h2>' + esc(t("Background reading")) + "</h2>" +
        general.map(function (r) { return reportHtml(r, "", false); }).join("") + "</section>" : "") + "</div>";
  }

  function chips(selected) {
    return '<button class="chip" data-actor="" aria-pressed="' + (!selected) + '">' + esc(t("All")) + "</button>" +
      D.actors.map(function (a) {
        return '<button class="chip" data-actor="' + a.id + '" aria-pressed="' + (selected === a.id) + '">' + esc(a.name) + "</button>";
      }).join("");
  }

  function viewTimeline() {
    var selected = "";
    app.innerHTML = '<div class="wrap page">' +
      pageHead(t("Timeline"), esc(t("Dated events taken from the source reports, oldest first."))) +
      '<div class="filters" id="tl-filters"></div><div id="tl-list"></div></div>';
    var filters = document.getElementById("tl-filters");
    function draw() {
      filters.innerHTML = chips(selected);
      document.getElementById("tl-list").innerHTML = timelineHtml(timeline.filter(function (e) {
        return !selected || e.actors.indexOf(selected) !== -1;
      }));
    }
    filters.addEventListener("click", function (e) {
      var b = e.target.closest(".chip");
      if (!b) return;
      selected = b.dataset.actor;
      draw();
    });
    draw();
  }

  function viewSources(focusId) {
    var state = { q: "", actor: "", findingsOnly: false };
    app.innerHTML = '<div class="wrap page">' +
      pageHead(t("Sources"), esc(t("Every report, article and advisory in the collection. Search covers titles, publishers and the extracted findings."))) +
      '<div class="filters"><input class="search" id="src-q" type="search" placeholder="' + esc(t("Search, e.g. Ministry of Defense, PinchDuke, 2019")) + '" aria-label="' + esc(t("Search sources")) + '">' +
      '<label class="check label"><input type="checkbox" id="src-f"> ' + esc(t("With Georgia findings only")) + "</label></div>" +
      '<div class="filters" id="src-filters"></div><p class="count label" id="src-count" aria-live="polite"></p><div id="src-list"></div></div>';
    var filters = document.getElementById("src-filters");
    function draw() {
      var q = state.q.trim().toLowerCase();
      var hits = D.reports.filter(function (r) {
        if (state.actor && r.actors.indexOf(state.actor) === -1) return false;
        if (state.findingsOnly && !r.findings.length) return false;
        if (!q) return true;
        var hay = [r.title, r.publisher, r.year || ""].concat(r.findings, findingsOf(r), r.actors.map(function (id) {
          return actorById[id].name + " " + actorById[id].aliases.join(" ");
        })).join(" ").toLowerCase();
        return hay.indexOf(q) !== -1;
      });
      filters.innerHTML = chips(state.actor);
      document.getElementById("src-count").textContent = lang === "ka"
        ? count(hits.length, "source") + " / " + D.reports.length
        : count(hits.length, "source") + " of " + D.reports.length;
      document.getElementById("src-list").innerHTML = hits.length
        ? hits.map(function (r) { return reportHtml(r, state.q.trim(), !!q || r.id === focusId); }).join("")
        : '<p class="empty">' + esc(t("Nothing matches. Try a shorter search or clear the filters.")) + "</p>";
    }
    document.getElementById("src-q").addEventListener("input", function (e) { state.q = e.target.value; draw(); });
    document.getElementById("src-f").addEventListener("change", function (e) { state.findingsOnly = e.target.checked; draw(); });
    filters.addEventListener("click", function (e) {
      var b = e.target.closest(".chip");
      if (!b) return;
      state.actor = b.dataset.actor;
      draw();
    });
    draw();
    if (focusId) {
      var el = document.getElementById("r-" + focusId);
      if (el) { el.classList.add("focus"); el.scrollIntoView({ block: "start" }); }
    }
  }

  function viewAbout() {
    app.innerHTML = '<div class="wrap page">' + pageHead(t("About")) + '<div class="prose">' +
      "<p>" + esc(t("Georgian Threat Matrix aggregates data from public sources on cyber threats targeting Georgia. It covers reports on APT groups, mentions of Georgia in cyber-related findings, and malware used against Georgian targets.")) + "</p>" +
      "<p>" + esc(t("Everything here is collected through OSINT techniques and manual research. All reports are sourced from public research, and credit for the original findings goes to the respective authors. Findings are reproduced from the linked source so they can be checked against it; entries tagged summary are paraphrased rather than quoted.")) + "</p>" +
      "<h2>" + esc(t("How it is organised")) + "</h2><ul>" +
      "<li><b>" + esc(t("Threat actors")) + "</b>: " + esc(t("one page per group, with a description summarised from MITRE ATT&CK, aliases, attribution and every report that ties it to Georgia.")) + "</li>" +
      "<li><b>" + esc(t("Timeline")) + "</b>: " + esc(t("dated events drawn from those reports.")) + "</li>" +
      "<li><b>" + esc(t("Sources")) + "</b>: " + esc(t("the full searchable list of documents. Items marked archived also have a copy kept in the repository.")) + "</li></ul>" +
      "<h2>" + esc(t("Contribute")) + "</h2>" +
      "<p>" + esc(t("Know of a report that mentions Georgia and is missing here? Email")) + " <b>" + esc(D.contact.email) + "</b> " + esc(t("or message")) +
      ' <a href="https://x.com/' + esc(D.contact.x) + '" target="_blank" rel="noopener noreferrer">@' + esc(D.contact.x) + "</a> " + esc(t("on X.")) + "</p></div></div>";
  }

  function viewMissing() {
    app.innerHTML = '<div class="wrap page">' + pageHead(t("Page not found"), '<a href="#/">' + esc(t("Back to the home page")) + "</a>") + "</div>";
  }

  /* ---------- globe ---------- */

  var globeRun = 0;
  function setupGlobe() {
    var canvas = document.getElementById("globe");
    if (!canvas || !G) return;
    var run = ++globeRun;
    var pin = document.getElementById("globe-pin");
    var ctx = canvas.getContext("2d");
    var RAD = Math.PI / 180;
    var TILT = 24;             // degrees the north is tipped towards the viewer, so Georgia sits above centre
    var HOME = G.tbilisi[0];   // longitude the globe starts near
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var css = getComputedStyle(document.documentElement);
    var colDot = css.getPropertyValue("--globe-dot").trim();
    var colRed = css.getPropertyValue("--red").trim();

    // Pre-compute each land dot as sin/cos so a frame is only a rotation.
    var n = G.dots.length / 2;
    var lon = new Float32Array(n), sinLat = new Float32Array(n), cosLat = new Float32Array(n);
    for (var i = 0; i < n; i++) {
      lon[i] = G.dots[2 * i] / 10 * RAD;
      sinLat[i] = Math.sin(G.dots[2 * i + 1] / 10 * RAD);
      cosLat[i] = Math.cos(G.dots[2 * i + 1] / 10 * RAD);
    }

    var size = 0, dpr = 1, R = 0, offset = 0, tiltOffset = 0, tilt = TILT * RAD, dragging = false, lastX = 0, lastY = 0,
      visible = true, start = performance.now(), last = start, spin = 25;

    function resize() {
      size = canvas.clientWidth;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = canvas.height = Math.round(size * dpr);
      R = size * 0.46;
    }
    // Returns [x, y, depth]; depth > 0 means the point faces the viewer.
    function project(lonRad, sLat, cLat, centre) {
      var l = lonRad - centre;
      var x = cLat * Math.sin(l), y = sLat, z = cLat * Math.cos(l);
      var y2 = y * Math.cos(tilt) - z * Math.sin(tilt);
      var z2 = y * Math.sin(tilt) + z * Math.cos(tilt);
      return [size / 2 + R * x, size / 2 - R * y2, z2];
    }
    function projectDeg(p, centre) {
      return project(p[0] * RAD, Math.sin(p[1] * RAD), Math.cos(p[1] * RAD), centre);
    }

    function draw(now) {
      if (run !== globeRun || !canvas.isConnected) return;
      requestAnimationFrame(draw);
      if (!visible && !dragging) return;
      var time = (now - start) / 1000;
      var dt = Math.min(0.1, (now - last) / 1000); last = now;
      if (!reduced && !dragging) spin -= dt * 9;   // degrees per second: one full turn every 40 s
      var centre = (HOME + spin + offset) * RAD;
      var nod = reduced ? 0 : 10 * Math.sin(time / 4.3);
      tilt = (TILT + nod + tiltOffset) * RAD;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, size, size);

      var g = ctx.createRadialGradient(size * 0.4, size * 0.34, R * 0.1, size / 2, size / 2, R);
      g.addColorStop(0, "rgba(139, 92, 246, 0.22)");
      g.addColorStop(1, "rgba(139, 92, 246, 0.04)");
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(size / 2, size / 2, R, 0, 2 * Math.PI); ctx.fill();
      ctx.strokeStyle = "rgba(167, 139, 250, 0.35)"; ctx.lineWidth = 1; ctx.stroke();

      ctx.fillStyle = colDot;
      var r = Math.max(1, size / 420);
      for (var i = 0; i < n; i++) {
        var p = project(lon[i], sinLat[i], cosLat[i], centre);
        if (p[2] <= 0.02) continue;
        ctx.globalAlpha = 0.25 + 0.75 * p[2];
        ctx.beginPath(); ctx.arc(p[0], p[1], r, 0, 2 * Math.PI); ctx.fill();
      }
      ctx.globalAlpha = 1;

      // Georgia's outline, filled red.
      G.georgia.forEach(function (ring) {
        var pts = ring.map(function (q) { return projectDeg(q, centre); });
        if (pts.some(function (q) { return q[2] <= 0.05; })) return;
        ctx.beginPath();
        pts.forEach(function (q, k) { if (k) ctx.lineTo(q[0], q[1]); else ctx.moveTo(q[0], q[1]); });
        ctx.closePath();
        ctx.fillStyle = "rgba(255, 77, 94, 0.55)"; ctx.fill();
        ctx.strokeStyle = colRed; ctx.lineWidth = 1.2; ctx.stroke();
      });

      var c = projectDeg(G.tbilisi, centre);
      var shown = c[2] > 0.1;
      pin.hidden = !shown;
      if (shown) {
        var pulse = reduced ? 0.5 : (time % 2.2) / 2.2;
        ctx.strokeStyle = colRed; ctx.lineWidth = 1.5;
        ctx.globalAlpha = 1 - pulse;
        ctx.beginPath(); ctx.arc(c[0], c[1], 5 + pulse * 20, 0, 2 * Math.PI); ctx.stroke();
        ctx.globalAlpha = 1;
        ctx.fillStyle = colRed;
        ctx.beginPath(); ctx.arc(c[0], c[1], 5, 0, 2 * Math.PI); ctx.fill();
        pin.style.transform = "translate(" + (c[0] + 14) + "px," + (c[1] - 34) + "px)";
      }
    }

    canvas.addEventListener("pointerdown", function (e) {
      dragging = true; lastX = e.clientX; lastY = e.clientY; canvas.setPointerCapture(e.pointerId);
    });
    canvas.addEventListener("pointermove", function (e) {
      if (!dragging) return;
      offset -= (e.clientX - lastX) * 0.35; lastX = e.clientX;
      tiltOffset += (e.clientY - lastY) * 0.35; lastY = e.clientY;
    });
    function release() { dragging = false; }
    canvas.addEventListener("pointerup", release);
    canvas.addEventListener("pointercancel", release);
    window.addEventListener("resize", resize);
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (en) { visible = en[0].isIntersecting; }).observe(canvas);
    }
    resize();
    requestAnimationFrame(draw);
  }

  /* ---------- rail ---------- */

  function setupRail() {
    var rail = app.querySelector(".rail");
    if (!rail) return;
    var thumb = app.querySelector(".rail-bar i");
    var buttons = app.querySelectorAll("[data-rail]");

    function sync() {
      var max = rail.scrollWidth - rail.clientWidth;
      thumb.style.width = (rail.clientWidth / rail.scrollWidth * 100) + "%";
      thumb.style.left = (rail.scrollLeft / rail.scrollWidth * 100) + "%";
      buttons[0].disabled = rail.scrollLeft <= 1;
      buttons[1].disabled = rail.scrollLeft >= max - 1;
    }
    rail.addEventListener("scroll", sync, { passive: true });
    window.addEventListener("resize", sync);
    sync();

    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        var step = rail.querySelector(".rail-card").offsetWidth + 16;
        rail.scrollBy({ left: step * 2 * +b.dataset.rail, behavior: "smooth" });
      });
    });

    // Mouse drag; touch and trackpad use native scrolling.
    var down = false, moved = false, startX = 0, startLeft = 0;
    rail.addEventListener("pointerdown", function (e) {
      if (e.pointerType !== "mouse" || e.button !== 0) return;
      down = true; moved = false; startX = e.clientX; startLeft = rail.scrollLeft;
    });
    rail.addEventListener("pointermove", function (e) {
      if (!down) return;
      var dx = e.clientX - startX;
      if (!moved && Math.abs(dx) > 4) {
        moved = true;
        rail.classList.add("dragging");
        rail.setPointerCapture(e.pointerId);
      }
      if (moved) rail.scrollLeft = startLeft - dx;
    });
    function end() { down = false; rail.classList.remove("dragging"); }
    rail.addEventListener("pointerup", end);
    rail.addEventListener("pointercancel", end);
    rail.addEventListener("click", function (e) {
      if (moved) { e.preventDefault(); e.stopPropagation(); moved = false; }
    }, true);
    rail.addEventListener("dragstart", function (e) { e.preventDefault(); });
  }

  /* ---------- router ---------- */

  // Translates the fixed parts of the page (navigation, footer) and the switch itself.
  function applyLang() {
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-t]").forEach(function (el) {
      if (!el.dataset.en) el.dataset.en = el.textContent.trim();
      el.textContent = t(el.dataset.en);
    });
    var b = document.getElementById("lang-toggle");
    b.textContent = lang === "ka" ? "EN" : "ქარ";
    b.setAttribute("aria-label", lang === "ka" ? "Switch to English" : "ქართულ ენაზე გადართვა");
  }

  function route() {
    var parts = location.hash.replace(/^#\/?/, "").split("/");
    var page = parts[0] || "home";
    var nav = page === "actor" ? "actors" : page;
    globeRun++; // stops a globe left over from the previous view
    if (page === "home") viewHome();
    else if (page === "actors") viewActors();
    else if (page === "actor") viewActor(parts[1]);
    else if (page === "timeline") viewTimeline();
    else if (page === "sources") viewSources(parts[1]);
    else if (page === "about") viewAbout();
    else viewMissing();

    document.querySelectorAll("nav a").forEach(function (a) {
      if (a.dataset.nav === nav) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    var h1 = app.querySelector("h1");
    document.title = (page === "home" || !h1 ? "" : h1.textContent + " · ") + "Georgian Threat Matrix";
    setupGlobe();
    setupRail();
  }

  document.getElementById("lang-toggle").addEventListener("click", function () {
    lang = lang === "ka" ? "en" : "ka";
    try { localStorage.setItem("gtm-lang", lang); } catch (e) { /* storage unavailable */ }
    var y = window.scrollY;
    applyLang();
    route();
    window.scrollTo(0, y);
  });
  window.addEventListener("hashchange", function () {
    route();
    if (!/^#\/sources\/./.test(location.hash)) window.scrollTo(0, 0);
  });
  applyLang();
  route();
})();
