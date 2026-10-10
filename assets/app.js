(function () {
  "use strict";

  var D = window.GTM;
  var G = window.GTM_GLOBE;
  var app = document.getElementById("app");
  var actorById = {};
  var reportById = {};
  D.actors.forEach(function (a) { actorById[a.id] = a; });
  D.reports.forEach(function (r) { reportById[r.id] = r; });
  var timeline = D.timeline.slice().sort(function (a, b) { return a.sort < b.sort ? -1 : 1; });
  var firstYear = +timeline[0].sort.slice(0, 4);
  var lastYear = +timeline[timeline.length - 1].sort.slice(0, 4);

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
  function plural(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }
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

  /* ---------- shared fragments ---------- */

  function reportHtml(r, q, open) {
    var links = r.links.map(function (l) {
      return '<li><a href="' + esc(l.url) + '" target="_blank" rel="noopener noreferrer">' + esc(l.label) + "</a>" +
        (l.archived ? ' <span class="pill quiet" title="A copy of this document is kept in the repository">archived</span>' : "") + "</li>";
    }).join("");
    var findings = "";
    if (r.findings.length) {
      findings = "<details" + (open ? " open" : "") + "><summary>" + plural(r.findings.length, "finding") + " on Georgia</summary>" +
        '<ul class="findings">' + r.findings.map(function (f) { return "<li>" + highlight(f, q) + "</li>"; }).join("") + "</ul></details>";
    }
    return '<article class="report" id="r-' + r.id + '">' +
      "<h3>" + highlight(r.title, q) + "</h3>" +
      '<div class="report-meta"><span class="label">' + highlight(r.publisher, q) + (r.year ? " · " + r.year : "") + "</span>" + actorPills(r.actors) +
      (r.general ? '<span class="pill quiet">background</span>' : "") +
      (r.paraphrased ? '<span class="pill quiet" title="Findings are summaries written for this site, not quotations">summary</span>' : "") + "</div>" +
      '<ul class="links">' + links + "</ul>" + findings + "</article>";
  }

  function timelineHtml(events) {
    if (!events.length) return '<p class="empty">No dated events recorded for this selection.</p>';
    return '<ol class="timeline">' + events.map(function (e) {
      var r = reportById[e.report];
      return "<li><time>" + esc(e.when) + "</time><div><h3>" + esc(e.title) + "</h3><p>" + esc(e.text) + "</p>" +
        '<div class="row">' + actorPills(e.actors) +
        '<a class="src" href="#/sources/' + r.id + '">Source: ' + esc(r.publisher) + "</a></div></div></li>";
    }).join("") + "</ol>";
  }

  // One card per actor: name, origin, MITRE description, and where to read more.
  function actorCard(a, cls) {
    var ev = eventsFor(a.id);
    var desc = a.mitreDesc || a.summary;
    return '<a class="card ' + (cls || "") + '" href="#/actor/' + a.id + '">' +
      '<div class="card-top"><h3>' + esc(a.name) + '</h3><span class="pill quiet">' + esc(a.origin) + "</span></div>" +
      '<p class="label">' + (a.mitre ? "MITRE ATT&amp;CK " + a.mitre : "Not in MITRE ATT&amp;CK") + "</p>" +
      "<p>" + esc(desc) + "</p>" +
      '<div class="meta label"><span>' + plural(reportsFor(a.id).length, "source") + "</span>" +
      (ev.length ? "<span>First seen " + ev[0].sort.slice(0, 4) + "</span>" : "") + '<span class="go">View profile →</span></div></a>';
  }

  function matrixHtml() {
    var head = D.sectors.map(function (s) { return '<th scope="col">' + esc(s.name) + "</th>"; }).join("");
    var rows = D.actors.map(function (a) {
      var cells;
      if (a.sectorNote) {
        cells = '<td class="note" colspan="' + D.sectors.length + '">' + esc(a.sectorNote) + "</td>";
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
      '<div class="legend label"><span><i class="sq"></i> Targeting documented in a source</span>' +
      '<span><i class="sq suggested"></i> Suggested by lure or decoy content</span></div>';
  }

  /* ---------- views ---------- */

  function viewHome() {
    app.innerHTML =
      '<section class="hero"><div class="wrap hero-in">' +
      "<h1>Cyber threats against Georgia, in one place</h1>" +
      '<p class="lede">Georgian Threat Matrix collects public reports on the state-backed hacking groups that have targeted Georgia. ' +
      "For each group you can see who they are, what they did here and when, with a link to every source.</p>" +
      '<div class="globe-wrap"><canvas id="globe" aria-label="Globe centred on Georgia, which is marked in red" role="img"></canvas>' +
      '<div class="globe-pin" id="globe-pin"><i></i>Georgia</div></div>' +
      '<div class="stats">' +
      "<div><b>" + D.actors.length + "</b><span>threat actors</span></div>" +
      "<div><b>" + timeline.length + "</b><span>dated events</span></div>" +
      "<div><b>" + D.reports.length + "</b><span>sources</span></div>" +
      "<div><b>" + firstYear + "–" + lastYear + "</b><span>years covered</span></div></div>" +
      "</div></section>" +

      '<section class="band"><div class="wrap section-head"><div><h2>Threat actors</h2>' +
      '<p class="sub">Who they are, according to MITRE ATT&amp;CK. Open a profile for what each did in Georgia.</p></div>' +
      '<div class="rail-controls"><button type="button" data-rail="-1" aria-label="Previous actors">←</button><button type="button" data-rail="1" aria-label="More actors">→</button></div></div>' +
      '<div class="rail" tabindex="0" aria-label="Threat actors, scroll horizontally">' +
      D.actors.map(function (a) { return actorCard(a, "rail-card"); }).join("") + "</div>" +
      '<div class="wrap"><div class="rail-bar"><i></i></div></div></section>' +

      '<section class="band"><div class="wrap"><h2>Where to go next</h2><div class="next">' +
      '<a href="#/timeline"><h3>Timeline</h3><p>Every dated event from ' + firstYear + " to " + lastYear + ', oldest first, filterable by actor.</p><span class="label">Open timeline →</span></a>' +
      '<a href="#/sources"><h3>Sources</h3><p>Search all ' + D.reports.length + ' reports, advisories and articles, and the passages that mention Georgia.</p><span class="label">Search sources →</span></a>' +
      '<a href="#/about"><h3>About and contributing</h3><p>How the collection is put together, and how to send in a report that is missing.</p><span class="label">Read more →</span></a>' +
      "</div></div></section>";
  }

  function pageHead(title, lede) {
    return '<div class="page-head"><h1>' + title + "</h1>" + (lede ? '<p class="lede">' + lede + "</p>" : "") + "</div>";
  }

  function viewActors() {
    app.innerHTML = '<div class="wrap page">' +
      pageHead("Threat actors", "Groups that public reporting ties to activity against Georgian targets. Descriptions are summarised from MITRE ATT&amp;CK where the group has an entry.") +
      '<div class="cards">' + D.actors.map(function (a) { return actorCard(a); }).join("") + "</div>" +
      '<section class="section"><h2>Who targeted what</h2><p class="sub">Sectors each actor is reported to have targeted in Georgia.</p>' + matrixHtml() + "</section></div>";
  }

  function viewActor(id) {
    var a = actorById[id];
    if (!a) return viewMissing();
    var reports = reportsFor(id);
    var specific = reports.filter(function (r) { return !r.general; });
    var general = reports.filter(function (r) { return r.general; });
    var facts =
      "<dt>Origin</dt><dd>" + esc(a.origin) + "</dd>" +
      (a.sponsor ? "<dt>Attributed to</dt><dd>" + esc(a.sponsor) + "</dd>" : "") +
      (a.aliases.length ? '<dt>Also known as</dt><dd><div class="pills">' + a.aliases.map(function (x) { return '<span class="pill quiet">' + esc(x) + "</span>"; }).join("") + "</div></dd>" : "") +
      (a.related ? '<dt>Tracked together with</dt><dd><div class="pills">' + actorPills(a.related) + "</div></dd>" : "") +
      (a.note ? "<dt>Attribution note</dt><dd>" + esc(a.note) + "</dd>" : "");
    var mitre = a.mitreDesc
      ? '<div class="callout"><p class="label">About this group · ' + mitreLink(a) + "</p><p>" + esc(a.mitreDesc) + "</p></div>"
      : '<div class="callout"><p class="label">About this group</p><p>This group has no MITRE ATT&amp;CK entry. What is known comes from the reports below.</p></div>';
    app.innerHTML = '<div class="wrap page">' +
      '<p class="crumb"><a href="#/actors">← All threat actors</a></p>' +
      '<div class="page-head"><h1>' + esc(a.name) + "</h1>" + mitre +
      '<div class="callout red"><p class="label">In Georgia</p><p>' + esc(a.summary) + "</p></div>" +
      '<dl class="facts">' + facts + "</dl></div>" +
      '<section class="section" style="margin-top:0"><h2>Activity against Georgia</h2>' + timelineHtml(eventsFor(id)) + "</section>" +
      '<section class="section"><h2>Reports mentioning Georgia</h2>' +
      specific.map(function (r) { return reportHtml(r, "", true); }).join("") + "</section>" +
      (general.length ? '<section class="section"><h2>Background reading</h2>' +
        general.map(function (r) { return reportHtml(r, "", false); }).join("") + "</section>" : "") + "</div>";
  }

  function chips(selected) {
    return '<button class="chip" data-actor="" aria-pressed="' + (!selected) + '">All</button>' +
      D.actors.map(function (a) {
        return '<button class="chip" data-actor="' + a.id + '" aria-pressed="' + (selected === a.id) + '">' + esc(a.name) + "</button>";
      }).join("");
  }

  function viewTimeline() {
    var selected = "";
    app.innerHTML = '<div class="wrap page">' +
      pageHead("Timeline", "Dated events taken from the source reports, oldest first.") +
      '<div class="filters" id="tl-filters"></div><div id="tl-list"></div></div>';
    var filters = document.getElementById("tl-filters");
    function draw() {
      filters.innerHTML = chips(selected);
      document.getElementById("tl-list").innerHTML = timelineHtml(timeline.filter(function (e) {
        return !selected || e.actors.indexOf(selected) !== -1;
      }));
    }
    filters.addEventListener("click", function (ev) {
      var b = ev.target.closest(".chip");
      if (!b) return;
      selected = b.dataset.actor;
      draw();
    });
    draw();
  }

  function viewSources(focusId) {
    var state = { q: "", actor: "", findingsOnly: false };
    app.innerHTML = '<div class="wrap page">' +
      pageHead("Sources", "Every report, article and advisory in the collection. Search covers titles, publishers and the extracted findings.") +
      '<div class="filters"><input class="search" id="src-q" type="search" placeholder="Search, e.g. Ministry of Defense, PinchDuke, 2019" aria-label="Search sources">' +
      '<label class="check label"><input type="checkbox" id="src-f"> With Georgia findings only</label></div>' +
      '<div class="filters" id="src-filters"></div><p class="count label" id="src-count" aria-live="polite"></p><div id="src-list"></div></div>';
    var filters = document.getElementById("src-filters");
    function draw() {
      var q = state.q.trim().toLowerCase();
      var hits = D.reports.filter(function (r) {
        if (state.actor && r.actors.indexOf(state.actor) === -1) return false;
        if (state.findingsOnly && !r.findings.length) return false;
        if (!q) return true;
        var hay = [r.title, r.publisher, r.year || ""].concat(r.findings, r.actors.map(function (id) {
          return actorById[id].name + " " + actorById[id].aliases.join(" ");
        })).join(" ").toLowerCase();
        return hay.indexOf(q) !== -1;
      });
      filters.innerHTML = chips(state.actor);
      document.getElementById("src-count").textContent = plural(hits.length, "source") + " of " + D.reports.length;
      document.getElementById("src-list").innerHTML = hits.length
        ? hits.map(function (r) { return reportHtml(r, state.q.trim(), !!q || r.id === focusId); }).join("")
        : '<p class="empty">Nothing matches. Try a shorter search or clear the filters.</p>';
    }
    document.getElementById("src-q").addEventListener("input", function (ev) { state.q = ev.target.value; draw(); });
    document.getElementById("src-f").addEventListener("change", function (ev) { state.findingsOnly = ev.target.checked; draw(); });
    filters.addEventListener("click", function (ev) {
      var b = ev.target.closest(".chip");
      if (!b) return;
      state.actor = b.dataset.actor;
      draw();
    });
    draw();
    if (focusId) {
      var el = document.getElementById("r-" + focusId);
      if (el) el.scrollIntoView({ block: "start" });
    }
  }

  function viewAbout() {
    app.innerHTML = '<div class="wrap page">' + pageHead("About") + '<div class="prose">' +
      "<p>Georgian Threat Matrix aggregates data from public sources on cyber threats targeting Georgia. It covers reports on APT groups, mentions of Georgia in cyber-related findings, and malware used against Georgian targets.</p>" +
      "<p>Everything here is collected through OSINT techniques and manual research. All reports are sourced from public research, and credit for the original findings goes to the respective authors. Findings are reproduced from the linked source so they can be checked against it; entries tagged <i>summary</i> are paraphrased rather than quoted.</p>" +
      "<h2>How it is organised</h2><ul>" +
      "<li><b>Threat actors</b>: one page per group, with a description summarised from MITRE ATT&amp;CK, aliases, attribution and every report that ties it to Georgia.</li>" +
      "<li><b>Timeline</b>: dated events drawn from those reports.</li>" +
      "<li><b>Sources</b>: the full searchable list of documents. Items marked <i>archived</i> also have a copy kept in the repository.</li></ul>" +
      "<h2>Contribute</h2>" +
      "<p>Know of a report that mentions Georgia and is missing here? Email <b>" + esc(D.contact.email) + "</b> or message " +
      '<a href="https://x.com/' + esc(D.contact.x) + '" target="_blank" rel="noopener noreferrer">@' + esc(D.contact.x) + "</a> on X.</p></div></div>";
  }

  function viewMissing() {
    app.innerHTML = '<div class="wrap page">' + pageHead("Page not found", '<a href="#/">Back to the home page</a>') + "</div>";
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
    var HOME = G.tbilisi[0];   // longitude the globe rests on
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

    var size = 0, dpr = 1, R = 0, offset = 0, tiltOffset = 0, tilt = TILT * RAD, dragging = false, lastX = 0, lastY = 0, visible = true, start = performance.now();

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
      var t = (now - start) / 1000;
      var sway = reduced || dragging ? 0 : 26 * Math.sin(t / 7);
      var centre = (HOME + sway + offset) * RAD;
      var nod = reduced || dragging ? 0 : 10 * Math.sin(t / 4.3);
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
        var pulse = reduced ? 0.5 : (t % 2.2) / 2.2;
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
      // Keep Georgia on the visible half: limit how far the globe can be tipped.
      tiltOffset = Math.max(-40, Math.min(40, tiltOffset + (e.clientY - lastY) * 0.3)); lastY = e.clientY;
    });
    function release() { dragging = false; start = performance.now(); }
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
    if (!(page === "sources" && parts[1])) window.scrollTo(0, 0);
    setupGlobe();
    setupRail();
  }

  window.addEventListener("hashchange", route);
  route();
})();
