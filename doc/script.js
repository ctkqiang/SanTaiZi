/* 三太子 SanTaiZi documentation behavior. No external dependencies. */
(function () {
  "use strict";

  const root = document.documentElement;
  const body = document.body;
  const header = document.querySelector(".topbar");
  const sidebar = document.getElementById("sidebar");
  const scrim = document.getElementById("sidebar-scrim");
  const menuToggle = document.getElementById("menu-toggle");
  const themeToggle = document.getElementById("theme-toggle");
  const themeIcon = themeToggle ? themeToggle.querySelector(".theme-icon") : null;
  const searchInput = document.getElementById("doc-search");
  const searchClear = document.getElementById("search-clear");
  const searchEmpty = document.getElementById("search-empty");
  const searchTrigger = document.getElementById("search-trigger");
  const navLinks = Array.from(document.querySelectorAll(".nav-link"));
  const tocGroups = Array.from(document.querySelectorAll(".toc-group"));
  const progressBar = document.getElementById("reading-progress-bar");
  const toTop = document.getElementById("to-top");

  const THEME_KEY = "santai-zi-docs-theme";
  const mobileQuery = window.matchMedia("(max-width: 960px)");

  /* Theme ------------------------------------------------------------------ */

  function readStoredTheme() {
    try {
      return window.localStorage.getItem(THEME_KEY);
    } catch (_error) {
      return null;
    }
  }

  function storeTheme(theme) {
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch (_error) {
      /* file:// or privacy mode */
    }
  }

  function applyTheme(theme) {
    const next = theme === "dark" ? "dark" : "light";
    root.dataset.theme = next;
    if (themeToggle) {
      const isDark = next === "dark";
      themeToggle.setAttribute("aria-pressed", isDark ? "true" : "false");
      themeToggle.setAttribute("title", isDark ? "切换到浅色" : "切换到深色");
      if (themeIcon) themeIcon.textContent = isDark ? "☀" : "☾";
    }
  }

  const storedTheme = readStoredTheme();
  const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  applyTheme(storedTheme || (systemDark ? "dark" : "light"));

  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      applyTheme(root.dataset.theme === "dark" ? "light" : "dark");
      storeTheme(root.dataset.theme);
    });
  }

  /* Mobile drawer ----------------------------------------------------------- */

  function isMobile() {
    return mobileQuery.matches;
  }

  function openSidebar() {
    if (!sidebar) return;
    sidebar.classList.add("open");
    if (scrim) scrim.hidden = false;
    if (menuToggle) {
      menuToggle.setAttribute("aria-expanded", "true");
      menuToggle.setAttribute("aria-label", "关闭目录");
    }
    if (isMobile()) body.style.overflow = "hidden";
  }

  function closeSidebar() {
    if (!sidebar) return;
    sidebar.classList.remove("open");
    if (scrim) scrim.hidden = true;
    if (menuToggle) {
      menuToggle.setAttribute("aria-expanded", "false");
      menuToggle.setAttribute("aria-label", "打开目录");
    }
    body.style.overflow = "";
  }

  if (menuToggle) {
    menuToggle.addEventListener("click", function () {
      if (sidebar && sidebar.classList.contains("open")) closeSidebar();
      else openSidebar();
    });
  }
  if (scrim) scrim.addEventListener("click", closeSidebar);
  navLinks.forEach(function (link) {
    link.addEventListener("click", function () {
      if (isMobile()) closeSidebar();
    });
  });
  mobileQuery.addEventListener("change", function () {
    if (!isMobile()) closeSidebar();
  });

  /* Search ------------------------------------------------------------------ */

  const searchIndex = navLinks.map(function (link) {
    const target = document.querySelector(link.getAttribute("href"));
    const sectionText = target ? target.textContent : "";
    return {
      link: link,
      text: (link.textContent + " " + sectionText).replace(/\s+/g, " ").toLowerCase()
    };
  });

  function refreshGroupVisibility() {
    tocGroups.forEach(function (group) {
      let hasVisible = false;
      let node = group.nextElementSibling;
      while (node && !node.classList.contains("toc-group")) {
        if (node.classList.contains("nav-link") && !node.hidden) {
          hasVisible = true;
          break;
        }
        node = node.nextElementSibling;
      }
      group.hidden = !hasVisible;
    });
  }

  function applySearch(query) {
    const needle = query.trim().toLowerCase();
    let visible = 0;

    searchIndex.forEach(function (entry) {
      const matches = needle === "" || entry.text.includes(needle);
      entry.link.hidden = !matches;
      if (matches) visible++;
    });

    if (searchClear) searchClear.style.display = needle ? "block" : "none";
    if (searchEmpty) searchEmpty.hidden = visible !== 0 || needle === "";
    refreshGroupVisibility();
  }

  function focusSearch() {
    if (!searchInput) return;
    if (isMobile()) openSidebar();
    window.setTimeout(function () {
      searchInput.focus();
      searchInput.select();
    }, isMobile() ? 80 : 0);
  }

  if (searchInput) {
    searchInput.addEventListener("input", function () {
      applySearch(searchInput.value);
    });
    searchInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        const first = navLinks.find(function (link) { return !link.hidden; });
        if (first) {
          event.preventDefault();
          first.click();
          window.location.hash = first.getAttribute("href");
          if (isMobile()) closeSidebar();
        }
      } else if (event.key === "Escape") {
        searchInput.value = "";
        applySearch("");
        searchInput.blur();
      }
    });
  }

  if (searchClear) {
    searchClear.addEventListener("click", function () {
      if (!searchInput) return;
      searchInput.value = "";
      applySearch("");
      searchInput.focus();
    });
  }

  if (searchTrigger) {
    searchTrigger.addEventListener("click", focusSearch);
  }

  document.addEventListener("keydown", function (event) {
    const target = event.target;
    const isTyping = target && (
      target.tagName === "INPUT" ||
      target.tagName === "TEXTAREA" ||
      target.tagName === "SELECT" ||
      target.isContentEditable
    );

    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      focusSearch();
      return;
    }
    if (!isTyping && event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey) {
      event.preventDefault();
      focusSearch();
      return;
    }
    if (event.key === "Escape" && isMobile() && sidebar && sidebar.classList.contains("open")) {
      closeSidebar();
    }
  });

  /* Scrollspy + progress ---------------------------------------------------- */

  const sections = navLinks
    .map(function (link) {
      return document.querySelector(link.getAttribute("href"));
    })
    .filter(Boolean);

  function setActiveSection(id) {
    navLinks.forEach(function (link) {
      const active = link.getAttribute("href") === "#" + id;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
  }

  let ticking = false;

  function updateScrollState() {
    ticking = false;
    const y = window.scrollY || window.pageYOffset;
    const docHeight = document.documentElement.scrollHeight - window.innerHeight;
    const percent = docHeight > 0 ? Math.min(100, Math.max(0, (y / docHeight) * 100)) : 0;
    if (progressBar) progressBar.style.width = percent.toFixed(2) + "%";
    if (toTop) toTop.hidden = y < 520;

    const offset = (header ? header.offsetHeight : 62) + 48;
    let current = sections.length ? sections[0].id : "";
    sections.forEach(function (section) {
      if (section.getBoundingClientRect().top - offset <= 0) current = section.id;
    });
    if (current) setActiveSection(current);
  }

  function onScroll() {
    if (ticking) return;
    ticking = true;
    window.requestAnimationFrame(updateScrollState);
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", function () {
    updateScrollState();
    if (!isMobile()) closeSidebar();
  }, { passive: true });
  window.addEventListener("hashchange", function () {
    if (window.location.hash) setActiveSection(window.location.hash.slice(1));
  });

  /* Responsive table labels ------------------------------------------------ */

  document.querySelectorAll("table").forEach(function (table) {
    const headers = Array.from(table.querySelectorAll("thead th")).map(function (cell) {
      return cell.textContent.trim();
    });
    if (!headers.length) return;
    const wrap = table.closest(".table-wrap");
    if (wrap) wrap.classList.add("is-responsive");
    table.querySelectorAll("tbody tr").forEach(function (row) {
      Array.from(row.children).forEach(function (cell, index) {
        if (!cell.hasAttribute("data-label")) {
          cell.setAttribute("data-label", headers[index] || "");
        }
        if (!cell.textContent.trim()) {
          cell.classList.add("is-empty");
        }
      });
    });
  });

  /* Copy code --------------------------------------------------------------- */

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.top = "-1000px";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        const copied = document.execCommand("copy");
        document.body.removeChild(area);
        if (copied) resolve();
        else reject(new Error("copy failed"));
      } catch (error) {
        document.body.removeChild(area);
        reject(error);
      }
    });
  }

  document.querySelectorAll("pre").forEach(function (pre) {
    const code = pre.querySelector("code");
    if (!code) return;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy-code";
    button.textContent = "复制";
    button.setAttribute("aria-label", "复制代码");
    button.addEventListener("click", function () {
      copyText(code.innerText || code.textContent || "").then(function () {
        button.textContent = "已复制";
        button.classList.add("copied");
        window.setTimeout(function () {
          button.textContent = "复制";
          button.classList.remove("copied");
        }, 1600);
      }).catch(function () {
        button.textContent = "复制失败";
        window.setTimeout(function () { button.textContent = "复制"; }, 1600);
      });
    });
    pre.appendChild(button);
  });

  /* Back to top ------------------------------------------------------------- */

  if (toTop) {
    toTop.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  /* Initial state ----------------------------------------------------------- */

  applySearch("");
  updateScrollState();
  if (window.location.hash) {
    setActiveSection(window.location.hash.slice(1));
  }
})();
