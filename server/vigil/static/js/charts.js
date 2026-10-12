// Minimal dependency-free SVG charts: area (single series, crosshair tooltip)
// and stacked columns (per-column tooltip). Thin marks, recessive grid, one axis.
import { esc, fmtCompact, fmtNum, fmtTime } from "./lib.js";

let tip;
function tooltip() {
  if (!tip) { tip = document.createElement("div"); tip.className = "tooltip"; tip.hidden = true; document.body.appendChild(tip); }
  return tip;
}
function showTip(evt, htmlStr) {
  const t = tooltip();
  t.innerHTML = htmlStr;
  t.hidden = false;
  const x = Math.min(evt.clientX + 14, window.innerWidth - t.offsetWidth - 10);
  const y = Math.min(evt.clientY + 14, window.innerHeight - t.offsetHeight - 10);
  t.style.left = x + "px"; t.style.top = y + "px";
}
export function hideTip() { if (tip) tip.hidden = true; }

// Nice axis: step from {1, 2, 2.5, 5} x 10^k so ticks land on round numbers.
function niceScale(v) {
  v = Math.max(v, 4);
  const raw = v / 4;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * p).find((s) => s >= raw);
  const ticks = Math.ceil(v / step);
  return { max: ticks * step, ticks };
}

function frame(width, height, scale, n, start, step) {
  const { max, ticks } = scale;
  const pad = { l: 40, r: 8, t: 8, b: 22 };
  const w = width - pad.l - pad.r, h = height - pad.t - pad.b;
  let g = "";
  for (let i = 0; i <= ticks; i++) {
    const y = pad.t + h - (h * i) / ticks;
    g += `<line class="${i === 0 ? "axis-line" : "grid-line"}" x1="${pad.l}" x2="${pad.l + w}" y1="${y}" y2="${y}"/>`;
    g += `<text class="tick" x="${pad.l - 6}" y="${y + 4}" text-anchor="end">${fmtCompact((max * i) / ticks)}</text>`;
  }
  const labels = Math.min(6, n);
  for (let i = 0; i < labels; i++) {
    const idx = Math.round((i * (n - 1)) / Math.max(1, labels - 1));
    const x = pad.l + (w * (idx + 0.5)) / n;
    const span = step * n;
    const d = new Date((start + idx * step) * 1000);
    const lab = span > 2 * 86400 ? d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" })
      : d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    g += `<text class="tick" x="${x}" y="${height - 4}" text-anchor="middle">${lab}</text>`;
  }
  return { pad, w, h, g };
}

export function areaChart(el, { values, start, step, color = "var(--series-1)", label = "Events", height = 200 }) {
  const width = el.clientWidth || 600;
  const n = values.length;
  const scale = niceScale(Math.max(...values, 1));
  const max = scale.max;
  const { pad, w, h, g } = frame(width, height, scale, n, start, step);
  const x = (i) => pad.l + (w * (i + 0.5)) / n;
  const y = (v) => pad.t + h - (h * v) / max;
  const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  const area = `M${x(0)},${pad.t + h} L${pts.join(" L")} L${x(n - 1)},${pad.t + h} Z`;
  el.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(label)} over time">${g}
    <path d="${area}" fill="${color}" opacity="0.16"/>
    <polyline points="${pts.join(" ")}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>
    <line class="cross" x1="0" x2="0" y1="${pad.t}" y2="${pad.t + h}" visibility="hidden"/>
    <circle class="dot" r="4" fill="${color}" stroke="var(--surface-1)" stroke-width="2" visibility="hidden"/>
    <rect class="hit" x="${pad.l}" y="${pad.t}" width="${w}" height="${h}"/></svg>`;
  const svg = el.querySelector("svg"), cross = svg.querySelector(".cross"), dot = svg.querySelector(".dot");
  svg.querySelector(".hit").addEventListener("mousemove", (e) => {
    const r = svg.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * width;
    const i = Math.max(0, Math.min(n - 1, Math.floor(((px - pad.l) / w) * n)));
    cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i)); cross.setAttribute("visibility", "visible");
    dot.setAttribute("cx", x(i)); dot.setAttribute("cy", y(values[i])); dot.setAttribute("visibility", "visible");
    showTip(e, `<div class="tt-t">${esc(fmtTime(start + i * step))}</div><div class="tt-r"><span><i class="sw" style="background:${color}"></i>${esc(label)}</span><b>${fmtNum(values[i])}</b></div>`);
  });
  svg.querySelector(".hit").addEventListener("mouseleave", () => { hideTip(); cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); });
}

export function stackedColumns(el, { series, start, step, height = 200, onClick }) {
  // series: [{label, color, values[]}] drawn bottom-up in the given order
  const width = el.clientWidth || 600;
  const n = series[0]?.values.length || 0;
  const totals = Array.from({ length: n }, (_, i) => series.reduce((a, s) => a + s.values[i], 0));
  const scale = niceScale(Math.max(...totals, 1));
  const max = scale.max;
  const { pad, w, h, g } = frame(width, height, scale, n, start, step);
  const bw = Math.max(2, (w / n) - 2);
  let bars = "";
  for (let i = 0; i < n; i++) {
    let acc = 0;
    const x0 = pad.l + (w * i) / n + 1;
    const segs = series.filter((s) => s.values[i] > 0);
    segs.forEach((s, j) => {
      const v = s.values[i];
      const y1 = pad.t + h - (h * (acc + v)) / max, y0 = pad.t + h - (h * acc) / max;
      const hh = Math.max(1, y0 - y1 - (j < segs.length - 1 ? 0 : 0));
      const top = j === segs.length - 1;
      const r = Math.min(3, bw / 2, hh);
      bars += top
        ? `<path d="M${x0},${y0} V${y1 + r} Q${x0},${y1} ${x0 + r},${y1} H${x0 + bw - r} Q${x0 + bw},${y1} ${x0 + bw},${y1 + r} V${y0} Z" fill="${s.color}"/>`
        : `<rect x="${x0}" y="${y1 + 1}" width="${bw}" height="${Math.max(0.5, hh - 1)}" fill="${s.color}"/>`;
      acc += v;
    });
    bars += `<rect class="hit" data-i="${i}" x="${pad.l + (w * i) / n}" y="${pad.t}" width="${w / n}" height="${h}"/>`;
  }
  el.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Alerts over time by severity">${g}${bars}</svg>`;
  el.querySelectorAll(".hit").forEach((r) => {
    r.addEventListener("mousemove", (e) => {
      const i = +r.dataset.i;
      const rows = [...series].reverse().map((s) => `<div class="tt-r"><span><i class="sw" style="background:${s.color}"></i>${esc(s.label)}</span><b>${fmtNum(s.values[i])}</b></div>`).join("");
      showTip(e, `<div class="tt-t">${esc(fmtTime(start + i * step))}</div>${rows}`);
    });
    r.addEventListener("mouseleave", hideTip);
    if (onClick) r.addEventListener("click", () => onClick(+r.dataset.i));
  });
}
