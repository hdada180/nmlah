/* Nemla colony scene: a small dependency-free 3D renderer on a 2D canvas.
   World: the nest (this computer) sits at the origin, hosts float around it,
   open ports orbit their host, and pheromone-trail arcs link everything. */
(function () {
  'use strict';

  const TAU = Math.PI * 2;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const lerp = (a, b, t) => a + (b - a) * t;
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const easeBack = (t) => { const c1 = 1.70158, c3 = c1 + 1; return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2); };
  const MONO = '"JetBrains Mono","DejaVu Sans Mono",ui-monospace,Consolas,monospace';

  const COLORS = {
    ember: '#FF7A1A', amber: '#FFC46B', mint: '#3EE6B4', sky: '#4CC2FF',
    violet: '#A08BFF', rose: '#FF5D8F', gold: '#FFC247', slate: '#8FA0C4', white: '#F4F6FB'
  };

  const CATEGORIES = {
    web: { color: COLORS.sky, ports: [80, 443, 3128, 8000, 8080, 8081, 8443, 8888] },
    remote: { color: COLORS.rose, ports: [22, 23, 1723, 3389, 5900, 5985, 5986, 6000] },
    db: { color: COLORS.violet, ports: [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017] },
    mail: { color: COLORS.mint, ports: [25, 110, 143, 465, 587, 993, 995] },
    files: { color: COLORS.gold, ports: [21, 111, 135, 139, 445, 2049] },
    other: { color: COLORS.slate, ports: [] }
  };
  const PORT_CAT = {};
  Object.keys(CATEGORIES).forEach((c) => CATEGORIES[c].ports.forEach((p) => { PORT_CAT[p] = c; }));
  const categoryOf = (port) => PORT_CAT[port] || 'other';

  function rgba(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return 'rgba(' + (n >> 16) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }

  const sprites = new Map();
  function glowSprite(hex) {
    let s = sprites.get(hex);
    if (s) return s;
    const size = 128;
    s = document.createElement('canvas');
    s.width = s.height = size;
    const g = s.getContext('2d');
    const grd = g.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    grd.addColorStop(0, rgba(hex, 1));
    grd.addColorStop(0.16, rgba(hex, 0.7));
    grd.addColorStop(0.42, rgba(hex, 0.2));
    grd.addColorStop(1, rgba(hex, 0));
    g.fillStyle = grd;
    g.fillRect(0, 0, size, size);
    sprites.set(hex, s);
    return s;
  }

  function hash(str) {
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ((h >>> 0) % 100000) / 100000;
  }

  // R2 low-discrepancy sequence: quasi-uniform points that stay put as more arrive.
  function layout(i) {
    const g = 1.32471795724474602596;
    const u = (0.5 + (i + 1) / g) % 1;
    const v = (0.5 + (i + 1) / (g * g)) % 1;
    const y = (2 * v - 1) * 0.74;
    const ring = Math.sqrt(1 - y * y);
    const R = 190 + 34 * Math.cbrt(i);
    return { x: R * ring * Math.cos(TAU * u), y: R * y, z: R * ring * Math.sin(TAU * u), R: R };
  }

  class NemlaScene {
    constructor(canvas, opts) {
      opts = opts || {};
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.onHover = opts.onHover || function () {};
      this.onSelect = opts.onSelect || function () {};
      this.reduced = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

      this.nodes = new Map();
      this.order = [];
      this.time = 0;
      this.phase = 'idle';
      this.showLabels = true;
      this.hoverIp = null;
      this.selectedIp = null;
      this.insets = { l: 0, r: 0, t: 0, b: 0 };
      this.inset = { x: 0, y: 0 };
      this.rmax = 190;
      this.floorY = -220;
      this.waves = [];
      this.nextWave = 0;
      this.fpsAvg = 16;
      this.lowQuality = false;

      this.cam = { yaw: 0.65, pitch: 0.42, dist: 720, tx: 0, ty: 0, tz: 0 };
      this.goal = { yaw: 0.65, pitch: 0.42, dist: 720, tx: 0, ty: 0, tz: 0 };
      this.vel = { yaw: 0, pitch: 0 };
      this.userZoom = false;
      this.lastInput = -10;
      this.pointer = { x: 0, y: 0, nx: 0, ny: 0, down: false, moved: 0, inside: false };
      this.par = { x: 0, y: 0 };
      this.pinch = null;
      this.pointers = new Map();

      this.dust = [];
      for (let i = 0; i < 260; i++) {
        const r = 900 + Math.random() * 1500, a = Math.random() * TAU, b = Math.acos(2 * Math.random() - 1);
        this.dust.push({ x: r * Math.sin(b) * Math.cos(a), y: r * Math.cos(b), z: r * Math.sin(b) * Math.sin(a), s: 0.6 + Math.random() * 1.6, p: Math.random() * TAU });
      }
      this.cells = this._buildFloor();
      this.logo = new Image();
      this.logo.src = 'brand/nemla-mark.svg';
      this.tmp = { x: 0, y: 0, z: 0, s: 1 };
      this.tmp2 = { x: 0, y: 0, z: 0, s: 1 };
      this.nest = { sx: 0, sy: 0, sr: 0, z: 0 };

      this._bind();
      this._resize();
      this._last = performance.now();
      this._raf = requestAnimationFrame((t) => this._tick(t));
    }

    /* ------------------------------------------------------------ public */

    clear() {
      this.nodes.clear();
      this.order = [];
      this.rmax = 190;
      this.selectedIp = null;
      this.hoverIp = null;
      this.waves = [];
      this.select(null);
      this.resetView();
    }

    setPhase(phase) { this.phase = phase; if (phase === 'discovery' || phase === 'ports') this.nextWave = 0; }
    setLabels(on) { this.showLabels = on; }
    setInsets(l, r, t, b) { this.insets = { l: l, r: r, t: t, b: b }; }

    addHost(info) {
      if (this.nodes.has(info.ip)) return this.nodes.get(info.ip);
      const idx = this.nodes.size;
      const p = layout(idx);
      const h = hash(info.ip);
      const node = {
        ip: info.ip, idx: idx, x: p.x, y: p.y, z: p.z, len: Math.hypot(p.x, p.y, p.z),
        born: this.time, state: 'up', ports: [], os: info.os_guess || '',
        r: 8, color: COLORS.slate, glow: 0,
        lift: (h - 0.5) * 2 * 0.2 + 0.12, side: (hash(info.ip + 's') - 0.5) * 0.3,
        flow: [{ t: Math.random(), v: 0.16 + Math.random() * 0.1 }],
        tx: (hash(info.ip + 'a')) * TAU, tz: (hash(info.ip + 'b')) * Math.PI,
        rings: [{ t0: this.time }], sx: 0, sy: 0, sr: 0, sz: 0
      };
      node.ctx = Math.cos(node.tx); node.stx = Math.sin(node.tx); node.ctz = Math.cos(node.tz); node.stz = Math.sin(node.tz);
      this.nodes.set(info.ip, node);
      this.order.push(node);
      this.rmax = Math.max(this.rmax, p.R);
      return node;
    }

    setHostState(ip, state) {
      const n = this.nodes.get(ip);
      if (!n || n.state === state) return;
      n.state = state;
      const want = state === 'scanning' ? 5 : 1;
      while (n.flow.length < want) n.flow.push({ t: Math.random(), v: 0.28 + Math.random() * 0.25 });
      while (n.flow.length > want) n.flow.pop();
      if (state === 'done') n.rings.push({ t0: this.time });
    }

    addAlarm(ip, severity) {
      let n = this.nodes.get(ip);
      if (!n) { n = this.addHost({ ip: ip }); n.alarmOnly = true; n.r = 11; }
      n.alarm = { sev: severity, t0: this.time };
      return n;
    }

    setHostNew(ip) {
      const n = this.nodes.get(ip);
      if (n) n.isNew = true;
    }

    addGhost(ip) {
      let n = this.nodes.get(ip);
      if (n) return n;
      n = this.addHost({ ip: ip });
      n.ghost = true; n.r = 8; n.state = 'gone'; n.flow = [];
      return n;
    }

    clearAlarms() {
      this.nodes.forEach((n) => { n.alarm = null; });
    }

    setHostRisk(ip, level) {
      const n = this.nodes.get(ip);
      if (n) n.risk = level === 'high' || level === 'medium' ? level : null;
    }

    addPort(ip, port) {
      const n = this.nodes.get(ip);
      if (!n || n.ports.some((p) => p.port === port.port)) return;
      const k = n.ports.length;
      const cat = categoryOf(port.port);
      n.ports.push({
        port: port.port, service: port.service, cat: cat, color: CATEGORIES[cat].color, born: this.time,
        ring: Math.floor(k / 7), ang: (k * 2.399963) % TAU, speed: (0.5 + hash(ip + port.port) * 0.5) * (k % 2 ? 1 : -1) * (0.9 - Math.floor(k / 7) * 0.12)
      });
      n.r = 8 + Math.min(9, n.ports.length * 1.1);
      n.glow = this.time;
    }

    select(ip) {
      this.selectedIp = ip || null;
      const n = ip ? this.nodes.get(ip) : null;
      if (n) {
        this.goal.tx = n.x * 0.55; this.goal.ty = n.y * 0.55; this.goal.tz = n.z * 0.55;
        this.goal.dist = clamp(Math.max(430, n.len * 1.3 + 150), 380, 900);
        this.userZoom = true;
      } else if (!ip) {
        this.goal.tx = this.goal.ty = this.goal.tz = 0;
        if (!this.userZoomManual) this.userZoom = false;
      }
      this.onSelect(n ? n.ip : null);
    }

    hover(ip) { this.hoverIp = ip || null; }

    resetView() {
      this.goal.tx = this.goal.ty = this.goal.tz = 0;
      this.goal.yaw = this.cam.yaw; this.goal.pitch = 0.42;
      this.userZoom = false; this.userZoomManual = false;
      this.selectedIp = null;
      this.vel.yaw = this.vel.pitch = 0;
      this.lastInput = this.time;
    }

    /* ---------------------------------------------------------- internals */

    _buildFloor() {
      const cells = [], HR = 56, W = Math.sqrt(3) * HR, limit = 900;
      for (let r = -20; r <= 20; r++) {
        for (let q = -20; q <= 20; q++) {
          const x = W * (q + r / 2), z = 1.5 * HR * r, d = Math.hypot(x, z);
          if (d > limit) continue;
          const v = [];
          for (let k = 0; k < 6; k++) { const a = TAU / 6 * k + Math.PI / 6; v.push([x + HR * 0.94 * Math.cos(a), z + HR * 0.94 * Math.sin(a)]); }
          cells.push({ x: x, z: z, d: d, v: v });
        }
      }
      return cells;
    }

    _bind() {
      const c = this.canvas;
      new ResizeObserver(() => this._resize()).observe(c);
      c.addEventListener('pointerdown', (e) => {
        c.setPointerCapture(e.pointerId);
        this.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
        this.pointer.down = true; this.pointer.moved = 0; this.pointer.t0 = performance.now();
        this.pointer.x = e.clientX; this.pointer.y = e.clientY;
        const r0 = c.getBoundingClientRect();
        this.pointer.mx = e.clientX - r0.left; this.pointer.my = e.clientY - r0.top;
        if (this.pointers.size === 2) this.pinch = this._pinchDist();
        c.classList.add('dragging');
      });
      c.addEventListener('pointermove', (e) => {
        const rect = c.getBoundingClientRect();
        this.pointer.inside = true;
        this.pointer.nx = (e.clientX - rect.left) / rect.width * 2 - 1;
        this.pointer.ny = (e.clientY - rect.top) / rect.height * 2 - 1;
        const prev = this.pointers.get(e.pointerId);
        if (prev) { prev.x = e.clientX; prev.y = e.clientY; }
        if (this.pointer.down && this.pointers.size === 1) {
          const dx = e.clientX - this.pointer.x, dy = e.clientY - this.pointer.y;
          this.pointer.moved += Math.abs(dx) + Math.abs(dy);
          this.goal.yaw -= dx * 0.0055; this.goal.pitch = clamp(this.goal.pitch + dy * 0.0045, 0.06, 1.38);
          this.vel.yaw = -dx * 0.0055; this.vel.pitch = dy * 0.0045;
          this.lastInput = this.time;
        } else if (this.pointers.size === 2) {
          const d = this._pinchDist();
          if (this.pinch) { this.goal.dist = clamp(this.goal.dist * this.pinch / d, 260, 2000); this.userZoom = this.userZoomManual = true; }
          this.pinch = d; this.lastInput = this.time;
        }
        this.pointer.x = e.clientX; this.pointer.y = e.clientY;
        this.pointer.mx = e.clientX - rect.left; this.pointer.my = e.clientY - rect.top;
      });
      const up = (e) => {
        this.pointers.delete(e.pointerId);
        if (this.pointers.size < 2) this.pinch = null;
        if (!this.pointers.size) {
          this.pointer.down = false; c.classList.remove('dragging');
          if (this.pointer.moved < 6 && performance.now() - this.pointer.t0 < 400 && e.type === 'pointerup') {
            const hit = this._pick(this.pointer.mx, this.pointer.my);
            this.select(hit ? hit.ip : null);
          }
        }
      };
      c.addEventListener('pointerup', up);
      c.addEventListener('pointercancel', up);
      c.addEventListener('pointerleave', () => {
        this.pointer.inside = false; this._lastHover = null;
        c.classList.remove('over-node'); this.onHover(null);
      });
      c.addEventListener('wheel', (e) => {
        e.preventDefault();
        this.goal.dist = clamp(this.goal.dist * Math.exp(e.deltaY * 0.0012), 260, 2000);
        this.userZoom = this.userZoomManual = true;
        this.lastInput = this.time;
      }, { passive: false });
      c.addEventListener('dblclick', () => this.select(null));
    }

    _pinchDist() {
      const p = [...this.pointers.values()];
      return Math.hypot(p[0].x - p[1].x, p[0].y - p[1].y) || 1;
    }

    _resize() {
      const c = this.canvas, dpr = Math.min(window.devicePixelRatio || 1, 2);
      this.w = c.clientWidth || window.innerWidth;
      this.h = c.clientHeight || window.innerHeight;
      c.width = Math.round(this.w * dpr); c.height = Math.round(this.h * dpr);
      this.dpr = dpr;
      this.focal = Math.min(this.w * 0.95, this.h * 1.25);
    }

    _pick(mx, my) {
      let best = null, bestD = 1e9;
      for (const n of this.order) {
        if (n.sr <= 0) continue;
        const d = Math.hypot(n.sx - mx, n.sy - my);
        if (d < Math.max(n.sr * 1.6, 14) && (d < bestD)) { best = n; bestD = d; }
      }
      return best;
    }

    _project(x, y, z, o) {
      x -= this.cam.tx; y -= this.cam.ty; z -= this.cam.tz;
      const x1 = x * this._cy - z * this._sy;
      const z1 = x * this._sy + z * this._cy;
      const y1 = y * this._cp + z1 * this._sp;
      const z2 = -y * this._sp + z1 * this._cp + this.cam.dist;
      const s = this.focal / Math.max(z2, 20);
      o.x = this.cx + x1 * s; o.y = this.cy - y1 * s; o.z = z2; o.s = s;
      return o;
    }

    _tick(now) {
      const dt = Math.min(0.05, (now - this._last) / 1000);
      this._last = now;
      this.time += dt;
      this.fpsAvg = lerp(this.fpsAvg, dt * 1000, 0.05);
      if (this.fpsAvg > 26 && !this.lowQuality) this.lowQuality = true;
      if (this.fpsAvg < 18 && this.lowQuality) this.lowQuality = false;
      this._update(dt);
      this._draw(dt);
      this._raf = requestAnimationFrame((t) => this._tick(t));
    }

    _update(dt) {
      const cam = this.cam, goal = this.goal, k = 1 - Math.exp(-dt * 6);
      // idle auto-orbit and inertia
      const idle = this.time - this.lastInput > 3.5 && !this.selectedIp && !this.pointer.down;
      if (idle && !this.reduced) goal.yaw += dt * 0.07;
      if (!this.pointer.down) { goal.yaw += this.vel.yaw * 0.5; goal.pitch = clamp(goal.pitch + this.vel.pitch * 0.5, 0.06, 1.38); this.vel.yaw *= 0.9; this.vel.pitch *= 0.9; }
      if (!this.userZoom) goal.dist = clamp(470 + this.rmax * 1.25, 600, 1800);
      cam.yaw = lerp(cam.yaw, goal.yaw, k);
      cam.pitch = lerp(cam.pitch, goal.pitch, k);
      cam.dist = lerp(cam.dist, goal.dist, 1 - Math.exp(-dt * 4));
      cam.tx = lerp(cam.tx, goal.tx, k); cam.ty = lerp(cam.ty, goal.ty, k); cam.tz = lerp(cam.tz, goal.tz, k);

      // panels push the scene toward the free area between them
      const i = this.insets, want = { x: (i.l - i.r) / 2, y: (i.t - i.b) / 2 };
      this.inset.x = lerp(this.inset.x, want.x, 1 - Math.exp(-dt * 5));
      this.inset.y = lerp(this.inset.y, want.y, 1 - Math.exp(-dt * 5));

      // gentle parallax toward the pointer
      const tx = this.reduced || !this.pointer.inside ? 0 : this.pointer.nx, ty = this.reduced || !this.pointer.inside ? 0 : this.pointer.ny;
      this.par.x = lerp(this.par.x, tx, 1 - Math.exp(-dt * 3)); this.par.y = lerp(this.par.y, ty, 1 - Math.exp(-dt * 3));

      this.floorY = lerp(this.floorY, -(this.rmax * 0.78 + 60), 1 - Math.exp(-dt * 2));

      // scan waves
      if ((this.phase === 'discovery' || this.phase === 'ports') && this.time >= this.nextWave) {
        this.waves.push({ t0: this.time, strong: this.phase === 'discovery' });
        this.nextWave = this.time + (this.phase === 'discovery' ? 1.5 : 2.6);
      }
      this.waves = this.waves.filter((w) => this.time - w.t0 < 3.4);

      for (const n of this.order) {
        for (const f of n.flow) { f.t += dt * f.v * (this.reduced ? 0.4 : 1); if (f.t > 1) f.t -= 1; }
        n.rings = n.rings.filter((r) => this.time - r.t0 < 1.4);
      }
    }

    /* -------------------------------------------------------------- draw */

    _draw() {
      const ctx = this.ctx, w = this.w, h = this.h;
      const cam = this.cam, T = this.time;
      const yaw = cam.yaw + this.par.x * 0.05, pitch = clamp(cam.pitch + this.par.y * 0.03, 0.05, 1.4);
      this._cy = Math.cos(yaw); this._sy = Math.sin(yaw); this._cp = Math.cos(pitch); this._sp = Math.sin(pitch);
      this.cx = w / 2 + this.inset.x; this.cy = h / 2 + this.inset.y + Math.min(30, h * 0.03);

      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      ctx.lineCap = 'round'; ctx.lineJoin = 'round';
      ctx.direction = 'ltr'; // IP addresses must not be bidi-reordered when the page is RTL

      this._drawDust();
      this._drawFloor();
      this._drawWaves();
      this._drawEdges();

      // depth-sorted bodies: nodes (with their satellites) and the nest
      const p = this._project(0, 0, 0, this.tmp);
      this.nest.sx = p.x; this.nest.sy = p.y; this.nest.sr = 46 * p.s; this.nest.z = p.z;
      const list = [];
      for (const n of this.order) {
        this._project(n.x, n.y, n.z, this.tmp);
        n.sx = this.tmp.x; n.sy = this.tmp.y; n.sz = this.tmp.z; n.ss = this.tmp.s;
        const born = clamp((T - n.born) / 0.9, 0, 1);
        n.sr = n.r * this.tmp.s * easeBack(born) * (n === this._selectedNode() ? 1.12 : 1);
        if (n.sr < 0) n.sr = 0;
        list.push(n);
      }
      list.push(this.nest);
      list.sort((a, b) => (b.sz !== undefined ? b.sz : b.z) - (a.sz !== undefined ? a.sz : a.z));
      const nestZ = this.nest.z;
      for (const n of list) {
        if (n === this.nest) this._drawNest(); else this._drawNode(n, nestZ);
      }
      this._drawReticle();
      this._drawLabels();

      // pointer hover
      if (this.pointer.inside && !this.pointer.down && this.pointer.mx !== undefined) {
        const hit = this._pick(this.pointer.mx, this.pointer.my);
        const ip = hit ? hit.ip : null;
        if (ip !== this._lastHover) {
          this._lastHover = ip;
          this.canvas.classList.toggle('over-node', !!ip);
          this.onHover(ip ? { ip: ip, node: hit, x: this.pointer.x, y: this.pointer.y } : null);
        }
      }
    }

    _selectedNode() { return this.selectedIp ? this.nodes.get(this.selectedIp) : null; }

    _drawDust() {
      const ctx = this.ctx, T = this.time, o = this.tmp;
      ctx.globalCompositeOperation = 'lighter';
      const step = this.lowQuality ? 2 : 1;
      for (let i = 0; i < this.dust.length; i += step) {
        const d = this.dust[i];
        this._project(d.x, d.y, d.z, o);
        if (o.z < 50 || o.x < -10 || o.x > this.w + 10 || o.y < -10 || o.y > this.h + 10) continue;
        const a = (0.18 + 0.32 * (0.5 + 0.5 * Math.sin(T * 0.8 + d.p))) * clamp(1.4 - o.z / 3200, 0.15, 1);
        ctx.fillStyle = 'rgba(190,205,255,' + a.toFixed(3) + ')';
        ctx.beginPath(); ctx.arc(o.x, o.y, d.s * Math.max(0.6, o.s * 1.4), 0, TAU); ctx.fill();
      }
      ctx.globalCompositeOperation = 'source-over';
    }

    _drawFloor() {
      const ctx = this.ctx, a = this.tmp, y = this.floorY, T = this.time;
      const cells = this.cells, step = this.lowQuality ? 2 : 1;
      ctx.lineWidth = 1;
      const waveR = this.waves.map((wv) => ({ r: (T - wv.t0) * 330, a: wv.strong ? 1 : 0.6, f: 1 - (T - wv.t0) / 3.4 }));
      for (let ci = 0; ci < cells.length; ci += step) {
        const c = cells[ci];
        let alpha = 0.035 + 0.10 * Math.pow(1 - c.d / 900, 1.6);
        let lit = 0;
        for (const wv of waveR) { const e = (c.d - wv.r) / 46; lit = Math.max(lit, Math.exp(-e * e) * wv.a * wv.f); }
        alpha += lit * 0.55;
        if (alpha < 0.02) continue;
        ctx.beginPath();
        let ok = true;
        for (let k = 0; k < 6; k++) {
          this._project(c.v[k][0], y, c.v[k][1], a);
          if (a.z < 40) { ok = false; break; }
          if (k === 0) ctx.moveTo(a.x, a.y); else ctx.lineTo(a.x, a.y);
        }
        if (!ok) continue;
        ctx.closePath();
        if (lit > 0.08) { ctx.fillStyle = 'rgba(255,122,26,' + (lit * 0.10).toFixed(3) + ')'; ctx.fill(); }
        ctx.strokeStyle = lit > 0.08 ? 'rgba(255,170,90,' + alpha.toFixed(3) + ')' : 'rgba(150,170,220,' + alpha.toFixed(3) + ')';
        ctx.stroke();
      }
    }

    _ring3d(radius, y, tiltX, tiltZ, rot, seg) {
      const a = this.tmp2, ctx = this.ctx, ct = Math.cos(tiltX), st = Math.sin(tiltX), cz = Math.cos(tiltZ), sz = Math.sin(tiltZ);
      ctx.beginPath();
      let started = false;
      for (let i = 0; i <= seg; i++) {
        const ang = rot + (i / seg) * TAU;
        let x = radius * Math.cos(ang), yy = 0, z = radius * Math.sin(ang);
        const y1 = yy * ct - z * st, z1 = yy * st + z * ct;
        const x2 = x * cz - y1 * sz, y2 = x * sz + y1 * cz;
        this._project(x2, y2 + y, z1, a);
        if (a.z < 30) { started = false; continue; }
        if (!started) { ctx.moveTo(a.x, a.y); started = true; } else ctx.lineTo(a.x, a.y);
      }
    }

    _drawWaves() {
      const ctx = this.ctx, T = this.time;
      ctx.globalCompositeOperation = 'lighter';
      for (const wv of this.waves) {
        const age = T - wv.t0, r = age * 330, f = clamp(1 - age / 3.4, 0, 1);
        if (r < 8) continue;
        this._ring3d(r, 0, 0, 0, 0, 72);
        ctx.strokeStyle = 'rgba(255,140,50,' + (0.5 * f * (wv.strong ? 1 : 0.6)).toFixed(3) + ')';
        ctx.lineWidth = 2.2; ctx.stroke();
        ctx.strokeStyle = 'rgba(255,190,110,' + (0.16 * f).toFixed(3) + ')';
        ctx.lineWidth = 9; ctx.stroke();
      }
      ctx.globalCompositeOperation = 'source-over';
    }

    _bez(n, t, o) {
      // quadratic arc nest -> host, lifted and swirled a little
      const len = n.len, mx = n.x * 0.5, my = n.y * 0.5, mz = n.z * 0.5;
      const sx = -n.z / (len || 1), sz = n.x / (len || 1);
      const px = mx + sx * len * n.side, py = my + len * n.lift, pz = mz + sz * len * n.side;
      const u = 1 - t;
      return this._project(2 * u * t * px + t * t * n.x, 2 * u * t * py + t * t * n.y, 2 * u * t * pz + t * t * n.z, o);
    }

    _drawEdges() {
      const ctx = this.ctx, a = this.tmp, T = this.time, sel = this.selectedIp, hov = this.hoverIp || this._lastHover;
      const seg = this.lowQuality ? 6 : 10;
      ctx.globalCompositeOperation = 'lighter';
      for (const n of this.order) {
        if (n.ghost) continue;
        const born = clamp((T - n.born) / 0.8, 0, 1);
        if (born <= 0) continue;
        const active = n.state === 'scanning', chosen = n.ip === sel || n.ip === hov;
        const alpha = (n.alarm ? 0.9 : chosen ? 0.8 : active ? 0.55 : n.state === 'done' ? 0.2 : 0.11) * born;
        ctx.strokeStyle = n.alarm ? 'rgba(255,93,143,' + alpha + ')' : chosen ? 'rgba(255,215,160,' + alpha + ')' : 'rgba(255,122,26,' + alpha + ')';
        ctx.lineWidth = n.alarm ? 2.8 : chosen ? 2.4 : active ? 1.8 : 1.1;
        ctx.beginPath();
        let started = false;
        const upto = ease(born);
        for (let i = 0; i <= seg; i++) {
          const t = (i / seg) * upto;
          this._bez(n, t, a);
          if (a.z < 30) { started = false; continue; }
          if (!started) { ctx.moveTo(a.x, a.y); started = true; } else ctx.lineTo(a.x, a.y);
        }
        ctx.stroke();
        // pheromone: bright specks travelling along the trail
        if (born >= 1) {
          const spr = glowSprite(active ? COLORS.amber : COLORS.ember);
          for (const f of n.flow) {
            this._bez(n, f.t, a);
            if (a.z < 30) continue;
            const s = (active ? 15 : 9) * Math.max(0.5, a.s);
            ctx.globalAlpha = active ? 0.95 : 0.5;
            ctx.drawImage(spr, a.x - s / 2, a.y - s / 2, s, s);
          }
          ctx.globalAlpha = 1;
        }
      }
      ctx.globalCompositeOperation = 'source-over';
    }

    _drawNest() {
      const ctx = this.ctx, T = this.time, n = this.nest, sr = n.sr;
      const pulse = 1 + 0.06 * Math.sin(T * 2.2);
      ctx.globalCompositeOperation = 'lighter';
      let s = sr * 6.5 * pulse; const spr = glowSprite(COLORS.ember);
      ctx.globalAlpha = 0.85; ctx.drawImage(spr, n.sx - s / 2, n.sy - s / 2, s, s);
      s = sr * 3; ctx.globalAlpha = 0.6; ctx.drawImage(glowSprite(COLORS.amber), n.sx - s / 2, n.sy - s / 2, s, s);
      ctx.globalAlpha = 1;
      // orbit rings with small guard ants
      const rings = [[74, 0.5, 0.0, 0.22], [104, -0.3, 0.9, 0.16], [138, 0.15, -0.6, 0.11]];
      rings.forEach((r, i) => {
        this._ring3d(r[0], 0, r[1], r[2], T * 0.1 * (i % 2 ? -1 : 1), 64);
        ctx.strokeStyle = 'rgba(255,150,70,' + r[3] + ')'; ctx.lineWidth = 1.3; ctx.stroke();
        const ang = T * (0.7 - i * 0.2) * (i % 2 ? -1 : 1), a = this.tmp2;
        const x = r[0] * Math.cos(ang), z = r[0] * Math.sin(ang), ct = Math.cos(r[1]), st = Math.sin(r[1]), cz = Math.cos(r[2]), sz = Math.sin(r[2]);
        const y1 = -z * st, z1 = z * ct, x2 = x * cz - y1 * sz, y2 = x * sz + y1 * cz;
        this._project(x2, y2, z1, a);
        if (a.z > 30) { const g = 16 * a.s; ctx.drawImage(glowSprite(COLORS.amber), a.x - g / 2, a.y - g / 2, g, g); }
      });
      ctx.globalCompositeOperation = 'source-over';
      // hex plate + logo billboard
      const R = sr * 1.02;
      ctx.beginPath();
      for (let k = 0; k < 6; k++) { const a = Math.PI / 6 + k * TAU / 6; const px = n.sx + R * Math.cos(a), py = n.sy + R * Math.sin(a); if (k) ctx.lineTo(px, py); else ctx.moveTo(px, py); }
      ctx.closePath();
      const g = ctx.createRadialGradient(n.sx, n.sy - R * 0.3, R * 0.1, n.sx, n.sy, R);
      g.addColorStop(0, 'rgba(48,30,20,.95)'); g.addColorStop(1, 'rgba(14,10,10,.95)');
      ctx.fillStyle = g; ctx.fill();
      ctx.lineWidth = Math.max(1.5, sr * 0.06); ctx.strokeStyle = 'rgba(255,140,60,.95)'; ctx.stroke();
      if (this.logo.complete && this.logo.naturalWidth) {
        const L = R * 1.45; ctx.drawImage(this.logo, n.sx - L / 2, n.sy - L / 2 - 1, L, L);
      }
    }

    _drawNode(n, nestZ) {
      const ctx = this.ctx, T = this.time, x = n.sx, y = n.sy, r = n.sr;
      if (r <= 0.2) return;
      if (x < -80 || x > this.w + 80 || y < -80 || y > this.h + 80) return;
      const fog = clamp(1.15 - Math.max(0, n.sz - (this.cam.dist - 250)) / 1100, 0.4, 1);
      if (n.ghost) {
        // a host that answered last time and did not now: only a dashed outline is left
        ctx.globalAlpha = 0.6 * fog; ctx.strokeStyle = 'rgba(143,160,196,.85)'; ctx.lineWidth = 1.6;
        ctx.setLineDash([4, 4]); ctx.beginPath(); ctx.arc(x, y, r * 1.3, 0, TAU); ctx.stroke();
        ctx.setLineDash([]); ctx.globalAlpha = 1;
        return;
      }
      const chosen = n.ip === this.selectedIp || n.ip === (this.hoverIp || this._lastHover);
      const base = n.alarm ? COLORS.rose : n.state === 'scanning' ? COLORS.ember : n.state === 'done' ? COLORS.mint : COLORS.slate;
      const beat = n.state === 'scanning' ? 1 + 0.16 * Math.sin(T * 9) : 1;

      const sat = this._satellites(n);
      // satellites behind the body
      for (const s of sat) if (s.z > n.sz) this._drawSat(s, fog);

      ctx.globalCompositeOperation = 'lighter';
      let g = r * (chosen ? 6 : 4.6) * beat; ctx.globalAlpha = (chosen ? 1 : 0.8) * fog;
      ctx.drawImage(glowSprite(base), x - g / 2, y - g / 2, g, g);
      const since = T - n.glow;
      if (since < 0.9) { g = r * (4 + (1 - since / 0.9) * 8); ctx.globalAlpha = (1 - since / 0.9) * 0.7; ctx.drawImage(glowSprite(COLORS.amber), x - g / 2, y - g / 2, g, g); }
      ctx.globalAlpha = 1;
      for (const rg of n.rings) {
        const k = (T - rg.t0) / 1.4;
        ctx.strokeStyle = rgba(base, (1 - k) * 0.7);
        ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(x, y, r * (1.2 + ease(k) * 4.5), 0, TAU); ctx.stroke();
      }
      if (n.risk) {
        // a slow warning pulse: rose for high findings, gold for medium
        const col = n.risk === 'high' ? COLORS.rose : COLORS.gold;
        const pulse = 0.5 + 0.5 * Math.sin(T * (n.risk === 'high' ? 3.4 : 2.2) + n.idx);
        g = r * (5.2 + pulse * 1.4); ctx.globalAlpha = (0.42 + 0.25 * pulse) * fog;
        ctx.drawImage(glowSprite(col), x - g / 2, y - g / 2, g, g);
        ctx.globalAlpha = 1;
        ctx.strokeStyle = rgba(col, 0.5 + 0.4 * pulse); ctx.lineWidth = 1.7;
        ctx.setLineDash([3, 4]); ctx.beginPath(); ctx.arc(x, y, r * 1.85 + pulse * 2.5, 0, TAU); ctx.stroke();
        ctx.setLineDash([]);
      }
      if (n.isNew) {
        const ph = (T * 0.9 + n.idx * 0.13) % 1;
        ctx.strokeStyle = rgba(COLORS.sky, (1 - ph) * 0.75); ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(x, y, r * (1.5 + ph * 3.6), 0, TAU); ctx.stroke();
      }
      if (n.alarm) {
        // an intruder: shock rings roll outward from the node and a rose flare sits on it
        for (let k = 0; k < 3; k++) {
          const ph = (T * 0.75 + k / 3) % 1;
          ctx.strokeStyle = rgba(COLORS.rose, (1 - ph) * 0.8); ctx.lineWidth = 2.4;
          ctx.beginPath(); ctx.arc(x, y, r * (1.7 + ph * 7.5), 0, TAU); ctx.stroke();
        }
        g = r * 9; ctx.globalAlpha = 0.6 * fog; ctx.drawImage(glowSprite(COLORS.rose), x - g / 2, y - g / 2, g, g);
        ctx.globalAlpha = 1;
      }
      ctx.globalCompositeOperation = 'source-over';

      // body: a glossy orb
      const grd = ctx.createRadialGradient(x - r * 0.35, y - r * 0.4, r * 0.1, x, y, r);
      grd.addColorStop(0, '#FFFFFF'); grd.addColorStop(0.35, base); grd.addColorStop(1, rgba(base, 0.55));
      ctx.globalAlpha = fog;
      ctx.fillStyle = grd; ctx.beginPath(); ctx.arc(x, y, r, 0, TAU); ctx.fill();
      ctx.lineWidth = chosen ? 2 : 1; ctx.strokeStyle = chosen ? 'rgba(255,255,255,.95)' : 'rgba(255,255,255,.45)'; ctx.stroke();
      ctx.globalAlpha = 1;

      for (const s of sat) if (s.z <= n.sz) this._drawSat(s, fog);
      n._sat = sat;
    }

    _satellites(n) {
      const out = [], T = this.time, o = { x: 0, y: 0, z: 0, s: 1 };
      for (const p of n.ports) {
        const born = clamp((T - p.born) / 0.7, 0, 1);
        const R = n.r * 1.9 + 8 + p.ring * 9;
        const ang = p.ang + T * p.speed;
        const x0 = R * Math.cos(ang), z0 = R * Math.sin(ang);
        const y1 = -z0 * n.stx, z1 = z0 * n.ctx;
        const x2 = x0 * n.ctz - y1 * n.stz, y2 = x0 * n.stz + y1 * n.ctz;
        this._project(n.x + x2, n.y + y2, n.z + z1, o);
        out.push({ x: o.x, y: o.y, z: o.z, s: o.s, port: p, scale: easeBack(born), r: n.r * 0.42 });
      }
      return out;
    }

    _drawSat(s, fog) {
      const ctx = this.ctx, r = Math.max(1.6, s.r * s.s * Math.max(s.scale, 0));
      const c = s.port.color;
      ctx.globalCompositeOperation = 'lighter';
      const g = r * 5; ctx.globalAlpha = 0.9 * fog; ctx.drawImage(glowSprite(c), s.x - g / 2, s.y - g / 2, g, g);
      ctx.globalCompositeOperation = 'source-over';
      ctx.globalAlpha = fog; ctx.fillStyle = c; ctx.beginPath(); ctx.arc(s.x, s.y, r, 0, TAU); ctx.fill();
      ctx.fillStyle = 'rgba(255,255,255,.75)'; ctx.beginPath(); ctx.arc(s.x - r * 0.3, s.y - r * 0.3, r * 0.35, 0, TAU); ctx.fill();
      ctx.globalAlpha = 1;
    }

    _drawReticle() {
      const n = this._selectedNode();
      if (!n || n.sr <= 0) return;
      const ctx = this.ctx, T = this.time, r = n.sr * 2.3 + 10;
      ctx.save();
      ctx.strokeStyle = 'rgba(255,196,107,.95)'; ctx.lineWidth = 1.6;
      ctx.setLineDash([7, 7]); ctx.lineDashOffset = -T * 16;
      ctx.beginPath(); ctx.arc(n.sx, n.sy, r, 0, TAU); ctx.stroke();
      ctx.setLineDash([]); ctx.lineWidth = 2.4;
      for (let k = 0; k < 4; k++) {
        const a = T * 0.9 + k * Math.PI / 2;
        ctx.beginPath(); ctx.arc(n.sx, n.sy, r + 7, a, a + 0.32); ctx.stroke();
      }
      ctx.restore();
      // port numbers for the selected host
      if (n._sat) {
        ctx.font = '600 10px ' + MONO; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        for (const s of n._sat) {
          if (s.scale < 0.8) continue;
          ctx.lineWidth = 3; ctx.strokeStyle = 'rgba(6,8,12,.9)'; ctx.strokeText(s.port.port, s.x, s.y - s.r * s.s - 9);
          ctx.fillStyle = s.port.color; ctx.fillText(s.port.port, s.x, s.y - s.r * s.s - 9);
        }
      }
    }

    _drawLabels() {
      const ctx = this.ctx;
      ctx.font = '600 11px ' + MONO; ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
      const many = this.order.length > 60, hov = this.hoverIp || this._lastHover;
      for (const n of this.order) {
        const chosen = n.ip === this.selectedIp || n.ip === hov || !!n.alarm || !!n.ghost || !!n.isNew;
        if (!chosen && (!this.showLabels || n.sr < (many ? 11 : 4))) continue;
        if (n.sx < -40 || n.sx > this.w + 40) continue;
        const tag = n.alarm ? '! ' : n.ghost ? '− ' : n.isNew ? '+ ' : '';
        const text = tag + n.ip, tx = n.sx + n.sr + 8, ty = n.sy - n.sr * 0.2;
        ctx.lineWidth = 3.5; ctx.strokeStyle = 'rgba(6,8,12,.92)'; ctx.strokeText(text, tx, ty);
        ctx.fillStyle = n.alarm ? '#FF8FB0' : n.isNew ? '#8FDBFF' : n.ghost ? 'rgba(160,175,205,.8)' : chosen ? '#FFFFFF' : 'rgba(225,232,247,.82)';
        ctx.fillText(text, tx, ty);
      }
    }
  }

  window.NemlaScene = NemlaScene;
  window.NemlaScene.COLORS = COLORS;
  window.NemlaScene.CATEGORIES = CATEGORIES;
  window.NemlaScene.categoryOf = categoryOf;
})();
