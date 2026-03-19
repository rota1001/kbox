/* UI controls: theme, pause/resume, filters, export */
'use strict';

var KControls = {
  init: function() {
    /* Theme toggle */
    var btn = document.getElementById('btn-theme');
    if (btn) btn.addEventListener('click', function() {
      document.body.classList.toggle('light');
      localStorage.setItem('kbox-theme',
        document.body.classList.contains('light') ? 'light' : 'dark');
    });

    /* Restore theme */
    if (localStorage.getItem('kbox-theme') === 'light')
      document.body.classList.add('light');

    /* Pause/resume */
    var pauseBtn = document.getElementById('btn-pause');
    if (pauseBtn) pauseBtn.addEventListener('click', function() {
      var want = !KState.paused;
      pauseBtn.disabled = true;
      fetch('/api/control', {
        method: 'POST',
        body: JSON.stringify({ action: want ? 'pause' : 'resume' })
      }).then(function(res) {
        if (!res.ok) throw new Error('server error');
        KState.paused = want;
        pauseBtn.textContent = want ? 'Resume' : 'Pause';
      }).catch(function(){}).finally(function() {
        pauseBtn.disabled = false;
      });
    });

    /* Event filters */
    var fSc = document.getElementById('f-syscall');
    var fProc = document.getElementById('f-process');
    var fErr = document.getElementById('f-errors');
    if (fSc) fSc.addEventListener('change', function() {
      KEvents.filters.syscall = fSc.checked;
    });
    if (fProc) fProc.addEventListener('change', function() {
      KEvents.filters.process = fProc.checked;
    });
    if (fErr) fErr.addEventListener('change', function() {
      KEvents.filters.errorsOnly = fErr.checked;
    });

    /* Export CSV (chart data from snapshot history) */
    var csvBtn = document.getElementById('btn-export-csv');
    if (csvBtn) csvBtn.addEventListener('click', function() {
      KControls.exportCSV();
    });

    /* Export JSON (event feed) */
    var jsonBtn = document.getElementById('btn-export-json');
    if (jsonBtn) jsonBtn.addEventListener('click', function() {
      KControls.exportJSON();
    });
  },

  exportCSV: function() {
    var rows = ['timestamp_ns,uptime_s,syscalls,continue,return,enosys,' +
                'ctx_switches,mem_free_kb,mem_cached_kb,pgfault,loadavg_1'];
    KState.snapHistory.forEach(function(s) {
      var d = s.dispatch || {};
      rows.push([
        s.timestamp_ns,
        (s.uptime_ns / 1e9).toFixed(1),
        d.total || 0, d['continue'] || 0, d['return'] || 0, d.enosys || 0,
        s.context_switches || 0,
        s.mem ? s.mem.free : 0,
        s.mem ? s.mem.cached : 0,
        s.pgfault || 0,
        s.loadavg ? s.loadavg[0] : 0
      ].join(','));
    });
    KControls._download('kbox-telemetry.csv', rows.join('\n'), 'text/csv');
  },

  exportJSON: function() {
    var data = JSON.stringify(KState.events, null, 2);
    KControls._download('kbox-events.json', data, 'application/json');
  },

  _download: function(filename, content, mime) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
};
