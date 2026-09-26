(() => {
  const message = document.getElementById('live');
  const status = document.getElementById('socket-state');
  let socket = null;
  let active = true;
  let historyRestores = 0;

  function connect() {
    if (!active || socket) return;
    status.textContent = 'WebSocket connecting…';
    const current = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
    socket = current;
    current.onopen = () => {
      if (socket === current && active) status.textContent = 'WebSocket connected; history restores: ' + historyRestores;
    };
    current.onmessage = event => {
      if (socket === current && active) message.textContent = event.data;
    };
    current.onerror = () => {
      if (socket === current && active) status.textContent = 'WebSocket failed';
    };
    current.onclose = event => {
      if (socket !== current || !active) return;
      socket = null;
      status.textContent = 'WebSocket closed (code ' + event.code + ')';
    };
  }

  window.addEventListener('pagehide', () => {
    active = false;
    const previous = socket;
    socket = null;
    status.textContent = 'WebSocket paused for navigation';
    if (previous && previous.readyState < WebSocket.CLOSING) previous.close(1000, 'page hidden');
  });
  window.addEventListener('pageshow', event => {
    active = true;
    if (event.persisted) {
      historyRestores++;
      connect();
    }
  });
  connect();
})();
