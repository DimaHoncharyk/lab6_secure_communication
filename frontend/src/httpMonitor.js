const listeners = new Set();
let requests = [];

export function subscribeHttpMonitor(listener) {
  listeners.add(listener);
  listener([...requests]);

  return () => {
    listeners.delete(listener);
  };
}

export function addHttpRequest(entry) {
  requests = [
    {
      id: crypto.randomUUID(),
      timestamp: new Date().toLocaleTimeString(),
      ...entry
    },
    ...requests
  ].slice(0, 100);

  for (const listener of listeners) {
    listener([...requests]);
  }
}

export function clearHttpRequests() {
  requests = [];

  for (const listener of listeners) {
    listener([]);
  }
}
