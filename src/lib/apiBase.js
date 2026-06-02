/** Express API origin — must match PORT in .env */
const DEFAULT_API = 'http://localhost:7000';

/** Lovable/TanStack sandbox often injects this; ignore when our .env uses another port */
const STALE_SANDBOX_API = 'http://localhost:5000';

function resolveApiBase() {
  if (typeof localStorage !== 'undefined') {
    const override = localStorage.getItem('fl_api_base');
    if (override) return override;
  }

  const fromVite = import.meta.env.VITE_API_URL;
  if (fromVite && fromVite !== STALE_SANDBOX_API) return fromVite;

  return DEFAULT_API;
}

export const API_BASE = resolveApiBase();
