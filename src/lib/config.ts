export const config = {
  app: {
    name: import.meta.env.VITE_APP_NAME || 'Jailbreak Training Simulator',
    version: import.meta.env.VITE_APP_VERSION || '2.0.0',
    env: import.meta.env.VITE_APP_ENV || 'development',
  },
  api: {
    url: import.meta.env.VITE_API_URL || 'http://localhost:3000',
    key: import.meta.env.VITE_API_KEY || '',
  },
  analytics: {
    id: import.meta.env.VITE_ANALYTICS_ID || '',
    enabled: import.meta.env.VITE_ENABLE_ANALYTICS === 'true',
  },
  features: {
    leaderboard: import.meta.env.VITE_ENABLE_LEADERBOARD === 'true',
    certificates: import.meta.env.VITE_ENABLE_CERTIFICATES === 'true',
    multiplayer: import.meta.env.VITE_ENABLE_MULTIPLAYER === 'true',
    pwa: import.meta.env.VITE_ENABLE_PWA === 'true',
  },
  security: {
    rateLimitAttempts: parseInt(import.meta.env.VITE_RATE_LIMIT_ATTEMPTS || '10'),
    rateLimitWindowMs: parseInt(import.meta.env.VITE_RATE_LIMIT_WINDOW_MS || '60000'),
  },
  social: {
    email: import.meta.env.VITE_SOCIAL_EMAIL || 'littlehakr@protonmail.com',
    instagram: import.meta.env.VITE_SOCIAL_INSTAGRAM || 'https://www.instagram.com/little_hakr/',
    tiktok: import.meta.env.VITE_SOCIAL_TIKTOK || 'https://www.tiktok.com/@littlehakr',
    linktree: import.meta.env.VITE_SOCIAL_LINKTREE || 'https://linktr.ee/littlehakr',
    linkedin: import.meta.env.VITE_SOCIAL_LINKEDIN || 'https://www.linkedin.com/in/david-kyazze-ntwatwa',
  },
} as const;