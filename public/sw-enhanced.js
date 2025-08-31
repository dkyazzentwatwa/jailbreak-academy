
const CACHE_NAME = 'jailbreak-sim-secure-v2.0.0';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/favicon.ico',
  '/manifest.json'
];

// Security configuration
const ALLOWED_ORIGINS = [self.location.origin];
const MAX_CACHE_SIZE = 50 * 1024 * 1024; // 50MB
const CACHE_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days

// Install event with integrity checks
self.addEventListener('install', (event) => {
  console.log('[SW] Installing service worker with enhanced security');
  
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      console.log('[SW] Caching static assets with integrity validation');
      
      // Cache static assets with validation
      for (const asset of STATIC_ASSETS) {
        try {
          const response = await fetch(asset);
          if (response.ok && isValidResponse(response)) {
            await cache.put(asset, response);
          } else {
            console.warn(`[SW] Failed to cache ${asset}: Invalid response`);
          }
        } catch (error) {
          console.warn(`[SW] Failed to cache ${asset}:`, error);
        }
      }
    })
  );
  
  self.skipWaiting();
});

// Activate event with security cleanup
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating service worker with security cleanup');
  
  event.waitUntil(
    Promise.all([
      // Clean up old caches
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== CACHE_NAME) {
              console.log('[SW] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      }),
      // Enforce cache size limits
      enforceCacheSizeLimit()
    ])
  );
  
  self.clients.claim();
});

// Enhanced fetch handler with security checks
self.addEventListener('fetch', (event) => {
  const { request } = event;
  
  // Security validations
  if (!isSecureRequest(request)) {
    console.warn('[SW] Blocking insecure request:', request.url);
    return;
  }

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip cross-origin requests not in allowed list
  if (!isAllowedOrigin(request.url)) {
    return;
  }

  event.respondWith(
    caches.match(request).then(async (cachedResponse) => {
      // Check cache validity
      if (cachedResponse && isCacheValid(cachedResponse)) {
        return cachedResponse;
      }

      try {
        const networkResponse = await fetch(request);
        
        // Validate network response
        if (!isValidResponse(networkResponse)) {
          throw new Error('Invalid network response');
        }

        // Cache valid responses
        if (shouldCache(request, networkResponse)) {
          const cache = await caches.open(CACHE_NAME);
          const responseClone = networkResponse.clone();
          
          // Add security metadata
          const secureResponse = addSecurityHeaders(responseClone);
          await cache.put(request, secureResponse);
        }

        return networkResponse;
        
      } catch (error) {
        console.warn('[SW] Network request failed:', error);
        
        // Fallback to cache even if expired
        if (cachedResponse) {
          logSecurityEvent('CACHE_FALLBACK', `Serving stale cache for ${request.url}`);
          return cachedResponse;
        }
        
        // Ultimate fallback for navigation requests
        if (request.destination === 'document') {
          const fallbackResponse = await caches.match('/index.html');
          if (fallbackResponse) {
            return fallbackResponse;
          }
        }
        
        throw error;
      }
    })
  );
});

// Security helper functions
function isSecureRequest(request) {
  const url = new URL(request.url);
  
  // Ensure HTTPS in production
  if (url.protocol !== 'https:' && url.hostname !== 'localhost') {
    return false;
  }
  
  // Check for suspicious patterns
  const suspiciousPatterns = [
    /[<>'"]/,
    /javascript:/i,
    /data:/i,
    /vbscript:/i
  ];
  
  return !suspiciousPatterns.some(pattern => pattern.test(request.url));
}

function isAllowedOrigin(url) {
  try {
    const requestOrigin = new URL(url).origin;
    return ALLOWED_ORIGINS.includes(requestOrigin);
  } catch {
    return false;
  }
}

function isValidResponse(response) {
  return response && 
         response.status >= 200 && 
         response.status < 400 &&
         response.type === 'basic';
}

function isCacheValid(response) {
  const cacheTime = response.headers.get('sw-cache-time');
  if (!cacheTime) return false;
  
  const age = Date.now() - parseInt(cacheTime);
  return age < CACHE_EXPIRY;
}

function shouldCache(request, response) {
  const url = new URL(request.url);
  
  // Don't cache API calls
  if (url.pathname.startsWith('/api/')) {
    return false;
  }
  
  // Don't cache large responses
  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength) > 5 * 1024 * 1024) { // 5MB
    return false;
  }
  
  return response.status === 200;
}

function addSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('sw-cache-time', Date.now().toString());
  headers.set('X-Cached-By', 'ServiceWorker');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: headers
  });
}

async function enforceCacheSizeLimit() {
  const cache = await caches.open(CACHE_NAME);
  const requests = await cache.keys();
  
  let totalSize = 0;
  const sizedRequests = [];
  
  for (const request of requests) {
    const response = await cache.match(request);
    if (response) {
      const size = parseInt(response.headers.get('content-length')) || 0;
      totalSize += size;
      sizedRequests.push({ request, size });
    }
  }
  
  if (totalSize > MAX_CACHE_SIZE) {
    // Remove oldest items first
    sizedRequests.sort((a, b) => {
      const aTime = parseInt(a.response?.headers.get('sw-cache-time')) || 0;
      const bTime = parseInt(b.response?.headers.get('sw-cache-time')) || 0;
      return aTime - bTime;
    });
    
    let removedSize = 0;
    for (const { request, size } of sizedRequests) {
      if (totalSize - removedSize <= MAX_CACHE_SIZE) break;
      
      await cache.delete(request);
      removedSize += size;
      logSecurityEvent('CACHE_CLEANUP', `Removed ${request.url} (${size} bytes)`);
    }
  }
}

function logSecurityEvent(type, message) {
  console.log(`[SW-SECURITY] ${new Date().toISOString()} - ${type}: ${message}`);
  
  // In a real application, you might want to send this to a logging service
  // self.clients.matchAll().then(clients => {
  //   clients.forEach(client => {
  //     client.postMessage({
  //       type: 'SECURITY_EVENT',
  //       data: { type, message, timestamp: Date.now() }
  //     });
  //   });
  // });
}

// Message handling for security events
self.addEventListener('message', (event) => {
  const { type, data } = event.data;
  
  switch (type) {
    case 'SECURITY_SCAN':
      logSecurityEvent('MANUAL_SCAN', 'Manual security scan triggered');
      break;
    case 'CLEAR_CACHE':
      caches.delete(CACHE_NAME).then(() => {
        logSecurityEvent('CACHE_CLEARED', 'Cache manually cleared');
        event.ports[0].postMessage({ success: true });
      });
      break;
  }
});
