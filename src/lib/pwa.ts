import { config } from './config';

class PWAManager {
  private registration: ServiceWorkerRegistration | null = null;
  private updateAvailable = false;

  async init() {
    if (!config.features.pwa) {
      console.log('PWA features disabled');
      return;
    }

    if (!('serviceWorker' in navigator)) {
      console.log('Service workers not supported');
      return;
    }

    try {
      // Register service worker
      this.registration = await navigator.serviceWorker.register('/sw.js');
      console.log('Service worker registered:', this.registration);

      // Check for updates
      this.registration.addEventListener('updatefound', () => {
        this.handleUpdateFound();
      });

      // Handle controller change
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        this.handleControllerChange();
      });

      // Check for app update on visibility change
      document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
          this.checkForUpdates();
        }
      });

      // Set up periodic update checks (every hour)
      setInterval(() => this.checkForUpdates(), 3600000);

    } catch (error) {
      console.error('Service worker registration failed:', error);
    }
  }

  private handleUpdateFound() {
    const newWorker = this.registration?.installing;
    if (!newWorker) return;

    newWorker.addEventListener('statechange', () => {
      if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
        // New service worker available
        this.updateAvailable = true;
        this.notifyUpdateAvailable();
      }
    });
  }

  private handleControllerChange() {
    // Service worker has been updated
    window.location.reload();
  }

  private notifyUpdateAvailable() {
    // You can show a toast or notification here
    console.log('Update available! Reload to get the latest version.');
    
    // Store update status
    localStorage.setItem('pwa_update_available', 'true');
  }

  async checkForUpdates() {
    if (!this.registration) return;
    
    try {
      await this.registration.update();
    } catch (error) {
      console.error('Failed to check for updates:', error);
    }
  }

  async skipWaiting() {
    if (!this.registration?.waiting) return;
    
    // Tell the waiting service worker to activate
    this.registration.waiting.postMessage({ type: 'SKIP_WAITING' });
  }

  isUpdateAvailable(): boolean {
    return this.updateAvailable || localStorage.getItem('pwa_update_available') === 'true';
  }

  clearUpdateFlag() {
    this.updateAvailable = false;
    localStorage.removeItem('pwa_update_available');
  }

  // Install prompt handling
  private deferredPrompt: any = null;

  setupInstallPrompt() {
    window.addEventListener('beforeinstallprompt', (e) => {
      // Prevent Chrome 67 and earlier from automatically showing the prompt
      e.preventDefault();
      // Stash the event so it can be triggered later
      this.deferredPrompt = e;
      // Update UI to show install button
      this.showInstallButton();
    });

    window.addEventListener('appinstalled', () => {
      console.log('App installed');
      this.deferredPrompt = null;
      this.hideInstallButton();
    });
  }

  private showInstallButton() {
    // Dispatch custom event that UI can listen to
    window.dispatchEvent(new CustomEvent('pwa-install-available'));
  }

  private hideInstallButton() {
    window.dispatchEvent(new CustomEvent('pwa-install-hidden'));
  }

  async promptInstall() {
    if (!this.deferredPrompt) {
      console.log('Install prompt not available');
      return false;
    }

    // Show the install prompt
    this.deferredPrompt.prompt();
    
    // Wait for the user to respond to the prompt
    const { outcome } = await this.deferredPrompt.userChoice;
    
    console.log(`User response to install prompt: ${outcome}`);
    
    // Clear the deferred prompt
    this.deferredPrompt = null;
    
    return outcome === 'accepted';
  }

  // Check if app is installed
  isInstalled(): boolean {
    // Check if running in standalone mode
    if (window.matchMedia('(display-mode: standalone)').matches) {
      return true;
    }
    
    // Check for iOS
    if ((window.navigator as any).standalone) {
      return true;
    }
    
    return false;
  }

  // Offline detection
  setupOfflineDetection() {
    window.addEventListener('online', () => {
      console.log('Back online');
      window.dispatchEvent(new CustomEvent('pwa-online'));
    });

    window.addEventListener('offline', () => {
      console.log('Gone offline');
      window.dispatchEvent(new CustomEvent('pwa-offline'));
    });
  }

  isOnline(): boolean {
    return navigator.onLine;
  }
}

export const pwaManager = new PWAManager();