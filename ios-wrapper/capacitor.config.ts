import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.apexib.app',
  appName: 'Apex IB',
  webDir: 'www',

  // "Remote" mode: the native shell loads your live site instead of a bundled
  // copy. This means every Railway deploy updates the app instantly with no
  // App Store resubmission — same as a PWA, but wrapped as a real native app.
  server: {
    url: 'https://apex-ib-production.up.railway.app',
    cleartext: false
  },

  ios: {
    // Lets RevenueCat's StoreKit calls and Stripe's checkout domain load
    // inside the in-app browser without being blocked.
    allowsLinkPreview: false
  }
};

export default config;
