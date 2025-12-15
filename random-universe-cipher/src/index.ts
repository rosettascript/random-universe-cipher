/**
 * Random Universe Cipher - Demo Entry Point
 */

import { initDemo } from './ui/demo';

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDemo);
} else {
  initDemo();
}

// Export cipher for console access
export * from './cipher';

