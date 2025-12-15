/**
 * Random Universe Cipher - Demo UI Logic
 */

import {
  RandomUniverseCipher,
  bytesToBase64,
  base64ToBytes,
  BYTES,
  verifySBoxProperties,
  generateSBox,
  hammingDistance,
  secureEncrypt,
  secureDecrypt,
  encryptWithPasswordAEAD,
  decryptWithPasswordAEAD,
} from '../cipher';

// DOM Elements
let passwordInput: HTMLInputElement;
let plaintextInput: HTMLTextAreaElement;
let ciphertextInput: HTMLTextAreaElement;
let encryptOutput: HTMLElement;
let decryptOutput: HTMLElement;
let keyTimeDisplay: HTMLElement;
let encTimeDisplay: HTMLElement;
let decTimeDisplay: HTMLElement;
let throughputDisplay: HTMLElement;
let useAeadCheckbox: HTMLInputElement;
let useArgon2Checkbox: HTMLInputElement;
let saltDisplay: HTMLElement;

// File encryption elements
let dropZone: HTMLElement;
let fileInput: HTMLInputElement;
let fileInfo: HTMLElement;
let fileName: HTMLElement;
let fileSize: HTMLElement;
let encryptFileBtn: HTMLButtonElement;
let decryptFileBtn: HTMLButtonElement;
let fileProgress: HTMLElement;
let progressFill: HTMLElement;
let progressText: HTMLElement;
let fileOutput: HTMLElement;
let fileOutputText: HTMLElement;
let downloadFileBtn: HTMLButtonElement;

// Current file state
let currentFile: File | null = null;
let processedFileData: Uint8Array | null = null;
let processedFileName: string = '';

// Web Worker for background processing
let cryptoWorker: Worker | null = null;
let pendingOperation: { resolve: (data: Uint8Array) => void; reject: (error: Error) => void } | null = null;

/**
 * Initialize the demo UI
 */
export function initDemo(): void {
  // Get DOM elements
  passwordInput = document.getElementById('password') as HTMLInputElement;
  plaintextInput = document.getElementById('plaintext') as HTMLTextAreaElement;
  ciphertextInput = document.getElementById('ciphertext') as HTMLTextAreaElement;
  encryptOutput = document.getElementById('encrypt-output') as HTMLElement;
  decryptOutput = document.getElementById('decrypt-output') as HTMLElement;
  keyTimeDisplay = document.getElementById('key-time') as HTMLElement;
  encTimeDisplay = document.getElementById('enc-time') as HTMLElement;
  decTimeDisplay = document.getElementById('dec-time') as HTMLElement;
  throughputDisplay = document.getElementById('throughput') as HTMLElement;

  // Get optional elements
  useAeadCheckbox = document.getElementById('use-aead') as HTMLInputElement;
  useArgon2Checkbox = document.getElementById('use-argon2') as HTMLInputElement;
  saltDisplay = document.getElementById('salt-display') as HTMLElement;

  // Set up event listeners
  document.getElementById('generate-key')?.addEventListener('click', generateRandomPassword);
  document.getElementById('encrypt-btn')?.addEventListener('click', handleEncrypt);
  document.getElementById('decrypt-btn')?.addEventListener('click', handleDecrypt);
  document.getElementById('copy-ciphertext')?.addEventListener('click', () => copyToClipboard(encryptOutput));
  document.getElementById('copy-plaintext')?.addEventListener('click', () => copyToClipboard(decryptOutput));
  document.getElementById('run-avalanche')?.addEventListener('click', runAvalancheTest);

  // Initialize file encryption UI
  initFileEncryption();

  // Generate initial password
  generateRandomPassword();
  
  // Set sample plaintext
  plaintextInput.value = 'Hello, Random Universe Cipher! 🚀\n\nThis is a demo of the 256-bit quantum-resistant encryption algorithm.';
  
  console.log('Random Universe Cipher Demo initialized');
}

/**
 * Generate a random password for demo purposes
 */
function generateRandomPassword(): void {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  const array = new Uint8Array(24);
  crypto.getRandomValues(array);
  for (let i = 0; i < 24; i++) {
    password += chars[array[i] % chars.length];
  }
  passwordInput.value = password;
}

/**
 * Handle encryption
 */
async function handleEncrypt(): Promise<void> {
  const password = passwordInput.value;
  const plaintext = plaintextInput.value;
  const useAead = useAeadCheckbox?.checked ?? false;
  const useArgon2 = useArgon2Checkbox?.checked ?? false;

  if (!password) {
    showError(encryptOutput, 'Please enter a password');
    return;
  }

  if (!plaintext) {
    showError(encryptOutput, 'Please enter text to encrypt');
    return;
  }

  try {
    let base64Result: string;
    let keyTime: number;
    let encTime: number;
    
    // Use the new simplified API when both AEAD and Argon2 are enabled
    if (useAead && useArgon2) {
      // RECOMMENDED: secureEncrypt bundles salt automatically
      const start = performance.now();
      base64Result = await secureEncrypt(plaintext, password, 'interactive');
      const totalTime = performance.now() - start;
      keyTime = totalTime * 0.7; // Estimate: ~70% is key derivation
      encTime = totalTime * 0.3;
      
      if (saltDisplay) {
        saltDisplay.textContent = '✅ Salt auto-bundled with ciphertext';
        saltDisplay.style.display = 'block';
      }
    } else {
      // Manual mode for other combinations
      const keyStart = performance.now();
      let cipher: RandomUniverseCipher;
      
      if (useArgon2) {
        const result = await RandomUniverseCipher.fromPasswordAsync(password, undefined, 'interactive');
        cipher = result.cipher;
        if (saltDisplay) {
          saltDisplay.textContent = '⚠️ Salt NOT bundled (enable AEAD for auto-bundling)';
          saltDisplay.style.display = 'block';
        }
      } else {
        cipher = RandomUniverseCipher.fromPassword(password);
        if (saltDisplay) {
          saltDisplay.style.display = 'none';
        }
      }
      
      keyTime = performance.now() - keyStart;

      const encStart = performance.now();
      const ciphertext = useAead 
        ? cipher.encryptAuthenticated(plaintext)
        : cipher.encrypt(plaintext);
      encTime = performance.now() - encStart;
      
      base64Result = bytesToBase64(ciphertext);
    }
    
    keyTimeDisplay.textContent = `${keyTime.toFixed(2)} ms${useArgon2 ? ' (Argon2)' : ''}`;
    encTimeDisplay.textContent = `${encTime.toFixed(2)} ms${useAead ? ' (AEAD)' : ''}`;

    // Calculate throughput
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const throughput = (plaintextBytes.length / 1024) / (encTime / 1000); // KB/s
    throughputDisplay.textContent = throughput > 1024 
      ? `${(throughput / 1024).toFixed(2)} MB/s`
      : `${throughput.toFixed(2)} KB/s`;

    // Display result
    encryptOutput.textContent = base64Result;
    encryptOutput.classList.remove('error');
    encryptOutput.classList.add('success');

    // Auto-fill ciphertext input for decryption
    ciphertextInput.value = base64Result;
  } catch (error) {
    showError(encryptOutput, `Encryption failed: ${error}`);
  }
}

/**
 * Handle decryption
 */
async function handleDecrypt(): Promise<void> {
  const password = passwordInput.value;
  const ciphertextBase64 = ciphertextInput.value;
  const useAead = useAeadCheckbox?.checked ?? false;
  const useArgon2 = useArgon2Checkbox?.checked ?? false;

  if (!password) {
    showError(decryptOutput, 'Please enter a password');
    return;
  }

  if (!ciphertextBase64) {
    showError(decryptOutput, 'Please enter ciphertext to decrypt');
    return;
  }

  try {
    let plaintext: string;
    let decTime: number;
    
    // Use the new simplified API when both AEAD and Argon2 are enabled
    if (useAead && useArgon2) {
      // RECOMMENDED: secureDecrypt extracts salt automatically
      const start = performance.now();
      plaintext = await secureDecrypt(ciphertextBase64, password, 'interactive');
      decTime = performance.now() - start;
    } else {
      // Manual mode for other combinations
      const cipher = useArgon2
        ? (await RandomUniverseCipher.fromPasswordAsync(password, undefined, 'interactive')).cipher
        : RandomUniverseCipher.fromPassword(password);
      
      const decStart = performance.now();
      const ciphertext = base64ToBytes(ciphertextBase64);
      
      if (useAead) {
        plaintext = cipher.decryptAuthenticatedToString(ciphertext);
      } else {
        plaintext = cipher.decryptToString(ciphertext);
      }
      
      decTime = performance.now() - decStart;
    }
    
    decTimeDisplay.textContent = `${decTime.toFixed(2)} ms${useAead ? ' (verified)' : ''}`;

    // Display result
    decryptOutput.textContent = plaintext;
    decryptOutput.classList.remove('error');
    decryptOutput.classList.add('success');
  } catch (error) {
    const errorMsg = String(error);
    if (errorMsg.includes('Authentication failed')) {
      showError(decryptOutput, '❌ Authentication failed: Data was tampered or wrong key!');
    } else {
      showError(decryptOutput, `Decryption failed: ${error}`);
    }
  }
}

/**
 * Show error in output element
 */
function showError(element: HTMLElement, message: string): void {
  element.textContent = message;
  element.classList.remove('success');
  element.classList.add('error');
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(element: HTMLElement): Promise<void> {
  const text = element.textContent;
  if (text) {
    await navigator.clipboard.writeText(text);
    // Show feedback (could add a toast notification)
    console.log('Copied to clipboard');
  }
}

/**
 * Run avalanche effect test
 */
async function runAvalancheTest(): Promise<void> {
  const resultsElement = document.getElementById('avalanche-results');
  if (!resultsElement) return;

  resultsElement.innerHTML = '<span class="loading"></span> Running avalanche test...';

  // Use setTimeout to allow UI to update
  setTimeout(() => {
    try {
      const password = passwordInput.value || 'test-password';
      const cipher = RandomUniverseCipher.fromPassword(password);
      
      // Test 100 pairs
      const numTests = 100;
      let totalFlipRate = 0;
      const flipRates: number[] = [];

      for (let i = 0; i < numTests; i++) {
        // Generate random plaintext
        const plaintext1 = new Uint8Array(32);
        crypto.getRandomValues(plaintext1);

        // Flip one bit
        const plaintext2 = new Uint8Array(plaintext1);
        const bitPos = Math.floor(Math.random() * 256);
        const byteIdx = Math.floor(bitPos / 8);
        const bitIdx = bitPos % 8;
        plaintext2[byteIdx] ^= (1 << bitIdx);

        // Encrypt both
        const ciphertext1 = cipher.encrypt(plaintext1);
        const ciphertext2 = cipher.encrypt(plaintext2);

        // Skip nonce (first 16 bytes) and compute Hamming distance
        const c1Data = ciphertext1.subarray(BYTES.NONCE);
        const c2Data = ciphertext2.subarray(BYTES.NONCE);
        
        const distance = hammingDistance(c1Data, c2Data);
        const flipRate = distance / (c1Data.length * 8);
        flipRates.push(flipRate);
        totalFlipRate += flipRate;
      }

      const avgFlipRate = totalFlipRate / numTests;

      // Check if it passes (should be 0.5 ± 0.1)
      const passed = avgFlipRate >= 0.4 && avgFlipRate <= 0.6;
      
      resultsElement.innerHTML = `
        <span style="color: ${passed ? 'var(--success)' : 'var(--error)'}">
          ${passed ? '✓ PASSED' : '✗ FAILED'} - ${(avgFlipRate * 100).toFixed(1)}% avg flip rate (${numTests} tests)
        </span>
      `;
    } catch (error) {
      resultsElement.innerHTML = `<span style="color: var(--error)">Test failed: ${error}</span>`;
    }
  }, 50);
}

/**
 * Run S-box analysis (called from console for debugging)
 */
export function analyzeSBox(): void {
  const key = new Uint8Array(64);
  crypto.getRandomValues(key);
  
  console.log('Analyzing S-box properties...');
  
  const sbox = generateSBox(key, 0);
  const props = verifySBoxProperties(sbox);
  
  console.log('S-box Analysis Results:');
  console.log(`  Bijective: ${props.bijective ? 'Yes ✓' : 'No ✗'}`);
  console.log(`  Non-linearity: ${props.nonlinearity} (target: ≥100)`);
  console.log(`  Differential Uniformity: ${props.differentialUniformity} (target: ≤4)`);
  console.log(`  Algebraic Degree: ${props.algebraicDegree} (target: ≥7)`);
  console.log(`  Overall: ${props.valid ? 'VALID ✓' : 'INVALID ✗'}`);
}

// Export for debugging
(window as unknown as { analyzeSBox: typeof analyzeSBox }).analyzeSBox = analyzeSBox;

// ============================================================
// FILE ENCRYPTION UI
// ============================================================

/**
 * Initialize file encryption UI
 */
function initFileEncryption(): void {
  // Get DOM elements
  dropZone = document.getElementById('drop-zone') as HTMLElement;
  fileInput = document.getElementById('file-input') as HTMLInputElement;
  fileInfo = document.getElementById('file-info') as HTMLElement;
  fileName = document.getElementById('file-name') as HTMLElement;
  fileSize = document.getElementById('file-size') as HTMLElement;
  encryptFileBtn = document.getElementById('encrypt-file-btn') as HTMLButtonElement;
  decryptFileBtn = document.getElementById('decrypt-file-btn') as HTMLButtonElement;
  fileProgress = document.getElementById('file-progress') as HTMLElement;
  progressFill = document.getElementById('progress-fill') as HTMLElement;
  progressText = document.getElementById('progress-text') as HTMLElement;
  fileOutput = document.getElementById('file-output') as HTMLElement;
  fileOutputText = document.getElementById('file-output-text') as HTMLElement;
  downloadFileBtn = document.getElementById('download-file-btn') as HTMLButtonElement;

  if (!dropZone) return;

  // Initialize Web Worker for background processing
  initCryptoWorker();

  // Drag and drop events
  dropZone.addEventListener('dragover', handleDragOver);
  dropZone.addEventListener('dragleave', handleDragLeave);
  dropZone.addEventListener('drop', handleDrop);
  dropZone.addEventListener('click', () => fileInput?.click());

  // File input change
  fileInput?.addEventListener('change', handleFileSelect);

  // Button clicks
  encryptFileBtn?.addEventListener('click', handleEncryptFile);
  decryptFileBtn?.addEventListener('click', handleDecryptFile);
  document.getElementById('clear-file')?.addEventListener('click', clearFile);
  downloadFileBtn?.addEventListener('click', downloadFile);
}

/**
 * Handle drag over
 */
function handleDragOver(e: DragEvent): void {
  e.preventDefault();
  e.stopPropagation();
  dropZone.classList.add('drag-over');
}

/**
 * Handle drag leave
 */
function handleDragLeave(e: DragEvent): void {
  e.preventDefault();
  e.stopPropagation();
  dropZone.classList.remove('drag-over');
}

/**
 * Handle file drop
 */
function handleDrop(e: DragEvent): void {
  e.preventDefault();
  e.stopPropagation();
  dropZone.classList.remove('drag-over');

  const files = e.dataTransfer?.files;
  if (files && files.length > 0) {
    selectFile(files[0]);
  }
}

/**
 * Handle file selection via input
 */
function handleFileSelect(e: Event): void {
  const input = e.target as HTMLInputElement;
  if (input.files && input.files.length > 0) {
    selectFile(input.files[0]);
  }
}

/**
 * Select and display a file
 */
function selectFile(file: File): void {
  currentFile = file;
  processedFileData = null;
  
  // Update UI
  fileName.textContent = file.name;
  fileSize.textContent = formatFileSize(file.size);
  
  dropZone.style.display = 'none';
  fileInfo.style.display = 'flex';
  fileOutput.style.display = 'none';
  
  // Enable buttons
  encryptFileBtn.disabled = false;
  decryptFileBtn.disabled = false;
}

/**
 * Clear current file
 */
function clearFile(): void {
  currentFile = null;
  processedFileData = null;
  processedFileName = '';
  
  // Reset UI
  dropZone.style.display = 'block';
  fileInfo.style.display = 'none';
  fileOutput.style.display = 'none';
  fileProgress.style.display = 'none';
  
  // Disable buttons
  encryptFileBtn.disabled = true;
  decryptFileBtn.disabled = true;
  
  // Clear file input
  if (fileInput) fileInput.value = '';
}

/**
 * Format file size for display
 */
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Show progress
 */
function showProgress(text: string, percent: number): void {
  fileProgress.style.display = 'block';
  progressText.textContent = text;
  progressFill.style.width = `${percent}%`;
}

/**
 * Hide progress
 */
function hideProgress(): void {
  fileProgress.style.display = 'none';
}

/**
 * Show file output
 */
function showFileOutput(success: boolean, message: string): void {
  fileOutput.style.display = 'flex';
  fileOutput.classList.toggle('error', !success);
  
  const icon = fileOutput.querySelector('.file-output-icon') as HTMLElement;
  if (icon) icon.textContent = success ? '✅' : '❌';
  
  fileOutputText.textContent = message;
  downloadFileBtn.style.display = success ? 'inline-flex' : 'none';
}

/**
 * Initialize the crypto web worker
 */
function initCryptoWorker(): void {
  try {
    cryptoWorker = new Worker(
      new URL('../worker/crypto-worker.ts', import.meta.url),
      { type: 'module' }
    );
    
    cryptoWorker.onmessage = (event) => {
      const { type, data, error, progress, message } = event.data;
      
      if (type === 'progress') {
        showProgress(message || 'Processing...', progress || 0);
      } else if (type === 'success' && pendingOperation) {
        pendingOperation.resolve(data);
        pendingOperation = null;
      } else if (type === 'error' && pendingOperation) {
        pendingOperation.reject(new Error(error || 'Unknown error'));
        pendingOperation = null;
      }
    };
    
    cryptoWorker.onerror = (error) => {
      console.error('Worker error:', error);
      if (pendingOperation) {
        pendingOperation.reject(new Error('Worker error'));
        pendingOperation = null;
      }
    };
    
    console.log('Crypto worker initialized');
  } catch (error) {
    console.warn('Web Worker not supported, using main thread:', error);
    cryptoWorker = null;
  }
}

/**
 * Process with worker or fallback to main thread
 */
async function processWithWorker(
  type: 'encrypt' | 'decrypt',
  data: Uint8Array,
  password: string
): Promise<Uint8Array> {
  if (cryptoWorker) {
    return new Promise((resolve, reject) => {
      pendingOperation = { resolve, reject };
      cryptoWorker!.postMessage({
        type,
        id: Date.now().toString(),
        data,
        password,
      });
    });
  } else {
    // Fallback: run on main thread with yielding
    showProgress('Processing (main thread)...', 30);
    await yieldToMain();
    
    if (type === 'encrypt') {
      const result = await encryptWithPasswordAEAD(data, password, undefined, 'interactive');
      return result;
    } else {
      const result = await decryptWithPasswordAEAD(data, password, undefined, 'interactive');
      return result;
    }
  }
}

/**
 * Yield to main thread to keep UI responsive
 */
function yieldToMain(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 0));
}

/**
 * Encrypt the current file
 */
async function handleEncryptFile(): Promise<void> {
  if (!currentFile) return;
  
  const password = passwordInput.value;
  if (!password) {
    showFileOutput(false, 'Please enter a password first');
    return;
  }

  // Disable buttons during processing
  encryptFileBtn.disabled = true;
  decryptFileBtn.disabled = true;

  try {
    showProgress('Reading file...', 10);
    await yieldToMain();
    
    // Read file as ArrayBuffer
    const arrayBuffer = await currentFile.arrayBuffer();
    const fileData = new Uint8Array(arrayBuffer);
    
    // Add filename to the beginning so we can recover it
    const filenameBytes = new TextEncoder().encode(currentFile.name);
    const filenameLength = new Uint8Array(2);
    filenameLength[0] = (filenameBytes.length >> 8) & 0xff;
    filenameLength[1] = filenameBytes.length & 0xff;
    
    // Combine: filenameLength (2) + filename + fileData
    const dataToEncrypt = new Uint8Array(2 + filenameBytes.length + fileData.length);
    dataToEncrypt.set(filenameLength, 0);
    dataToEncrypt.set(filenameBytes, 2);
    dataToEncrypt.set(fileData, 2 + filenameBytes.length);
    
    // Encrypt with worker
    const encrypted = await processWithWorker('encrypt', dataToEncrypt, password);
    
    showProgress('Complete!', 100);
    
    // Store result
    processedFileData = encrypted;
    processedFileName = currentFile.name + '.ruc';
    
    setTimeout(() => {
      hideProgress();
      showFileOutput(true, `Encrypted successfully! Size: ${formatFileSize(encrypted.length)}`);
    }, 300);
    
  } catch (error) {
    hideProgress();
    showFileOutput(false, `Encryption failed: ${error}`);
  } finally {
    // Re-enable buttons
    encryptFileBtn.disabled = false;
    decryptFileBtn.disabled = false;
  }
}

/**
 * Decrypt the current file
 */
async function handleDecryptFile(): Promise<void> {
  if (!currentFile) return;
  
  const password = passwordInput.value;
  if (!password) {
    showFileOutput(false, 'Please enter a password first');
    return;
  }

  // Disable buttons during processing
  encryptFileBtn.disabled = true;
  decryptFileBtn.disabled = true;

  try {
    showProgress('Reading file...', 10);
    await yieldToMain();
    
    // Read file as ArrayBuffer
    const arrayBuffer = await currentFile.arrayBuffer();
    const encryptedData = new Uint8Array(arrayBuffer);
    
    // Decrypt with worker
    let decrypted: Uint8Array;
    try {
      decrypted = await processWithWorker('decrypt', encryptedData, password);
    } catch (error) {
      const msg = String(error);
      if (msg.includes('Authentication failed')) {
        throw new Error('Wrong password or file was tampered!');
      }
      throw error;
    }
    
    showProgress('Extracting file...', 90);
    await yieldToMain();
    
    // Extract filename and data
    const filenameLength = (decrypted[0] << 8) | decrypted[1];
    const filenameBytes = decrypted.subarray(2, 2 + filenameLength);
    const originalFilename = new TextDecoder().decode(filenameBytes);
    const fileData = decrypted.subarray(2 + filenameLength);
    
    showProgress('Complete!', 100);
    
    // Store result
    processedFileData = fileData;
    processedFileName = originalFilename;
    
    setTimeout(() => {
      hideProgress();
      showFileOutput(true, `Decrypted successfully! Original: ${originalFilename} (${formatFileSize(fileData.length)})`);
    }, 300);
    
  } catch (error) {
    hideProgress();
    showFileOutput(false, `Decryption failed: ${error}`);
  } finally {
    // Re-enable buttons
    encryptFileBtn.disabled = false;
    decryptFileBtn.disabled = false;
  }
}

/**
 * Download the processed file
 */
function downloadFile(): void {
  if (!processedFileData || !processedFileName) return;
  
  // Create a copy to ensure it's a regular ArrayBuffer (not SharedArrayBuffer)
  const buffer = new ArrayBuffer(processedFileData.length);
  new Uint8Array(buffer).set(processedFileData);
  const blob = new Blob([buffer], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = processedFileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  
  URL.revokeObjectURL(url);
}

