/**
 * Crypto Web Worker
 * 
 * Runs encryption/decryption in a background thread to keep the UI responsive.
 */

import {
  encryptWithPasswordAEAD,
  decryptWithPasswordAEAD,
} from '../cipher';

export interface WorkerMessage {
  type: 'encrypt' | 'decrypt';
  id: string;
  data: Uint8Array;
  password: string;
}

export interface WorkerResponse {
  type: 'success' | 'error' | 'progress';
  id: string;
  data?: Uint8Array;
  error?: string;
  progress?: number;
  message?: string;
}

// Handle messages from main thread
self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
  const { type, id, data, password } = event.data;

  try {
    // Send progress update
    postProgress(id, 'Deriving key with Argon2...', 20);

    if (type === 'encrypt') {
      postProgress(id, 'Encrypting...', 50);
      const encrypted = await encryptWithPasswordAEAD(data, password, undefined, 'interactive');
      postProgress(id, 'Complete!', 100);
      
      self.postMessage({
        type: 'success',
        id,
        data: encrypted,
      } as WorkerResponse);
      
    } else if (type === 'decrypt') {
      postProgress(id, 'Decrypting and verifying...', 50);
      const decrypted = await decryptWithPasswordAEAD(data, password, undefined, 'interactive');
      postProgress(id, 'Complete!', 100);
      
      self.postMessage({
        type: 'success',
        id,
        data: decrypted,
      } as WorkerResponse);
    }
    
  } catch (error) {
    self.postMessage({
      type: 'error',
      id,
      error: String(error),
    } as WorkerResponse);
  }
};

function postProgress(id: string, message: string, progress: number): void {
  self.postMessage({
    type: 'progress',
    id,
    message,
    progress,
  } as WorkerResponse);
}

