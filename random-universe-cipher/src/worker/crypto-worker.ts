/**
 * Crypto Web Worker
 * 
 * Runs encryption/decryption in a background thread to keep the UI responsive.
 * Uses optimized chunked processing for fast file encryption/decryption.
 */

import {
  encryptWithPasswordAEAD,
  decryptWithPasswordAEAD,
  encryptWithPasswordAEADFast,
  decryptWithPasswordAEADFast,
} from '../cipher';

export interface WorkerMessage {
  type: 'encrypt' | 'decrypt';
  id: string;
  data: Uint8Array;
  password: string;
  useFast?: boolean; // Use fast chunked processing
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
  const { type, id, data, password, useFast = true } = event.data;

  try {
    if (type === 'encrypt') {
      // Use fast method for files larger than 1KB
      // Fast method uses adaptive chunk sizes:
      // - Small files: 64 blocks (2KB chunks)
      // - Medium files: 256 blocks (8KB chunks)  
      // - Large files/videos: 1024 blocks (32KB chunks)
      const useFastMethod = useFast && data.length > 1024;
      
      const encrypted = useFastMethod
        ? await encryptWithPasswordAEADFast(
            data,
            password,
            undefined,
            'interactive',
            (progress) => {
              postProgress(
                id,
                progress < 20 ? 'Deriving key...' : progress < 80 ? 'Encrypting...' : 'Finalizing...',
                progress
              );
            }
          )
        : await encryptWithPasswordAEAD(data, password, undefined, 'interactive');
      
      postProgress(id, 'Complete!', 100);
      
      self.postMessage({
        type: 'success',
        id,
        data: encrypted,
      } as WorkerResponse);
      
    } else if (type === 'decrypt') {
      // Use fast method for files larger than 1KB, standard for smaller
      const useFastMethod = useFast && data.length > 1024;
      
      const decrypted = useFastMethod
        ? await decryptWithPasswordAEADFast(
            data,
            password,
            undefined,
            'interactive',
            (progress) => {
              postProgress(
                id,
                progress < 20 ? 'Deriving key...' : progress < 80 ? 'Decrypting...' : 'Verifying...',
                progress
              );
            }
          )
        : await decryptWithPasswordAEAD(data, password, undefined, 'interactive');
      
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

