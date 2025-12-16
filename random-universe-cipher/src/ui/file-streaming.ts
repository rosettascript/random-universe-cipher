/**
 * Streaming file reader for large files (videos, etc.)
 * 
 * Reads files in chunks to avoid loading entire file into memory
 */

/**
 * Read a file in chunks and process with a callback
 * 
 * @param file - File to read
 * @param chunkSize - Size of each chunk in bytes (default: 1MB)
 * @param onChunk - Callback for each chunk (chunk, offset, totalSize)
 * @param onProgress - Optional progress callback (0-100)
 */
export async function readFileInChunks(
  file: File,
  chunkSize: number = 1024 * 1024, // 1MB chunks
  onChunk: (chunk: Uint8Array, offset: number, totalSize: number) => Promise<void> | void,
  onProgress?: (progress: number) => void
): Promise<void> {
  const totalSize = file.size;
  let offset = 0;
  
  while (offset < totalSize) {
    const chunk = file.slice(offset, offset + chunkSize);
    const arrayBuffer = await chunk.arrayBuffer();
    const chunkData = new Uint8Array(arrayBuffer);
    
    await onChunk(chunkData, offset, totalSize);
    
    offset += chunkData.length;
    
    if (onProgress) {
      const progress = Math.floor((offset / totalSize) * 100);
      onProgress(progress);
    }
  }
}

/**
 * Check if a file is a video file based on extension
 */
export function isVideoFile(filename: string): boolean {
  const videoExtensions = [
    '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv',
    '.m4v', '.3gp', '.ogv', '.ts', '.mts', '.m2ts'
  ];
  const ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  return videoExtensions.includes(ext);
}

/**
 * Check if a file is likely to be large (video, large archives, etc.)
 */
export function isLargeFile(file: File): boolean {
  // Consider files > 50MB as "large"
  return file.size > 50 * 1024 * 1024;
}

/**
 * Get recommended chunk size for a file
 */
export function getRecommendedChunkSize(fileSize: number): number {
  if (fileSize < 1024 * 1024) {
    // Small files: 64KB
    return 64 * 1024;
  } else if (fileSize < 100 * 1024 * 1024) {
    // Medium files: 512KB
    return 512 * 1024;
  } else {
    // Large files (videos): 2MB
    return 2 * 1024 * 1024;
  }
}

