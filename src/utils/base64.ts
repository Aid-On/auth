/**
 * Base64 encoding/decoding utilities with Unicode support
 * 
 * Native btoa/atob only support ASCII characters.
 * These utilities properly handle Unicode (including Japanese) characters.
 */

/**
 * Encode a string to Base64URL format
 * Properly handles Unicode characters (Japanese, emoji, etc.)
 */
export function encodeBase64Url(str: string): string {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  
  // Convert Uint8Array to binary string for btoa
  const binString = Array.from(data, (byte) => String.fromCharCode(byte)).join("");
  
  // Encode to Base64 and convert to Base64URL format
  return btoa(binString)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, ""); // Remove padding
}

/**
 * Decode a Base64URL string
 * Properly handles Unicode characters
 */
export function decodeBase64Url(str: string): string {
  // Convert Base64URL to standard Base64
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  
  // Add padding if necessary
  const pad = str.length % 4;
  if (pad) {
    str += "=".repeat(4 - pad);
  }
  
  // Decode Base64 to binary string
  const binString = atob(str);
  
  // Convert binary string to Uint8Array
  const bytes = Uint8Array.from(binString, (c) => c.charCodeAt(0));
  
  // Decode UTF-8 bytes to string
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

/**
 * Encode an object to Base64URL format
 * Handles Unicode in object properties
 */
export function encodeBase64UrlJson(obj: unknown): string {
  const json = JSON.stringify(obj);
  return encodeBase64Url(json);
}

/**
 * Decode a Base64URL string to an object
 * Handles Unicode in object properties
 */
export function decodeBase64UrlJson<T = unknown>(str: string): T {
  const json = decodeBase64Url(str);
  return JSON.parse(json) as T;
}