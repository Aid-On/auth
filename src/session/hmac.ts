/** HMAC-SHA256 signing utilities */

export async function signHmac(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const binString = String.fromCharCode(...new Uint8Array(signature));
  return btoa(binString)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function verifyHmac(data: string, signature: string, secret: string): Promise<boolean> {
  const expectedSig = await signHmac(data, secret);
  return signature === expectedSig;
}
