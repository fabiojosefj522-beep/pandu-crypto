/* pandu-crypto for Java and Kotlin (Android 8+ or any JVM 8+): the same format as src/pandu-crypto.js (see FORMAT.md).
   No dependencies. decrypt() returns the JSON text; parse it with the JSON library you already use.
   MIT License - Copyright (c) 2026 Fábio José dos Santos (Pandu SOS, https://usepandu.com.br) */
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class PanduCrypto {
  private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  private static final Pattern LINK = Pattern.compile("#([DP])=([A-Z2-7]{16})([A-Z2-7]{26}|[A-Z2-7]{52})$");
  private static final int PIN_ITER = 100000;
  private static final SecureRandom RNG = new SecureRandom();

  private PanduCrypto() {}

  /** id and key go into the QR; tok (the edit token) stays only with the owner. */
  public static final class Card {
    public final String id, key, tok, share; /* share: only for QR + PIN cards (null otherwise) */
    Card(String id, String key, String tok, String share) { this.id = id; this.key = key; this.tok = tok; this.share = share; }
  }

  public static final class Sealed {
    public final String ct, iv, s, ph; /* s and ph: only when a PIN is set (send them to the server) */
    Sealed(String ct, String iv) { this(ct, iv, null, null); }
    Sealed(String ct, String iv, String s, String ph) { this.ct = ct; this.iv = iv; this.s = s; this.ph = ph; }
  }

  /** Base32, RFC 4648 alphabet, no padding. */
  public static String b32(byte[] data) {
    StringBuilder out = new StringBuilder();
    int buf = 0, n = 0;
    for (byte b : data) {
      buf = (buf << 8) | (b & 255); n += 8;
      while (n >= 5) { out.append(B32.charAt((buf >>> (n - 5)) & 31)); n -= 5; }
      buf &= (1 << n) - 1;
    }
    if (n > 0) out.append(B32.charAt((buf << (5 - n)) & 31));
    return out.toString();
  }

  public static byte[] unb32(String s) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int buf = 0, n = 0;
    for (int i = 0; i < s.length(); i++) {
      int v = B32.indexOf(s.charAt(i));
      if (v < 0) throw new IllegalArgumentException("invalid base32");
      buf = (buf << 5) | v; n += 5;
      if (n >= 8) { out.write((buf >>> (n - 8)) & 255); n -= 8; }
      buf &= (1 << n) - 1;
    }
    return out.toByteArray();
  }

  public static String b64url(byte[] data) { return Base64.getUrlEncoder().withoutPadding().encodeToString(data); }
  public static byte[] unb64url(String s) { return Base64.getUrlDecoder().decode(s); }

  private static byte[] random(int n) { byte[] b = new byte[n]; RNG.nextBytes(b); return b; }

  /** bits: 128 (default in the other versions, smaller QR) or 256. */
  public static Card newCard(int bits) { return newCard(bits, false); }

  /** pin = true: a QR + PIN card, with a share for the server. */
  public static Card newCard(int bits, boolean pin) {
    if (bits != 128 && bits != 256) throw new IllegalArgumentException("bits must be 128 or 256");
    return new Card(b32(random(10)), b32(random(bits / 8)), b64url(random(32)), pin ? b64url(random(16)) : null);
  }

  public static String makeLink(String base, String id, String key) { return makeLink(base, id, key, false); }

  public static String makeLink(String base, String id, String key, boolean pin) {
    if (!id.matches("[A-Z2-7]{16}") || !key.matches("[A-Z2-7]{26}|[A-Z2-7]{52}")) throw new IllegalArgumentException("bad id or key");
    int h = base.indexOf('#');
    return (h >= 0 ? base.substring(0, h) : base) + (pin ? "#P=" : "#D=") + id + key;
  }

  /** Returns {id, key, "pin" or ""}, or null if the link is not a Pandu-style link. */
  public static String[] parseLink(String link) {
    Matcher m = LINK.matcher(link == null ? "" : link);
    return m.find() ? new String[] { m.group(2), m.group(3), m.group(1).equals("P") ? "pin" : "" } : null;
  }

  /** What the server keeps instead of the edit token: hex SHA-256 of the token string. */
  public static String tokenHash(String tok) throws Exception {
    byte[] d = MessageDigest.getInstance("SHA-256").digest(tok.getBytes(StandardCharsets.US_ASCII));
    StringBuilder sb = new StringBuilder();
    for (byte b : d) sb.append(String.format("%02x", b & 255));
    return sb.toString();
  }

  /** Encrypts JSON text (already serialized). */
  public static Sealed encrypt(String json, String key) throws Exception {
    byte[] body = json.getBytes(StandardCharsets.UTF_8), packed = deflateRaw(body);
    int flag = 0;
    if (packed.length < body.length) { body = packed; flag = 1; }
    byte[] plain = new byte[body.length + 1];
    plain[0] = (byte) flag;
    System.arraycopy(body, 0, plain, 1, body.length);
    byte[] iv = random(12);
    return new Sealed(b64url(aes(Cipher.ENCRYPT_MODE, unb32(key), iv, plain)), b64url(iv));
  }

  /** Returns the JSON text, or null if the key is wrong or the bytes were changed. */
  public static String decrypt(String ct, String iv, String key) {
    try {
      byte[] plain = aes(Cipher.DECRYPT_MODE, unb32(key), unb64url(iv), unb64url(ct));
      byte[] body = new byte[plain.length - 1];
      System.arraycopy(plain, 1, body, 0, body.length);
      if (plain[0] == 1) body = inflateRaw(body);
      return new String(body, StandardCharsets.UTF_8);
    } catch (Exception e) {
      return null;
    }
  }

  /* ---------- QR + PIN (FORMAT.md, section 8) ---------- */
  static byte[] hkdf(byte[] ikm, byte[] salt, String info, int len) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(salt, "HmacSHA256"));
    byte[] prk = mac.doFinal(ikm);
    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
    mac.update(info.getBytes(StandardCharsets.US_ASCII));
    mac.update((byte) 1);
    byte[] okm = mac.doFinal(), out = new byte[len]; /* len <= 32: one block is enough */
    System.arraycopy(okm, 0, out, 0, len);
    return out;
  }

  /** What the reader sends to the server to get the share. PIN: 4 to 12 digits. */
  public static String pinProof(String id, String key, String pin) throws Exception {
    if (!pin.matches("\\d{4,12}")) throw new IllegalArgumentException("the PIN must be 4 to 12 digits");
    byte[] salt = hkdf(unb32(key), unb32(id), "pandu-pin-v1/pin", 16);
    PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, PIN_ITER, 256);
    return b64url(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded());
  }

  static byte[] pinDataKey(String id, String key, String share) throws Exception {
    byte[] k1 = unb32(key), k2 = unb64url(share), ikm = new byte[k1.length + k2.length];
    System.arraycopy(k1, 0, ikm, 0, k1.length);
    System.arraycopy(k2, 0, ikm, k1.length, k2.length);
    return hkdf(ikm, unb32(id), "pandu-pin-v1/data", k1.length);
  }

  /** Encrypts JSON text for a PIN card; with a PIN (not null) it also fills s and ph for the server. */
  public static Sealed encryptPin(String json, Card card, String pin) throws Exception {
    Sealed e = encrypt(json, b32(pinDataKey(card.id, card.key, card.share)));
    return pin == null ? e : new Sealed(e.ct, e.iv, card.share, tokenHash(pinProof(card.id, card.key, pin)));
  }

  public static String decryptPin(String ct, String iv, String id, String key, String share) {
    try { return decrypt(ct, iv, b32(pinDataKey(id, key, share))); } catch (Exception e) { return null; }
  }

  static byte[] aes(int mode, byte[] key, byte[] iv, byte[] data) throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); /* the 128-bit tag is appended, as in Web Crypto */
    c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
    return c.doFinal(data);
  }

  private static byte[] deflateRaw(byte[] data) {
    Deflater d = new Deflater(9, true); /* raw DEFLATE, no zlib header */
    d.setInput(data); d.finish();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buf = new byte[4096];
    while (!d.finished()) out.write(buf, 0, d.deflate(buf));
    d.end();
    return out.toByteArray();
  }

  private static byte[] inflateRaw(byte[] data) throws Exception {
    Inflater inf = new Inflater(true);
    byte[] in = new byte[data.length + 1]; /* "nowrap" needs one extra dummy byte */
    System.arraycopy(data, 0, in, 0, data.length);
    inf.setInput(in);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buf = new byte[4096];
    while (!inf.finished()) {
      int n = inf.inflate(buf);
      if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break;
      out.write(buf, 0, n);
    }
    inf.end();
    return out.toByteArray();
  }
}
