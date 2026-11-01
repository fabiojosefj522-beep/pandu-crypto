/* Checks PanduCrypto.java against test/vectors.json (no JSON library needed: a tiny parser is below).
   javac -d build examples/java/*.java && java -cp build VectorsTest test/vectors.json */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class VectorsTest {
  static int pass = 0, fail = 0;
  static void ok(boolean c, String name) { if (c) pass++; else { fail++; System.out.println("  FAIL " + name); } }

  public static void main(String[] args) throws Exception {
    String text = new String(Files.readAllBytes(Paths.get(args.length > 0 ? args[0] : "test/vectors.json")), StandardCharsets.UTF_8);
    @SuppressWarnings("unchecked") Map<String, Object> v = (Map<String, Object>) new Json(text).value();

    boolean b32ok = true;
    for (Object o : (List<?>) v.get("base32")) {
      Map<?, ?> x = (Map<?, ?>) o;
      String t = (String) x.get("text"), b = (String) x.get("base32");
      b32ok &= PanduCrypto.b32(t.getBytes(StandardCharsets.UTF_8)).equals(b) && new String(PanduCrypto.unb32(b), StandardCharsets.UTF_8).equals(t);
    }
    ok(b32ok, "base32");
    boolean b64ok = true;
    for (Object o : (List<?>) v.get("base64url")) { Map<?, ?> x = (Map<?, ?>) o; b64ok &= PanduCrypto.b64url(hex((String) x.get("hex"))).equals(x.get("base64url")); }
    ok(b64ok, "base64url");
    Map<?, ?> l = (Map<?, ?>) v.get("link");
    ok(PanduCrypto.makeLink((String) l.get("base"), (String) l.get("id"), (String) l.get("key")).equals(l.get("link")), "link");
    String[] p = PanduCrypto.parseLink((String) l.get("link"));
    ok(p != null && p[0].equals(l.get("id")) && p[1].equals(l.get("key")) && PanduCrypto.b32(hex((String) l.get("id_hex"))).equals(l.get("id")), "parse link");
    Map<?, ?> t = (Map<?, ?>) v.get("token");
    ok(PanduCrypto.tokenHash((String) t.get("tok")).equals(t.get("sha256_hex")), "token hash");
    for (Object o : (List<?>) v.get("aes_gcm")) {
      Map<?, ?> x = (Map<?, ?>) o;
      String name = (String) x.get("name");
      ok(x.get("json").equals(PanduCrypto.decrypt((String) x.get("ct"), (String) x.get("iv"), (String) x.get("key"))), "decrypt " + name);
      byte[] ct = PanduCrypto.aes(javax.crypto.Cipher.ENCRYPT_MODE, PanduCrypto.unb32((String) x.get("key")), PanduCrypto.unb64url((String) x.get("iv")), hex((String) x.get("plaintext_hex")));
      ok(PanduCrypto.b64url(ct).equals(x.get("ct")), "encrypt " + name);
    }
    String json = "{\"n\":\"Maria\",\"note\":\"" + "á é í ó ú ç 🐼 ".repeat(20) + "\"}";
    for (int bits : new int[] { 128, 256 }) {
      PanduCrypto.Card c = PanduCrypto.newCard(bits);
      PanduCrypto.Sealed s = PanduCrypto.encrypt(json, c.key);
      ok(json.equals(PanduCrypto.decrypt(s.ct, s.iv, c.key)), "round trip " + bits);
      ok(PanduCrypto.decrypt(s.ct, s.iv, PanduCrypto.newCard(bits).key) == null, "wrong key " + bits);
    }
    System.out.println(pass + " passed, " + fail + " failed");
    System.exit(fail == 0 ? 0 : 1);
  }

  static byte[] hex(String h) {
    byte[] out = new byte[h.length() / 2];
    for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
    return out;
  }

  /* minimal JSON reader: objects, arrays, strings (with \\uXXXX), numbers, true/false/null */
  static final class Json {
    final String s; int i = 0;
    Json(String s) { this.s = s; }
    void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    Object value() {
      ws(); char c = s.charAt(i);
      if (c == '{') { i++; Map<String, Object> m = new LinkedHashMap<>(); ws(); if (s.charAt(i) == '}') { i++; return m; }
        while (true) { ws(); String k = str(); ws(); i++; m.put(k, value()); ws(); if (s.charAt(i++) == '}') return m; } }
      if (c == '[') { i++; List<Object> a = new ArrayList<>(); ws(); if (s.charAt(i) == ']') { i++; return a; }
        while (true) { a.add(value()); ws(); if (s.charAt(i++) == ']') return a; } }
      if (c == '"') return str();
      if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
      if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
      if (s.startsWith("null", i)) { i += 4; return null; }
      int st = i; while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
      return Double.parseDouble(s.substring(st, i));
    }
    String str() {
      StringBuilder b = new StringBuilder(); i++;
      while (true) {
        char c = s.charAt(i++);
        if (c == '"') return b.toString();
        if (c != '\\') { b.append(c); continue; }
        char e = s.charAt(i++);
        switch (e) {
          case 'n': b.append('\n'); break; case 't': b.append('\t'); break; case 'r': b.append('\r'); break;
          case 'b': b.append('\b'); break; case 'f': b.append('\f'); break;
          case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
          default: b.append(e);
        }
      }
    }
  }
}
