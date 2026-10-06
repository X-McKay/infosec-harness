---
name: cwe-611-xxe
description: Recognize XML external entity sinks and define a sandbox-file oracle. Use this when the
  finding is CWE-611 or untrusted XML is parsed with entity resolution enabled.
metadata:
  owner: appsec
  version: 2.0.0
---

# CWE-611: XML external entity (XXE)

## Use this skill when

- The finding is classified CWE-611, or names XXE or external entity expansion.
- Untrusted XML reaches a parser whose entity or DTD processing is not disabled.

## Do not use this skill when

- The parser has entity resolution explicitly disabled and the finding is about something else.
- The document is JSON or YAML — use `cwe-502-deserialization`.

## When another skill also applies

- `cwe-502-deserialization` also fires when the XML goes to something that instantiates the types it names rather than to a plain parser, while its own negative criteria send every XML payload back here. **That skill wins** there: the oracle has to observe object construction, which an entity-expansion probe never exercises. Keep this skill when the hazard is the parser resolving an external entity or a DTD.

## Procedure

**Sink.** Parsing untrusted XML with a parser that resolves external entities/DTDs:
misconfigured `lxml`, `DocumentBuilderFactory` without secure processing, `XMLReader` with
external entities enabled.

**Source.** Untrusted XML documents.

**Neutralized when.** The parser disables DTDs / external entity resolution (secure-processing
feature on, `resolve_entities=False`, `disallow-doctype-decl`).

## Oracle

Condition: **the parser resolved an external entity to local file content.** At run time,
create a marker file under `/tmp` containing a unique nonce, and a document whose DOCTYPE
declares an external entity pointing at that file (`file://` under `/tmp`) and expands it
in the body. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real parse entry point, with its own parser configuration, received
  the document, including when it rejects the DOCTYPE or leaves the entity unresolved.
- `vulnerability_observed`: the nonce appears in the parsed result the target returns.
- `positive_control`: the same document through a parser deliberately configured to resolve
  external entities yields the nonce, proving the document and check work.
- `negative_control`: an equivalent document without the DOCTYPE, holding plain text, passes
  through the target and the nonce is absent.

Point entities only at the probe's marker file; never at system files or network URLs.

## Concrete oracle recipe

The pattern is identical in every language; only the parser calls change:

1. Write a fresh random **nonce** into a marker file under `/tmp` (the file content *is* the
   nonce). Build its absolute `file://` URI.
2. **Attack document:** a DOCTYPE declaring `<!ENTITY xxe SYSTEM "file:///tmp/...">` and a
   body that expands `&xxe;`.
3. **Negative control:** the same shape with **no** DOCTYPE, holding plain text.
4. Call the real loader entry point on each document and read the text it returns.
5. Decide, then print one `HARNESS_PROBE` line with the five strict JSON booleans (see `probe`):
   - `vulnerability_observed`: the returned text **contains the nonce** (entity resolved).
     Rejected = an exception or text without the nonce.
   - `positive_control`: the attack document through a **plain**
     `DocumentBuilderFactory.newInstance()` (Java) / entity-resolving parser (other langs)
     with **no** secure-processing or entity flags set — it yields the nonce, proving the
     document and the check work. Build the positive control this way; do **not** hand-toggle
     `secure-processing` / `external-general-entities` / `ACCESS_EXTERNAL_DTD` attributes
     (they differ by JDK and `--release` level and give false negatives).
   - `negative_control`: the no-DOCTYPE document yields text without the nonce.

The commonest oracle bug: writing a fixed string (e.g. `"EXPECTED_NONCE"`) into the marker
but searching the output for a *different* random nonce. The entity resolves, yet every
field reads `false`. Write the nonce itself and search for that same nonce. If the positive
control is `false`, the oracle is broken, not the target — fix it before iterating (see `probe`).

### Java (OpenJDK 17 in the workspace)

Compile the target class(es) and this single-file runner directly with the workspace JDK —
`--release 17` or no `--release` flag, **never `--release 7`** (it lacks
`XMLConstants.ACCESS_EXTERNAL_DTD` and warns about an obsolete target). No Maven, no JUnit;
see `lang-java`.

```java
// ProbeRunner.java  — adjust the import and the loader call to the real entry point.
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import com.example.XmlLoader;               // the target under investigation

public class ProbeRunner {
    public static void main(String[] args) throws Exception {
        String nonce = "xxe_nonce_" + Long.toHexString(System.nanoTime());
        Path marker = Files.createTempFile("xxe_probe_", ".txt");
        Files.writeString(marker, nonce);                 // file content IS the nonce
        String uri = marker.toUri().toString();           // file:///tmp/...

        String attack = "<?xml version=\"1.0\"?>\n"
            + "<!DOCTYPE r [ <!ENTITY xxe SYSTEM \"" + uri + "\"> ]>\n<r>&xxe;</r>";
        String benign = "<?xml version=\"1.0\"?>\n<r>plain</r>";

        boolean reached = false, vuln = false, pos = false, neg = false;
        try {                                             // real target, its own config
            String out = new XmlLoader().loadTitle(attack);   // String entry point
            reached = true; vuln = out != null && out.contains(nonce);
        } catch (Exception e) { reached = true; }         // reached it; it rejected
        try { String out = new XmlLoader().loadTitle(benign); neg = out == null || !out.contains(nonce); }
        catch (Exception e) { neg = true; }
        try { pos = plain(attack).contains(nonce); } catch (Exception e) {}
        Files.deleteIfExists(marker);

        System.out.println("HARNESS_PROBE {\"target_reached\": " + reached
            + ", \"oracle_valid\": true, \"positive_control\": " + pos
            + ", \"negative_control\": " + neg
            + ", \"vulnerability_observed\": " + vuln + "}");
    }
    // Positive control: a plain factory, no secure-processing or entity flags.
    static String plain(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = f.newDocumentBuilder();
        Document d = b.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
        return d.getDocumentElement().getTextContent();
    }
}
```

Match the loader call to the real signature: a `String` loader takes the document directly;
a loader taking an `InputStream` gets `new ByteArrayInputStream(doc.getBytes("UTF-8"))`; a
loader taking a `File` gets the attack document written to a temp file whose path you pass.
Compile and run, from `/workspace/repo`:

```bash
javac -d /tmp/probe_classes src/main/java/com/example/XmlLoader.java ProbeRunner.java
java -cp /tmp/probe_classes ProbeRunner
```

Verified against the corpus with OpenJDK (`--release 17`): the plain loader resolves the
entity (`vulnerability_observed: true`, `positive_control: true`), and a loader that sets
`disallow-doctype-decl` rejects the DOCTYPE (`vulnerability_observed: false`, controls still
`true`).

### Python

The sink family varies (`xml.sax`, `lxml`, `xml.etree`); call whichever the target uses and
keep the positive control a parser that deliberately resolves external general entities:

```python
import io, json, os, tempfile, xml.sax
from xml.sax.handler import feature_external_ges

nonce = "xxe_nonce_" + os.urandom(6).hex()
fd, marker = tempfile.mkstemp(prefix="xxe_", suffix=".txt")
os.write(fd, nonce.encode()); os.close(fd)
attack = f'<?xml version="1.0"?>\n<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file://{marker}"> ]>\n<r>&xxe;</r>'
benign = '<?xml version="1.0"?>\n<r>plain</r>'

def pos_control(doc):                       # resolves entities on purpose
    p = xml.sax.make_parser(); p.setFeature(feature_external_ges, True)
    class H(xml.sax.ContentHandler):
        def __init__(self): self.c = []
        def characters(self, s): self.c.append(s)
    h = H(); p.setContentHandler(h); p.parse(io.StringIO(doc)); return "".join(h.c)

# from target import parse_note            # the real entry point
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

For an `lxml` target, the resolving positive control is
`etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)` with
`etree.fromstring(doc, parser)`; for `xml.etree.ElementTree`, note it does not expand external
entities at all, so a target built only on it is a structural `likely_not_exploitable` —
probe the real entry point and report `vulnerability_observed: false`.

### Other languages

The corpus has no JavaScript or Perl XXE case; if one appears, keep the same shape — nonce
marker file, DOCTYPE with an external `SYSTEM` entity, plain-text negative control, and a
positive control whose parser is configured to resolve entities. In Perl that control is
`XML::LibXML->new(expand_entities => 1, no_network => 1)`; in JavaScript it is `libxmljs`
with `{ noent: true }`, or the parser's documented entity-resolution flag.
