import io
import xml.sax
from xml.sax.handler import feature_external_ges


class _TextHandler(xml.sax.ContentHandler):
    """Collect the character data of a document."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []

    def characters(self, content: str) -> None:
        self._chunks.append(content)

    @property
    def text(self) -> str:
        return "".join(self._chunks)


def parse_note(document: str) -> str:
    """Return the text of an uploaded XML note."""
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, True)
    handler = _TextHandler()
    parser.setContentHandler(handler)
    parser.parse(io.StringIO(document))
    return handler.text
