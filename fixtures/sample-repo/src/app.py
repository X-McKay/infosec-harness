"""Intentionally small, read-only fixture used only for harness triage tests."""


def render_profile(request):
    # The scanner flags this source-to-sink path. A real service would validate input.
    template = request["template"]
    return render(template)


def render(value):
    return value
