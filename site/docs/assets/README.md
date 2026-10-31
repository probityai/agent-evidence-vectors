# Presentation assets

These original diagrams are maintained in the Probity Atlas repository. Their text comes from the reviewed public project catalog and the retained observer admission procedure.

The [admission presentation packet](../experiments/observer-admission/README.md) binds the article, these images, retained inputs and recorded result. It returns to the original experiment and Lab record.

| Source | Purpose |
| --- | --- |
| `component-tasks.svg` | Public component entry points grouped by task; no dependency chain |
| `admission-replay.svg` | The worked replay's inputs, consumer decision and required refusals |
| `admission-social.svg` | The worked article's social preview; preserves the same-operator PEER scope |

The SVG files are the editable sources. Each includes a title and description. Page image text and social metadata provide the corresponding text alternative.

`admission-social.png` is the served preview, exported at the SVG's native 1200 by 630 dimensions with CairoSVG 2.9.0. From the repository root:

```sh
uv run --no-project --with cairosvg==2.9.0 python - <<'PY'
import cairosvg
cairosvg.svg2png(url="assets/admission-social.svg", write_to="assets/admission-social.png")
PY
```

Raster output can differ with the renderer or system fonts. Inspect any new export and run the native build and metadata controls before committing it. The checked source and raster are kept together.

A page can set `social_image` to an `assets/*.png` path and `social_image_alt` to its plain text alternative. Both fields are required together. The image must have a PNG signature and a regular source file declared in `tools/build.py`'s `COPIES` for that page. Paths, rich markup, empty text, controls and text longer than 512 characters refuse. Description and social attributes are escaped before Pandoc receives the generated fragment.
