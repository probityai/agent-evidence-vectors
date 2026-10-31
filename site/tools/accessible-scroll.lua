-- Keep native table semantics inside a keyboard-accessible scroll region.
-- The label comes from the content, so it survives translated page headings.
function Table(element)
  local label = pandoc.utils.stringify(element.caption.long)
  if label == "" then
    local headers = {}
    for _, row in ipairs(element.head.rows) do
      for _, cell in ipairs(row.cells) do
        table.insert(headers, pandoc.utils.stringify(cell.contents))
      end
    end
    label = table.concat(headers, " / ")
  end
  if label == "" then
    label = "Table"
  end
  return pandoc.Div({element}, pandoc.Attr("", {"table-scroll"}, {
    {"tabindex", "0"},
    {"role", "region"},
    {"aria-label", label}
  }))
end

-- Long commands can need horizontal scrolling on a small screen too.
function CodeBlock(element)
  return pandoc.Div({element}, pandoc.Attr("", {"code-scroll"}, {
    {"tabindex", "0"},
    {"role", "region"},
    {"aria-label", "Code example"}
  }))
end
