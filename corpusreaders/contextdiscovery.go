package corpora

import (
	"sort"
	"strings"
)

// lcdRejections judges a discovery snapshot under
// draft-arsentev-llm-context-discovery-00. It is the Go statement of
// packaging/agent_evidence_vectors/contextdiscovery.py: the same sentences,
// bound to the same LCD-R-nnn identifiers, so the parity test can diff the two.

const lcdWellKnown = "/.well-known/llm-context"

var lcdRedirects = map[int64]bool{301: true, 302: true, 307: true, 308: true}

func lcdR(n int) string { return "LCD-R-" + pad3(n) }

type lcdRejects map[string]bool

func (r lcdRejects) add(n int) { r[lcdR(n)] = true }

func lcdShapeErrors(value any) []string {
	document, ok := value.(map[string]any)
	if !ok {
		return []string{"the document is not a JSON object"}
	}
	var out []string
	if !isStr(document["origin"]) {
		out = append(out, "the snapshot carries no string origin")
	}
	if !isObj(document["resources"]) {
		out = append(out, "the snapshot carries no resources object")
	}
	if !isObj(document["consumer"]) {
		out = append(out, "the snapshot carries no consumer object")
	}
	for _, slot := range []string{"well-known", "link", "robots"} {
		if raw, present := document[slot]; present && raw != nil && !isObj(raw) {
			out = append(out, slot+" is present and is not an object")
		}
	}
	return lcdShapeLists(document, out)
}

// lcdListOf: container[key], when present, is an array whose every element
// has one type. Absent is allowed; any other JSON type, null included, is a
// shape defect, never an empty list.
func lcdListOf(container any, key, where, item string, out []string) []string {
	object, ok := container.(map[string]any)
	if !ok {
		return out
	}
	value, present := object[key]
	if !present {
		return out
	}
	list, isList := value.([]any)
	if !isList {
		return append(out, where+"."+key+" is not an array")
	}
	for i, element := range list {
		if item == "string" && !isStr(element) {
			out = append(out, where+"."+key+"["+itoa(i)+"] is not a string")
		} else if item == "object" && !isObj(element) {
			out = append(out, where+"."+key+"["+itoa(i)+"] is not an object")
		}
	}
	return out
}

// lcdShapeLists: the members the draft gives a JSON type that the rows then
// iterate. Section 4.3 and RFC 9309 make robots.txt exclusion rules and
// records sequences, a consumer's retrievals are a list of URIs, and every
// entry of resources describes one resource.
func lcdShapeLists(document map[string]any, out []string) []string {
	out = lcdListOf(document["robots"], "disallow", "robots", "string", out)
	out = lcdListOf(document["robots"], "records", "robots", "object", out)
	out = lcdListOf(document["consumer"], "retrieved", "consumer", "string", out)
	if resources, ok := document["resources"].(map[string]any); ok {
		uris := make([]string, 0, len(resources))
		for uri := range resources {
			uris = append(uris, uri)
		}
		sort.Strings(uris)
		for _, uri := range uris {
			if !isObj(resources[uri]) {
				out = append(out, "resources."+uri+" is not an object")
			}
		}
	}
	return out
}

func lcdAbsolute(v any) bool {
	s, ok := v.(string)
	return ok && (strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://"))
}

func lcdOrigin(uri string) string {
	scheme, rest, _ := strings.Cut(uri, "://")
	host, _, _ := strings.Cut(rest, "/")
	return scheme + "://" + host
}

func lcdPath(uri string) string {
	_, rest, _ := strings.Cut(uri, "://")
	_, path, found := strings.Cut(rest, "/")
	if !found {
		return "/"
	}
	return "/" + path
}

func lcdDisallowed(uri string, origin string, robots map[string]any) bool {
	if !lcdAbsolute(uri) || lcdOrigin(uri) != origin || robots == nil {
		return false
	}
	rules, _ := robots["disallow"].([]any)
	for _, raw := range rules {
		rule, ok := raw.(string)
		if ok && rule != "" && strings.HasPrefix(lcdPath(uri), rule) {
			return true
		}
	}
	return false
}

func lcdRecords(robots map[string]any) []any {
	if robots == nil {
		return nil
	}
	records, _ := robots["records"].([]any)
	var out []any
	for _, raw := range records {
		record, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, ok := record["name"].(string)
		if !ok {
			continue
		}
		if strings.ToLower(name) == "llm-context" {
			out = append(out, record["value"])
		}
	}
	return out
}

// lcdWellKnownTarget is the URI the well-known mechanism advertises, and
// whether it advertises one at all.
func lcdWellKnownTarget(document map[string]any, out lcdRejects) (string, bool) {
	response, ok := document["well-known"].(map[string]any)
	if !ok {
		return "", false
	}
	status, isInt := intValue(response["status"])
	if isInt && status == 404 {
		return "", false
	}
	if isInt && status >= 200 && status < 300 {
		if contentType, ok := response["content-type"].(string); ok && strings.HasPrefix(strings.ToLower(contentType), "text/html") {
			out.add(1)
		}
		if negotiated, _ := response["negotiated"].(bool); negotiated && !isStr(response["content-language"]) {
			out.add(10)
		}
		origin, _ := document["origin"].(string)
		return origin + lcdWellKnown, true
	}
	if isInt && lcdRedirects[status] && lcdAbsolute(response["location"]) {
		return response["location"].(string), true
	}
	out.add(3)
	return "", false
}

func lcdRowsPublisher(document map[string]any, out lcdRejects) (string, bool) {
	origin, _ := document["origin"].(string)
	resources, _ := document["resources"].(map[string]any)
	robots, _ := document["robots"].(map[string]any)
	link, _ := document["link"].(map[string]any)
	linkTarget, hasLink := link["target"].(string)
	wellKnown, hasWellKnown := lcdWellKnownTarget(document, out)
	var robotsTargets []string
	for _, value := range lcdRecords(robots) {
		if !lcdAbsolute(value) {
			out.add(4)
			continue
		}
		target := value.(string)
		if lcdDisallowed(target, origin, robots) {
			out.add(5)
		}
		robotsTargets = append(robotsTargets, target)
	}
	var targets []string
	if hasLink {
		targets = append(targets, linkTarget)
	}
	if hasWellKnown {
		targets = append(targets, wellKnown)
	}
	targets = append(targets, robotsTargets...)
	for _, target := range targets {
		if resource, ok := resources[target].(map[string]any); ok {
			if role, _ := resource["role"].(string); role == "detail" {
				out.add(2)
				break
			}
		}
	}
	switch {
	case hasLink:
		return linkTarget, true
	case hasWellKnown:
		return wellKnown, true
	case len(robotsTargets) > 0:
		return robotsTargets[0], true
	}
	return "", false
}

func lcdRowsConsumer(document map[string]any, selected string, selectedOK bool, out lcdRejects) {
	origin, _ := document["origin"].(string)
	resources, _ := document["resources"].(map[string]any)
	robots, _ := document["robots"].(map[string]any)
	consumer, _ := document["consumer"].(map[string]any)
	if resolved, present := consumer["resolved"]; present && resolved != nil {
		s, isString := resolved.(string)
		if !isString || !selectedOK || s != selected {
			out.add(6)
		}
	}
	retrieved := lcdRetrieved(consumer)
	if lcdIndexCount(retrieved, resources) > 1 {
		out.add(7)
	}
	resolved, _ := consumer["resolved"].(string)
	foreign := lcdAbsolute(consumer["resolved"]) && lcdOrigin(resolved) != origin
	if foreign && jsonEqual(consumer["attributed-to"], origin) {
		out.add(8)
	}
	if ceiling, ok := intValue(consumer["ceiling-octets"]); !ok || ceiling <= 0 {
		out.add(9)
	}
	for _, uri := range retrieved {
		if lcdDisallowed(uri, origin, robots) {
			out.add(11)
			break
		}
	}
}

// lcdRetrieved: the string members of consumer.retrieved, in order.
func lcdRetrieved(consumer map[string]any) []string {
	rawRetrieved, _ := consumer["retrieved"].([]any)
	var retrieved []string
	for _, raw := range rawRetrieved {
		if s, ok := raw.(string); ok {
			retrieved = append(retrieved, s)
		}
	}
	return retrieved
}

// lcdIndexCount: how many retrieved resources the document files under the
// index role.
func lcdIndexCount(retrieved []string, resources map[string]any) int {
	indexes := 0
	for _, uri := range retrieved {
		if resource, ok := resources[uri].(map[string]any); ok {
			if role, _ := resource["role"].(string); role == "index" {
				indexes++
			}
		}
	}
	return indexes
}

func lcdRejections(document map[string]any) []string {
	out := lcdRejects{}
	selected, ok := lcdRowsPublisher(document, out)
	lcdRowsConsumer(document, selected, ok, out)
	ids := make([]string, 0, len(out))
	for id := range out {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
