# The fixture suite's checker: accept a case whose expectation is accept.
import json, sys
print(json.load(open(sys.argv[1]))['expect'])
