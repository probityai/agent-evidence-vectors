"""Read the installed released registry without using a source checkout."""

import hashlib
import json
from importlib import metadata, resources
from pathlib import Path

import agent_evidence_vocabulary
import yaml

source = Path(__file__).resolve().parents[1]
installed = Path(agent_evidence_vocabulary.__file__).resolve()
if installed.is_relative_to(source):
    raise ValueError("consumer imported the source checkout")
raw = resources.files("agent_evidence_vocabulary").joinpath("vocabulary.yaml").read_bytes()
vocabulary = yaml.safe_load(raw)
version = metadata.version("agent-evidence-vocabulary")
if vocabulary["meta"]["version"] != version:
    raise ValueError("installed distribution and registry versions differ")
digest = hashlib.sha256(raw).hexdigest()
if digest != "76233ba8924cebdf053f0449ce023186805156aedca4121b9b156bd747a411b4":
    raise ValueError("installed registry differs from the pinned registry")
values = vocabulary["evidence_dimensions"]["observation_vantage"]["values"]
if values != ["substrate", "artifact"]:
    raise ValueError("released observation_vantage values changed")
print(json.dumps({"installed_module": str(installed), "version": version,
                  "sha256": digest, "observation_vantage": values}, sort_keys=True))
