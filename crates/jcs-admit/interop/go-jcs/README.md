# Go JCS with raw admission

This adapter admits the original bytes with jcs-admit, then calls the [pinned Go writer](https://github.com/cyberphone/json-canonicalization/tree/19d51d7fe467d4706a3ff08adf8a748f29fc21e0). It requires exact canonical-byte agreement. Go receives the original input after admission; parsing first would lose duplicate-member evidence.

From the repository root:

```sh
git clone https://github.com/cyberphone/json-canonicalization interop/go-jcs/upstream
git -C interop/go-jcs/upstream checkout 19d51d7fe467d4706a3ff08adf8a748f29fc21e0
python3 interop/go-jcs/check.py --installation /absolute/path/outside-checkout/installed
```

[MANIFEST.json](MANIFEST.json) pins the original modules, license, native tests and corpus. The compiled modules are byte-identical copies. Installed commands run outside the checkout.

The 1,263 cases retain six RFC documents, 39 cross-rail inputs, 317 string/key/member attacks, 850 ECMAScript number ties, 24 finite Appendix B rows and 27 finite controls. Number samples use declared one-element arrays for Go's object/array root domain. The original attack scalar stays unchanged with a separate root refusal. NaN and Infinity rows stay unselected.

The consumer yields 1,077 exact byte matches, 181 raw refusals and five root refusals. Bare Go observations stay alongside them. RFC 8785 and opt-in I-JSON keep distinct policies. Go already refuses duplicate names; its UTF-8 assumption, malformed surrogate pairing, depth/size limits and I-JSON controls need the raw gate.

```sh
printf '%s' '{"b":1,"a":2}' | /absolute/path/installed/go-jcs --admission /absolute/path/installed/go-jcs-admission --profile rfc8785
```

Select the installed admission executable through trusted configuration. `ijson` opts into safe integers and noncharacters; `ijson-integers` also refuses fractions. Caps can only lower the defaults. Byte disagreement refuses separately.

CI runs Go 1.25.5 and 1.27.1, the original native byte suite, [adapter controls](adapter_test.go), [pin controls](test_check.py) and [all cases](check.py). It retains exact sources and results.
