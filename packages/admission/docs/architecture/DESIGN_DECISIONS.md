# Host consumer design decisions

## Keep the selected source checks together

The host consumer accepts one reviewed source contract and one retained archive.
It binds each source to a digest and a full Git commit before execution. It copies
the selected installed sources into a fresh private directory before replay.
Python runs that copy with `-I -S -B`. Candidate bytecode, import hooks and packet
helpers cannot select the reader code.

The first implementation combined installation receipts, site selection and
namespace checks in one function with complexity 22. Those inputs have distinct
trust boundaries. `installation_site` now binds the receipt and selects the
private Python site. `verify_package_sources` closes that site's reader
namespace. `verify_installation` coordinates those checks.

The private library and site each have a declared limit of 128 entries. The
installation receipt has a declared limit of 65,536 bytes. Its reader and every
source or archive reader open without following the final symlink and without
blocking on a pipe, then check the opened descriptor's regular file type before
the bounded read. The selected reader has
one flat namespace with its exact selected file population. Streaming directory
enumeration stops at the first excess entry. It never descends into an unexpected
directory. Each source read has a declared limit of 1,048,576 bytes, including the
second read before the isolated source copy. These limits bound work on a poisoned
installation before import. A reviewed future selection that needs larger source
files must review the host limit with its consumer code.

Archive validation now produces a complete extraction plan before any file write.
`validate_archive_population` binds unique member names and total expanded size
to the host selection. `archive_member_path` checks one member's canonical path
and accepts only regular or unspecified ZIP file types. `archive_extraction_plan`
refuses file and ancestor collisions in either order. This prevents a late
unsafe member from leaving an earlier file extracted. `repeat_selected_reader`
owns the two reader results, their logs and the repeated decision contract.
`copy_selected_sources` owns the source copy before the private import directory
enters the reader's search path. These functions separate actual trust inputs and
resource lifetimes; they do not add alternate names for an existing API.

Three functions still keep a complete boundary visible in one place. Their branch
counts come from `radon cc` on the final consumer source. These are explicit
exceptions to the default limit of ten; the limit remains in force elsewhere.

| Function | Complexity | Reason to keep these checks together |
| --- | --- | --- |
| `consumer.verify_package_sources` | 12 | Namespace traversal checks the package directory, exact population, entry types, source ancestry and every selected source digest before any reader import. The independent predicates describe distinct unselected source shapes. A further split would fragment the same closed namespace check. |
| `consumer.download` | 11 | Network coordination enforces HTTPS, exclusive output creation, declared length, a hard deadline and archive authentication. The cleanup and alarm restoration stay adjacent to their resource acquisition. |
| `verify_native.verify` | 12 | The check coordinates two fresh installations, the original native replay, concrete hostile mutations, a bytecode positive control, replacement recovery and distinct CLI exits. It retains the receipt for each tested boundary. |

No general compatibility layer or alternate import name exists. The reader's
namespace is the exact public package namespace named by the source contract.
Refusal conditions keep their explicit checks. A later change that adds an
independent responsibility must extract that responsibility and reassess these
exceptions.

The host owns its selected interpreter, operating system, build tools and
selection file. Source digests cover reader source bytes; they do not authenticate
the host interpreter or establish outside adoption or independent custody.
