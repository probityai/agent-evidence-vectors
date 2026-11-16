// Unpublished test harness. check.py builds this module from a checkout of this
// repository; nothing publishes it and nothing fetches it. The module path is a
// local name for the import paths inside the harness, under the reserved .invalid
// top-level domain (RFC 2606), so no proxy, VCS or registry can resolve it. The
// earlier path, github.com/probityai/jcs-admit/interop/go-jcs, named a repository
// that now redirects to an archive, and proxy.golang.org served that archive's
// stale copy for it.
module jcsadmit.invalid/go-jcs

go 1.23
