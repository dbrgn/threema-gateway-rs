# Releasing

Set variables:

    $ export VERSION=X.Y.Z
    $ export GPG_KEY=E7ADD9914E260E8B35DFB50665FDE935573ACDA6

Update version numbers:

    $ vim threema-gateway/Cargo.toml
    $ cargo update

Update changelog:

    $ vim threema-gateway/CHANGELOG.md

Commit & tag:

    $ git commit -S${GPG_KEY} -m "Release v${VERSION}"
    $ git tag -s -u ${GPG_KEY} v${VERSION} -m "Version ${VERSION}"

Publish:

    $ cargo publish -p threema-gateway
    $ git push && git push --tags
