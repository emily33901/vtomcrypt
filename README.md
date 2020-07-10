# vtomcrypt

A rushed, simplistic wrapper around [libtomcrypt](https://www.libtom.net/LibTomCrypt/). It currently exposes rsa and aes encryption in the way that I needed it to for [vapor](https://github.com/emily33901/vapor). No attempt has been made to make a complete library - or indeed hide the C'isms of it in any way. It just works and thats what I needed.

libtomcrypt and libtommath are included in here so that no additional downloads (or `git submodule update --init`) are required.

No pre-building is required either since every single object file is included in `tomobjs.v` and `tommathobjs.v`.

## Examples

See [vapor](https://github.com/emily33901/vapor/)