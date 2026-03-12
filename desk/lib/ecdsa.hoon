::  /lib/ecdsa/hoon
::  Thin wrapper around zuse's secp256k1:secp:crypto for Groundwire signing
::
|%
+$  point  [x=@ y=@]
::
++  sign
  |=  [hash=@uvI priv=@]
  ^-  [v=@ r=@ s=@]
  (ecdsa-raw-sign:secp256k1:secp:crypto hash priv)
::
++  recover
  |=  [hash=@ sig=[v=@ r=@ s=@]]
  ^-  point
  (ecdsa-raw-recover:secp256k1:secp:crypto hash sig)
::
++  pubkey
  |=  priv=@
  ^-  point
  (priv-to-pub:secp256k1:secp:crypto priv)
::
++  compress
  |=  pub=point
  ^-  @
  (compress-point:secp256k1:secp:crypto pub)
::
++  decompress
  |=  compressed=@
  ^-  point
  (decompress-point:secp256k1:secp:crypto compressed)
::
++  verify
  |=  [hash=@ sig=[v=@ r=@ s=@] expected=point]
  ^-  ?
  =/  recovered  (recover hash sig)
  &(=(x.recovered x.expected) =(y.recovered y.expected))
::
++  hash-cord
  |=  content=@t
  ^-  @
  =/  len  (met 3 content)
  (shay len content)
::
++  sig-to-hex
  |=  [v=@ r=@ s=@]
  ^-  @t
  =/  v-str  (trip (pad-to 2 v))
  =/  r-str  (trip (pad-to 64 r))
  =/  s-str  (trip (pad-to 64 s))
  (crip (weld v-str (weld r-str s-str)))
::
++  point-to-hex
  |=  pub=point
  ^-  @t
  (pad-to 66 (compress pub))
::
++  pad-to
  |=  [chars=@ n=@]
  ^-  @t
  =/  raw     (trip (scot %ux n))
  =/  nodots  (skim (slag 2 raw) |=(c=@ !=(c '.')))
  =/  cur     (lent nodots)
  ?:  (gte cur chars)
    (crip (slag (sub cur chars) nodots))
  (crip (weld (reap (sub chars cur) '0') nodots))
--
