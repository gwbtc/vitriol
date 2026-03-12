::  /sur/gwgh/hoon
::  Groundwire for GitHub — types
::
|%
::  Hex-encoded public key string
+$  pubkey-hex  @t
::
::  A recognized Groundwire identity
+$  gw-id
  $:  pubkey=pubkey-hex
      name=@t
      added=@da
  ==
::
::  Poke actions
+$  action
  $%  [%sign content=@t]
      [%add-key pubkey=pubkey-hex name=@t]
      [%remove-key pubkey=pubkey-hex]
      [%generate-key ~]
      [%set-key privkey=@t]
  ==
--
