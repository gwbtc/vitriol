::  /sur/vitriol/hoon
::  Groundwire for GitHub — shared type definitions
::
::  cashu-proof          — a single Cashu token (NUT-00)
::  pending-mint-quote   — in-flight Lightning invoice → token mint flow (NUT-04)
::  pending-verify       — in-flight NUT-03 swap verification of incoming tokens
::
|%
+$  cashu-proof
  $:  amount=@ud
      id=@t
      secret=@t
      c=@t
  ==
::
+$  pending-mint-quote
  $:  mint=@t
      quote-id=@t
      bolt11=@t
      amount=@ud
      keyset-id=@t
      expiry=@da
      step=?(%fetch-keys %keyset %quote %check-quote %mint-tokens)
      secrets=(list @t)
      blinding-factors=(list @)
  ==
::
+$  pending-melt
  $:  mint=@t
      step=?(%quote %execute)
      invoice=@t
      proofs-used=(list cashu-proof)
      quote-id=@t
      fee-reserve=@ud
  ==
::
+$  pending-verify
  $:  signer=@p
      life=@ud
      mint=@t
      tokens=(list cashu-proof)
      token-total=@ud
      step=?(%fetch-keys %swap)
      keyset-id=@t
      secrets=(list @t)
      blinding-factors=(list @)
      result=?(%pending %verified %failed)
      error=@t
  ==
--
