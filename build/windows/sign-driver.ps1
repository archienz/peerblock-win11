# Back-compat wrapper. Prefer sign-pbfilter.ps1 next to pbfilter.sys.
& (Join-Path $PSScriptRoot "sign-pbfilter.ps1") @args
