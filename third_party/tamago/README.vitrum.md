# Vitrum TamaGo patch

This directory is TamaGo v1.26.6, commit
`48bec198b759921f3aea800c9ca0468a2552f961`.

Vitrum carries one patch in `soc/nxp/usdhc`: preserve CMD23 bit 31 as the
RPMB reliable-write flag while passing the decoded 16-bit block count to the
uSDHC controller transfer.
