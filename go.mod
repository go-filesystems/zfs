module github.com/go-filesystems/zfs

go 1.25.0

require (
	github.com/go-encryptions/zfscrypt v0.0.0
	github.com/go-filesystems/interface v0.0.0
	github.com/klauspost/compress v1.18.6
)

require github.com/go-encryptions/ccm v0.0.0 // indirect

replace github.com/go-filesystems/interface => ../interface

replace github.com/go-encryptions/zfscrypt => ../../go-encryptions/zfscrypt

replace github.com/go-encryptions/ccm => ../../go-encryptions/ccm
