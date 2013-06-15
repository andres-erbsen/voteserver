package lsags

// #cgo CFLAGS: -O3 -fPIC
// #cgo LDFLAGS: -lcrypto -llsags
// #include <lsags.h>
import "C"
import "unsafe"
import "errors"

func Verify(pks, msg, tag, sig []byte) error {
	if C.int(0) == C.LSAGS_verify(
		(*C.uchar)(unsafe.Pointer(&pks[0])), C.size_t(len(pks)),
		(*C.uchar)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(&tag[0])), C.size_t(len(tag)),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		nil) {
		return errors.New("lsags: verification error")
	}
	return nil
}
