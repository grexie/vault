//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <Security/Security.h>
#include <stdlib.h>
static OSStatus vault_generic(UInt32 *len, void **data) {
 return SecKeychainFindGenericPassword(NULL,19,"Chrome Safe Storage",6,"Chrome",len,data,NULL);
}
static OSStatus vault_internet(const char *host,UInt32 hostLen,const char *account,UInt32 accountLen,UInt32 *len,void **data) {
 return SecKeychainFindInternetPassword(NULL,hostLen,host,0,NULL,accountLen,account,0,NULL,0,kSecProtocolTypeHTTPS,kSecAuthenticationTypeDefault,len,data,NULL);
}
static void vault_free(void *data,UInt32 len){if(data){volatile unsigned char *p=data;for(UInt32 i=0;i<len;i++)p[i]=0;SecKeychainItemFreeContent(NULL,data);}}
*/
import "C"
import (
	"errors"
	"unsafe"
)

type nativeKeychain struct{}

func newNative() Native { return nativeKeychain{} }
func (nativeKeychain) ChromePassword() ([]byte, error) {
	var n C.UInt32
	var p unsafe.Pointer
	status := C.vault_generic(&n, &p)
	defer C.vault_free(p, n)
	if status != 0 || n == 0 || n > 65536 {
		return nil, errors.New("macOS did not authorize Chrome Safe Storage access; no fallback unlock is attempted")
	}
	return C.GoBytes(p, C.int(n)), nil
}
func (nativeKeychain) InternetPassword(host, account string) ([]byte, error) {
	h := C.CString(host)
	a := C.CString(account)
	defer C.free(unsafe.Pointer(h))
	defer C.free(unsafe.Pointer(a))
	var n C.UInt32
	var p unsafe.Pointer
	status := C.vault_internet(h, C.UInt32(len(host)), a, C.UInt32(len(account)), &n, &p)
	defer C.vault_free(p, n)
	if status != 0 || n == 0 || n > 32768 {
		return nil, errors.New("this website password is not accessible through macOS Keychain; export the selected login from Apple's Passwords app and use --csv")
	}
	return C.GoBytes(p, C.int(n)), nil
}
