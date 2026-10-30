package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework SystemConfiguration
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>
// A temporary dynamic-store entry is removed by configd even after SIGKILL.
static SCDynamicStoreRef installDNS(const char *name, const char *servers, const char *iface) {
 SCDynamicStoreRef store=SCDynamicStoreCreate(NULL,CFSTR("Undercore"),NULL,NULL);
 if (!store) return NULL;
 CFStringRef key=CFStringCreateWithCString(NULL,name,kCFStringEncodingUTF8);
 CFStringRef list=CFStringCreateWithCString(NULL,servers,kCFStringEncodingUTF8);
 CFStringRef interface=CFStringCreateWithCString(NULL,iface,kCFStringEncodingUTF8);
 CFArrayRef addresses=CFStringCreateArrayBySeparatingStrings(NULL,list,CFSTR(","));
 const void *domainValues[]={CFSTR("")};
 CFArrayRef domains=CFArrayCreate(NULL,domainValues,1,&kCFTypeArrayCallBacks);
 int zero=0,one=1;
 CFNumberRef order=CFNumberCreate(NULL,kCFNumberIntType,&zero);
 CFNumberRef noSearch=CFNumberCreate(NULL,kCFNumberIntType,&one);
 const void *orderValues[]={order};
 CFArrayRef orders=CFArrayCreate(NULL,orderValues,1,&kCFTypeArrayCallBacks);
 const void *keys[]={CFSTR("ServerAddresses"),CFSTR("SupplementalMatchDomains"),CFSTR("SupplementalMatchOrders"),CFSTR("SupplementalMatchDomainsNoSearch"),CFSTR("InterfaceName")};
 const void *values[]={addresses,domains,orders,noSearch,interface};
 CFDictionaryRef config=CFDictionaryCreate(NULL,keys,values,5,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 Boolean ok=SCDynamicStoreAddTemporaryValue(store,key,config);
 CFRelease(key);CFRelease(list);CFRelease(interface);CFRelease(addresses);CFRelease(domains);CFRelease(order);CFRelease(orders);CFRelease(noSearch);CFRelease(config);
 if (!ok) {CFRelease(store);return NULL;} return store;
}
static void closeDNS(SCDynamicStoreRef store) { if (store) CFRelease(store); }
*/
import "C"
import (
	"errors"
	"strings"
	"unsafe"
)

func openDNS(name, iface string, p profile) (func(), error) {
	var addresses []string
	for _, a := range p.dns {
		addresses = append(addresses, a.String())
	}
	key := C.CString("State:/Network/Service/Undercore-" + name + "/DNS")
	defer C.free(unsafe.Pointer(key))
	values := C.CString(strings.Join(addresses, ","))
	defer C.free(unsafe.Pointer(values))
	intf := C.CString(iface)
	defer C.free(unsafe.Pointer(intf))
	store := C.installDNS(key, values, intf)
	if store == 0 {
		return nil, errors.New("dns failed")
	}
	return func() { C.closeDNS(store) }, nil
}
