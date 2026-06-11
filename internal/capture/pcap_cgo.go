package capture

/*
#cgo LDFLAGS: -lwpcap -lpacket
#cgo CFLAGS: -I.

#include <stdlib.h>
#include <string.h>

typedef struct pcap pcap_t;
typedef struct pcap_pkthdr pcap_pkthdr;

pcap_t* pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
int pcap_datalink(pcap_t *p);
int pcap_loop(pcap_t *p, int cnt, void *callback, u_char *user);
void pcap_breakloop(pcap_t *p);
void pcap_close(pcap_t *p);
int pcap_compile(pcap_t *p, void *fp, const char *str, int optimize, bpf_u_int32 netmask);
int pcap_setfilter(pcap_t *p, void *fp);
char* pcap_geterr(pcap_t *p);
int pcap_findalldevs(void **alldevsp, char *errbuf);
void pcap_freealldevs(void *alldevs);

typedef struct {
    char *name;
    char *description;
    void *addresses;
    void *next;
    u_int flags;
} pcap_if_t;

typedef struct {
    void *next;
    void *addr;
    void *netmask;
    void *broadaddr;
    void *dstaddr;
} pcap_addr_t;

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

extern void goPacketHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

static inline int cgo_pcap_loop(pcap_t *p, int cnt, u_char *user) {
    return pcap_loop(p, cnt, (pcap_handler)goPacketHandler, user);
}
*/
import "C"
import (
	"errors"
	"sync"
	"unsafe"
)

var (
	ErrDeviceNotFound = errors.New("device not found")
	ErrOpenFailed     = errors.New("failed to open device")
)

type PacketHandler func(data []byte, timestamp int64)

type PcapHandle struct {
	pcap        *C.pcap_t
	handler     PacketHandler
	mu          sync.Mutex
	running     bool
	stopChan    chan struct{}
	deviceName  string
}

func NewPcapHandle(deviceName string, snapLen int32, promisc bool) (*PcapHandle, error) {
	errbuf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(errbuf))

	cDevice := C.CString(deviceName)
	defer C.free(unsafe.Pointer(cDevice))

	var promiscFlag C.int
	if promisc {
		promiscFlag = 1
	}

	pcap := C.pcap_open_live(cDevice, C.int(snapLen), promiscFlag, 1000, errbuf)
	if pcap == nil {
		return nil, errors.New("pcap_open_live failed: " + C.GoString(errbuf))
	}

	handle := &PcapHandle{
		pcap:       pcap,
		deviceName: deviceName,
		stopChan:   make(chan struct{}),
	}

	return handle, nil
}

func (h *PcapHandle) SetFilter(filter string) error {
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	var bpf C.struct_bpf_program
	result := C.pcap_compile(h.pcap, unsafe.Pointer(&bpf), cFilter, 1, 0)
	if result < 0 {
		return errors.New("pcap_compile failed: " + C.GoString(C.pcap_geterr(h.pcap)))
	}

	result = C.pcap_setfilter(h.pcap, unsafe.Pointer(&bpf))
	if result < 0 {
		return errors.New("pcap_setfilter failed: " + C.GoString(C.pcap_geterr(h.pcap)))
	}

	return nil
}

func (h *PcapHandle) Start(handler PacketHandler) error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return errors.New("already running")
	}
	h.handler = handler
	h.running = true
	h.mu.Unlock()

	go func() {
		h.mu.Lock()
		pcap := h.pcap
		h.mu.Unlock()

		if pcap == nil {
			return
		}

		userData := (*C.u_char)(unsafe.Pointer(h))
		C.cgo_pcap_loop(pcap, -1, userData)
	}()

	return nil
}

func (h *PcapHandle) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	if h.pcap != nil {
		C.pcap_breakloop(h.pcap)
	}

	h.running = false
	select {
	case <-h.stopChan:
	default:
		close(h.stopChan)
	}
}

func (h *PcapHandle) Close() {
	h.Stop()

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.pcap != nil {
		C.pcap_close(h.pcap)
		h.pcap = nil
	}
}

//export goPacketHandler
func goPacketHandler(user *C.u_char, hdr *C.struct_pcap_pkthdr, bytes *C.u_char) {
	if user == nil || hdr == nil || bytes == nil {
		return
	}

	handle := (*PcapHandle)(unsafe.Pointer(user))

	length := int(hdr.len)
	data := C.GoBytes(unsafe.Pointer(bytes), C.int(length))

	tvSec := int64(hdr.ts.tv_sec)
	tvUSec := int64(hdr.ts.tv_usec)
	timestamp := tvSec*1000000 + tvUSec

	if handle.handler != nil {
		handle.handler(data, timestamp)
	}
}

func ListDevices() ([]string, error) {
	var alldevs *C.pcap_if_t
	errbuf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(errbuf))

	result := C.pcap_findalldevs((*unsafe.Pointer)(unsafe.Pointer(&alldevs)), errbuf)
	if result < 0 {
		return nil, errors.New("pcap_findalldevs failed: " + C.GoString(errbuf))
	}
	defer C.pcap_freealldevs(unsafe.Pointer(alldevs))

	var devices []string
	dev := alldevs
	for dev != nil {
		name := C.GoString(dev.name)
		devices = append(devices, name)
		dev = (*C.pcap_if_t)(dev.next)
	}

	return devices, nil
}

func CreateGOOSEFilter() string {
	return "ether proto 0x88B8"
}
