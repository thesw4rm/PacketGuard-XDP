package main

import (
	"C"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

import (
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/rlimit"
)

const (
	TYPE_ENTER = 1
	TYPE_DROP  = 2
	TYPE_PASS  = 3
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	// Remove MEMLOCK resource limit
	if err := rlimit.RemoveMemlock(); err != nil {
		// Handle error
		fmt.Printf("Failed to remove MEMLOCK limit: %v\n", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("please provide the network interface")
		return
	}

	iface := os.Args[1]
	spec, err := ebpf.LoadCollectionSpec("dropipv4.o")
	if err != nil {
		panic(err)
	}
	coll, _ := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new collection: %v\n", err))
	}
	defer coll.Close()

	prog := coll.Programs["capture_packets"]
	if prog == nil {
		panic("No program named 'capture_packets' found in collection")
	}

	iface_idx, err := net.InterfaceByName(iface)
	if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", iface, err))
	}
	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface_idx.Index,
		// Flags is one of XDPAttachFlags (optional).
	}

	lnk, err := link.AttachXDP(opts)
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully loaded and attached BPF program.")
	fmt.Println("Press Ctrl+c to end detach the program")
	<-sig
	defer lnk.Close()

}
