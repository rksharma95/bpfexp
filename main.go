//go:build linux
// +build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sample.bpf.c -- -I/usr/include/ -O2 -g

type eventBPF struct {
	Pid   uint32
	PidNS uint32
	MntNS uint32
	Comm  [80]uint8
	Daddr uint32
}

// nskey Structure acts as an Identifier for containers
type nskey struct {
	PidNS uint32
	MntNS uint32
}

type deets struct {
	ContainerID   string
	ContainerName string
	ContainerPID  string
	ProcessName   string
	ProcessPID    uint32
}

var cmap map[nskey]deets

func main() {

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}

	cmap = make(map[nskey]deets)

	fmt.Printf("detected %d containers\n", len(containers))

	for _, container := range containers {
		inspect, _ := cli.ContainerInspect(context.Background(), container.ID)
		c := deets{}

		c.ContainerID = inspect.ID
		c.ContainerName = strings.TrimLeft(inspect.Name, "/")
		pid := strconv.Itoa(inspect.State.Pid)
		c.ContainerPID = pid

		fmt.Printf("container %s has been detected\n", c.ContainerName)

		key := nskey{}

		if data, err := os.Readlink("/proc/" + pid + "/ns/pid"); err == nil {
			fmt.Sscanf(data, "pid:[%d]\n", &key.PidNS)
		}

		if data, err := os.Readlink("/proc/" + pid + "/ns/mnt"); err == nil {
			fmt.Sscanf(data, "mnt:[%d]\n", &key.MntNS)
		}

		cmap[key] = c
	}

	// fn := "sys_execve"

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kpc, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceSoconn})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpc.Close()

	kpcr, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceSocketCreate})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpcr.Close()

	kpicr, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceInetConnRequest})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpicr.Close()

	kpskb, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceSocketSockRcvSkb})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpskb.Close()
	// kpb, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceSobind})
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer kpb.Close()

	kpa, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceSoacc})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpa.Close()

	ksn, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceGetsockname})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer ksn.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")
	var event eventBPF
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		key := nskey{
			PidNS: event.PidNS,
			MntNS: event.MntNS,
		}

		if val, ok := cmap[key]; ok {
			val.ProcessPID = event.Pid
			val.ProcessName = unix.ByteSliceToString(event.Comm[:])
			ipBytes := make([]byte, 4)
			// Fill the byte slice with the IP address in big-endian format.
			binary.LittleEndian.PutUint32(ipBytes, event.Daddr)

			// Convert the byte slice into an IP object.
			ipAddr := net.IP(ipBytes)
			b, err := json.MarshalIndent(val, "", "  ")
			if err != nil {
				fmt.Println("error:", err)
			}
			fmt.Print(string(b), ipAddr.String())

		}

	}
}
