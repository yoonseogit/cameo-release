//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cc clang -cflags "-O2 -g -Wall" guard bpf/bypass_guard.bpf.c -- -Ibpf

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	roleUntrusted uint32 = 1
	roleMediator  uint32 = 2

	/*
		Fast DDS / RTPS default UDP port mapping에서
		현재 prototype이 사용하는 domain block 계산값.

		base(domain) = 7400 + 250 * domain

		각 domain을 하나의 250-port block으로 보호한다.
	*/
	rtpsPortBase   uint64 = 7400
	rtpsDomainGain uint64 = 250
	rtpsDomainSpan uint64 = 250

	maxUDPPort uint64 = 65535
)

/*
BPF struct guard_config_value와 동일한 layout.
*/
type guardConfigValue struct {
	ProtectedPortMin uint32
	ProtectedPortMax uint32
}

func parsePID(s string) uint32 {
	v, err :=
		strconv.ParseUint(
			s,
			10,
			32,
		)

	if err != nil {
		log.Fatalf(
			"invalid PID %q: %v",
			s,
			err,
		)
	}

	if v == 0 {
		log.Fatalf(
			"invalid PID %q: PID must be greater than 0",
			s,
		)
	}

	return uint32(v)
}

func parseProtectedDomain(s string) uint32 {
	v, err :=
		strconv.ParseUint(
			s,
			10,
			32,
		)

	if err != nil {
		log.Fatalf(
			"invalid protected domain %q: %v",
			s,
			err,
		)
	}

	return uint32(v)
}

/*
현재 prototype에서 사용하는 default RTPS domain block 계산.

Example:

domain 10:

	7400 + 250 * 10
	= 9900

	range = 9900 ~ 10149

domain 20:

	7400 + 250 * 20
	= 12400

	range = 12400 ~ 12649
*/
func protectedPortRange(
	domainID uint32,
) (uint32, uint32, error) {

	base :=
		rtpsPortBase +
			rtpsDomainGain*
				uint64(domainID)

	end :=
		base +
			rtpsDomainSpan -
			1

	if base > maxUDPPort {
		return 0, 0, fmt.Errorf(
			"domain %d produces invalid RTPS base port %d",
			domainID,
			base,
		)
	}

	if end > maxUDPPort {
		return 0, 0, fmt.Errorf(
			"domain %d produces RTPS block %d-%d beyond UDP port %d",
			domainID,
			base,
			end,
			maxUDPPort,
		)
	}

	return uint32(base),
		uint32(end),
		nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(
			os.Stderr,
			"usage: %s <untrusted-pid> <mediator-pid> <protected-domain-id>\n",
			os.Args[0],
		)

		os.Exit(1)
	}

	untrustedPID :=
		parsePID(
			os.Args[1],
		)

	mediatorPID :=
		parsePID(
			os.Args[2],
		)

	protectedDomain :=
		parseProtectedDomain(
			os.Args[3],
		)

	protectedPortMin,
		protectedPortMax,
		err :=
		protectedPortRange(
			protectedDomain,
		)

	if err != nil {
		log.Fatalf(
			"calculate protected RTPS port range: %v",
			err,
		)
	}

	if err :=
		rlimit.RemoveMemlock(); err != nil {
		log.Fatalf(
			"remove memlock: %v",
			err,
		)
	}

	var objs guardObjects

	if err :=
		loadGuardObjects(
			&objs,
			nil,
		); err != nil {
		log.Fatalf(
			"load BPF objects: %v",
			err,
		)
	}

	defer objs.Close()

	/*
		Protected DDS domain configuration 등록.
	*/
	configKey :=
		uint32(0)

	configValue :=
		guardConfigValue{
			ProtectedPortMin: protectedPortMin,

			ProtectedPortMax: protectedPortMax,
		}

	if err :=
		objs.GuardConfig.Put(
			configKey,
			configValue,
		); err != nil {
		log.Fatalf(
			"register protected domain configuration: %v",
			err,
		)
	}

	/*
		Process role 등록.
	*/
	if err :=
		objs.ProcessRoles.Put(
			untrustedPID,
			roleUntrusted,
		); err != nil {
		log.Fatalf(
			"register untrusted PID: %v",
			err,
		)
	}

	if err :=
		objs.ProcessRoles.Put(
			mediatorPID,
			roleMediator,
		); err != nil {
		log.Fatalf(
			"register mediator PID: %v",
			err,
		)
	}

	/*
		LSM attach.
	*/
	lsmLink, err :=
		link.AttachLSM(
			link.LSMOptions{
				Program: objs.GuardSocketSendmsg,
			},
		)

	if err != nil {
		log.Fatalf(
			"attach socket_sendmsg LSM: %v",
			err,
		)
	}

	defer lsmLink.Close()

	fmt.Println("========================================")
	fmt.Println("Kernel Bypass Guard - ENFORCE MODE")
	fmt.Println("========================================")

	fmt.Printf(
		"Untrusted TGID   : %d\n",
		untrustedPID,
	)

	fmt.Printf(
		"Mediator TGID    : %d\n",
		mediatorPID,
	)

	fmt.Printf(
		"Protected Domain : %d\n",
		protectedDomain,
	)

	fmt.Printf(
		"RTPS Base Port   : %d\n",
		protectedPortMin,
	)

	fmt.Printf(
		"Protected Range  : UDP %d-%d\n",
		protectedPortMin,
		protectedPortMax,
	)

	fmt.Println(
		"Transport        : IPv4 UDP",
	)

	fmt.Println(
		"Enforcement      : ENABLED",
	)

	fmt.Println("========================================")

	sig :=
		make(
			chan os.Signal,
			1,
		)

	signal.Notify(
		sig,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	<-sig

	fmt.Println(
		"\n[STOP] bypass guard",
	)
}
