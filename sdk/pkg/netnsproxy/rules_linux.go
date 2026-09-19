package netnsproxy

import (
	"encoding/binary"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type ports struct {
	family byte
	tcp    uint16
	udp    uint16
}

const statusDestinationNAT = 1 << 5
const routingMark = 0x616e
const routingTable = 16666

func interfaceMatch(index int) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIF, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, uint32(index))},
	}
}

func protocolMatch(protocol byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
	}
}

func redirectRules(conn *nftables.Conn, table *nftables.Table, index int, listeners []ports, udp bool) {
	prerouting := conn.AddChain(&nftables.Chain{
		Name: "prerouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest,
	})
	udpPrerouting := conn.AddChain(&nftables.Chain{
		Name: "udp_prerouting", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle,
	})
	conn.AddRule(&nftables.Rule{Table: table, Chain: udpPrerouting, Exprs: append(interfaceMatch(index),
		&expr.Immediate{Register: 1, Data: make([]byte, 4)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1})})
	for _, listener := range listeners {
		for _, transport := range []struct {
			protocol byte
			port     uint16
		}{{unix.IPPROTO_TCP, listener.tcp}, {unix.IPPROTO_UDP, listener.udp}} {
			expressions := interfaceMatch(index)
			expressions = append(expressions,
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{listener.family}},
			)
			expressions = append(expressions, protocolMatch(transport.protocol)...)
			if transport.protocol == unix.IPPROTO_UDP && !udp {
				expressions = append(expressions,
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 53)},
				)
			}
			expressions = append(expressions, &expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, transport.port)})
			chain := prerouting
			if transport.protocol == unix.IPPROTO_UDP {
				chain = udpPrerouting
				expressions = append(expressions,
					&expr.TProxy{Family: listener.family, RegPort: 1},
					&expr.Immediate{Register: 1, Data: binary.NativeEndian.AppendUint32(nil, routingMark)},
					&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
					&expr.Verdict{Kind: expr.VerdictAccept},
				)
			} else {
				expressions = append(expressions, &expr.Redir{RegisterProtoMin: 1})
			}
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: expressions})
		}
	}
	input := conn.AddChain(&nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
	})
	markedUDP := append(interfaceMatch(index), protocolMatch(unix.IPPROTO_UDP)...)
	markedUDP = append(markedUDP,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, routingMark)},
		&expr.Verdict{Kind: expr.VerdictAccept})
	conn.AddRule(&nftables.Rule{Table: table, Chain: input, Exprs: markedUDP})
	for _, protocol := range []byte{unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6} {
		expressions := append(interfaceMatch(index), protocolMatch(protocol)...)
		expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictAccept})
		conn.AddRule(&nftables.Rule{Table: table, Chain: input, Exprs: expressions})
	}
	for _, listener := range listeners {
		expressions := append(interfaceMatch(index), protocolMatch(unix.IPPROTO_TCP)...)
		expressions = append(expressions,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{listener.family}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, listener.tcp)},
			&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binary.NativeEndian.AppendUint32(nil, statusDestinationNAT), Xor: make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		)
		conn.AddRule(&nftables.Rule{Table: table, Chain: input, Exprs: expressions})
	}
	conn.AddRule(&nftables.Rule{Table: table, Chain: input, Exprs: append(interfaceMatch(index),
		&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH})})
	forward := conn.AddChain(&nftables.Chain{
		Name: "forward", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
	})
	conn.AddRule(&nftables.Rule{Table: table, Chain: forward,
		Exprs: append(interfaceMatch(index), &expr.Verdict{Kind: expr.VerdictDrop})})
}
