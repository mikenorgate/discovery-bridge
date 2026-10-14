package dnswire

import "github.com/miekg/dns"

// NameFields exposes structured RDATA domain names, never opaque text or unknown
// RDATA. Callers may mutate these fields only on their own copied records.
func NameFields(record dns.RR) []*string {
	switch value := record.(type) {
	case *dns.CNAME:
		return []*string{&value.Target}
	case *dns.PTR:
		return []*string{&value.Ptr}
	case *dns.SRV:
		return []*string{&value.Target}
	case *dns.NS:
		return []*string{&value.Ns}
	case *dns.MX:
		return []*string{&value.Mx}
	case *dns.DNAME:
		return []*string{&value.Target}
	case *dns.NAPTR:
		return []*string{&value.Replacement}
	case *dns.SOA:
		return []*string{&value.Ns, &value.Mbox}
	case *dns.RP:
		return []*string{&value.Mbox, &value.Txt}
	case *dns.AFSDB:
		return []*string{&value.Hostname}
	case *dns.RT:
		return []*string{&value.Host}
	case *dns.KX:
		return []*string{&value.Exchanger}
	case *dns.MB:
		return []*string{&value.Mb}
	case *dns.MD:
		return []*string{&value.Md}
	case *dns.MF:
		return []*string{&value.Mf}
	case *dns.MG:
		return []*string{&value.Mg}
	case *dns.MR:
		return []*string{&value.Mr}
	case *dns.MINFO:
		return []*string{&value.Rmail, &value.Email}
	case *dns.PX:
		return []*string{&value.Map822, &value.Mapx400}
	case *dns.TALINK:
		return []*string{&value.PreviousName, &value.NextName}
	case *dns.LP:
		return []*string{&value.Fqdn}
	case *dns.SVCB:
		return []*string{&value.Target}
	case *dns.HTTPS:
		return []*string{&value.Target}
	case *dns.NSEC:
		return []*string{&value.NextDomain}
	}
	return nil
}
