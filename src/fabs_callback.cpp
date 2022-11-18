#include "fabs_callback.hpp"

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "fabs_id.hpp"
#include "fabs_ether.hpp"
#include <netinet/in.h>

using namespace std;

fabs_callback::fabs_callback()
{

}


uint32_t fabs_callback::calc_hash(const uint8_t *bytes){
    uint8_t proto;
    int len;
    uint16_t vlanid = 0xffff;
    const uint8_t *ip_hdr = m_ether->get_ip_hdr(bytes, len, proto, vlanid);
    uint32_t hash;

    if (ip_hdr == NULL)
        return 0;

    if (proto == IPPROTO_IP) {
        const ip *iph = (const ip*)ip_hdr;
        hash = ntohl(iph->ip_src.s_addr ^ iph->ip_dst.s_addr);
    } else if (proto == IPPROTO_IPV6) {
        const ip6_hdr *iph = (const ip6_hdr*)ip_hdr;
        const uint32_t *p1, *p2;

        p1 = (uint32_t*)&iph->ip6_src;
        p2 = (uint32_t*)&iph->ip6_dst;

        hash = p1[0] ^ p1[1] ^ p1[2] ^ p1[3] ^ p2[0] ^ p2[1] ^ p2[2] ^ p2[3];
        hash = ntohl(hash);
    } else {
        return 1;
    }

    return hash;
}


void
fabs_callback::operator() (int idx, ptr_fabs_bytes buf, uint16_t vlanid) {
    fabs_direction dir;
    fabs_id        id;
    char          *l4hdr;
    int            len; // payload length

    dir = id.set_iph(buf->get_head(), vlanid, &l4hdr, &len);

    if (l4hdr == NULL || dir == FROM_NONE) {
        return;
    }

    if (! buf->skip(l4hdr - buf->get_head()))
        return;

    if (len < buf->get_len()) {
        if (! buf->skip_tail(buf->get_len() - len)) { // skip ethernet padding
            return;
        }
    }
    id.m_spanid = buf->m_spanid;
    switch (id.get_l4_proto()) {
    case IPPROTO_GRE:{
      char *d = buf->get_head();
      uint32_t spanid = (d[8+2] * 256 + d[8+2+1])&0x3FF;
      std::cout << "GRE packet found" << std::endl;
      // GRE:8octed, ERSPAN: 12octed
      buf->skip(8+12);
      buf->m_spanid = spanid;
      int hash = calc_hash((uint8_t*)buf->get_head());
      m_ether->produce(hash & (m_appif->get_num_tcp_threads() - 1), std::move(buf));}
      break;
    case IPPROTO_TCP:
        m_tcp[idx]->input_tcp(id, dir, std::move(buf));
        break;
    case IPPROTO_UDP:
        m_udp.input_udp(id, dir, std::move(buf));
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        m_icmp.input_icmp(id, dir, std::move(buf));
        break;
    default:
        ;
    }
}
