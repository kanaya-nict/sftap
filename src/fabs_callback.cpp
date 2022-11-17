#include "fabs_callback.hpp"

#include "fabs_id.hpp"

#include <netinet/in.h>

using namespace std;

fabs_callback::fabs_callback()
{

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
    if(id.get_l4_proto()==IPPROTO_GRE) {
      char *d = buf->get_head();
      uint32_t spanid = (d[8+2] * 256 + d[8+2+1])&0x3FF;
      std::cout << "GRE packet found" << std::endl;
      // GRE:8octed, ERSPAN: 12octed
      buf->skip(8+12+14);
      dir = id.set_iph(buf->get_head(), vlanid, &l4hdr, &len);
      id.m_spanid = spanid;
      if (! buf->skip(l4hdr - buf->get_head()))
	return;
      if (len < buf->get_len()) {
	if (! buf->skip_tail(buf->get_len() - len)) { // skip ethernet padding
	  return;
	}
      }
    }

    switch (id.get_l4_proto()) {
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
