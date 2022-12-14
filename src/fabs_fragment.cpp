#include "fabs_fragment.hpp"
#include "fabs_ether.hpp"

#include <net/ethernet.h>

#include <functional>

#define FRAGMENT_GC_TIMER 30

using namespace std;

fabs_fragment::fragments::fragments ()
{

}

fabs_fragment::fragments::fragments(const ip *iph4, ptr_fabs_bytes bytes, uint16_t vlanid, uint32_t netid)
    : m_bytes(new std::map<int, ptr_fabs_bytes>),
      m_is_last(false)
{
    m_time = m_init = time(NULL);

    int offset = ntohs(iph4->ip_off) & IP_OFFMASK;
    int mflag  = ntohs(iph4->ip_off) & IP_MF;

    (*m_bytes)[offset] = std::move(bytes);

    if (! mflag) {
        m_is_last = true;
        m_size = offset * 8 + ntohs(iph4->ip_len) - iph4->ip_hl * 4;
    }

    m_ip_src = ntohl(iph4->ip_src.s_addr);
    m_ip_dst = ntohl(iph4->ip_dst.s_addr);
    m_id     = ntohs(iph4->ip_id);
    m_vlanid = ntohs(vlanid);
    m_netid  = ntohl(netid);
}

fabs_fragment::fragments::~fragments ()
{

}

bool
fabs_fragment::fragments::operator< (const fragments &rhs) const {
    if (m_ip_src == rhs.m_ip_src) {
        if (m_ip_dst == rhs.m_ip_dst) {
            if (m_vlanid == rhs.m_vlanid) {
                return m_id < rhs.m_id;
            } else {
                return m_vlanid < rhs.m_vlanid;
            }
        } else {
            return m_ip_dst < rhs.m_ip_dst;
        }
    } else {
        return m_ip_src < rhs.m_ip_src;
    }
}

bool
fabs_fragment::fragments::operator== (const fragments &rhs) const {
    return (m_ip_src == rhs.m_ip_src &&
            m_ip_dst == rhs.m_ip_dst &&
            m_id     == rhs.m_id     &&
            m_vlanid == rhs.m_vlanid &&
            m_netid == rhs.m_netid);
}

fabs_fragment::fabs_fragment(fabs_ether &fether, ptr_fabs_appif appif) :
    m_is_del(false),
    m_thread_gc(std::bind(&fabs_fragment::gc_timer, this)),
    m_ether(fether),
    m_appif(appif)
{

}

fabs_fragment::~fabs_fragment()
{
    m_is_del = true;

    {
        std::unique_lock<std::mutex> lock(m_mutex_gc);
        m_condition_gc.notify_one();
    }

    m_thread_gc.join();
}

void
fabs_fragment::gc_timer()
{
    for (;;) {
        std::unique_lock<std::mutex> lock_gc(m_mutex_gc);
        m_condition_gc.wait_for(lock_gc, std::chrono::milliseconds(FRAGMENT_GC_TIMER * 1000));

        if (m_is_del) {
            return;
        }

        std::unique_lock<std::mutex> lock(m_mutex);

        auto &seq = m_fragments.get<1>();
        time_t t  = time(NULL);

        for (auto it = seq.begin(); it != seq.end(); ) {
            if (t - it->m_init > FRAGMENT_GC_TIMER) {
                it = seq.erase(it);
                continue;
            } else {
                break;
            }
        }
    }
}

// true:  fragmented
// false: not fragmented
bool
fabs_fragment::input_ip(qtype &buf)
{
    ip *iph4 = (ip*)buf.m_buf->get_head();

    if (iph4->ip_v != 4) {
        return false;
    }

    if (ntohs(iph4->ip_len) > buf.m_buf->get_len()) {
        return false;
    }

    int offset = ntohs(iph4->ip_off) & IP_OFFMASK;
    int mflag  = ntohs(iph4->ip_off) & IP_MF;

    if (mflag || offset) {
        fragments frag;

        frag.m_ip_src = ntohl(iph4->ip_src.s_addr);
        frag.m_ip_dst = ntohl(iph4->ip_dst.s_addr);
        frag.m_id     = ntohs(iph4->ip_id);
        frag.m_vlanid = ntohs(buf.m_vlanid);
        frag.m_netid  = buf.m_netid;

        std::unique_lock<std::mutex> lock(m_mutex);
        auto it = m_fragments.find(frag);
        if (it == m_fragments.end()) {
            m_fragments.insert(fragments(iph4, std::move(buf.m_buf), buf.m_vlanid, buf.m_netid));
        } else {
            auto it2 = it->m_bytes->find(offset);
            if (it2 == it->m_bytes->end()) {
                (*it->m_bytes)[offset] = std::move(buf.m_buf);

                if (! mflag) {
                    it->m_is_last = true;
                    it->m_size = offset * 8 + ntohs(iph4->ip_len) - iph4->ip_hl * 4;
                    if (it->m_size < 0) {
                        // error
                        m_fragments.erase(it);
                    }
                }
            }

            if (it->m_is_last) {
                ptr_fabs_bytes buf(new fabs_bytes);
                if (defragment(*it, buf)) {
                    // packets are defragmented
                    buf->m_tm = it->m_bytes->begin()->second->m_tm;
                    m_fragments.erase(it);
                    lock.unlock();

                    uint32_t hash = ntohl(iph4->ip_src.s_addr ^ iph4->ip_dst.s_addr);

                    m_ether.produce(hash & (m_appif->get_num_tcp_threads() - 1), std::move(buf));
                }
            }
        }

        return true;
    }

    return false;
}

bool
fabs_fragment::defragment(const fragments &frg, ptr_fabs_bytes &buf)
{
    int next = 0;
    int hlen;
    ip *iph;

    assert(frg.m_bytes->size() != 0);

    iph = (ip*)frg.m_bytes->begin()->second->get_head();
    hlen = iph->ip_hl * 4;

    int ehdrlen;
    if (frg.m_vlanid == 0xffff) {
        ehdrlen = sizeof(ether_header);
        buf->alloc(frg.m_size + hlen + ehdrlen);
        if (buf->get_len() == 0)
            return false;

        ether_header *ehdr = (ether_header*)buf->get_head();
        memset(ehdr, 0, sizeof(ether_header));
        ehdr->ether_type = htons(ETHERTYPE_IP);
    } else { // VLAN??????????????????????????????
        ehdrlen = sizeof(ether_header) + sizeof(vlanhdr);
        buf->alloc(frg.m_size + hlen + ehdrlen);
        if (buf->get_len() == 0)
            return false;

        ether_header *ehdr = (ether_header*)buf->get_head();
        memset(ehdr, 0, sizeof(ether_header));
        ehdr->ether_type = htons(ETHERTYPE_VLAN);

        vlanhdr *vhdr = (vlanhdr*)(buf->get_head() + sizeof(ether_header));
        vhdr->m_type = htons(ETHERTYPE_IP);
        vhdr->m_tci  = htons(frg.m_vlanid);
    }

    memcpy(buf->get_head() + ehdrlen, iph, hlen);

    for (auto it = frg.m_bytes->begin(); it != frg.m_bytes->end(); ++it) {
        int offset = it->first;
        ip *iph4   = (ip*)it->second->get_head();
        int len    = ntohs(iph4->ip_len) - iph4->ip_hl * 4;
        int pos    = offset * 8;

        if (next < pos) {
            // couldn't defragment
            return false;
        } else if (next > pos ||
                   len + pos > frg.m_size) {
            // error
            m_fragments.erase(frg);
            return false;
        }

        memcpy(buf->get_head() + pos + hlen + ehdrlen,
               it->second->get_head() + iph4->ip_hl * 4, len);

        next += len;
    }

    iph = (ip*)(buf->get_head() + ehdrlen);

    iph->ip_id  = 0;
    iph->ip_off = 0;
    iph->ip_len = htons(frg.m_size);

    return true;
}
