#include "mlvpn.h"

circular_buffer_t *
mlvpn_filters_choose(mlvpn_tunnel_t *t, uint32_t pktlen, const u_char *pktdata) {
    int i;
    struct bpf_program *filter;
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = pktlen;
    hdr.len = pktlen;
    for(i = 0; i < t->filters_count; i++) {
        filter = &t->filters[i];
        if (pcap_offline_filter(filter, &hdr, pktdata) != 0) {
            log_debug("filters", "filter %d matches", i);
            return t->hpsbuf;
        }
    }
    return t->sbuf;
}