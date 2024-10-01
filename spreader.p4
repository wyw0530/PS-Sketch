#include <core.p4>
#include <tna.p4>

#include "include/util.p4"
#include "include/p_sketch.p4"
#include "include/s_sketch.p4"
#include "include/header.p4"

struct metadata_t{
    //epoch duration 1s = 1000ms = 1000000000ns 

}

parser SwitchIngressParser(
    packet_in pkt,
    out headers_t hdr,
    out metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    TofinoIngressParser() tofino_parser;
    state start {
        // parser code begins here
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4:  parse_ipv4;
            default:    accept;
        }
    }

    state parse_ipv4{
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control SwitchIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    curr_time_t curr_time = 0;
    high_pos_time_t into_p_time = 0;

    UpdateP_Sketch() updatep_sketch;
    UpdateS_Sketch() updates_sketch;
    flag_t flag;
    CRCPolynomial<bit<16>>(
        16w0x1021,    // polynomial
        true,         // reversed
        true,         // use msb?
        false,        // extended?
        16w0xFFFF,    // initial shift register value
        16w0x0000     // result xor
    ) crc16_ccitt_poly;
    CRCPolynomial<bit<16>>(
        16w0xA001,    // polynomial
        true,         // reversed
        false,         // use msb?
        false,        // extended?
        16w0xFFFF,    // initial shift register value
        16w0x0000     // result xor
    ) crc16_modbus_poly;


    Hash<p_index_t>(HashAlgorithm_t.CUSTOM, crc16_ccitt_poly) hash_p1;
    Hash<p_index_t>(HashAlgorithm_t.CUSTOM, crc16_modbus_poly) hash_p2;
    Hash<s_index_t>(HashAlgorithm_t.CUSTOM, crc16_ccitt_poly) hash_s1;//for hashing srcdst(x)
    Hash<s_index_t>(HashAlgorithm_t.CUSTOM, crc16_modbus_poly) hash_s2;

    Hash<bit_string_t>(HashAlgorithm_t.CUSTOM, crc16_modbus_poly) hash_ss;//for hashing src-dst{x, y} to 0_1 
    
    high_pos_time_t high_pos_time;
    ip4Addr_t src;
    ip4Addr_t dst;
    ip4Addr_t new_src;
    persistence_t persistence;
    persistence_t persistence1;
    persistence_t persistence2;
    msb_value_t msb_value = 1; 
    bit_string_t hash_str;
    M_index_t groupid;
    p_index_t p_index1;
    p_index_t p_index2;
    s_index_t s_index1;
    s_index_t s_index2;
    
    bit<4> h1;
    bit<12> h2;
    bit<8> shift_length = 1;
    flag_t flag_to_p_array1 = 1;
    flag_t flag_to_p_array2 = 1;
    flag_t flag_to_exec_S = 1;
    flag_t update_time_flag = 1;

    M_index_t M1_index;
    M_index_t M2_index;
    
    
    action update_time(){
        curr_time = ig_prsr_md.global_tstamp;
    }

    action cal_msb(msb_value_t value){
        msb_value  = value;
    }
    
    table table_msb{
        key = {
            h2: lpm;
        }
        actions = {
            cal_msb;
        }
        const default_action = cal_msb(10);
        size = 32;
    }
    
    action forward(PortId_t port){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid = 0;
    }
    action drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }
    table table_forward{
        key = {
            hdr.ipv4.dstAddr: exact;
        }

        actions = {
            forward;
            drop;
        }
        const default_action = drop();   
        size = 512;
    }
    
    action cal_shift(bit<8> shift_value){
        shift_length = shift_value;
    }
    table table_shift{
        key = {
            persistence: ternary;
        }
        actions = {
            cal_shift;
        }
        const default_action = cal_shift(1);
        size = 32;
    }
    
    apply{
        src = hdr.ipv4.srcAddr;
        dst = hdr.ipv4.dstAddr;
        new_src = hdr.ipv4.srcAddr;
        high_pos_time = ig_prsr_md.global_tstamp[47:16] & 0xFFFFC000;
        high_pos_time_t _curr_time = curr_time[47:16] & 0xFFFFC000;

        if(high_pos_time != _curr_time){
            update_time();
        }
        
        p_index1 = hash_p1.get({src,dst})[14:0];
        p_index2 = hash_p2.get({src,dst})[14:0];
        
        updatep_sketch.apply(high_pos_time,
                         p_index1,
                         p_index2,
                         flag_to_p_array1,
                         flag_to_p_array2,
                         persistence1,
                         persistence2
                            );
        hash_str = hash_ss.get({src, dst});//hash to 0_1 string 

        h1 = hash_str[15:12];
        h2 = hash_str[11:0];
        table_msb.apply();
        
        groupid = (M_index_t)(h1);
        
        s_index1 = hash_s1.get({src})[10:0];
        s_index2 = hash_s2.get({src})[10:0];
        M1_index = (M_index_t)(s_index1);
        M2_index = (M_index_t)(s_index2);
        
        persistence_t persist_diff = persistence1 - persistence2;
        if(persist_diff < 0){
            persistence = persistence1;
        }
        else{
            persistence = persistence2;
        }
        table_shift.apply();
        msb_value = msb_value + shift_length;

        table_forward.apply(); 
        M1_index = M1_index << 4;
        M2_index = M2_index << 4;
        M1_index = M1_index + groupid;
        M2_index = M2_index + groupid;
        if(flag_to_p_array1 == 1){
            if(flag_to_p_array2 == 1){
                updates_sketch.apply(s_index1,
                                     s_index2,
                                     M1_index,
                                     M2_index,
                                     new_src,
                                     msb_value,
                                     groupid,
                                     high_pos_time
                                    );
            }
        }
    }
}

control SwitchIngressDeparser(
    packet_out pkt,
    inout headers_t hdr,
    in metadata_t meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Checksum() ipv4_csum;
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_csum.update({
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                /* skip hdr.ipv4.hdr_checksum, */
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr});
        }
        pkt.emit(hdr);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t meta_eg,
        out egress_intrinsic_metadata_t eg_intr_md) {


    TofinoEgressParser() tofino_eparser;
    state start {
        tofino_eparser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4:  parse_ipv4;
            default:    accept;
        }
    }

    state parse_ipv4{
        pkt.extract(hdr.ipv4);
        transition accept;
    }

}

control SwitchEgress(
    inout headers_t hdr,
    inout metadata_t meta_eg,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport
) {
    apply{}
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t meta_eg,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs) {
    Checksum() ipv4_checksum;
    apply {        
        hdr.ipv4.hdrChecksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr});

         pkt.emit(hdr);
    }
}



Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()) pipe;
    
Switch(pipe) main;
