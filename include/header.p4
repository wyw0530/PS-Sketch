#ifndef _HEADER_
#define _HEADER_
const bit<16> TYPE_IPV4  = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<48> curr_time_t;
typedef bit<32> high_pos_time_t;
typedef bit<16> epoch_duration_t;

typedef bit<64> src_dst_t;
typedef bit<32> persistence_t;

typedef bit<1> flag_t;
typedef bit<15> p_index_t;
typedef bit<11> s_index_t;
typedef bit<15> M_index_t;//s_index * 2^b

typedef bit<16> bit_string_t;
typedef bit<8> msb_value_t;

#define P_ARRAY_CELL_NUM 32768
#define S_ARRAY_CELL_NUM 2048
#define S_ARRAY_M_NUM 32768

struct curr_time_3216_t {
    bit<32> hi;
    bit<16> lo;
}

header ethernet_t{
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers_t{
    ethernet_t    ethernet;
    ipv4_t      ipv4;
}

#endif
