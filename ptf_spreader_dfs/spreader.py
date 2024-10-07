# PTF test for SpreaderTest
# p4testgen seed: 1000

import logging
import itertools
import time

from ptf import config
from bfruntime_client_base_tests import BfRuntimeTest
from ptf.mask import Mask
from ptf.testutils import send_packet
from ptf.testutils import verify_packet
from ptf.testutils import verify_no_other_packets
import ptf.testutils as testutils

import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

logger = logging.getLogger('SpreaderTest')
logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    if len(swports) >= 4:
        break
swports.sort()
print(swports)

class AbstractTest(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, 'SpreaderTest')
        self.dev_id = 0
        self.table_entries = []
        self.bfrt_info = None
        # Get bfrt_info and set it as part of the test.
        self.bfrt_info = self.interface.bfrt_info_get('SpreaderTest')

        # Set target to all pipes on device self.dev_id.
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)

    def tearDown(self):
        # Reset tables.
        for elt in reversed(self.table_entries):
            test_table = self.bfrt_info.table_get(elt[0])
            test_table.entry_del(self.target, elt[1])
        self.table_entries = []

        # End session.
        BfRuntimeTest.tearDown(self)

    def insertTableEntry(
        self, table_name, key_fields=None, action_name=None, data_fields=[]
    ):
        test_table = self.bfrt_info.table_get(table_name)
        key_list = [test_table.make_key(key_fields)]
        data_list = [test_table.make_data(data_fields, action_name)]
        test_table.entry_add(self.target, key_list, data_list)
        self.table_entries.append((table_name, key_list))

    def _responseDumpHelper(self, request):
        for response in self.interface.stub.Read(request, timeout=2):
            yield response

    def overrideDefaultEntry(self, table_name, action_name=None, data_fields=[]):
        test_table = self.bfrt_info.table_get(table_name)
        data = test_table.make_data(data_fields, action_name)
        test_table.default_entry_set(self.target, data)

    def setRegisterValue(self, reg_name, value, index):
        reg_table = self.bfrt_info.table_get(reg_name)
        key_list = [reg_table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])]
        value_list = []
        if isinstance(value, list):
            for val in value:
                value_list.append(gc.DataTuple(val[0], val[1]))
        else:
            value_list.append(gc.DataTuple("f1", value))
        reg_table.entry_add(self.target, key_list, [reg_table.make_data(value_list)])

    def entryAdd(self, table_obj, target, table_entry):
        req = bfruntime_pb2.WriteRequest()
        gc._cpy_target(req, target)
        req.atomicity = bfruntime_pb2.WriteRequest.CONTINUE_ON_ERROR
        update = req.updates.add()
        update.type = bfruntime_pb2.Update.MODIFY
        update.entity.table_entry.CopyFrom(table_entry)
        resp = self.interface.reader_writer_interface._write(req)
        table_obj.get_parser._parse_entry_write_response(resp)

    def setDirectRegisterValue(self, tbl_name, value):
        test_table = self.bfrt_info.table_get(tbl_name)
        table_id = test_table.info.id
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id
        gc._cpy_target(req, self.target)
        entity = req.entities.add()
        table = entity.table_entry
        table.table_id = table_id
        table_entry = None
        for response in self._responseDumpHelper(req):
            for entity in response.entities:
                assert entity.WhichOneof("entity") == "table_entry"
                table_entry = entity.table_entry
                break
        if table_entry is None:
            raise self.failureException(
                "No entry in the table that the meter is attached to."
            )
        table_entry.ClearField("data")
        value_list = []
        if isinstance(value, list):
            for val in value:
                df = table_entry.data.fields.add()
        else:
            df = table_entry.data.fields.add()
            df.value = gc.DataTuple(gc.DataTuple("f1", value))
        self.entryAdd(test_table, self.target, table_entry)

    def setupCtrlPlane(self):
        pass

    def sendPacket(self):
        pass

    def verifyPackets(self):
        pass

    def runTestImpl(self):
        self.setupCtrlPlane()
        logger.info("Sending Packet ...")
        self.sendPacket()
        logger.info("Verifying Packet ...")
        self.verifyPackets()
        logger.info("Verifying no other packets ...")


class Test0(AbstractTest):
    # Date generated: 2024-08-01-10:49:45.691
    # Current statement coverage: 0.86

    def setupCtrlPlane(self):
        #simple_lpf.pipe.SwitchIngress.p_array_lpf1> add(0, 'RATE', 16000000, 16000000, 4)
        #simple_lpf.pipe.SwitchIngress.p_array_lpf2> add(0, 'RATE', 16000000, 16000000, 4)
        for i in range(64): 
            self.setRegisterValue('SwitchIngress.updatep_sketch.p_array1', 0x00000000, i)
            self.setRegisterValue('SwitchIngress.updatep_sketch.p_array2', 0x00000000, i)
            self.setRegisterValue('SwitchIngress.updates_sketch.s_M1', 0x00, i)
            self.setRegisterValue('SwitchIngress.updates_sketch.s_M2', 0x00, i)
            self.setRegisterValue('SwitchIngress.updatep_sketch.p_persist', 0x00000000, i)
        self.setRegisterValue('SwitchIngress.updates_sketch.s_time1', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.updates_sketch.s_time2', 0x00000000, 0)
        self.setRegisterValue('SwitchIngress.msb_reg', 0x00, 0)
        self.setRegisterValue('SwitchIngress.h2_reg', 0x0000, 0)
        for i in range(4):  
            self.setRegisterValue('SwitchIngress.updates_sketch.s_msb_value1', 0x00, i)
            self.setRegisterValue('SwitchIngress.updates_sketch.s_src1', 0x00000000, i)
            
            self.setRegisterValue('SwitchIngress.updates_sketch.s_msb_value2', 0x00, i)
            self.setRegisterValue('SwitchIngress.updates_sketch.s_src2', 0x00000000, i)
        eg_port = swports[2]
        self.insertTableEntry(
            'SwitchIngress.table_forward',
            [
                gc.KeyTuple('hdr.ipv4.dstAddr', 0xC0A80102),
            ],
            'SwitchIngress.forward',
            [
                gc.DataTuple('port', swports[2])  # 端口号作为数据字段
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_forward',
            [
                gc.KeyTuple('hdr.ipv4.dstAddr', 0xC1A80102),
            ],
            'SwitchIngress.drop',
            [
            ]
        )
            
        self.insertTableEntry(
            'SwitchIngress.table_msb',
            [
                gc.KeyTuple('h2', 0b000000000000, prefix_len=1),
            ],
            'SwitchIngress.cal_msb',
            [
                gc.DataTuple('value', 0)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_msb',
            [
                gc.KeyTuple('h2', 0b100000000000, prefix_len=2),
            ],
            'SwitchIngress.cal_msb',
            [
                gc.DataTuple('value', 1)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_msb',
            [
                gc.KeyTuple('h2', 0b110000000000, prefix_len=3),
            ],
            'SwitchIngress.cal_msb',
            [
                gc.DataTuple('value', 2)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_msb',
            [
                gc.KeyTuple('h2', 0b111000000000, prefix_len=4),
            ],
            'SwitchIngress.cal_msb',
            [
                gc.DataTuple('value', 3)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_msb',
            [
                gc.KeyTuple('h2', 0b111100000000, prefix_len=5),
            ],
            'SwitchIngress.cal_msb',
            [
                gc.DataTuple('value', 4)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_msb',
            [
                gc.KeyTuple('h2', 0b111110000000, prefix_len=6),
            ],
            'SwitchIngress.cal_msb',
            [
                gc.DataTuple('value', 5)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_msb',
            [
                gc.KeyTuple('h2', 0b111111000000, prefix_len=7),
            ],
            'SwitchIngress.cal_msb',
            [
                gc.DataTuple('value', 6)
            ]
        )
            
        
        self.insertTableEntry(
            'SwitchIngress.table_shift',
            [
                gc.KeyTuple('persistence', 0x00002000, 0x00002000),
            ],
            'SwitchIngress.cal_shift',
            [
                gc.DataTuple('shift_value', 5)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_shift',
            [
                gc.KeyTuple('persistence', 0x00001000, 0x00001000),
            ],
            'SwitchIngress.cal_shift',
            [
                gc.DataTuple('shift_value', 4)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_shift',
            [
                gc.KeyTuple('persistence', 0x00000800, 0x00000800),
            ],
            'SwitchIngress.cal_shift',
            [
                gc.DataTuple('shift_value', 3)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_shift',
            [
                gc.KeyTuple('persistence', 0x00000400, 0x00000400),
            ],
            'SwitchIngress.cal_shift',
            [
                gc.DataTuple('shift_value', 2)
            ]
        )
        self.insertTableEntry(
            'SwitchIngress.table_shift',
            [
                gc.KeyTuple('persistence', 0x00000200, 0x00000200),
            ],
            'SwitchIngress.cal_shift',
            [
                gc.DataTuple('shift_value', 1)
            ]
        )
            
        table_names=self.bfrt_info.table_dict.keys()

        relevant_table_names=[n for n in table_names if 'lpf' in n.lower()]
        relevant_tables=[]
        for n in sorted(relevant_table_names):
            t=self.bfrt_info.table_dict[n]
            if t not in relevant_tables:
                relevant_tables.append(t)

        def lpf_make_keytuple(i):
            return [gc.KeyTuple("$LPF_INDEX",value=i)]
        def lpf_make_datatuple(rate_or_sample, time_const, scale_out):
            assert(rate_or_sample in ['RATE','SAMPLE'])
            dt1=gc.DataTuple("$LPF_SPEC_TYPE", str_val=rate_or_sample)
            dt2=gc.DataTuple("$LPF_SPEC_GAIN_TIME_CONSTANT_NS", float_val=time_const)
            dt3=gc.DataTuple("$LPF_SPEC_DECAY_TIME_CONSTANT_NS",float_val=time_const)
            dt4=gc.DataTuple("$LPF_SPEC_OUT_SCALE_DOWN_FACTOR",val=scale_out)
            return [dt1,dt2,dt3,dt4]

        lpf_params=['RATE', 5e8, 1] #TODO: use argparse
        print("Using LPF parameters:",lpf_params)

        for t in relevant_tables:
            print('Initializing table ',t.info.name,' size=',t.info.size)
            data=t.make_data( lpf_make_datatuple( *lpf_params ) )
            key_list=[]
            for i in range(t.info.size): 
                #todo: make it batch mode!
                key=t.make_key( lpf_make_keytuple(i) )
                key_list.append(key)
            data_list=[data]*len(key_list)
            t.entry_add(self.target, key_list=key_list, data_list=data_list)
                
        print('Finished adding to all LPF tables.')
            
        register_table = self.bfrt_info.table_get("updatep_sketch.p_array1")
        resp = register_table.entry_get(
            self.target,
            [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
            {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        num_pipes = int(testutils.test_param_get('num_pipes'))
        for i in range(num_pipes):
            value = data_dict['SwitchIngress.updatep_sketch.p_array1.f1'][i]
            assert value == 0x00000000, "Register field lo didn't match with the read value."
    def sendPacket(self):
        
        ig_port = swports[1]
        packet1 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='192.168.1.2',
                                   ip_src='192.168.112.1',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet2 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='24.111.111.1',
                                   ip_src='192.168.112.1',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet3 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='56.128.1.3',
                                   ip_src='192.178.112.7',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet4 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='22.131.11.1',
                                   ip_src='192.168.112.1',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet5 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='217.131.111.25',
                                   ip_src='192.168.112.1',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet6 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='1.1.11.1',
                                   ip_src='192.168.112.1',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        packet7 = testutils.simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                                   eth_src='00:11:22:33:44:66',
                                   ip_dst='3.3.2.2',
                                   ip_src='192.168.112.1',
                                   tcp_sport=1234,
                                   tcp_dport=80)
        
        print("send first packet")
        send_packet(self, ig_port, packet4)  
        time.sleep(0.1)
        
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        
        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value2")
        for i in range(4):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        
        send_packet(self, ig_port, packet2) 
        time.sleep(0.1)
        #register_table = self.bfrt_info.table_get("updatep_sketch.p_persist")
        #for i in range(64):
            #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                #{"from_hw": True})
            #data, _ = next(resp)
            
            #data_dict = data.to_dict()
            #print(data_dict)
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value2")
        for i in range(4):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        
        
        send_packet(self, ig_port, packet3) 
        time.sleep(0.1)
        #register_table = self.bfrt_info.table_get("updatep_sketch.p_persist")
        #for i in range(64):
            #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                #{"from_hw": True})
            #data, _ = next(resp)
            
            #data_dict = data.to_dict()
            #print(data_dict)
        #register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                #{"from_hw": True})
        #data, _ = next(resp)
        #data_dict = data.to_dict()
        #print(data_dict)
        
        print("---------------------------------start-----------------------------------")
        send_packet(self, ig_port, packet4) 
        time.sleep(2)
        
        print("packet4")
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value2")
        for i in range(4):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        
        #time.sleep(0.1)
        #send_packet(self, ig_port, packet5) 
        send_packet(self, ig_port, packet5) 
        time.sleep(2)
        print("packet5")
        

        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value2")
        for i in range(4):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        
        send_packet(self, ig_port, packet6) 
        send_packet(self, ig_port, packet6) 
        time.sleep(2)
        print("packet6")
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value2")
        for i in range(4):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        

        send_packet(self, ig_port, packet7) 
        time.sleep(2)
        print("packet7")
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value2")
        for i in range(4):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        print("---------------------------------stop-----------------------------------")
        
        time.sleep(0.1)
        send_packet(self, ig_port, packet3) 
        time.sleep(0.1)
        
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)

        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        
        
        #for i in range(64): 
            #self.setRegisterValue('SwitchIngress.updatep_sketch.p_array1', 0x00000000, i)
            #self.setRegisterValue('SwitchIngress.updatep_sketch.p_array2', 0x00000000, i)
            #self.setRegisterValue('SwitchIngress.updates_sketch.s_M1', 0x00, i)
            #self.setRegisterValue('SwitchIngress.updates_sketch.s_M2', 0x00, i)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_time1', 0x00000000, 0)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_time2', 0x00000000, 0)
        #for i in range(4):  
            #self.setRegisterValue('SwitchIngress.updates_sketch.s_msb_value1', 0x00, 0)
            #self.setRegisterValue('SwitchIngress.updates_sketch.s_src1', 0x00000000, 0)
            
            #self.setRegisterValue('SwitchIngress.updates_sketch.s_msb_value2', 0x00, 0)
            #self.setRegisterValue('SwitchIngress.updates_sketch.s_src2', 0x00000000, 0)
        time.sleep(0.1)
        send_packet(self, ig_port, packet1)  
        time.sleep(0.1)
        send_packet(self, ig_port, packet1)  
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)

        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updatep_sketch.p_persist")
        for i in range(64):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        
            
        time.sleep(0.5)
        send_packet(self, ig_port, packet1)  
        time.sleep(0.5)
        send_packet(self, ig_port, packet1)  
        time.sleep(0.5)
        send_packet(self, ig_port, packet1)
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)

        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        register_table = self.bfrt_info.table_get("updatep_sketch.p_persist")
        for i in range(64):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        
        time.sleep(1)
        send_packet(self, ig_port, packet1)
        time.sleep(1)
        send_packet(self, ig_port, packet1)
        time.sleep(1)
        send_packet(self, ig_port, packet1)
        
            
        time.sleep(1)
        send_packet(self, ig_port, packet2) 
        register_table = self.bfrt_info.table_get("SwitchIngress.msb_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)

        register_table = self.bfrt_info.table_get("SwitchIngress.h2_reg")
        resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
                {"from_hw": True})
        data, _ = next(resp)
        data_dict = data.to_dict()
        print(data_dict)
        
        register_table = self.bfrt_info.table_get("updatep_sketch.p_persist")
        for i in range(64):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        #time.sleep(1)
        #send_packet(self, ig_port, packet3)  
        

    def verifyPackets(self):
        
        #register_table = self.bfrt_info.table_get("updatep_sketch.p_array2")
        #for i in range(64):
            #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                #{"from_hw": True})
            #data, _ = next(resp)
            
            #data_dict = data.to_dict()
            #print(data_dict)
        #register_table = self.bfrt_info.table_get("updatep_sketch.p_persist")
        #for i in range(64):
            #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                #{"from_hw": True})
            #data, _ = next(resp)
            
            #data_dict = data.to_dict()
            #print(data_dict)
        #register_table = self.bfrt_info.table_get("updates_sketch.s_M1")
        #for i in range(64):
            #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                #{"from_hw": True})
            #data, _ = next(resp)
            
            #data_dict = data.to_dict()
            #print(data_dict)
        #register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value1")
        #for i in range(4):
            #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                #{"from_hw": True})
            #data, _ = next(resp)
            
            #data_dict = data.to_dict()
            #print(data_dict)
        register_table = self.bfrt_info.table_get("updates_sketch.s_msb_value2")
        for i in range(4):
            resp = register_table.entry_get(
                self.target,
                [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            data, _ = next(resp)
            
            data_dict = data.to_dict()
            print(data_dict)
        

    def runTest(self):
        self.runTestImpl()


#class Test3(AbstractTest):
    #Date generated: 2024-08-01-10:49:45.731
    #Current statement coverage: 0.88

    #def setupCtrlPlane(self):
        #self.setRegisterValue('SwitchIngress.updatep_sketch.p_array1', 0x00000000, 0)
        #self.setRegisterValue('SwitchIngress.updatep_sketch.p_array2', 0x00000000, 0)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_time1', 0x00000000, 0)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_time2', 0x00000000, 0)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_M1', 0x00, 11)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_msb_value1', 0x00, 0)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_src1', 0x00000000, 0)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_M2', 0x00, 11)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_msb_value2', 0x00, 0)
        #self.setRegisterValue('SwitchIngress.updates_sketch.s_src2', 0x00000000, 0)
        #Table SwitchIngress.table_forward
        #self.insertTableEntry(
            #'SwitchIngress.table_forward',
            #[
                #gc.KeyTuple('hdr.ipv4.dstAddr', 0xC0A80102),
            #],
            #'SwitchIngress.drop',
            #[
            #]
        #)

    #def sendPacket(self):
        #ig_port = swports[1]
        #dmac = '00:11:22:33:44:55'
        #pkt = testutils.simple_tcp_packet(eth_dst=dmac)
        #testutils.send_packet(self, ig_port, pkt)

    #def verifyPackets(self):
        #register_table = self.bfrt_info.table_get("updates_sketch.s_src1")
        #for i in range(4):
            #resp = register_table.entry_get(
                #self.target,
                #[register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                #{"from_hw": True})
            #data, _ = next(resp)
            
            #data_dict = data.to_dict()
            #print(data_dict)


    #def runTest(self):
        #self.runTestImpl()

