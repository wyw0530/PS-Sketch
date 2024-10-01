#ifndef _SSKETCH_
#define _SSKETCH_
#include "header.p4"

control UpdateS_Sketch(
    in s_index_t array1_index,
    in s_index_t array2_index,
    in M_index_t M1_index,
    in M_index_t M2_index,
    in ip4Addr_t new_src,
    in msb_value_t new_msb_value,
    in M_index_t groupid,
    in high_pos_time_t curr_time
)
{

    Register<high_pos_time_t,s_index_t>(S_ARRAY_CELL_NUM) s_time1;
    RegisterAction<high_pos_time_t, s_index_t, flag_t>(s_time1) update_s_time1 = {
        void apply(inout high_pos_time_t curr_epoch_time, out flag_t flag){
            flag =  0;
            if(curr_time != curr_epoch_time){
                flag = 1;
                curr_epoch_time = curr_time;
            }
        }
    };
    
    Register<high_pos_time_t,s_index_t>(S_ARRAY_CELL_NUM) s_time2;
    RegisterAction<high_pos_time_t, s_index_t, flag_t>(s_time2) update_s_time2 = {
        void apply(inout high_pos_time_t curr_epoch_time, out flag_t flag){
            flag =  0;
            if(curr_time != curr_epoch_time){
                flag = 1;
                curr_epoch_time = curr_time;
            }
        }
    };
    

    Register<ip4Addr_t,s_index_t>(S_ARRAY_CELL_NUM) s_src1;
    RegisterAction<ip4Addr_t, s_index_t, void>(s_src1) update_s_src1 = {
        void apply(inout ip4Addr_t src){
            src = new_src;
        }
    };
    Register<ip4Addr_t,s_index_t>(S_ARRAY_CELL_NUM) s_src2;
    RegisterAction<ip4Addr_t, s_index_t, void>(s_src2) update_s_src2 = {
        void apply(inout ip4Addr_t src){
            src = new_src;
        }
    };

    Register<msb_value_t, s_index_t>(S_ARRAY_CELL_NUM) s_msb_value1;
    RegisterAction<msb_value_t, s_index_t, flag_t>(s_msb_value1) update_s_msb_value1 = {
        void apply(inout msb_value_t msb_value, out flag_t flag){
            flag = 0;
            if(new_msb_value > msb_value){
                msb_value = new_msb_value;
                flag = 1;
            }
        }
    };
    RegisterAction<msb_value_t, s_index_t, void>(s_msb_value1) update_s_msb_value1_new_epoch = {
        void apply(inout msb_value_t msb_value){
            msb_value = new_msb_value;
        }
    };
    
    Register<msb_value_t, s_index_t>(S_ARRAY_CELL_NUM) s_msb_value2;
    RegisterAction<msb_value_t, s_index_t, flag_t>(s_msb_value2) update_s_msb_value2 = {
        void apply(inout msb_value_t msb_value, out flag_t flag){
            flag = 0;
            if(new_msb_value > msb_value){
                msb_value = new_msb_value;
                flag = 1;
            }
        }
    };
    RegisterAction<msb_value_t, s_index_t, void>(s_msb_value2) update_s_msb_value2_new_epoch = {
        void apply(inout msb_value_t msb_value){
            msb_value = new_msb_value;
        }
    };
    

    Register<msb_value_t, M_index_t>(S_ARRAY_M_NUM) s_M1;
    RegisterAction<msb_value_t, M_index_t, void>(s_M1) update_s_M1 = {
        void apply(inout msb_value_t msb_value){
            if(new_msb_value > msb_value){
                msb_value = new_msb_value;
            }
        }
    };
    RegisterAction<msb_value_t, M_index_t, void>(s_M1) update_s_M1_new_epoch = {
        void apply(inout msb_value_t msb_value){
            msb_value = new_msb_value;
        }
    };
    
    Register<msb_value_t, M_index_t>(S_ARRAY_M_NUM) s_M2;
    RegisterAction<msb_value_t, M_index_t, void>(s_M2) update_s_M2 = {
        void apply(inout msb_value_t msb_value){
            if(new_msb_value > msb_value){
                msb_value = new_msb_value;
            }
        }
    };
    RegisterAction<msb_value_t, M_index_t, void>(s_M2) update_s_M2_new_epoch = {
        void apply(inout msb_value_t msb_value){
            msb_value = new_msb_value;
        }
    };
    
 
    
    flag_t flag1 = 0;
    flag_t flag2 = 0;
    flag_t time_flag1;
    flag_t time_flag2;

    apply{
        time_flag1 = update_s_time1.execute(array1_index);
        time_flag2 = update_s_time2.execute(array2_index);
        
        if(time_flag1 == 1){
            update_s_msb_value1_new_epoch.execute(array1_index);
            update_s_M1_new_epoch.execute(M1_index);
            update_s_src1.execute(array1_index);
        }
        else {
            update_s_M1.execute(M1_index);
            flag1 = update_s_msb_value1.execute(array1_index);
            if(flag1 == 1){
                update_s_src1.execute(array1_index);
            }
        }
        
        if(time_flag2 == 1){
            update_s_msb_value2_new_epoch.execute(array2_index);
            update_s_M2_new_epoch.execute(M2_index);
            update_s_src2.execute(array2_index);
        }
        else {
            update_s_M2.execute(M2_index);
            flag2 = update_s_msb_value2.execute(array2_index);
            if(flag2 == 1){
                update_s_src2.execute(array2_index);
            }
        }
    }
}

#endif
