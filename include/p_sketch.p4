#ifndef _PSKETCH_
#define _PSKETCH_
#include "header.p4"

control UpdateP_Sketch(
    in high_pos_time_t curr_time,
    in p_index_t array1_index,
    in p_index_t array2_index,
    out flag_t flag_to_p_array1,
    out flag_t flag_to_p_array2,
    out persistence_t persistence1,
    out persistence_t persistence2
)
{
    //there are two arrays in p_sketch, here with register to store curr_time and lpf to calculate persistence 
    Register<high_pos_time_t,p_index_t>(P_ARRAY_CELL_NUM) p_array1;
    RegisterAction<high_pos_time_t,p_index_t,flag_t>(p_array1) update_p_array1 = {
        void apply(inout high_pos_time_t epoch_time, out flag_t flag){
            flag = 0;
            if(curr_time != epoch_time){
                epoch_time = curr_time;
                flag = 1;
            }
        }
    };
    Lpf<persistence_t, p_index_t>(size=P_ARRAY_CELL_NUM) p_array_lpf1;

    Register<high_pos_time_t,p_index_t>(P_ARRAY_CELL_NUM) p_array2;
    RegisterAction<high_pos_time_t,p_index_t,flag_t>(p_array2) update_p_array2 = {
        void apply(inout high_pos_time_t epoch_time, out flag_t flag){
            flag = 0;
            if(curr_time != epoch_time){
                epoch_time = curr_time;
                flag = 1;
            }
        }
    };
    Lpf<persistence_t, p_index_t>(size=P_ARRAY_CELL_NUM) p_array_lpf2;
    
    action trigger1(){
        flag_to_p_array1 = update_p_array1.execute(array1_index);
    }
    
    action trigger2(){
        flag_to_p_array2 = update_p_array2.execute(array2_index);
    }

    apply{
        trigger1();
        trigger2();
        bit<32> lpf_insert_value1;
        bit<32> lpf_insert_value2;
        lpf_insert_value1 = (bit<32>)flag_to_p_array1;
        lpf_insert_value1 = lpf_insert_value1 << 10;
        persistence1 = (persistence_t)p_array_lpf1.execute(lpf_insert_value1, array1_index);
        
        lpf_insert_value2 = (bit<32>)flag_to_p_array2;
        lpf_insert_value2 = lpf_insert_value2 << 10;
        persistence2 = (persistence_t)p_array_lpf2.execute(lpf_insert_value2, array2_index);
        
        

    }
}

#endif
