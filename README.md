# PS-Sketch #
### Paper ###

### Files ###
+ spreader.p4： main implementation of PS-Sketch
+ include/: include files used by spreader.p4
+ ptf_spreader_dfs/spreader.py: packet test file of PS-Sketch, which is to test the correctness of our PS-Sketch implementation's behavior

### Compiles ###
with sde environment, move all files to mydir 
```
mkdir ~mydir/build && cd ~mydir/build  
cmake <sde>/p4studio/ \
-DCMAKE_INSTALL_PREFIX=<sde>/install \
-DCMAKE_MODULE_PATH=<sde>/cmake      \
-DP4_NAME=<myprogram>                \
-DP4_PATH=<mydir>/spreader.p4
make <myprogram> && make install
```
### About Test Files ###
1) 配置虚拟端口：./pkgsrc/ptf-modules/ptf-utils/veth_setup.sh
2) ./run_tofino_model -p $Your Program$ -arch tf1 (上述两个步骤的主要目的是使用 SDE 运行一个虚拟的交换机模型，在实机上运行程序时不用)
3) ./run_switchd.sh -p $Your Program$ -arch tf1
4) ./run_p4_test.sh -p $Your Program$ –arch tf1 -t $the Dir where spreader.py is$
you can change code in spreader.py and modify different packets to see how various registers and tables action while packets come through
