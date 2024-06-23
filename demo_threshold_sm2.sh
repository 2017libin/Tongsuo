# ./config
# make clean
make -j12
gcc -o demo_threshold_sm2 demo_threshold_sm2.c ./test/libtestutil.a ./libcrypto.a -Iinclude -Iapps/include -Itest -lpthread -ldl && ./demo_threshold_sm2