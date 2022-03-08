export INSTALL_PATH=/home/boobee/myinstall
export INSTALL_DTBS_PATH=/home/boobee/myinstall
rm -rf /home/boobee/myinstall
mkdir -p /home/boobee/myinstall
CC=aarch64-linux-gnu-gcc make -j25 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image modules dtbs
CC=aarch64-linux-gnu-gcc make ARCH=arm64 INSTALL_MOD_PATH=/home/boobee/myinstall modules_install
#CC=aarch64-linux-gnu-gcc make ARCH=arm64 install
