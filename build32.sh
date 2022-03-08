export INSTALL_PATH=/home/boobee/myinstall
export INSTALL_DTBS_PATH=/home/boobee/myinstall
rm -rf /home/boobee/myinstall
mkdir -p /home/boobee/myinstall
CC=arm-linux-gnu-gcc make -j25 ARCH=arm CROSS_COMPILE=arm-linux-gnu- Image modules dtbs
CC=arm-linux-gnu-gcc make ARCH=arm INSTALL_MOD_PATH=/home/boobee/myinstall modules_install
