export INSTALL_PATH=/home/boobee/VMmyinstall
export INSTALL_DTBS_PATH=/home/boobee/VMmyinstall
rm -rf /home/boobee/VMmyinstall
mkdir -p /home/boobee/VMmyinstall
#CC=aarch64-linux-gnu-gcc ARCH=arm64 make defconfig
CC=aarch64-linux-gnu-gcc make -j40 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image modules dtbs
if [ $? -ne 0 ]
then
	exit
fi
CC=aarch64-linux-gnu-gcc make -j40 ARCH=arm64 INSTALL_MOD_PATH=/home/boobee/VMmyinstall modules_install
CC=aarch64-linux-gnu-gcc make ARCH=arm64 install
