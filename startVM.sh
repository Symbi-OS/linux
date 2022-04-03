qemu-system-aarch64 -machine virt -cpu cortex-a57 \
	-machine type=virt -nographic -smp 2 \
	-m 2048 \
	-S \
	-kernel /home/boobee/VMmyinstall/vmlinuz-5.14.0-00003-gdfdf4b60b9d8-dirty \
	-initrd /home/boobee/VMmyinstall/myinitramfs-5.14.0.img.gz \
	--append "mitigations=off nosmep nosmap console=ttyAMA0" \
	-gdb tcp::5090
	$1 $2
