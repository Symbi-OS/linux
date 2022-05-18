qemu-system-aarch64 -machine virt -cpu cortex-a57 \
	-machine type=virt -nographic -smp 2 \
	-m 2048 \
	-S \
	-kernel /home/boobee/VMmyinstall/vmlinuz-5.14.0-00009-g23198d4b72be-dirty \
	-initrd /home/boobee/ARMport/myinitramfs-5.14.0.img.gz \
	--append "mitigations=off console=ttyAMA0" \
	-gdb tcp::5090
	$1 $2
