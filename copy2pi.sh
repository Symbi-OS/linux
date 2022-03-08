cd ~
rm -r mydtb
mkdir mydtb
cp linux/arch/arm64/boot/dts/broadcom/*.dtb ~/mydtb
scp linux/System.map pi@128.197.11.172:
scp -r mydtb pi@128.197.11.172:
scp linux/arch/arm64/boot/Image pi@128.197.11.172:
rm myinstall/lib/modules/5.14.0-v8+/source
rm myinstall/lib/modules/5.14.0-v8+/build
scp -r myinstall/lib/modules pi@128.197.11.172:
