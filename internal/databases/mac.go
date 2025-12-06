package databases

// TODO: work on a more comprehensive OUI database or integrate with an external service
func LoadOUIDatabase() map[string]string {
	return map[string]string{
		"00:00:5E": "IANA",
		"00:01:42": "Cisco",
		"00:03:93": "Apple",
		"00:0C:29": "VMware",
		"00:0D:3A": "Microsoft",
		"00:15:5D": "Microsoft",
		"00:16:3E": "Xensource",
		"00:1A:11": "Google",
		"00:1B:21": "Intel",
		"00:1C:42": "Parallels",
		"00:50:56": "VMware",
		"08:00:27": "Oracle VirtualBox",
		"18:03:73": "Texas Instruments",
		"28:6A:BA": "Tp-Link",
		"3C:46:D8": "Tp-Link",
		"6C:4F:89": "Router/Gateway",
		"DC:62:79": "IoT Device",
		"52:54:00": "QEMU/KVM",
		"AC:DE:48": "Private",
		"B8:27:EB": "Raspberry Pi",
		"DC:A6:32": "Raspberry Pi",
		"E4:5F:01": "Raspberry Pi",
	}
}
