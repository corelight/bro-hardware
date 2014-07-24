module Hardware;

export {
	redef enum Log::ID += {
		LOG,
	};

	type Type: enum {
		TYPE_PCI,
		TYPE_USB,
	};

	type Info: record {
		## Timestamp for when the hardware was discovered.
		ts:      time &log;

		## A connection UID if the hardware was discovered from 
		## a particular network connection.
		uid:      string &optional &log;

		## The IP address of the host that the hardware was discovered on.
		host:    addr &log;

		## The type of hardware.
		h_type:  Hardware::Type &log;

		## These fields can be provided and will be auto looked up before logging.
		vendor_id: string &optional;
		device_id: string &optional;

		## The product vendor name looked up from the internal list of
		## vendors.
		vendor:  string &log &optional;

		## The device name looked up from the internal list of devices.
		device: string &log &optional;
	};

	## Function to call when hardware is discovered.
	global seen: function(info: Info);

	## Look up USB vendor names by Type and vendor ID.
	const vendors: table[Type, string] of string = {}
		&default=function(t: Type, vid: string):string { return fmt("unknown-%s-%s", t, vid); }
		&redef;

	## Look up device names by Type, vendor ID, and product ID.
	const devices: table[Type, string, string] of string = {}
		&default=function(t: Type, vid: string, pid: string):string { return fmt("unknown-%s-%s-%s", t, vid, pid); }
		&redef;
}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info]);
	}

function seen(info: Info)
	{
	if ( !info?$vendor && info?$vendor_id)
		info$vendor = vendors[info$h_type, info$vendor_id];
	if ( !info?$device && info?$vendor_id && info?$device_id )
		info$device = devices[info$h_type, info$vendor_id, info$device_id];

	Log::write(LOG, info);
	}
