#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# For iOS (tested on 64bit)
# For 32bit, please modify hook_code in instrument_debugger_checks
#
import frida
import sys
import time
import os
import argparse

#Settings, don't change anything you don't understand!
package_name = "com.nianticlabs.pokemongo"

sig_file_location = os.path.abspath(os.path.join(os.pardir,'Signature.proto'))
sig_directory_location = os.path.abspath(os.pardir)
dump_directory_location = os.path.abspath(os.path.join(os.pardir, 'dumps'))

#Process arguments
parser = argparse.ArgumentParser(description='Frida script for iOS devices')
parser.add_argument('-sd','--show-devices', action="store_true", help='Show all available devices and their index')
parser.add_argument('-d','--device', metavar='device_idx', type=int, help='The device index to which you want to connect, leave blank to connect with USB')
parser.add_argument('-p','--parse', action="store_true", help="Whether to parse proto using protoc's decode_raw (make sure protoc is in your dumps directory)")
args = parser.parse_args()

#Init input counter
input_counter = 0

#Fancy console output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def printlog(s, style=None):
	ts = time.time()
	ts = time.strftime('[%H:%M:%S]', time.localtime(ts))
	if style == None:
		print "{}{}          {}{}".format('',ts,s,'')
	if style == 'raw':
		print s
	elif (style == 'err') or (style == 'error'):
		print "{}{}[ERROR]   {}{}".format(bcolors.FAIL, ts, s, bcolors.ENDC)
	elif (style == 'warn') or (style == 'warning'):
		print "{}{}[WARNING] {}{}".format(bcolors.WARNING, ts, s, bcolors.ENDC)
	elif style == 'ok':
		print "{}{}[OK]      {}{}".format(bcolors.OKGREEN, ts, s, bcolors.ENDC)		
	elif style == 'debug':
		print "{}{}[DEBUG]   {}{}".format(bcolors.OKBLUE, ts, s, bcolors.ENDC)

#JS Callback to write dump on system
def get_messages_from_js(message, data):
		parse = False
		if data is None:
			return
		global input_counter
		file_name = 'dump'
		if message['payload']['name'] == 'result':
			input_counter -= 1
			file_name += str(input_counter)
			file_name += '_encrypted'
		elif message['payload']['name'] == 'start':
			file_name += str(input_counter)
			# Create a raw-decoded proto file.
			if args.parse:
				parse = True
		input_counter += 1

		file_name = os.path.join(dump_directory_location, file_name)
		f = open(file_name+'.bin', 'wb')
		f.write(data)
		f.close()
		if parse:
			command = "protoc --decode=Signature -IPATH={} {} < {} > {}" .format(sig_directory_location, sig_file_location, os.path.join(dump_directory_location, file_name+'.bin'), os.path.join(dump_directory_location, file_name+".txt"))
			b = os.system(command)
			parse = False
 
#Main debugger code
def instrument_debugger_checks():

        hook_code = """
		/* JavaScript Code Start */
		/* Constants */
		var BASE_MODULE = "pokemongo"
		var OFFSET_FN_PROCESS_UNK6_ARM64 = 0x15A59E0;
		var OFFSET_FN_PROCESS_UNK6_ARM7  = 0x1368604; //32-bit ARMv7 address, not tested.

		var OFFSET_FN_PROCESS_UNK6 = OFFSET_FN_PROCESS_UNK6_ARM64; //WARNING: change to ARM7 for 32bit!

		/* General Info */
		console.log("Architecture: "+Process.arch);
		console.log("Platform: "+Process.platform);
		console.log("Pointer Size: "+Process.pointerSize);

		/* Helper functions */
		var enumerateProcessModules = function(){ 
			Process.enumerateModules({
				onMatch: function(module){
					console.log([module.name, module.base, module.size, module.path].join("\t"));
				},
				onComplete: function(){

				}
			});
		};
		var enumerateProcessRanges = function()
		{
			Process.enumerateRanges({"protection": "rw-", "coalesce":true} ,
			{
				onMatch: function(range){
					console.log([range.base, '0x'+range.size.toString(16), range.protection].join("\t"));
				},
				onComplete: function(){

				}
			});
		};
		var enumerateBaseModuleRanges = function()
		{
			Module.enumerateRanges(BASE_MODULE, "---",
			{
				onMatch: function(range){
					console.log([range.base, '0x'+range.size.toString(16), range.protection].join("\t"));
				},
				onComplete: function(){

				}
			});
		};

		var fctToHookPtr = Module.findBaseAddress("pokemongo").add(OFFSET_FN_PROCESS_UNK6);
		console.log("Base address of Main Module: " + Module.findBaseAddress("pokemongo"));
		console.log("Offset : +"+OFFSET_FN_PROCESS_UNK6);
		console.log("Corrected RVA : " + fctToHookPtr);

		Interceptor.attach(fctToHookPtr, {
			onEnter: function (args) {
				var buf = Memory.readByteArray(args[0], args[1].toInt32());
				this.bufPtr = args[0];
				this.bufLen = args[1].toInt32();
				send({name:'start'},buf); /* send dump file directly to system */
			},
			onLeave: function(retval) {
				var buf = Memory.readByteArray(this.bufPtr, (this.bufLen + (256 - (this.bufLen % 256)) + 32));
				send({name:'result'},buf); /* send dump file directly to system */
			}
		});

		/* JavaScript Code End */
        """
        return hook_code


def get_device(device_idx):
	device_manager = frida.get_device_manager()
	devices = device_manager.enumerate_devices()
	return devices[device_idx]


def main():
	if args.show_devices:
		for i,device in enumerate(frida.get_device_manager().enumerate_devices()):
			print "Index: {} | {}".format(i,device)
		return

	#Get device
	if args.device is None: #no args supplied, use USB
		device = frida.get_usb_device()
	else: #use device_id if supplied
		device = get_device(args.device)


	printlog("Device Connected: {}".format(device.name), 'ok')

	try:
		pid = device.spawn([package_name]) #spawned process with pid at suspended state
	except (frida.TransportError, frida.NotSupportedError, frida.ExecutableNotFoundError) as e:
		printlog(e.message, 'error')
		return
	except Exception:
		raise
	printlog("Spawned target with PID: {}".format(pid), 'debug')

	process = device.attach(pid) #get a debug session from pid
	printlog("Process attached!", 'ok')
	device.resume(pid) #resume process from suspended state

	#Create dumps directory, if it does not exist
	if not os.path.exists(dump_directory_location):
	    os.makedirs(dump_directory_location)
	    printlog( "Created Dumps Directory: {}".format(dump_directory_location), 'debug')
	else:
		printlog( "Dumps Directory: {}".format(dump_directory_location), 'debug')

	script = process.create_script(instrument_debugger_checks())
	script.on('message',get_messages_from_js)
	printlog("Hook script start!", 'debug')

	script.load()
	try:
		sys.stdin.read()
	except KeyboardInterrupt:
		printlog("\r", 'raw')
		printlog("Abort script acknowledged, cleaning up...".format(pid))
		device.kill(pid)
		printlog("Killed target with PID: {}".format(pid), 'debug')
		printlog("Script Exit.")
		return
	except Exception:
		raise

if __name__ == '__main__':
	main()
