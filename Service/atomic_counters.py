#!/usr/bin/env python
"""
Usage:

    atomic_counters.py   

        use CTRL + c to exit!

    This module monitors the atomic counters configured on an ACI fabric and generates a security incident 
    in Phantom (phantom.us) when the matches on a couter exceeds a threshold.

    Copyright (c) 2016 World Wide Technology, Inc.
    All rights reserved.

    author: joel.king@wwt.com

    Requirements:
        This module references two additional WWT developed modules, PhantomIngest and AnsibleACI. 
        These imported modules facilitate communication with the REST APIs for Phantom and APIC.
        Both modules are published on my GitHub account,  https://github.com/joelwking


    Revision history:
      27 July 2016  |  1.0 - initial relese
       3 Aug  2016  |  1.1 - main logic complete
      10 Aug  2016  |  1.2 - basic functionality complete
      22 Aug  2016  |  1.3 - modifications for running on APIC rather than VM  Flint

"""

#  SYSTEM IMPORTS
import sys
import time
import json
import signal
import requests

#  LOCAL IMPORTS
import AnsibleACI as aci
import PhantomIngest as ingest

#  CONSTANTS
SLEEP_RETRY = 10
SLEEP_NORMAL = 60

#  GLOBALS
counter_array = []

#  CLASSES
class Counter(object):
    "This object maintains the state of the various counters we are watching"

    def __init__(self):                               
        " "
        self.dn = None
        self.attributes = {}
        self.epoch_time = 0

    def populate_fields(self, **kwargs):
        " "
        for key, value in kwargs.items():
            try:
                self.key = value
            except KeyError:
                print "KeyError populating instance variable %s" % key
                return False
        return True


#  MAIN LOGIC
def main(params):
    " "
    
    set_signals()
    apic = get_controller_object(params)
    phantom = ingest.PhantomIngest(params["phantom"]["host"], params["phantom"]["token"])
    
    while True:
        apic.aaaLogin()
        if not apic.is_connected():
            print "Failed to authenticate with APIC ... retrying"
            time.sleep(SLEEP_RETRY)
            continue
            
        for item in get_what_to_watch():
            try:
                query_atomic_counters(apic, phantom, **item)
            except AssertionError as e:
                print "AssertionError " + e
            except TypeError:
                print "Failure to load JSON data"
            except KeyError as e:
                print "Error accessing key " + e

        apic.aaaLogout()
        idle_time()
 
    return

def query_atomic_counters(apic, phantom, **kwargs):
    "for the APIC specified, issue a class query and get the counter specified"

    print "\n%s %s, searching %s, for %s" % (time.asctime(), apic.controllername, kwargs["class"], kwargs["counter"])
    

    apic.setgeneric_URL("%s://%s/api/node/class/" + kwargs["class"] + ".json")
    ret_code = apic.genericGET()
    assert (ret_code is requests.codes.ok), "Failure to communicate: %s" % ret_code

    content = json.loads(apic.get_content())

    for managed_object in content["imdata"]:
        if new_mo(managed_object, kwargs):
            update_object_list(managed_object, kwargs)
            continue
        else:
            if over_threshold(kwargs["class"], managed_object):
                create_artifact(phantom, '28', kwargs["class"], managed_object)    # Note, 28 is hard coded *******************

    return

def new_mo(managed_object, arguments):
    "check if this is a new atomic counter"
    # print "\nnew_mo = %s \narguments = %s" % (managed_object, arguments)
    for item in counter_array:
        if managed_object[arguments["class"]]["attributes"]["dn"] == item.dn:
            print "%s located mo: %s" % (time.asctime(), item.dn[0:80])
            return False
    return True

def update_object_list(managed_object, arguments):
    " add the object to the list"

    moc = Counter()
    try:
        moc.attributes = managed_object[arguments["class"]]["attributes"]
        moc.dn = managed_object[arguments["class"]]["attributes"]["dn"]
        moc.epoch_time = int(time.time())
    except KeyError:
        print "KeyError exception in update_object_list"
    else:
        counter_array.append(moc)
        print "%s added object: %s" %  (time.asctime(), moc.dn[0:80])
    return

def over_threshold(aci_class, managed_object):
    "Is this a reportable incident?"
    #
    #  You need to update the object with the new values
    #  In addition to doing the checks.
    #
    if int(managed_object[aci_class]["attributes"]["totTxP"]) > 0:
        return True
    if int(managed_object[aci_class]["attributes"]["totRxP"]) > 0:
        return True

    return False

def create_artifact(phantom, container_id, aci_class, managed_object):
    "Create an artifact in the Phantom container specified"

    # Populate the meta data with the key, value pairs, stripping off the class and attributes
    meta_data = managed_object[aci_class]["attributes"]
    # Populate the CEF fields
    cef = {"sourceAddress": meta_data["src"],
           "destinationAddress": meta_data["dst"],
           "transportProtocol": meta_data["filtEnt"],
           "endTime": meta_data["ts"],
           "message": meta_data["dn"],
           "out": meta_data["totTxP"],
           "in": meta_data["totRxP"]
          }

    art_i_fact = {"name": aci_class, "source_data_identifier": meta_data["ts"]}

    try:
        artifact_id = phantom.add_artifact(container_id, cef, meta_data, **art_i_fact)
    except AssertionError as e:
        print "Any HTTP return code other than OK %s %s" % (e, phantom.content)
    except Exception as e:
        print "Typically the phantom host did not respond, a connection error %s %s" % (e, phantom.content)

    print "%s added artifact: %s" %  (time.asctime(), artifact_id)
    return

def idle_time():
    "be quiet for a bit, and report occasionally we are alive"

    print "%s idle..." % time.asctime()
    time.sleep(SLEEP_NORMAL)

def what_todo_about_nothing():
    "Having not implemented this function in a meaningful way, advise the calling routine."

    raise NotImplementedError

def get_controller_object(params):
    "Initalize the APIC controller object, and return it."

    apic = aci.Connection()
    apic.setUsername(params["aci"]["username"])
    apic.setPassword(params["aci"]["password"])
    apic.setcontrollerIP(params["aci"]["host"])
    return apic

def set_signals():
    "Set the signals used to interrupt the program"

    signal.signal(signal.SIGINT, sig_handler)              # Enable Interrupt handler
    signal.signal(signal.SIGTERM, sig_handler)             # Enable TERM handler
    return

def sig_handler(signum, frame):
    "Handle signal interrupts."

    print '%s interrupt %s caught, exiting.' % (time.asctime(), signum)
    sys.exit()

def usage():
    "Print out the module documentation"

    print __doc__
    sys.exit()


def get_meta_data_keys():
    "***STUB ROUTINE*** Populate artifact with theses keys"
    return ("dst",
            "src",
            "ts",
            "filtEnt",
            "seqNo",
            "dn",
            "totRxP",
            "totTxP")

def get_what_to_watch():
    "***STUB ROUTINE*** Query these classes and look at the counter, create incident if threshold is exceeded."

    return ({"class": "dbgEpgToIpRslt", "counter": "totTxP", "threshold": None},
            {"class": "dbgIpToEpgRslt", "counter": "totTxP", "threshold": None})

def get_credentials():
    "***STUB ROUTINE*** to Return parameters for this run"

    try:
        import atomic_counters_constants
    except ImportError:
        usage()
        sys.exit()

    return atomic_counters_constants.params


if __name__ == '__main__':

    debug = False
    main(get_credentials())