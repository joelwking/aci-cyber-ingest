#!/usr/bin/env python
"""
   app_server.py

   An app must have a file named as "app_server.py". APIC starts the app_server.py when a state-full app is started. 
   App_server.py can include any other needed files, and other python modules.

   Copyright (c) 2016 World Wide Technology, Inc.
   All rights reserved.
"""

import atomic_counters
atomic_counters.main(atomic_counters.get_credentials())
