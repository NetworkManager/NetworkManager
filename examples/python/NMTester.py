#!/usr/bin/python

from NetworkManager import NetworkManager
import gtk

class NMTester(NetworkManager):

    def __init__(self):
        NetworkManager.__init__(self)

        for signal in self.NM_SIGNALS:
            self.nm_object.connect_to_signal(signal,
                                             self.nm_signal_handler)
        for signal in self.NMI_SIGNALS:
            self.nmi_object.connect_to_signal(signal,
                                              self.nmi_signal_handler)
        self.print_device_list()
        
    def print_device_list(self):
        d_list = self.get_devices()
        print
        print "========================================================="
        print        
        for d in d_list:
            for k,v in d.iteritems():
                print "%s: %s" % (k,v)
            print
            print "========================================================="
            print

    def nm_signal_handler(self, interface, signal_name,
                          service, path, message):
        self._print_device_list()

    def nmi_signal_handler(self, interface, signal_name,
                          service, path, message):
        print ("Received signal '%s.%s' from object '%s%s' with message %s"
               % (interface, signal_name, service, path, message))

if __name__ == "__main__":
    nmt = NMTester()
    gtk.main()

    
