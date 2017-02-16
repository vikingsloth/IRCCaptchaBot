import logging
import radix
import os
import urllib
import tarfile
import re
import glob

DEFAULT_GEOIP_URL = \
    'http://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz'

LOG = logging.getLogger(__name__)

class GeoIP(object):

    def __init__(self, directory = 'geoip', url = DEFAULT_GEOIP_URL,
                 updateOnInit = False):
        self.url = url
        self.directory = directory
        self.rtree = radix.Radix()
        if updateOnInit or not os.path.isdir(self.directory):
            self.update_files()
        self.load_files(glob.glob(directory + "/*.zone"))

    def lookup(self, ip):
        rnode = self.rtree.search_best(ip)
        if rnode:
            return rnode.data["cc"]
        else:
            return "unknown"

    def update_files(self):
        if not os.path.isdir(self.directory):
            LOG.info("Creating geoip directory: %s", self.directory)
            os.mkdirdirs(self.directory, 0700)
        LOG.info("Downloading file %s ...", self.url)
        filename = directory + '/all-zones.tar.gz'
        urllib.retrieve(self.url, filename)
        LOG.info("Extracting targz...")
        tar = tarfile.open(filename)
        tar.extractall(path = self.directory)
        tar.close()
        LOG.info("Done updating files")

    def load_files(self, files):
        newtree = radix.Radix()
        for filename in files:
            LOG.info("Loading file %s...", filename)
            country_code = os.path.splitext(os.path.basename(filename))[0]
            country_code = country_code.upper()
            f = open(filename, 'r')
            for cidr in f.readlines():
                cidr = cidr.rstrip()
                match = re.match("\d+\.\d+\.\d+\.\d+/\d+$", cidr)
                if match:
                    rnode = newtree.add(cidr)
                    rnode.data["cc"] = country_code
        LOG.info("Done loading files")
        self.rtree = newtree

