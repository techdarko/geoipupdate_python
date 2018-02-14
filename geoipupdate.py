import gzip
import hashlib
from optparse import OptionParser
import os
import shutil
import socket
import sys
import urllib2

# Python Updater For MaxMind GeoIP Subscriptions
# No Requirements Outside Standard Python Install
# If Your Python Build Does Not Support SSL, Change _proto to 'http'
# Initial Author: @techdarko

_proto = 'https'
_update_host = 'updates.maxmind.com'
_version = '0.01'


class GeoIpUpdater(object):
    def __init__(self, path, _licensekey, _userid, _editions, verbose=False):
        self.editions = _editions
        self.hash = 0
        self.ip = 0
        self.licensekey = _licensekey
        self.path = path
        self.useragent = "py_geoipupdate/{0}".format(_version)
        self.userid = _userid
        self.verbose = verbose
        if self.verbose:
            print("Starting up.\n"
                  "Version is {0}\n"
                  "Using {1} Protocol\n"
                  "Update Host: {2}\n"
                  "License Key Ending In: {3}\n"
                  "User ID: {4}\n"
                  "Products: {5}\n"
                  "User Agent: {6}\n".format(_version, _proto, _update_host, self.licensekey[-4:], self.userid,
                                             ', '.join(self.editions), self.useragent))

    def make_path(self, filename):
        return os.path.join(self.path, filename)

    def check_file(self, filename):
        return os.path.isfile(filename)

    def get_md5(self, filename):
        if not self.check_file(filename):
            return "00000000000000000000000000000000"
        else:
            md5 = hashlib.md5()
            with open(filename, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk)
            return md5.hexdigest()

    def get_ip(self):
        req = urllib2.Request("{0}://{1}/app/update_getipaddr".format(_proto, _update_host))
        req.add_header('User-Agent', self.useragent)
        resp = urllib2.urlopen(req)
        ip = resp.read()
        try:
            socket.inet_aton(ip)
            self.ip = ip
            if self.verbose:
                print("Client IP is {0}".format(self.ip))
            return
        except socket.error:
            print("Bad Value Returned From MaxMind For Client IP. Exiting.")
            sys.exit(1)

    def get_filename(self, productid):
        req = urllib2.Request("{0}://{1}/app/update_getfilename?product_id={2}".format(_proto, _update_host, productid))
        req.add_header('User-Agent', self.useragent)
        resp = urllib2.urlopen(req)
        return resp.read()

    def make_hash(self):
        self.get_ip()
        md5 = hashlib.md5()
        md5.update(self.licensekey)
        md5.update(self.ip)
        self.hash = md5.hexdigest()
        return

    def getupdate(self, dbhash, editionid, filename):
        self.make_hash()
        req = urllib2.Request("{0}://{1}/app/update_secure?db_md5={2}&challenge_md5={3}&user_id={4}"
                              "&edition_id={5}".format(_proto, _update_host, dbhash, self.hash, self.userid, editionid))
        req.add_header('User-Agent', self.useragent)
        if self.verbose:
            print("URL: {0}".format(req.get_full_url()))
        resp = urllib2.urlopen(req)
        if resp.info().gettype() == 'text/plain':
            data = resp.read()
            if data == "Invalid user ID or license key\n":
                print("Bad License Key Or User ID. Quiting.")
                sys.exit(1)
            elif data == "No new updates available\n":
                if self.verbose:
                    print("No New Updates Available For {0}".format(editionid))
                return False
            else:
                print("Unexpected message: {0}".format(data))
                sys.exit(1)
        else:
            tmpfile = "{0}.tmp".format(filename)
            if self.verbose:
                print("New File Grabbed! Saving To Temp File {0}".format(tmpfile))
            with open("{0}".format(tmpfile), 'wb') as f:
                while True:
                    chunk = resp.read(128)
                    if not chunk:
                        break
                    f.write(chunk)
            if self.verbose:
                print("Unzipping {0}!".format(filename))
            with gzip.open("{0}".format(tmpfile), 'rb') as fi, open(filename, 'wb') as fo:
                shutil.copyfileobj(fi, fo)
            os.remove(tmpfile)
            if self.verbose:
                print("File {0} Deleted".format(tmpfile))
            return self.get_md5(filename)

    def update_databases(self):
        for edition in self.editions:
            if self.verbose:
                print("\nRunning For Product: {0}\n".format(edition))
            filename = self.make_path(self.get_filename(edition))
            filehash = self.get_md5(filename)
            newfilehash = filehash
            result = True
            while result:
                if self.verbose:
                    print("Running Updater For {0}\n"
                          "Current Hash: {1}\n"
                          "Filename: {2}".format(filename.split('/')[-1].split('.')[0], filehash, filename))
                result = self.getupdate(newfilehash, edition, filename)
                newfilehash = result
                if self.verbose and newfilehash:
                    print("New Hash Is {0}".format(newfilehash))
            if self.verbose:
                print("Run Complete For {0}".format(edition))


def can_read(option, opt, value, parser):
    # Option Parser Callback Function - Checks if file/folder exists and is readable
    if os.path.isfile(os.path.abspath(value)) \
            and os.access(os.path.abspath(value), os.R_OK):
            setattr(parser.values, option.dest, value)
    else:
        parser.error("File Provided For {0} Is Not Readable Or Does Not Exist!".format(opt))


def can_readwrite(option, opt, value, parser):
    # Option Parser Callback Function - Checks if file/folder exists and is readable/writable
    _abspath = os.path.abspath(value)
    if os.path.isfile(_abspath) and os.access(_abspath, os.R_OK) and os.access(_abspath, os.W_OK):
            setattr(parser.values, option.dest, value)
    else:
        parser.error("File Provided For {0} Is Not Read/Writable Or Does Not Exist!".format(opt))


def process_conf(filename):
    _licensekey, _userid, _editions = False, False, False
    with open(filename, 'r') as f:
        for line in f:
            if line.startswith("UserId") or line.startswith("AccountID"):
                _userid = line.split()[1]
            if line.startswith("LicenseKey"):
                _licensekey = line.split()[1]
            if line.startswith("ProductIds") or line.startswith("EditionIDs"):
                _editions = line.split()[1:]
    if not (_licensekey and _userid and _editions):
        print("Error: Cannot Read License File")
        sys.exit(1)
    return _licensekey, _userid, _editions


if __name__ == "__main__":
    usage = "USAGE: %prog [-f license_file] [-d custom_directory]"
    version = "%prog Version {0}".format(_version)

    geoipupdater = OptionParser(usage=usage, version=version)

    geoipupdater.add_option('-l', '--license', action='callback', type='string', callback=can_read, dest='license',
                            help='Provide location of MaxMind license file')
    geoipupdater.add_option('-d', '--dir', action='callback', type='string', callback=can_readwrite, dest='dir',
                            help='Provide directory GeoIP Files are stored. Defaults to current working directory')
    geoipupdater.add_option('-v', '--verbose', action='store_true', dest='verbose',
                            help='Enable verbose output', default=False)

    options, args = geoipupdater.parse_args()

    if not options.license:
        geoipupdater.error("Alert: '-l', '--license' must be provided.")

    if not options.dir:
        options.dir = os.getcwd()

    licensekey, userid, editions = process_conf(options.license)

    updater = GeoIpUpdater(options.dir, licensekey, userid, editions, options.verbose)
    updater.update_databases()
    print("Run Complete")
    sys.exit(0)
