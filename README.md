# geoipupdate_python
Pure Python Version Of MaxMind's GeoIP2 Updater

Allows scripted updating of MaxMind GeoIP Databases

Usage: geoipupdate.py [-l \<license file\>] [-d \<directory\>] [--verbose]

License File is required and is the path to a standard MaxMind GeoIP license file which is structured as follows:
```
UserId 12345
LicenseKey abcd456EFGH
ProductIds 123 456 789 GeoIP2-City GeoIP2-Country GeoIP2-ISP GeoIP2-ASN
```
Directory is an optional item which specifies the directory the MaxMind DB files are located in. Defaults to the current working directory.

Verbose enables debug printing.
