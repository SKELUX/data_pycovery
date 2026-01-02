# data_pycovery
Bulk dumps every recognized file format it can find, doubles as a data privacy tool to format unallocated clusters.

Currently only supports NTFS, on Windows. FAT support is incomplete, use with caution.

This script will stress your drive a fair bit, and is not recommended for most use cases.

Install python (Made for python 3.12.4), run the script and follow the prompts. 
If you just want to recover files, enter the drive letter then hit enter a couple of times. 
It will pick up where you left off if you close the window partway through. 
The files are dumped into /drives/ in the same directory as data_pycovery.py. 

If you prefer to skip the prompts (Where X is the drive letter): python data_pycovery.py "\\.\X:" --types png,jpg,7z,zip,exe,pdf,mp3

If you are not trying to recover files, but instead trying to prevent data recovery by formatting unallocated clusters, run as admin and use --wipe.

Formats currently recovered during scan:
7z, exe, gif, jpg, mp3, mp4, nes, nsp, pdf, png, txt, webp, zip
