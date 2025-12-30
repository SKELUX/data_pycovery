# data_pycovery
A crappy but opensource data recovery option.
Also able to format unallocated clusters, while leaving existing files alone.

Currently only supports NTFS, on Windows.
Install python (Made for python 3.12.4), run the script and follow the prompts. 
If you just want to recover files, enter the drive letter then hit enter a couple of times. 
It will pick up where you left off if you close the window partway through. 
The files are dumped into /drives/ in the same directory as data_pycovery.py.

If you prefer to skip the prompts (Where X is the drive letter): python data_pycovery.py "\\.\X:" --types png,jpg,7z,zip,exe,pdf,mp3

If you are not trying to recover files, but instead trying to prevent data recovery by formatting allocated clusters, run as admin and use --wipe.

Formats currently recovered during scan:
7z, exe, jpg, mp3, pdf, png, txt, zip
