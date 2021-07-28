import idaapi
import idautils
import idc

del_items(0, 0, get_segm_end(0))

import os
import shutil

FVH_dirs = []
for something in os.listdir(os.getcwd()):
    if os.path.isdir(something):
        FVH_dirs.append(something)

#del FVH_dirs[-1]
print(FVH_dirs)


i = 0
while (len(FVH_dirs) - 1):
	shutil.rmtree(FVH_dirs[i], ignore_errors=False, onerror=None)
	i += 1