import os
import shutil

FVH_dirs = []
for something in os.listdir(os.getcwd()):
    if os.path.isdir(something):
        FVH_dirs.append(something)

#del FVH_dirs[-1]
print(FVH_dirs)


i = 0
while (len(FVH_dirs) ):
	shutil.rmtree(FVH_dirs[i], ignore_errors=False, onerror=None)
	i += 1