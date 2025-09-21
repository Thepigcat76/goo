#include "../dir.h"

#include <stdlib.h>
#include <dirent.h>

void dir_create(const char *dir_name) {
//#ifdef _WIN32
//#include <direct.h> // For _mkdir on Windows
//  _mkdir(dir_name);
//#else
//#include <sys/stat.h>
//#include <sys/types.h>
//  mkdir((dir_name), 0777);
//#endif
}

bool dir_exists(const char *path) {
  bool result = false;
  DIR *dir = opendir(path);

  if (dir != NULL) {
    result = true;
    closedir(dir);
  }

  return result;
}