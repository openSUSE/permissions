/* Copyright (c) 2004 SuSE Linux AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING); if not, write to the
 * Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA
 *
 ****************************************************************
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/capability.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <limits.h>

#define BAD_LINE() \
  fprintf(stderr, "bad permissions line %s:%d\n", permfiles[i], lcnt)

struct perm {
  struct perm *next;
  char *file;
  char *owner;
  char *group;
  mode_t mode;
  cap_t caps;
};

struct perm *permlist;
char **checklist;
size_t nchecklist;
uid_t euid;
char *root;
size_t rootl;
size_t nlevel;
char** level;
int do_set = -1;
int default_set = 1;
int have_fscaps = -1;
char** permfiles = NULL;
size_t npermfiles = 0;
char* force_level;

struct perm*
add_permlist(char *file, char *owner, char *group, mode_t mode)
{
  struct perm *ec, **epp;

  owner = strdup(owner);
  group = strdup(group);
  if (rootl)
    {
      char *nfile;
      nfile = malloc(strlen(file) + rootl + (*file != '/' ? 2 : 1));
      if (nfile)
        {
          strcpy(nfile, root);
          if (*file != '/')
            strcat(nfile, "/");
          strcat(nfile, file);
        }
      file = nfile;
    }
  else
    file = strdup(file);
  if (!owner || !group || !file)
    {
      perror("permlist entry alloc");
      exit(1);
    }
  for (epp = &permlist; (ec = *epp) != 0; )
    if (!strcmp(ec->file, file))
      {
        *epp = ec->next;
        free(ec->file);
        free(ec->owner);
        free(ec->group);
        free(ec);
      }
    else
      epp = &ec->next;
  ec = malloc(sizeof(struct perm));
  if (ec == 0)
    {
      perror("permlist entry alloc");
      exit(1);
    }
  ec->file = file;
  ec->owner = owner;
  ec->group = group;
  ec->mode = mode;
  ec->caps = NULL;
  ec->next = 0;
  *epp = ec;
  return ec;
}

int
in_checklist(char *e)
{
  size_t i;
  for (i = 0; i < nchecklist; i++)
    if (!strcmp(e, checklist[i]))
      return 1;
  return 0;
}

void
add_checklist(char *e)
{
  if (in_checklist(e))
    return;
  e = strdup(e);
  if (e == 0)
    {
      perror("checklist entry alloc");
      exit(1);
    }
  if ((nchecklist & 63) == 0)
    {
      checklist = realloc(checklist, sizeof(char *) * (nchecklist + 64));
      if (checklist == 0)
        {
          perror("checklist alloc");
          exit(1);
        }
    }
  checklist[nchecklist++] = e;
}

int
readline(FILE *fp, char *buf, size_t len)
{
  size_t l;
  if (!fgets(buf, (int)len, fp))
    return 0;
  l = strlen(buf);
  if (l && buf[l - 1] == '\n')
    {
      l--;
      buf[l] = 0;
    }
  if (l + 1 < len)
    return 1;
  fprintf(stderr, "warning: buffer overrun in line starting with '%s'\n", buf);
  char c;
  while ((c = getc(fp)) != EOF && c != '\n')
    ;
  buf[0] = 0;
  return 1;
}

int
in_level(char *e)
{
  size_t i;
  for (i = 0; i < nlevel; i++)
    if (!strcmp(e, level[i]))
      return 1;
  return 0;
}

void
ensure_array(void** array, size_t* size)
{
  if ((*size & 63) == 0)
    {
      *array = realloc(*array, sizeof(char *) * (*size + 64));
      if (*array == NULL)
        {
          perror("array alloc");
          exit(1);
        }
    }
}

void
add_level(char *e)
{
  if (in_level(e))
    return;
  e = strdup(e);
  if (e == 0)
    {
      perror("level entry alloc");
      exit(1);
    }
  ensure_array((void**)&level, &nlevel);
  level[nlevel++] = e;
}

static inline int isquote(char c)
{
    return (c == '"' || c == '\'');
}

int
parse_sysconf(const char* file)
{
  FILE* fp;
  char line[PATH_MAX];
  char* p;
  if ((fp = fopen(file, "r")) == 0)
    {
      fprintf(stderr, "error opening: %s: %s\n", file, strerror(errno));
      return 0;
    }
  while (readline(fp, line, sizeof(line)))
    {
      if (!*line)
        continue;
      for (p = line; *p == ' '; ++p);
      if (!*p || *p == '#')
        continue;
      if (!strncmp(p, "PERMISSION_SECURITY=", 20))
        {
          if (force_level)
            continue;

          p+=20;
          if (isquote(*p))
            ++p;
          p = strtok(p, " ");
          if (p && !isquote(*p))
            {
              do
                {
                  if (isquote(p[strlen(p)-1]))
                    {
                      p[strlen(p)-1] = '\0';
                    }
                  if (*p && strcmp(p, "local"))
                      add_level(p);
                }
              while ((p = strtok(NULL, " ")));
            }
        }
      else if (!strncmp(p, "CHECK_PERMISSIONS=", 18))
        {
          p+=18;
          if (isquote(*p))
            ++p;
          if (!strncmp(p, "set", 3))
            {
              p+=3;
              if (isquote(*p) || !*p)
                default_set=1;
            }
          else if ((!strncmp(p, "no", 2) && (!p[3] || isquote(p[3]))) || !*p || isquote(*p))
            {
              p+=2;
              if (isquote(*p) || !*p)
                {
                  default_set = -1;
                }
            }
          else
            {
              //fprintf(stderr, "invalid value for CHECK_PERMISSIONS (must be 'set', 'warn' or 'no')\n");
            }
        }
#define FSCAPSENABLE "PERMISSION_FSCAPS="
      else if (have_fscaps == -1 && !strncmp(p, FSCAPSENABLE, strlen(FSCAPSENABLE)))
        {
          p+=strlen(FSCAPSENABLE);
          if (isquote(*p))
            ++p;
          if (!strncmp(p, "yes", 3))
            {
              p+=3;
              if (isquote(*p) || !*p)
                have_fscaps=1;
            }
          else if (!strncmp(p, "no", 2))
            {
              p+=2;
              if (isquote(*p) || !*p)
                have_fscaps=0;
            } else
                have_fscaps=1; /* default */
        }
    }
  fclose(fp);
  return 0;
}

static int
compare(const void* a, const void* b)
{
  return strcmp(*(char* const*)a, *(char* const*)b);
}

static void
collect_permfiles()
{
  size_t i;
  DIR* dir;

  ensure_array((void**)&permfiles, &npermfiles);
  // 1. central fixed permissions file
  permfiles[npermfiles++] = strdup("/etc/permissions");

  // 2. central easy, secure paranoid as those are defined by SUSE
  for (i = 0; i < nlevel; ++i)
    {
      if (!strcmp(level[i], "easy")
              || !strcmp(level[i], "secure")
              || !strcmp(level[i], "paranoid"))
        {
          char fn[4096];
          snprintf(fn, sizeof(fn), "/etc/permissions.%s", level[i]);
          if (access(fn, R_OK) == 0)
            {
              ensure_array((void**)&permfiles, &npermfiles);
              permfiles[npermfiles++] = strdup(fn);
            }
        }
    }
  // 3. package specific permissions
  dir = opendir("/etc/permissions.d");
  if (dir)
    {
      char** files = NULL;
      size_t nfiles = 0;
      struct dirent* d;
      while ((d = readdir(dir)))
        {
          char* p;
          if (!strcmp("..", d->d_name) || !strcmp(".", d->d_name))
            continue;

          /* filter out backup files */
          if ((strlen(d->d_name)>2) && (d->d_name[strlen(d->d_name)-1] == '~'))
            continue;
          if (strstr(d->d_name,".rpmnew") || strstr(d->d_name,".rpmsave"))
            continue;

          ensure_array((void**)&files, &nfiles);
          if ((p = strchr(d->d_name, '.')))
            {
              *p = '\0';
            }
          files[nfiles++] = strdup(d->d_name);
        }
      closedir(dir);
      if (nfiles)
        {
          qsort(files, nfiles, sizeof(char*), compare);
          for (i = 0; i < nfiles; ++i)
            {
              char fn[4096];
              size_t l;
              // skip duplicates
              if (i && !strcmp(files[i-1], files[i]))
                continue;

              snprintf(fn, sizeof(fn), "/etc/permissions.d/%s", files[i]);
              if (access(fn, R_OK) == 0)
                {
                  ensure_array((void**)&permfiles, &npermfiles);
                  permfiles[npermfiles++] = strdup(fn);
                }

              for (l = 0; l < nlevel; ++l)
                {
                  snprintf(fn, sizeof(fn), "/etc/permissions.d/%s.%s", files[i], level[l]);

                  if (access(fn, R_OK) == 0)
                    {
                      ensure_array((void**)&permfiles, &npermfiles);
                      permfiles[npermfiles++] = strdup(fn);
                    }
                }

            }
          for (i = 0; i < nfiles; ++i)
            {
              free(files[i]);
            }
        }
      free(files);
    }
  // 4. central permissions files with user defined level incl 'local'
  for (i = 0; i < nlevel; ++i)
    {
      char fn[4096];

      if (!strcmp(level[i], "easy") || !strcmp(level[i], "secure") || !strcmp(level[i], "paranoid"))
        continue;

      snprintf(fn, sizeof(fn), "/etc/permissions.%s", level[i]);
      if (access(fn, R_OK) == 0)
        {
          ensure_array((void**)&permfiles, &npermfiles);
          permfiles[npermfiles++] = strdup(fn);
        }
    }
}


void
usage(int x)
{
  printf("Usage:\n"
"a) chkstat [OPTIONS] <permission-files>...\n"
"b) chkstat --system [OPTIONS] <files>...\n"
"\n"
"Options:\n"
"  --set                        apply changes\n"
"  --warn                only tell which changes are needed\n"
"  --noheader                don't print intro message\n"
"  --fscaps                force use of fscaps\n"
"  --no-fscaps                disable use of fscaps\n"
"  --system                system mode, act according to /etc/sysconfig/security\n"
"  --level LEVEL                force use LEVEL (only with --system)\n"
"  --examine FILE        apply to specified file only\n"
"  --files FILELIST        read list of files to apply from FILELIST\n"
"  --root DIR                check files relative to DIR\n"
);
  exit(x);
}

static bool
check_have_proc(void)
{
  char *override = secure_getenv("CHKSTAT_PRETEND_NO_PROC");

  struct statfs proc;
  int r = statfs("/proc", &proc);
  return override == NULL && r == 0 && proc.f_type == PROC_SUPER_MAGIC;
}

static const char proc_mount_path_pattern[] = "/tmp/chkstat.proc.XXXXXX";
static char proc_mount_path[sizeof(proc_mount_path_pattern)];
static int proc_mount_avail = 0;

static void
cleanup_proc(void)
{
  if (proc_mount_avail != 2)
    return;

  // intentionally no error checking during cleanup
  umount(proc_mount_path);
  rmdir(proc_mount_path);
}

#define _STRINGIFY(s) #s
#define STRINGIFY(s) _STRINGIFY(s)

#define PROC_PATH_SIZE (sizeof(proc_mount_path) + sizeof("/self/fd/") + sizeof(STRINGIFY(INT_MAX)))
static int
make_proc_path(int fd, char path[static PROC_PATH_SIZE])
{
  if (proc_mount_avail > 2)
    return 1;

  if (proc_mount_avail == 0)
    {
      if (check_have_proc())
        {
          proc_mount_avail = 1;
        }
      else
        {
          char *override = secure_getenv("CHKSTAT_PRETEND_PROC_MOUNT_FAIL");
          if (override != NULL)
            goto mount_fail;

          // We're running without /proc mounted. This happens when we're run inside a chroot, e.g. during image
          // builds, or during RPM install with the '--root' option.
          //
          // Other tools apparently sometimes misbehave and change things outside their chroot when they have
          // working /proc so this can't be changed.
          //
          // As a work-around, we mount our own private proc in a temporary directory. This requires
          // CAP_SYS_ADMIN (in addition to CAP_DAC_OVERRIDE like the rest of the tool).
          memcpy(proc_mount_path, proc_mount_path_pattern, sizeof(proc_mount_path));
          char *res = mkdtemp(proc_mount_path);
          if (res == NULL)
            goto mount_fail;
          int r = mount("proc", proc_mount_path, "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV|MS_RELATIME, "");
          if (r != 0)
            {
              rmdir(proc_mount_path);
              goto mount_fail;
            }
          proc_mount_avail = 2;
          atexit(cleanup_proc);
        }
    }

  snprintf(path, PROC_PATH_SIZE, "%s/self/fd/%d", proc_mount_avail == 1 ? "/proc" : proc_mount_path, fd);

  return 0;

mount_fail:
  proc_mount_avail = 3;
  return 1;
}


int
safe_open(char *path, struct stat *stb, uid_t target_uid, bool *traversed_insecure)
{
  char pathbuf[PATH_MAX];
  char *path_rest;
  int lcnt;
  int pathfd = -1;
  struct stat root_st;
  bool is_final_path_element = false;

  *traversed_insecure = false;

  lcnt = 0;
  if ((size_t)snprintf(pathbuf, sizeof(pathbuf), "%s", path + rootl) >= sizeof(pathbuf))
    goto fail;
  path_rest = pathbuf;
  while (!is_final_path_element)
    {
      *path_rest = '/';
      char *cursor = path_rest + 1;

      if (pathfd == -1)
        {
          pathfd = open(rootl ? root : "/", O_PATH | O_CLOEXEC);
          if (pathfd == -1)
            {
              fprintf(stderr, "failed to open root directory %s: %s\n", root, strerror(errno));
              goto fail;
            }
          if (fstat(pathfd, &root_st))
            {
              fprintf(stderr, "failed to stat root directory %s: %s\n", root, strerror(errno));
              goto fail;
            }
          // stb and pathfd must be in sync for the root-escape check below
          memcpy(stb, &root_st, sizeof(*stb));
        }

      path_rest = strchr(cursor, '/');
      // path_rest is NULL when we reach the final path element
      is_final_path_element = path_rest == NULL || strcmp("/", path_rest) == 0;
      if (!is_final_path_element)
        *path_rest = 0;

      // multiple consecutive slashes: ignore
      if (!is_final_path_element && *cursor == '\0')
        continue;

      // never move up from the configured root directory (using the stat result from the previous loop iteration)
      if (strcmp(cursor, "..") == 0 && rootl && stb->st_dev == root_st.st_dev && stb->st_ino == root_st.st_ino)
          continue;

      // cursor is an empty string for trailing slashes, open again with different open_flags.
      int newpathfd = openat(pathfd, *cursor ? cursor : ".", O_PATH | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
      if (newpathfd == -1)
        goto fail;

      close(pathfd);
      pathfd = newpathfd;

      if (fstat(pathfd, stb))
        goto fail;

      /* owner of directories must be trusted for setuid/setgid/capabilities as we have no way to verify file contents */
      /* for euid != 0 it is also ok if the owner is euid */
      if (stb->st_uid && stb->st_uid != euid && !is_final_path_element)
        *traversed_insecure = true;
      // path is in a world-writable directory, or file is world-writable itself.
      if (!S_ISLNK(stb->st_mode) && (stb->st_mode & S_IWOTH) && !is_final_path_element)
        *traversed_insecure = true;
      // if parent directory is not owned by root, the file owner must match the owner of parent
      if (stb->st_uid && stb->st_uid != target_uid && stb->st_uid != euid)
        {
          if (is_final_path_element)
            {
              fprintf(stderr, "%s: has unexpected owner. refusing to correct due to unknown integrity.\n", path+rootl);
              goto fail;
            }
          else
            goto fail_insecure_path;
        }

      if (S_ISLNK(stb->st_mode))
        {
          // Don't follow symlinks owned by regular users.
          // In theory, we could also trust symlinks where the owner of the target matches the owner
          // of the link, but we're going the simple route for now.
          if (stb->st_uid && stb->st_uid != euid)
            goto fail_insecure_path;

          if (++lcnt >= 256)
            goto fail;
          char linkbuf[PATH_MAX];
          ssize_t l = readlinkat(pathfd, "", linkbuf, sizeof(linkbuf) - 1);
          if (l <= 0 || (size_t)l >= sizeof(linkbuf) - 1)
            goto fail;
          while(l && linkbuf[l - 1] == '/')
            l--;
          linkbuf[l] = 0;
          if (linkbuf[0] == '/')
            {
              // absolute link
              close(pathfd);
              pathfd = -1;
            }
          size_t len;
          char tmp[sizeof(pathbuf) - 1]; // need a temporary buffer because path_rest points into pathbuf and snprintf doesn't allow the same buffer as source and destination
          if (is_final_path_element)
            len = (size_t)snprintf(tmp, sizeof(tmp), "%s", linkbuf);
          else
            len = (size_t)snprintf(tmp, sizeof(tmp), "%s/%s", linkbuf, path_rest + 1);
          if (len >= sizeof(tmp))
            goto fail;
          // the first byte of path_rest is always set to a slash at the start of the loop, so we offset by one byte
          strcpy(pathbuf + 1, tmp);
          path_rest = pathbuf;
        }
    }

  // world-writable file: error out due to unknown file integrity
  if (S_ISREG(stb->st_mode) && (stb->st_mode & S_IWOTH)) {
    fprintf(stderr, "%s: file has insecure permissions (world-writable)\n", path+rootl);
    goto fail;
  }

  return pathfd;
fail_insecure_path:

  {
    char linkpath[PATH_MAX] = "ancestor";
    char procpath[PROC_PATH_SIZE];
    int res = make_proc_path(pathfd, procpath);
    if (res == 0)
      {
        ssize_t l = readlink(procpath, linkpath, sizeof(linkpath) - 1);
        if (l > 0)
          linkpath[(size_t)l < sizeof(linkpath) ? (size_t)l : sizeof(linkpath) - 1] = '\0';
      }
    fprintf(stderr, "%s: on an insecure path - %s has different non-root owner who could tamper with the file.\n", path+rootl, linkpath);
  }

fail:
  if (pathfd >= 0)
    close(pathfd);
  return -1;
}


/* check /sys/kernel/fscaps, 2.6.39 */
static int
check_fscaps_enabled()
{
  FILE* fp;
  char line[128];
  int val = FSCAPS_DEFAULT_ENABLED;
  if ((fp = fopen("/sys/kernel/fscaps", "r")) == 0)
    {
      goto out;
    }
  if (readline(fp, line, sizeof(line)))
    {
      val = atoi(line);
    }
  fclose(fp);
out:
  return val;
}

int
main(int argc, char **argv)
{
  char *opt, *str;
  int told = 0;
  int use_checklist = 0;
  int systemmode = 0;
  int suseconfig = 0;
  FILE *fp;
  char line[512];
  char *part[4];
  int pcnt, lcnt;
  size_t i;
  int inpart;
  mode_t mode;
  struct perm *e;
  struct stat stb;
  struct passwd *pwd = 0;
  struct group *grp = 0;
  uid_t uid;
  gid_t gid;
  int fd = -1;
  int errors = 0;
  cap_t caps = NULL;

  while (argc > 1)
    {
      opt = argv[1];
      if (!strcmp(opt, "--"))
        break;
      if (*opt == '-' && opt[1] == '-')
        opt++;
      if (!strcmp(opt, "-system"))
        {
          argc--;
          argv++;
          systemmode = 1;
          continue;
        }
      // hidden option for use by suseconfig only
      if (!strcmp(opt, "-suseconfig"))
        {
          argc--;
          argv++;
          suseconfig = 1;
          systemmode = 1;
          continue;
        }
      if (!strcmp(opt, "-fscaps"))
        {
          argc--;
          argv++;
          have_fscaps = 1;
          continue;
        }
      if (!strcmp(opt, "-no-fscaps"))
        {
          argc--;
          argv++;
          have_fscaps = 0;
          continue;
        }
      if (!strcmp(opt, "-s") || !strcmp(opt, "-set"))
        {
          do_set=1;
          argc--;
          argv++;
          continue;
        }
      if (!strcmp(opt, "-warn"))
        {
          do_set=0;
          argc--;
          argv++;
          continue;
        }
      if (!strcmp(opt, "-n") || !strcmp(opt, "-noheader"))
        {
          told = 1;
          argc--;
          argv++;
          continue;
        }
      if (!strcmp(opt, "-e") || !strcmp(opt, "-examine"))
        {
          argc--;
          argv++;
          if (argc == 1)
            {
              fprintf(stderr, "examine: argument required\n");
              exit(1);
            }
          add_checklist(argv[1]);
          use_checklist = 1;
          argc--;
          argv++;
          continue;
        }
      if (!strcmp(opt, "-level"))
        {
          argc--;
          argv++;
          if (argc == 1)
            {
              fprintf(stderr, "level: argument required\n");
              exit(1);
            }
          force_level = argv[1];
          argc--;
          argv++;
          continue;
        }
      if (!strcmp(opt, "-f") || !strcmp(opt, "-files"))
        {
          argc--;
          argv++;
          if (argc == 1)
            {
              fprintf(stderr, "files: argument required\n");
              exit(1);
            }
          if ((fp = fopen(argv[1], "r")) == 0)
            {
              fprintf(stderr, "files: %s: %s\n", argv[1], strerror(errno));
              exit(1);
            }
          while (readline(fp, line, sizeof(line)))
            {
              if (!*line)
                continue;
              add_checklist(line);
            }
          fclose(fp);
          use_checklist = 1;
          argc--;
          argv++;
          continue;
        }
      if (!strcmp(opt, "-r") || !strcmp(opt, "-root"))
        {
          argc--;
          argv++;
          if (argc == 1)
            {
              fprintf(stderr, "root: argument required\n");
              exit(1);
            }
          root = argv[1];
          rootl = strlen(root);
          if (*root != '/')
            {
              fprintf(stderr, "root: must begin with '/'\n");
              exit(1);
            }
          argc--;
          argv++;
          continue;
        }
      if (*opt == '-')
        usage(!strcmp(opt, "-h") || !strcmp(opt, "-help") ? 0 : 1);
      break;
    }

  if (systemmode)
    {
      const char file[] = "/etc/sysconfig/security";
      parse_sysconf(file);
      if(do_set == -1)
        {
          if (default_set < 0)
            {
              fprintf(stderr, "permissions handling disabled in %s\n", file);
              exit(0);
            }
          if (suseconfig && default_set)
            {
              char* module = getenv("ONLY_MODULE");
              if (!module || strcmp(module, "permissions"))
                {
                  puts("no permissions will be changed if not called explicitly");
                  default_set = 0;
                }
            }
          do_set = default_set;
        }
      if (force_level)
        {
          char *p = strtok(force_level, " ");
          do
            {
              add_level(p);
            }
          while ((p = strtok(NULL, " ")));
        }

      if (!nlevel)
        add_level("secure");
      add_level("local"); // always add local

      for (i = 1; i < (size_t)argc; i++)
        {
          add_checklist(argv[i]);
          use_checklist = 1;
          continue;
        }
      collect_permfiles();
    }
  else if (argc <= 1)
    usage(1);
  else
    {
      npermfiles = (size_t)argc-1;
      permfiles = &argv[1];
    }

  if (have_fscaps == 1 && !check_fscaps_enabled())
    {
      fprintf(stderr, "Warning: running kernel does not support fscaps\n");
    }

  if  (do_set == -1)
    do_set = 0;

  // add fake list entries for all files to check
  for (i = 0; i < nchecklist; i++)
    add_permlist(checklist[i], "unknown", "unknown", 0);

  for (i = 0; i < npermfiles; i++)
    {
      if ((fp = fopen(permfiles[i], "r")) == 0)
        {
          perror(permfiles[i]);
          exit(1);
        }
      lcnt = 0;
      struct perm* last = NULL;
      int extline;
      while (readline(fp, line, sizeof(line)))
        {
          extline = 0;
          lcnt++;
          if (*line == 0 || *line == '#' || *line == '$')
            continue;
          inpart = 0;
          pcnt = 0;
          char *p;
          for (p = line; *p; p++)
            {
              if (*p == ' ' || *p == '\t')
                {
                  *p = 0;
                  if (inpart)
                    {
                      pcnt++;
                      inpart = 0;
                    }
                  continue;
                }
              if (pcnt == 0 && !inpart && *p == '+')
                {
                  extline = 1;
                  break;
                }
              if (!inpart)
                {
                  inpart = 1;
                  if (pcnt == 3)
                    break;
                  part[pcnt] = p;
                }
            }
          if (extline)
            {
              if (!last)
                {
                  BAD_LINE();
                  continue;
                }
              if (!strncmp(p, "+capabilities ", 14))
                {
                  if (have_fscaps != 1)
                    continue;
                  p += 14;
                  caps = cap_from_text(p);
                  if (caps)
                    {
                      cap_free(last->caps);
                      last->caps = caps;
                    }
                  continue;
                }
              BAD_LINE();
              continue;
            }
          if (inpart)
            pcnt++;
          if (pcnt != 3)
            {
              BAD_LINE();
              continue;
            }
          part[3] = part[2];
          part[2] = strchr(part[1], ':');
          if (!part[2])
            part[2] = strchr(part[1], '.');
          if (!part[2])
            {
              BAD_LINE();
              continue;
            }
          *part[2]++ = 0;
          mode = (mode_t)strtoul(part[3], part + 3, 8);
          if (mode > 07777 || part[3][0])
            {
              BAD_LINE();
              continue;
            }
          last = add_permlist(part[0], part[1], part[2], mode);
        }
      fclose(fp);
    }

  euid = geteuid();
  for (e = permlist; e; e = e->next)
    {
      if (use_checklist && !in_checklist(e->file+rootl))
        continue;

      pwd = strcmp(e->owner, "unknown") ? getpwnam(e->owner) : NULL;
      grp = strcmp(e->group, "unknown") ? getgrnam(e->group) : NULL;
      uid = pwd ? pwd->pw_uid : 0;
      gid = grp ? grp->gr_gid : 0;

      bool traversed_insecure;
      if (fd >= 0)
        {
          // close fd from previous loop iteration
          close(fd);
          fd = -1;
        }

      fd = safe_open(e->file, &stb, uid, &traversed_insecure);
      if (fd < 0)
        continue;
      if (S_ISLNK(stb.st_mode))
        continue;

      if (!e->mode && !strcmp(e->owner, "unknown"))
        {
          fprintf(stderr, "%s: cannot verify ", e->file+rootl);
          pwd = getpwuid(stb.st_uid);
          if (pwd)
            fprintf(stderr, "%s:", pwd->pw_name);
          else
            fprintf(stderr, "%d:", stb.st_uid);
          grp = getgrgid(stb.st_gid);
          if (grp)
            fprintf(stderr, "%s", grp->gr_name);
          else
            fprintf(stderr, "%d", stb.st_gid);
          fprintf(stderr, " %04o - not listed in /etc/permissions\n",
                          (int)(stb.st_mode&07777));
          continue;
        }
      if (!pwd)
        {
          fprintf(stderr, "%s: unknown user %s. ignoring entry.\n", e->file+rootl, e->owner);
          continue;
        }
      else if (!grp)
        {
          fprintf(stderr, "%s: unknown group %s. ignoring entry.\n", e->file+rootl, e->group);
          continue;
        }

      // fd is opened with O_PATH, file oeprations like cap_get_fd() and fchown() don't work with it.
      //
      // We also don't want to do a proper open() of the file, since that doesn't even work for sockets
      // and might have side effects for pipes or devices.
      //
      // So we use path-based operations (yes!) with /proc/self/fd/xxx. (Since safe_open already resolved
      // all symlinks, 'fd' can't refer to a symlink which we'd have to worry might get followed.)
      char fd_path_buf[PROC_PATH_SIZE];
      char *fd_path;
      int r = make_proc_path(fd, fd_path_buf);
      if (r == 0)
        fd_path = fd_path_buf;
      else
        // fall back to plain path-access for read-only operation. (this is fine)
        // below we make sure that in this case we report errors instead of trying to fix policy violations insecurely
        fd_path = e->file;

      caps = cap_get_file(fd_path);
      if (!caps)
        {
          // we get EBADF for files that don't support capabilities, e.g. sockets or FIFOs
          if (errno == EBADF)
            {
              if (e->caps)
                {
                  fprintf(stderr, "%s: cannot assign capabilities for this kind of file\n", e->file+rootl);
                  cap_free(e->caps);
                  errors++;
                }
              e->caps = NULL;
            }
          if (errno == EOPNOTSUPP)
            {
              if (e->caps)
                cap_free(e->caps);
              e->caps = NULL;
            }
        }
      if (e->caps)
        {
          e->mode &= 0777;
        }

      int perm_ok = (stb.st_mode & 07777) == e->mode;
      int owner_ok = stb.st_uid == uid && stb.st_gid == gid;
      int caps_ok = 0;

      if (!caps && !e->caps)
        caps_ok = 1;
      else if (caps && e->caps && !cap_compare(e->caps, caps))
        caps_ok = 1;

      if (perm_ok && owner_ok && caps_ok)
        continue;

      if (!told)
        {
          told = 1;
          printf("Checking permissions and ownerships - using the permissions files\n");
          for (i = 0; i < npermfiles; i++)
            printf("\t%s\n", permfiles[i]);
          if (rootl)
            {
              printf("Using root %s\n", root);
            }
        }

      if (do_set && fd_path != fd_path_buf)
        {
          fprintf(stderr, "ERROR: /proc is not available - unable to fix policy violations.\n");
          errors++;
          do_set = false;
        }

      if (!do_set)
        printf("%s should be %s:%s %04o", e->file+rootl, e->owner, e->group, e->mode);
      else
        printf("setting %s to %s:%s %04o", e->file+rootl, e->owner, e->group, e->mode);

      if (!caps_ok && e->caps)
        {
          str = cap_to_text(e->caps, NULL);
          printf(" \"%s\"", str);
          cap_free(str);
        }
      printf(". (wrong");
      if (!owner_ok)
        {
          pwd = getpwuid(stb.st_uid);
          grp = getgrgid(stb.st_gid);
          if (pwd)
            printf(" owner/group %s", pwd->pw_name);
          else
            printf(" owner/group %d", stb.st_uid);
          if (grp)
            printf(":%s", grp->gr_name);
          else
            printf(":%d", stb.st_gid);
          pwd = 0;
          grp = 0;
        }

      if (!perm_ok)
        printf(" permissions %04o", (int)(stb.st_mode & 07777));

      if (!caps_ok)
        {
          if (!perm_ok || !owner_ok)
            {
              fputc(',', stdout);
            }
          if (caps)
            {
              str = cap_to_text(caps, NULL);
              printf(" capabilities \"%s\"", str);
              cap_free(str);
            }
          else
            fputs(" missing capabilities", stdout);
        }
      putchar(')');
      putchar('\n');

      if (!do_set)
        continue;

      // don't give high privileges to files controlled by non-root users
      if ((e->caps || (e->mode & S_ISUID) || (e->mode & S_ISGID)) && !S_ISREG(stb.st_mode) && !S_ISDIR(stb.st_mode))
        {
          fprintf(stderr, "%s: will only assign capabilities or setXid bits to regular files or directories\n", e->file+rootl);
          errors++;
          continue;
        }
      if (traversed_insecure && (e->caps || (e->mode & S_ISUID) || ((e->mode & S_ISGID) && S_ISREG(stb.st_mode))))
        {
          fprintf(stderr, "%s: will not give away capabilities or setXid bits on an insecure path\n", e->file+rootl);
          errors++;
          continue;
        }

      if (euid == 0 && !owner_ok)
        {
         /* if we change owner or group of a setuid file the bit gets reset so
            also set perms again */
          if (e->mode & (S_ISUID | S_ISGID))
              perm_ok = 0;
          if (chown(fd_path, uid, gid))
            {
              fprintf(stderr, "%s: chown: %s\n", e->file+rootl, strerror(errno));
              errors++;
            }
        }
      if (!perm_ok && chmod(fd_path, e->mode))
        {
          fprintf(stderr, "%s: chmod: %s\n", e->file+rootl, strerror(errno));
          errors++;
        }
      if (!caps_ok)
        {
          if (S_ISREG(stb.st_mode))
            {
              // cap_set_file() tries to be helpful and does a lstat() to check that it isn't called on
              // a symlink. So we have to open() it (without O_PATH) and use cap_set_fd().
              int cap_fd = open(fd_path, O_NOATIME | O_CLOEXEC);
              if (cap_fd == -1)
                {
                  fprintf(stderr, "%s: open() for changing capabilities: %s\n", e->file+rootl, strerror(errno));
                  errors++;
                }
              else if (cap_set_fd(cap_fd, e->caps))
                {
                  fprintf(stderr, "%s: cap_set_fd: %s\n", e->file+rootl, strerror(errno));
                  errors++;
                }
              if (cap_fd != -1)
                close(cap_fd);
            }
          else
            {
              fprintf(stderr, "%s: cannot set capabilities: not a regular file\n", e->file+rootl);
              errors++;
            }
        }
    }
  // close fd from last loop iteration
  if (fd >= 0)
    {
      close(fd);
      fd = -1;
    }
  if (errors)
    {
      fprintf(stderr, "ERROR: not all operations were successful.\n");
      exit(1);
    }
  if (permfiles != argv + 1)
    {
      for (i = 0; i < npermfiles; i++)
        {
          free(permfiles[i]);
        }
      free(permfiles);
    }
  exit(0);
}

// vim: sw=4 cino+={.5s,n-.5s,^-.5s
