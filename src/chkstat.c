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

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/capability.h>
#define __USE_GNU
#include <fcntl.h>

#define BAD_LINE() \
  fprintf(stderr, "bad permissions line %s:%d\n", permfiles[i], lcnt);

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
int nchecklist;
uid_t euid;
char *root;
int rootl;
int nlevel;
char** level;
int do_set = -1;
int default_set = 1;
int have_fscaps = -1;
char** permfiles = NULL;
int npermfiles = 0;
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
  int i;
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
      if (checklist == 0)
	checklist = malloc(sizeof(char *) * (nchecklist + 64));
      else
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
readline(FILE *fp, char *buf, int len)
{
  int l;
  if (!fgets(buf, len, fp))
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
  while ((l = getc(fp)) != EOF && l != '\n')
    ;
  buf[0] = 0;
  return 1;
}

int
in_level(char *e)
{
  int i;
  for (i = 0; i < nlevel; i++)
    if (!strcmp(e, level[i]))
      return 1;
  return 0;
}

void
ensure_array(void** array, int* size)
{
  if ((*size & 63) == 0)
    {
      if (*array == NULL)
	*array = malloc(sizeof(char *) * (*size + 64));
      else
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
  char line[1024];
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
  int i;
  DIR* dir;

  ensure_array((void**)&permfiles, &npermfiles);
  // 1. central fixed permissions file
  permfiles[npermfiles++] = strdup("/etc/permissions");

  // 2. central easy, secure, restrivie, paranoid as those are defined by SUSE
  for (i = 0; i < nlevel; ++i)
    {
      if (!strcmp(level[i], "easy")
	      || !strcmp(level[i], "secure")
	      || !strcmp(level[i], "restrictive")
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
      int nfiles = 0;
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
	      int l;
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
	}
    }
  // 4. central permissions files with user defined level incl 'local'
  for (i = 0; i < nlevel; ++i)
    {
      char fn[4096];

      if (!strcmp(level[i], "easy") || !strcmp(level[i], "secure") || !strcmp(level[i], "paranoid") || !strcmp(level[i], "restrictive"))
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
"  --set			apply changes\n"
"  --warn		only tell which changes are needed\n"
"  --noheader		don't print intro message\n"
"  --fscaps		force use of fscaps\n"
"  --no-fscaps		disable use of fscaps\n"
"  --system		system mode, act according to /etc/sysconfig/security\n"
"  --level LEVEL		force use LEVEL (only with --system)\n"
"  --examine FILE	apply to specified file only\n"
"  --files FILELIST	read list of files to apply from FILELIST\n"
"  --root DIR		check files relative to DIR\n"
);
  exit(x);
}

int
safepath(char *path, uid_t uid, gid_t gid)
{
  struct stat stb;
  char pathbuf[1024];
  char linkbuf[1024];
  char *p, *p2;
  int l, l2, lcnt;

  lcnt = 0;
  l2 = strlen(path);
  if ((unsigned)l2 >= sizeof(pathbuf))
    return 0;
  strcpy(pathbuf, path);
  if (pathbuf[0] != '/') 
    return 0;
  p = pathbuf + rootl;
  for (;;)
    {
      p = strchr(p, '/');
      if (!p)
        return 1;
      *p = 0;
      if (lstat(*pathbuf ? pathbuf : "/", &stb))
	return 0;
      if (S_ISLNK(stb.st_mode))
	{
	  if (++lcnt >= 256)
	    return 0;
	  l = readlink(pathbuf, linkbuf, sizeof(linkbuf));
	  if (l <= 0 || (unsigned)l >= sizeof(linkbuf))
	    return 0;
	  while(l && linkbuf[l - 1] == '/')
	    l--;
	  if ((unsigned)l + 1 >= sizeof(linkbuf))
	    return 0;
	  linkbuf[l++] = '/';
	  linkbuf[l] = 0;
	  *p++ = '/';
	  if (linkbuf[0] == '/')
	    {
	      if (rootl)
		{
		  p[-1] = 0;
		  fprintf(stderr, "can't handle symlink %s at the moment\n", pathbuf);
		  return 0;
		}
	      l2 -= (p - pathbuf);
	      memmove(pathbuf + rootl, p, l2 + 1);
	      l2 += rootl;
	      p = pathbuf + rootl;
	    }
	  else
	    {
	      if (p - 1 == pathbuf)
		return 0;		/* huh, "/" is a symlink */
	      for (p2 = p - 2; p2 >= pathbuf; p2--)
		if (*p2 == '/')
		  break;
	      if (p2 < pathbuf + rootl)	/* cannot happen */
		return 0;
	      p2++;			/* am now after '/' */
              memmove(p2, p, pathbuf + l2 - p + 1);
	      l2 -= (p - p2);
	      p = p2;
	    }
	  if ((unsigned)(l + l2) >= sizeof(pathbuf))
	    return 0;
	  memmove(p + l, p, pathbuf + l2 - p + 1);
	  memmove(p, linkbuf, l);
	  l2 += l;
	  if (pathbuf[0] != '/')	/* cannot happen */
	    return 0;
	  if (p == pathbuf)
	    p++;
	  continue;
	}
      if (!S_ISDIR(stb.st_mode))
	return 0;

      /* write is always forbidden for other */
      if ((stb.st_mode & 02) != 0)
	return 0;

      /* owner must be ok as she may change the mode */
      /* for euid != 0 it is also ok if the owner is euid */
      if (stb.st_uid && stb.st_uid != uid && stb.st_uid != euid)
	return 0;

      /* group gid may do fancy things */
      /* for euid != 0 we don't check this */
      if ((stb.st_mode & 020) != 0 && !euid)
	if (!gid || stb.st_gid != gid)
	  return 0;

      *p++ = '/';
    }
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
  char *opt, *p, *str;
  int told = 0;
  int use_checklist = 0;
  int systemmode = 0;
  int suseconfig = 0;
  FILE *fp;
  char line[512];
  char *part[4];
  int i, pcnt, lcnt;
  int inpart;
  mode_t mode;
  struct perm *e;
  struct stat stb, stb2;
  struct passwd *pwd = 0;
  struct group *grp = 0;
  uid_t uid;
  gid_t gid;
  int fd, r;
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

      for (i = 1; i < argc; i++)
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
      npermfiles = argc-1;
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
          mode = strtoul(part[3], part + 3, 8);
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
      if (lstat(e->file, &stb))
	continue;
      if (S_ISLNK(stb.st_mode))
	continue;
      if (!e->mode && !strcmp(e->owner, "unknown"))
	{
	  char uids[16], gids[16];
	  pwd = getpwuid(stb.st_uid);
	  grp = getgrgid(stb.st_gid);
	  if (!pwd)
	    sprintf(uids, "%d", stb.st_uid);
	  if (!grp)
	    sprintf(gids, "%d", stb.st_gid);
	  fprintf(stderr, "%s: cannot verify %s:%s %04o - not listed in /etc/permissions\n",
		  e->file+rootl,
		  pwd?pwd->pw_name:uids,
		  grp?grp->gr_name:gids,
		  (int)(stb.st_mode&07777));
	  pwd = 0;
	  grp = 0;
	  continue;
	}
      if ((!pwd || strcmp(pwd->pw_name, e->owner)) && (pwd = getpwnam(e->owner)) == 0)
	{
	  fprintf(stderr, "%s: unknown user %s\n", e->file+rootl, e->owner);
	  continue;
	}
      if ((!grp || strcmp(grp->gr_name, e->group)) && (grp = getgrnam(e->group)) == 0)
	{
	  fprintf(stderr, "%s: unknown group %s\n", e->file+rootl, e->group);
	  continue;
	}
      uid = pwd->pw_uid;
      gid = grp->gr_gid;
      caps = cap_get_file(e->file);
      if (!caps)
	{
	  cap_free(caps);
	  caps = NULL;
	  if (errno == EOPNOTSUPP)
	    {
	      //fprintf(stderr, "%s: fscaps not supported\n", e->file+rootl);
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

      fd = -1;
      if (S_ISDIR(stb.st_mode))
	{
	  fd = open(e->file, O_RDONLY|O_DIRECTORY|O_NONBLOCK|O_NOFOLLOW);
	  if (fd == -1)
	    {
	      perror(e->file);
	      errors++;
	      continue;
	    }
	}
      else if (S_ISREG(stb.st_mode))
	{
	  fd = open(e->file, O_RDONLY|O_NONBLOCK|O_NOFOLLOW);
	  if (fd == -1)
	    {
	      perror(e->file);
	      errors++;
	      continue;
	    }
	  if (fstat(fd, &stb2))
	    continue;
	  if (stb.st_mode != stb2.st_mode || stb.st_nlink != stb2.st_nlink || stb.st_dev != stb2.st_dev || stb.st_ino != stb2.st_ino)
	    {
	      fprintf(stderr, "%s: too fluctuating\n", e->file+rootl);
	      errors++;
	      continue;
	    }
	  if (stb.st_nlink > 1 && !safepath(e->file, 0, 0))
	    {
	      fprintf(stderr, "%s: on an insecure path\n", e->file+rootl);
	      errors++;
	      continue;
	    }
	  else if (e->mode & 06000)
	    {
	      /* extra checks for s-bits */
	      if (!safepath(e->file, (e->mode & 02000) == 0 ? uid : 0, (e->mode & 04000) == 0 ? gid : 0))
		{
		  fprintf(stderr, "%s: will not give away s-bits on an insecure path\n", e->file+rootl);
		  errors++;
		  continue;
		}
	    }
	}
      else if (strncmp(e->file, "/dev/", 5) != 0) // handle special files only in /dev
	{
	  fprintf(stderr, "%s: don't know what to do with that type of file\n", e->file+rootl);
	  errors++;
	  continue;
	}
      if (euid == 0 && !owner_ok)
	{
	 /* if we change owner or group of a setuid file the bit gets reset so
	    also set perms again */
	  if (e->mode & 06000)
	      perm_ok = 0;
	  if (fd >= 0)
	    r = fchown(fd, uid, gid);
	  else
	    r = chown(e->file, uid, gid);
	  if (r)
	    {
	      fprintf(stderr, "%s: chown: %s\n", e->file+rootl, strerror(errno));
	      errors++;
	    }
	  if (fd >= 0)
	    r = fstat(fd, &stb);
	  else
	    r = lstat(e->file, &stb);
	  if (r)
	    {
	      fprintf(stderr, "%s: too fluctuating\n", e->file+rootl);
	      errors++;
	      continue;
	    }
	}
      if (!perm_ok)
	{
	  if (fd >= 0)
	    r = fchmod(fd, e->mode);
	  else
	    r = chmod(e->file, e->mode);
	  if (r)
	    {
	      fprintf(stderr, "%s: chmod: %s\n", e->file+rootl, strerror(errno));
	      errors++;
	    }
	}
      if (!caps_ok)
	{
	  if (fd >= 0)
	    r = cap_set_fd(fd, e->caps);
	  else
	    r = cap_set_file(e->file, e->caps);
	  if (r)
	    {
	      fprintf(stderr, "%s: cap_set_file: %s\n", e->file+rootl, strerror(errno));
	      errors++;
	    }
	}
      if (fd >= 0)
	close(fd);
    }
  if (errors)
    {
      fprintf(stderr, "ERROR: not all operations were successful.\n");
      exit(1);
    }
  exit(0);
}

// vim: sw=4 cino+={.5s,n-.5s,^-.5s
