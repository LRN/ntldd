/*
    ntldd - lists dynamic dependencies of a module

    Copyright (C) 2010 LRN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
Code is mostly written after
"An In-Depth Look into the Win32 Portable Executable File Format"
MSDN Magazine articles
*/

#include <windows.h>

#include <Imagehlp.h>

#include <winnt.h>

#include <string.h>
#include <stdio.h>

#define NTLDD_VERSION_MAJOR 0
#define NTLDD_VERSION_MINOR 1

/* MinGW doesn't have ImgDelayDescr defined at the moment */
typedef struct _ImgDelayDescr ImgDelayDescr;

struct _ImgDelayDescr
{
  DWORD grAttrs;
  DWORD rvaDLLName;
  DWORD rvaHmod;
  DWORD rvaIAT;
  DWORD rvaINT;
  DWORD rvaBoundIAT;
  DWORD rvaUnloadIAT;
  DWORD dwTimeStamp;
};

typedef struct _soff_entry soff_entry;

struct _soff_entry
{
  DWORD start;
  DWORD end;
  void *off;
};

void *MapPointer (soff_entry *soffs, int soffs_len, DWORD in_ptr)
{
  int i;
  for (i = 0; i < soffs_len; i++)
    if (soffs[i].start <= in_ptr && soffs[i].end >= in_ptr)
      return soffs[i].off + in_ptr;
  return NULL;
}

int FindSectionID (IMAGE_OPTIONAL_HEADER *oh, DWORD address, DWORD size)
{
  int i;
  for (i = 0; i < oh->NumberOfRvaAndSizes; i++)
  {
    if (oh->DataDirectory[i].VirtualAddress == address &&
        oh->DataDirectory[i].Size == size)
      return i;
  }
  return -1;
}

void ResizeResolved (char ***resolved, int *resolved_len, int *resolved_size)
{
  int i;
  int new_size = (*resolved_size) > 0 ? (*resolved_size) * 2 : 64;
  char **new_resolved = malloc (new_size * sizeof (char *));
  for (i = 0; i < *resolved_len; i++)
    new_resolved[i] = (*resolved)[i];
  free (*resolved);
  *resolved = new_resolved;
  *resolved_size = new_size;
}

void AddResolvedModule (char ***resolved, int *resolved_len,
    int *resolved_size, const char *name)
{
  if (*resolved_len >= *resolved_size)
    ResizeResolved (resolved, resolved_len, resolved_size);
  (*resolved)[(*resolved_len)++] = strdup (name);
}

int FindResolvedModule (char ***resolved, int *resolved_len, const char *name)
{
  int i;
  for (i = 0; i < *resolved_len; i++)
    if ((*resolved)[i] && strcmp ((*resolved)[i], name) == 0)
      return 1;
  return 0;
}

int PrintImageLinks (int first, int verbose, int unused, int datarelocs,
    int functionrelocs, char *name, int recursive, int current_depth,
    char ***resolved, int *resolved_len, int *resolved_size)
{
  LOADED_IMAGE loaded_image;
  LOADED_IMAGE *img;
  BOOL success;

  int i;
  int soffs_len;

  IMAGE_DATA_DIRECTORY *idata;
  const char *dllname = NULL;
  IMAGE_IMPORT_DESCRIPTOR *iid;
  ImgDelayDescr *idd;

  success = MapAndLoad (name, NULL, &loaded_image, FALSE, TRUE);

  if (!success)
  {
    DWORD error = GetLastError ();
    if (error == ERROR_FILE_NOT_FOUND)
    {
      success = MapAndLoad (name, NULL, &loaded_image, TRUE, TRUE);
      error = GetLastError ();
    }
    if (error == ERROR_FILE_NOT_FOUND)
    {
      if (!first)
        printf (" => not found\n");
      else
        fprintf (stderr, "%s: not found\n", name);
    }
    
    if (!success)
      return -1;
  }

  if (!first)
  {
    if (strcmp (name, loaded_image.ModuleName) == 0)
      printf (" (0x%p)\n", loaded_image.MappedAddress);
    else
      printf (" => %s (0x%p)\n", loaded_image.ModuleName,
          loaded_image.MappedAddress);
  }

  if (first || recursive)
  {
    img = &loaded_image;
    soff_entry *soffs;
    soffs_len = img->NumberOfSections;
    soffs = (soff_entry *) malloc (sizeof(soff_entry) * (soffs_len + 1));
    for (i = 0; i < img->NumberOfSections; i++)
    {
      soffs[i].start = img->Sections[i].VirtualAddress;
      soffs[i].end = soffs[i].start + img->Sections[i].Misc.VirtualSize;
      soffs[i].off = img->MappedAddress + img->Sections[i].PointerToRawData - 
          img->Sections[i].VirtualAddress;
    }
    for (i = img->NumberOfSections; i < img->NumberOfSections + 1; i++)
    {
      soffs[i].start = 0;
      soffs[i].end = 0;
      soffs[i].off = 0;
    }
  
    idata = &(img->FileHeader->OptionalHeader.\
        DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (idata->Size > 0 && idata->VirtualAddress != 0)
    {
      iid = (IMAGE_IMPORT_DESCRIPTOR *) MapPointer (soffs, soffs_len,
          idata->VirtualAddress);
      if (iid)
      {
        for (i = 0; iid[i].Characteristics || iid[i].TimeDateStamp ||
            iid[i].ForwarderChain || iid[i].Name || iid[i].FirstThunk; i++)
        {
          dllname = (char *) MapPointer (soffs, soffs_len, iid[i].Name);
          if (dllname)
          {
            int found = FindResolvedModule (resolved, resolved_len, dllname);
            if ((first || recursive) && !found)
              printf ("\t%*s%s", current_depth, current_depth > 0 ? " " : "",
                  dllname);
            if ((first || recursive) && !found)
            {
              AddResolvedModule (resolved, resolved_len, resolved_size,
                  dllname);
              if (PrintImageLinks (0, verbose, unused, datarelocs,
                  functionrelocs, (char *) dllname, recursive,
                  current_depth + 1, resolved, resolved_len,
                  resolved_size) < 0)
                printf ("\n");
            }
          }
        }
      }
    }
    
    idata = &(img->FileHeader->OptionalHeader.\
        DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
    if (idata->Size > 0 && idata->VirtualAddress != 0)
    {
      idd = (ImgDelayDescr *) MapPointer (soffs, soffs_len,
          idata->VirtualAddress);
      if (idd)
      {
        for (i = 0; idd[i].grAttrs || idd[i].rvaDLLName ||
            idd[i].rvaHmod || idd[i].rvaIAT || idd[i].rvaINT ||
            idd[i].rvaBoundIAT || idd[i].rvaUnloadIAT ||
            idd[i].dwTimeStamp; i++)
        {
          dllname = (char *) MapPointer (soffs, soffs_len, idd[i].rvaDLLName);
          if (dllname)
          {
            int found = FindResolvedModule (resolved, resolved_len, dllname);
            if ((first || recursive) && !found)
              printf ("\t%*s%s", current_depth, current_depth > 0 ? " " : "",
                  dllname);
            if ((first || recursive) && !found)
            {
              AddResolvedModule (resolved, resolved_len, resolved_size,
                  dllname);
              if (PrintImageLinks (0, verbose, unused, datarelocs,
                  functionrelocs, (char *) dllname, recursive,
                  current_depth + 1, resolved, resolved_len,
                  resolved_size) < 0)
                printf ("\n");
            }
          }
        }
      }
    }
    free (soffs);
  }

  UnMapAndLoad (&loaded_image);
  return 0;
}

void printversion()
{
  printf ("ntldd %d.%d\n\
Copyright (C) 2010 LRN\n\
This is free software; see the source for conditions. There is NO\n\
warranty; not event for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
Written by LRN.", NTLDD_VERSION_MAJOR, NTLDD_VERSION_MINOR);
}

void printhelp(char *argv0)
{
  printf("Usage: %s [OPTION]... FILE...\n\
OPTIONS:\n\
--version         Displays version\n\
-v, --verbose         Does not work\n\
-u, --unused          Does not work\n\
-d, --data-relocs     Does not work\n\
-r, --function-relocs Does not work\n\
-R, --recursive       Lists dependencies recursively,\n\
                        eliminating duplicates\n\
--help                Displays this message\n\
\n\
Use -- option to pass filenames that start with `--' or `-'\n\
For bug reporting instructions, please see:\n\
<somewhere>.", argv0);
}

int main (int argc, char **argv)
{
  int i;
  int verbose = 0;
  int unused = 0;
  int datarelocs = 0;
  int functionrelocs = 0;
  int skip = 0;
  int files = 0;
  int recursive = 0;
  int files_start = -1;
  for (i = 1; i < argc; i++)
  {
    if (strcmp (argv[i], "--version") == 0)
      printversion ();
    else if (strcmp (argv[i], "-v") == 0 || strcmp (argv[i], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[i], "-u") == 0 || strcmp (argv[i], "--unused") == 0)
      unused = 1;
    else if (strcmp (argv[i], "-d") == 0 || 
        strcmp (argv[i], "--data-relocs") == 0)
      datarelocs = 1;
    else if (strcmp (argv[i], "-r") == 0 || 
        strcmp (argv[i], "--function-relocs") == 0)
      functionrelocs = 1;
    else if (strcmp (argv[i], "-R") == 0 || 
        strcmp (argv[i], "--recursive") == 0)
      recursive = 1;
    else if (strcmp (argv[i], "--help") == 0)
    {
      printhelp (argv[0]);
      skip = 1;
      break;
    }
    else if (strcmp (argv[i], "--") == 0)
    {
      files = 1;
    }
    else if (strlen (argv[i]) > 1 && argv[i][0] == '-' && (argv[i][1] == '-' ||
        strlen (argv[i]) == 2) && !files)
    {
      fprintf (stderr, "Unrecognized option `%s'\n\
Try `ntldd --help' for more information\n", argv[i]);
      skip = 1;
      break;
    }
    else if (files_start < 0)
    {
      skip = 0;
      files_start = i;
      break;
    }
  }
  if (!skip && files_start > 0)
  {
    char **resolved = NULL;
    int resolved_len = 0;
    int resolved_size = 0;
    int multiple = files_start + 1 < argc;
    for (i = files_start; i < argc; i++)
    {
      if (multiple)
        printf ("%s:\n", argv[i]);
      PrintImageLinks (1, verbose, unused, datarelocs, functionrelocs,
         argv[i], recursive, 0, &resolved, &resolved_len, &resolved_size);
    }
  }
  return 0;
}