/*
    libntldd - builds a dependency tree of a module, with symbols

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
#include <stdint.h>

#include "libntldd.h"

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

void *MapPointer (soff_entry *soffs, int soffs_len, DWORD in_ptr, int *section)
{
  int i;
  for (i = 0; i < soffs_len; i++)
    if (soffs[i].start <= in_ptr && soffs[i].end >= in_ptr)
    {
      if (section != NULL)
        *section = i;
      return soffs[i].off + in_ptr;
    }
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

void ResizeArray (void **data, uint64_t *data_size, size_t sizeof_data)
{
  uint64_t new_size = (*data_size) > 0 ? (*data_size) * 2 : 64;
  void *new_data;
  new_data = realloc (*data, new_size * sizeof_data);
  memset (((unsigned char *) new_data) + (*data_size * sizeof_data), 0, (new_size - (*data_size)) * sizeof_data);
  *data = new_data;
  *data_size = new_size;
}

#define ResizeDepList(ptr_deptree, ptr_deptree_size) ResizeArray ((void **) ptr_deptree, ptr_deptree_size, sizeof (struct DepTreeElement *))
#define ResizeImportList(ptr_import_list, ptr_import_list_size) ResizeArray ((void **) ptr_import_list, ptr_import_list_size, sizeof (struct ImportTableItem))

void AddDep (struct DepTreeElement *parent, struct DepTreeElement *child)
{
  if (parent->childs_len >= parent->childs_size)
  {
    ResizeDepList (&parent->childs, &parent->childs_size);
  }
  parent->childs[parent->childs_len] = child;
  parent->childs_len += 1;
}

struct ImportTableItem *AddImport (struct DepTreeElement *self)
{
  if (self->imports_len >= self->imports_size)
  {
    ResizeImportList (&self->imports, &self->imports_size);
  }
  self->imports_len += 1;
  return &self->imports[self->imports_len - 1];
}

int FindDep (struct DepTreeElement *root, char *name, struct DepTreeElement **result)
{
  int ret = -1;
  int i;
  if (root->flags & DEPTREE_VISITED)
  {
    return -2;
  }
  root->flags |= DEPTREE_VISITED;
  for (i = 0; i < root->childs_len; i++)
  {
    if (strcmp (root->childs[i]->module, name) == 0)
    {
      if (result != NULL)
        *result = root->childs[i];
      root->flags &= ~DEPTREE_VISITED;
      return (root->childs[i]->flags & DEPTREE_UNRESOLVED) ? 1 : 0;
    }
  }
  for (i = 0; i < root->childs_len && ret < 0; i++)
  {
    ret = FindDep (root->childs[i], name, result);
  }
  root->flags &= ~DEPTREE_VISITED;
  return ret;
}

int BuildDepTree (int datarelocs, int functionrelocs, char *name, int recursive, struct DepTreeElement *root, struct DepTreeElement *self, int on_self);

struct DepTreeElement *ProcessDep (int datarelocs, int functionrelocs, int recursive, soff_entry *soffs, int soffs_len, DWORD name, struct DepTreeElement *root, struct DepTreeElement *self, int deep, int on_self)
{
  struct DepTreeElement *child = NULL;
  int found;
  char *dllname = (char *) MapPointer (soffs, soffs_len, name, NULL);
  if (dllname == NULL)
    return NULL;
  if (strlen (dllname) > 10 && strnicmp ("api-ms-win", dllname, 10) == 0)
  {
    /* TODO: find a better way to identify api stubs. Versioninfo, maybe? */
    return NULL;
  }
  found = FindDep (root, dllname, &child);
  if (found < 0)
  {
    child = (struct DepTreeElement *) malloc (sizeof (struct DepTreeElement));
    memset (child, 0, sizeof (struct DepTreeElement));
    if (deep == 0)
    {
      child->module = strdup (dllname);
      AddDep (self, child);
    }
  }
  if (deep == 1)
    BuildDepTree (datarelocs, functionrelocs, dllname, recursive, root, child, on_self);
  return child;
}


struct ExportTableItem *FindExportForward (struct DepTreeElement *self, char *dllname, char *export_name, DWORD export_ordinal)
{
  return NULL;
}

int ClearDepStatus (struct DepTreeElement *self, uint64_t flags)
{
  int i;
  for (i = 0; i < self->childs_len; i++)
    ClearDepStatus (self->childs[i], flags);
  self->flags &= ~flags;
  return 0;
}


int BuildDepTree (int datarelocs, int functionrelocs, char *name, int recursive, struct DepTreeElement *root, struct DepTreeElement *self, int on_self)
{
  LOADED_IMAGE loaded_image;
  LOADED_IMAGE *img;
  IMAGE_DOS_HEADER *dos;
  HMODULE hmod;
  BOOL success;

  int i, j;
  int soffs_len;
  soff_entry *soffs;

  IMAGE_DATA_DIRECTORY *idata;
  IMAGE_IMPORT_DESCRIPTOR *iid;
  IMAGE_EXPORT_DIRECTORY *ied;
  ImgDelayDescr *idd;
  IMAGE_THUNK_DATA *ith, *oith;

  if (self->flags & DEPTREE_PROCESSED)
  {
    return 0;
  }

  if (on_self)
  {
    char modpath[MAX_PATH];
    success = GetModuleHandleEx (GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &hmod);
    if (!success)
      return 1;
    if (GetModuleFileNameA (hmod, modpath, MAX_PATH) == 0)
      return 1;
    if (self->resolved_module == NULL)
      self->resolved_module = strdup (modpath);

    dos = (IMAGE_DOS_HEADER *) hmod;
    loaded_image.FileHeader = (IMAGE_NT_HEADERS *) ((char *) hmod + dos->e_lfanew);
    loaded_image.Sections = (IMAGE_SECTION_HEADER *) ((char *) hmod + dos->e_lfanew + sizeof (IMAGE_NT_HEADERS));
    loaded_image.NumberOfSections = loaded_image.FileHeader->FileHeader.NumberOfSections;
    loaded_image.MappedAddress = (void *) hmod;
  }
  else
  {	
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
        self->flags |= DEPTREE_UNRESOLVED;
      }
      
      if (!success)
        return 1;
    }
    if (self->resolved_module == NULL)
      self->resolved_module = strdup (loaded_image.ModuleName);
  }
  img = &loaded_image;

  self->mapped_address = loaded_image.MappedAddress;

  self->flags |= DEPTREE_PROCESSED;

  soffs_len = img->NumberOfSections;
  soffs = (soff_entry *) malloc (sizeof(soff_entry) * (soffs_len + 1));
  for (i = 0; i < img->NumberOfSections; i++)
  {
    soffs[i].start = img->Sections[i].VirtualAddress;
    soffs[i].end = soffs[i].start + img->Sections[i].Misc.VirtualSize;
    if (on_self)
      soffs[i].off = img->MappedAddress/* + img->Sections[i].VirtualAddress*/;
    else
      soffs[i].off = img->MappedAddress + img->Sections[i].PointerToRawData - 
          img->Sections[i].VirtualAddress;
  }
  soffs[img->NumberOfSections].start = 0;
  soffs[img->NumberOfSections].end = 0;
  soffs[img->NumberOfSections].off = 0;
  
  idata = &(img->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    int export_section = -2;
    ied = (IMAGE_EXPORT_DIRECTORY *) MapPointer (soffs, soffs_len, idata->VirtualAddress, &export_section);
    if (ied && ied->Name != 0)
    {
      char *export_module = MapPointer (soffs, soffs_len, ied->Name, NULL);
      if (export_module != NULL)
      {
        if (self->export_module == NULL)
          self->export_module = strdup (export_module);
      }
    }
    if (ied && ied->NumberOfFunctions > 0)
    {
      DWORD *addrs, *names;
      WORD *ords;
      int section = -1;
      self->exports_len = ied->NumberOfFunctions;
      self->exports = (struct ExportTableItem *) malloc (sizeof (struct ExportTableItem) * self->exports_len);
      memset (self->exports, 0, sizeof (struct ExportTableItem) * self->exports_len);
      addrs = (DWORD *) MapPointer (soffs, soffs_len, ied->AddressOfFunctions, NULL);
      ords = (WORD *) MapPointer (soffs, soffs_len, ied->AddressOfNameOrdinals, NULL);
      names = (DWORD *) MapPointer (soffs, soffs_len, ied->AddressOfNames, NULL);
      for (i = 0; i < ied->NumberOfNames; i++)
      {
        self->exports[ords[i]].ordinal = ords[i] + ied->Base;
        if (names[i] != 0)
        {
          char *s_name = (char *) MapPointer (soffs, soffs_len, names[i], NULL);
          if (s_name != NULL)
            self->exports[ords[i]].name = strdup (s_name);
        }
      }
      for (i = 0; i < ied->NumberOfFunctions; i++)
      {
        if (addrs[i] != 0)
        {
          if ((idata->VirtualAddress <= addrs[i]) && (idata->VirtualAddress + idata->Size > addrs[i]))
          {
            self->exports[i].address = NULL;
            self->exports[i].forward_str = strdup ((char *) MapPointer (soffs, soffs_len, addrs[i], NULL));
          }
          else
            self->exports[i].address = MapPointer (soffs, soffs_len, addrs[i], &section);
          self->exports[i].ordinal = i + ied->Base;
        }
      }
    }
  }

  idata = &(img->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    iid = (IMAGE_IMPORT_DESCRIPTOR *) MapPointer (soffs, soffs_len,
        idata->VirtualAddress, NULL);
    if (iid)
      for (i = 0; iid[i].Characteristics || iid[i].TimeDateStamp ||
          iid[i].ForwarderChain || iid[i].Name || iid[i].FirstThunk; i++)
      {
        struct DepTreeElement *dll;
        dll = ProcessDep (datarelocs, functionrelocs, recursive, soffs, soffs_len, iid[i].Name, root, self, 0, on_self);
        if (dll == NULL)
          continue;
        ith = (IMAGE_THUNK_DATA *) MapPointer (soffs, soffs_len, iid[i].FirstThunk, NULL);
        oith = (IMAGE_THUNK_DATA *) MapPointer (soffs, soffs_len, iid[i].OriginalFirstThunk, NULL);
        for (j = 0; ith[j].u1.Function != 0; j++)
        {
          struct ImportTableItem *imp = AddImport (self);
          imp->dll = dll;
          imp->orig_address = (void *) oith[j].u1.Function;
          if (on_self)
          {
            imp->address = (void *) ith[j].u1.Function;
          }
          if (oith[j].u1.Function & (1 << (sizeof (DWORD) * 8 - 1)))
          {
            imp->ordinal = oith[j].u1.Function & ~(1 << (sizeof (DWORD) * 8 - 1));
          }
          else
          {
            imp->ordinal = -1;
            IMAGE_IMPORT_BY_NAME *byname = (IMAGE_IMPORT_BY_NAME *) MapPointer (soffs, soffs_len, oith[j].u1.Function, NULL);
            if (byname != NULL)
              imp->name = strdup ((char *) byname->Name);
          }
        }
      }
  }
  
  idata = &(img->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    idd = (ImgDelayDescr *) MapPointer (soffs, soffs_len, idata->VirtualAddress, NULL);
    if (idd)
      for (i = 0; idd[i].grAttrs || idd[i].rvaDLLName ||
          idd[i].rvaHmod || idd[i].rvaIAT || idd[i].rvaINT ||
          idd[i].rvaBoundIAT || idd[i].rvaUnloadIAT ||
          idd[i].dwTimeStamp; i++)
      {
        struct DepTreeElement *dll;
        dll = ProcessDep (datarelocs, functionrelocs, recursive, soffs, soffs_len, idd[i].rvaDLLName, root, self, 0, on_self);
        if (dll == NULL)
          continue;
        if (idd[i].grAttrs & 0x00000001)
        {
          ith = (IMAGE_THUNK_DATA *) MapPointer (soffs, soffs_len, idd[i].rvaIAT, NULL);
          oith = (IMAGE_THUNK_DATA *) MapPointer (soffs, soffs_len, idd[i].rvaINT, NULL);
        }
        else
        {
          ith = (IMAGE_THUNK_DATA *) idd[i].rvaIAT;
          oith = (IMAGE_THUNK_DATA *) idd[i].rvaINT;
        }
        for (j = 0; ith[j].u1.Function != 0; j++)
        {
          struct ImportTableItem *imp = AddImport (self);
          imp->dll = dll;
          imp->orig_address = (void *) oith[j].u1.Function;
          if (on_self)
          {
            imp->address = (void *) ith[j].u1.Function;
          }
          if (oith[j].u1.Function & (1 << (sizeof (DWORD) * 8 - 1)))
          {
            imp->ordinal = oith[j].u1.Function & ~(1 << (sizeof (DWORD) * 8 - 1));
          }
          else
          {
            IMAGE_IMPORT_BY_NAME *byname = (IMAGE_IMPORT_BY_NAME *) MapPointer (soffs, soffs_len, oith[j].u1.Function, NULL);
            if (byname != NULL)
              imp->name = strdup ((char *) byname->Name);
          }
        }
      }
  }

  idata = &(img->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    iid = (IMAGE_IMPORT_DESCRIPTOR *) MapPointer (soffs, soffs_len,
        idata->VirtualAddress, NULL);
    if (iid)
      for (i = 0; iid[i].Characteristics || iid[i].TimeDateStamp ||
          iid[i].ForwarderChain || iid[i].Name || iid[i].FirstThunk; i++)
        ProcessDep (datarelocs, functionrelocs, recursive, soffs, soffs_len, iid[i].Name, root, self, 1, on_self);
  }
  
  idata = &(img->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    idd = (ImgDelayDescr *) MapPointer (soffs, soffs_len, idata->VirtualAddress, NULL);
    if (idd)
      for (i = 0; idd[i].grAttrs || idd[i].rvaDLLName ||
          idd[i].rvaHmod || idd[i].rvaIAT || idd[i].rvaINT ||
          idd[i].rvaBoundIAT || idd[i].rvaUnloadIAT ||
          idd[i].dwTimeStamp; i++)
        ProcessDep (datarelocs, functionrelocs, recursive, soffs, soffs_len, idd[i].rvaDLLName, root, self, 1, on_self);
  }

  free (soffs);

  if (!on_self)
    UnMapAndLoad (&loaded_image);

  /* Not sure if a forwarded export warrants an import. If it doesn't, then the dll to which the export is forwarded will NOT
   * be among the dependencies of this dll and it will be necessary to do yet another ProcessDep...
  for (i = 0; i < self->exports_len; i++)
  {
    if (self->exports[i]->forward_str != NULL && self-.exports[i]->forward == NULL)
    {
      char *forward_str_copy = NULL, *export_name = NULL, *rdot = NULL;
      DWORD export_ordinal = 0;
      forward_str_copy = strdup (self->exports[i]->forward_str);
      rdot = strrchr (forward_str_copy, '.');
      if (rdot != NULL && rdot[1] != 0)
      {
        rdot[0] = 0;
        export_name = &rdot[1];
        if (export_name[0] == '#' && export_name[1] >= '0' && export_name[1] <= '9')
        {
          export_ordinal = strtol (&export_name[1], NULL, 10);
          export_name = NULL;
        }
        self->exports[i]->forward = FindExportForward (forward_str_copy, export_name, export_ordinal);
      }
      free (forward_str_copy);
    }
  }
  */
  for (i = 0; i < self->imports_len; i++)
  {
    if (self->imports[i].mapped == NULL && self->imports[i].dll != NULL && (self->imports[i].name != NULL || self->imports[i].ordinal > 0))
    {
      struct DepTreeElement *dll = self->imports[i].dll;
      for (j = 0; j < dll->exports_len; j++)
      {
        if ((self->imports[i].name != NULL && dll->exports[j].name != NULL && strcmp (self->imports[i].name, dll->exports[j].name) == 0) ||
            (self->imports[i].ordinal > 0 && dll->exports[j].ordinal > 0 && self->imports[i].ordinal == dll->exports[j].ordinal))
        {
          self->imports[i].mapped = &dll->exports[j];
          break;
        }
      }
/*
      if (self->imports[i].mapped == NULL)
        printf ("Could not match %s (%d) in %s to %s\n", self->imports[i].name, self->imports[i].ordinal, self->module, dll->module);
*/
    }
  }
  return 0;
}