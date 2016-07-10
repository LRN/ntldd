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

#include <imagehlp.h>

#include <winnt.h>

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "libntldd.h"

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
      if (soffs[i].off)
        return soffs[i].off + in_ptr;
    }
  return NULL;
}

/*
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
*/

int FindSectionByRawData (LOADED_IMAGE *img, DWORD address)
{
  ULONG i;
  for (i = 0; i < img->NumberOfSections; i++)
  {
    DWORD start = img->Sections[i].VirtualAddress;
    DWORD end = start + img->Sections[i].SizeOfRawData;
    if (address >= start && address < end)
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
#define ResizeStack(ptr_stack, ptr_stack_size) ResizeArray ((void **) ptr_stack, ptr_stack_size, sizeof (char *))

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
  uint64_t i;
  if (root->flags & DEPTREE_VISITED)
  {
    return -2;
  }
  root->flags |= DEPTREE_VISITED;
  for (i = 0; i < root->childs_len; i++)
  {
    if (stricmp (root->childs[i]->module, name) == 0)
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

int BuildDepTree (BuildTreeConfig* cfg, char *name, struct DepTreeElement *root, struct DepTreeElement *self);

struct DepTreeElement *ProcessDep (BuildTreeConfig* cfg, soff_entry *soffs, int soffs_len, DWORD name, struct DepTreeElement *root, struct DepTreeElement *self, int deep)
{
  struct DepTreeElement *child = NULL;
  int found;
  int64_t i;
  char *dllname = (char *) MapPointer (soffs, soffs_len, name, NULL);
  if (dllname == NULL)
    return NULL;
  if (strlen (dllname) > 10 && strnicmp ("api-ms-win", dllname, 10) == 0)
  {
    /* TODO: find a better way to identify api stubs. Versioninfo, maybe? */
    return NULL;
  }
  for (i = (int64_t)*cfg->stack_len - 1; i >= 0; i--)
  {
    if ((*cfg->stack)[i] && stricmp ((*cfg->stack)[i], dllname) == 0)
      return NULL;
    if (i == 0)
      break;
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
  {
    BuildDepTree (cfg, dllname, root, child);
  }
  return child;
}


/*
struct ExportTableItem *FindExportForward (struct DepTreeElement *self, char *dllname, char *export_name, DWORD export_ordinal)
{
  return NULL;
}
*/

int ClearDepStatus (struct DepTreeElement *self, uint64_t flags)
{
  uint64_t i;
  for (i = 0; i < self->childs_len; i++)
    ClearDepStatus (self->childs[i], flags);
  self->flags &= ~flags;
  return 0;
}

void PushStack (char ***stack, uint64_t *stack_len, uint64_t *stack_size, char *name)
{
  if (*stack_len >= *stack_size)
  {
    ResizeStack (stack, stack_size);
  }
  (*stack)[*stack_len] = strdup (name);
  (*stack_len) += 1;
}

void PopStack (char ***stack, uint64_t *stack_len, uint64_t *stack_size, char *name)
{
  (*stack)[*stack_len] = NULL;
  (*stack_len) -= 1;
}

static uint64_t thunk_data_u1_function (void *thunk_array, DWORD index, BuildTreeConfig *cfg)
{
  if (cfg->machineType == IMAGE_FILE_MACHINE_I386)
    return ((IMAGE_THUNK_DATA32 *) thunk_array)[index].u1.Function;
  else
    return ((IMAGE_THUNK_DATA64 *) thunk_array)[index].u1.Function;
}

static void *opt_header_get_dd_entry (void *opt_header, DWORD entry_type, BuildTreeConfig *cfg)
{
  if (cfg->machineType == IMAGE_FILE_MACHINE_I386)
    return &(((PIMAGE_OPTIONAL_HEADER32) opt_header)->DataDirectory[entry_type]);
  else
    return &(((PIMAGE_OPTIONAL_HEADER64) opt_header)->DataDirectory[entry_type]);
}

static void BuildDepTree32or64 (LOADED_IMAGE *img, BuildTreeConfig* cfg, struct DepTreeElement *root, struct DepTreeElement *self, soff_entry *soffs, int soffs_len)
{
  IMAGE_DATA_DIRECTORY *idata;
  IMAGE_IMPORT_DESCRIPTOR *iid;
  IMAGE_EXPORT_DIRECTORY *ied;
  IMAGE_DELAYLOAD_DESCRIPTOR *idd;
  void *ith, *oith;
  void *opt_header = &img->FileHeader->OptionalHeader;
  DWORD i, j;

  idata = opt_header_get_dd_entry (opt_header, IMAGE_DIRECTORY_ENTRY_EXPORT, cfg);
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
          int section_index = FindSectionByRawData (img, addrs[i]);
          if ((idata->VirtualAddress <= addrs[i]) && (idata->VirtualAddress + idata->Size > addrs[i]))
          {
            self->exports[i].address = NULL;
            self->exports[i].forward_str = strdup ((char *) MapPointer (soffs, soffs_len, addrs[i], NULL));
          }
          else
            self->exports[i].address = MapPointer (soffs, soffs_len, addrs[i], &section);
          self->exports[i].ordinal = i + ied->Base;
          self->exports[i].section_index = section_index;
          self->exports[i].address_offset = addrs[i];
        }
      }
    }
  }

  idata = opt_header_get_dd_entry (opt_header, IMAGE_DIRECTORY_ENTRY_IMPORT, cfg);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    iid = (IMAGE_IMPORT_DESCRIPTOR *) MapPointer (soffs, soffs_len,
        idata->VirtualAddress, NULL);
    if (iid)
      for (i = 0; iid[i].Characteristics || iid[i].TimeDateStamp ||
          iid[i].ForwarderChain || iid[i].Name || iid[i].FirstThunk; i++)
      {
        struct DepTreeElement *dll;
        uint64_t impaddress;
        dll = ProcessDep (cfg, soffs, soffs_len, iid[i].Name, root, self, 0);
        if (dll == NULL)
          continue;
        ith = (void *) MapPointer (soffs, soffs_len, iid[i].FirstThunk, NULL);
        oith = (void *) MapPointer (soffs, soffs_len, iid[i].OriginalFirstThunk, NULL);
        for (j = 0; (impaddress = thunk_data_u1_function (ith, j, cfg)) != 0; j++)
        {
          struct ImportTableItem *imp = AddImport (self);
          imp->dll = dll;
          imp->ordinal = -1;
          if (oith);
            imp->orig_address = thunk_data_u1_function (oith, j, cfg);
          if (cfg->on_self)
          {
            imp->address = impaddress;
          }
          if (oith && imp->orig_address & (1 << (sizeof (DWORD) * 8 - 1)))
          {
            imp->ordinal = imp->orig_address & ~(1 << (sizeof (DWORD) * 8 - 1));
          }
          else if (oith)
          {
            IMAGE_IMPORT_BY_NAME *byname = (IMAGE_IMPORT_BY_NAME *) MapPointer (soffs, soffs_len, imp->orig_address, NULL);
            if (byname != NULL)
              imp->name = strdup ((char *) byname->Name);
          }
        }
      }
  }

  idata = opt_header_get_dd_entry (opt_header, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, cfg);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    idd = (IMAGE_DELAYLOAD_DESCRIPTOR *) MapPointer (soffs, soffs_len, idata->VirtualAddress, NULL);
    if (idd)
      for (i = 0; idd[i].Attributes.AllAttributes || idd[i].DllNameRVA ||
          idd[i].ModuleHandleRVA || idd[i].ImportAddressTableRVA || idd[i].ImportNameTableRVA ||
          idd[i].BoundImportAddressTableRVA || idd[i].UnloadInformationTableRVA ||
          idd[i].TimeDateStamp; i++)
      {
        struct DepTreeElement *dll;
        uint64_t impaddress;
        dll = ProcessDep (cfg, soffs, soffs_len, idd[i].DllNameRVA, root, self, 0);
        if (dll == NULL)
          continue;
        if (idd[i].Attributes.AllAttributes & 0x00000001)
        {
          ith = (void *) MapPointer (soffs, soffs_len, idd[i].ImportAddressTableRVA, NULL);
          oith = (void *) MapPointer (soffs, soffs_len, idd[i].ImportNameTableRVA, NULL);
        }
        else
        {
          ith = (void *) idd[i].ImportAddressTableRVA;
          oith = (void *) idd[i].ImportNameTableRVA;
        }
        for (j = 0; (impaddress = thunk_data_u1_function (ith, j, cfg)) != 0; j++)
        {
          struct ImportTableItem *imp = AddImport (self);
          imp->dll = dll;
          imp->ordinal = -1;
          if (oith)
            imp->orig_address = thunk_data_u1_function (oith, j, cfg);
          if (cfg->on_self)
          {
            imp->address = impaddress;
          }
          if (oith && imp->orig_address & (1 << (sizeof (DWORD) * 8 - 1)))
          {
            imp->ordinal = imp->orig_address & ~(1 << (sizeof (DWORD) * 8 - 1));
          }
          else if (oith)
          {
            IMAGE_IMPORT_BY_NAME *byname = (IMAGE_IMPORT_BY_NAME *) MapPointer (soffs, soffs_len, imp->orig_address, NULL);
            if (byname != NULL)
              imp->name = strdup ((char *) byname->Name);
          }
        }
      }
  }

  idata = opt_header_get_dd_entry (opt_header, IMAGE_DIRECTORY_ENTRY_IMPORT, cfg);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    iid = (IMAGE_IMPORT_DESCRIPTOR *) MapPointer (soffs, soffs_len,
        idata->VirtualAddress, NULL);
    if (iid)
      for (i = 0; iid[i].Characteristics || iid[i].TimeDateStamp ||
          iid[i].ForwarderChain || iid[i].Name || iid[i].FirstThunk; i++)
        ProcessDep (cfg, soffs, soffs_len, iid[i].Name, root, self, 1);
  }

  idata = opt_header_get_dd_entry (opt_header, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, cfg);
  if (idata->Size > 0 && idata->VirtualAddress != 0)
  {
    idd = (IMAGE_DELAYLOAD_DESCRIPTOR *) MapPointer (soffs, soffs_len, idata->VirtualAddress, NULL);
    if (idd)
      for (i = 0; idd[i].Attributes.AllAttributes || idd[i].DllNameRVA ||
          idd[i].ModuleHandleRVA || idd[i].ImportAddressTableRVA || idd[i].ImportNameTableRVA ||
          idd[i].BoundImportAddressTableRVA || idd[i].UnloadInformationTableRVA ||
          idd[i].TimeDateStamp; i++)
        ProcessDep (cfg, soffs, soffs_len, idd[i].DllNameRVA, root, self, 1);
  }
}

BOOL TryMapAndLoad (PCSTR name, PCSTR path, PLOADED_IMAGE loadedImage, int requiredMachineType)
{
    BOOL success = MapAndLoad (name, path, loadedImage, FALSE, TRUE);
    if (!success && GetLastError () == ERROR_FILE_NOT_FOUND)
        success = MapAndLoad (name, path, loadedImage, TRUE, TRUE);
    if (success && requiredMachineType != -1 && (int)loadedImage->FileHeader->FileHeader.Machine != requiredMachineType)
    {
        UnMapAndLoad (loadedImage);
        return FALSE;
    }
    return success;
}

int BuildDepTree (BuildTreeConfig* cfg, char *name, struct DepTreeElement *root, struct DepTreeElement *self)
{
  LOADED_IMAGE loaded_image;
  LOADED_IMAGE *img;
  IMAGE_DOS_HEADER *dos;
  HMODULE hmod;
  BOOL success;

  DWORD i, j;
  int soffs_len;
  soff_entry *soffs;

  if (self->flags & DEPTREE_PROCESSED)
  {
    return 0;
  }

  if (cfg->on_self)
  {
    char modpath[MAX_PATH];
    success = GetModuleHandleExA (GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &hmod);
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
    if (cfg->machineType != -1 && (int)loaded_image.FileHeader->FileHeader.Machine != cfg->machineType)
        return 1;
  }
  else
  {
    success = FALSE;
    for (i = 0; i < cfg->searchPaths->count && !success; ++i)
    {
      success = TryMapAndLoad (name, cfg->searchPaths->path[i], &loaded_image, cfg->machineType);
    }
    if (!success)
        success = TryMapAndLoad (name, NULL, &loaded_image, cfg->machineType);
    if (!success)
    {
      self->flags |= DEPTREE_UNRESOLVED;
      return 1;
    }
    if (self->resolved_module == NULL)
      self->resolved_module = strdup (loaded_image.ModuleName);
  }
  if (cfg->machineType == -1)
    cfg->machineType = (int)loaded_image.FileHeader->FileHeader.Machine;
  img = &loaded_image;

  PushStack (cfg->stack, cfg->stack_len, cfg->stack_size, name);

  self->mapped_address = loaded_image.MappedAddress;

  self->flags |= DEPTREE_PROCESSED;

  soffs_len = img->NumberOfSections;
  soffs = (soff_entry *) malloc (sizeof(soff_entry) * (soffs_len + 1));
  for (i = 0; i < img->NumberOfSections; i++)
  {
    soffs[i].start = img->Sections[i].VirtualAddress;
    soffs[i].end = soffs[i].start + img->Sections[i].Misc.VirtualSize;
    if (cfg->on_self)
      soffs[i].off = img->MappedAddress/* + img->Sections[i].VirtualAddress*/;
    else if (img->Sections[i].PointerToRawData != 0)
      soffs[i].off = img->MappedAddress + img->Sections[i].PointerToRawData - 
          img->Sections[i].VirtualAddress;
    else
      soffs[i].off = NULL;
  }
  soffs[img->NumberOfSections].start = 0;
  soffs[img->NumberOfSections].end = 0;
  soffs[img->NumberOfSections].off = 0;

  BuildDepTree32or64 (img, cfg, root, self, soffs, soffs_len);
  free (soffs);

  if (!cfg->on_self)
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
  /* By keeping items in the stack we turn it into a list of all
   * processed modules, this should be more effective at preventing
   * us from processing modules multiple times
   */
  /*PopStack (stack, stack_len, stack_size, name);*/
  return 0;
}
