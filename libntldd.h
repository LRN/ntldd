#ifndef __LIBNTLDD_H__
#define __LIBNTLDD_H__

#include <stdint.h>
#include <windows.h>

#define NTLDD_VERSION_MAJOR 0
#define NTLDD_VERSION_MINOR 1

struct DepTreeElement;

struct ExportTableItem
{
  void *address;
  char *name;
  WORD ordinal;
  char *forward_str;
  struct ExportTableItem *forward;
};

struct ImportTableItem
{
  void *orig_address;
  void *address;
  char *name;
  int ordinal;
  struct DepTreeElement *dll;
  struct ExportTableItem *mapped;
};

struct DepTreeElement
{
  uint64_t flags;
  char *module;
  char *export_module;
  char *resolved_module;
  void *mapped_address;
  struct DepTreeElement **childs;
  uint64_t childs_size;
  uint64_t childs_len;
  uint64_t imports_len;
  uint64_t imports_size;
  struct ImportTableItem *imports;
  uint64_t exports_len;
  struct ExportTableItem *exports;
};

#define DEPTREE_VISITED    0x00000001
#define DEPTREE_UNRESOLVED 0x00000002
#define DEPTREE_PROCESSED  0x00000004

int ClearDepStatus (struct DepTreeElement *self, uint64_t flags);

void AddDep (struct DepTreeElement *parent, struct DepTreeElement *child);

int BuildDepTree (int datarelocs, int functionrelocs, char *name, int recursive, struct DepTreeElement *root, struct DepTreeElement *self, int on_self);

#endif