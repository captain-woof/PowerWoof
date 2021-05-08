#pragma once
#include "DictionaryOfLists.h"
#include "LinkedList.h"
#include "StringLinkedList.h"

class DictionaryOfListsA
{
private:
	StringLinkedListA Keys;
	LinkedList ValueLists;
	int Size;
	BOOL CleanupRequiredInLists, CleanupRequiredInKeys;

public:
	DictionaryOfListsA();
	~DictionaryOfListsA();
	void Add(PCHAR Key, LPVOID Value);
	void RemoveList(PCHAR Key);
	void RemoveFromList(PCHAR Key, int Index);
	void SetCleanupRequiredInLists(BOOL Required);
	void SetCleanupRequiredInKeys(BOOL Required);
	LPVOID GetList(PCHAR Key);
	LPVOID GetList(int Index);
	LPVOID GetElementP(PCHAR Key, int Index);
	PCHAR GetKey(int Index);
	int GetNumOfKeys();
	StringLinkedListA GetKeys();
	void Clear();
};

class DictionaryOfListsW {
private:
	StringLinkedListW Keys;
	LinkedList ValueLists;
	int Size;
	BOOL CleanupRequiredInLists, CleanupRequiredInKeys;

public:
	DictionaryOfListsW();
	~DictionaryOfListsW();
	void Add(PWCHAR Key, LPVOID Value);
	void RemoveList(PWCHAR Key);
	void RemoveFromList(PWCHAR Key, int Index);
	void SetCleanupRequiredInLists(BOOL Required);
	void SetCleanupRequiredInKeys(BOOL Required);
	LPVOID GetList(PWCHAR Key);
	LPVOID GetList(int Index);
	LPVOID GetElementP(PWCHAR Key, int Index);
	PWCHAR GetKey(int Index);
	int GetNumOfKeys();
	StringLinkedListW GetKeys();
	void Clear();
};
