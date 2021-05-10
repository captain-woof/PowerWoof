#pragma once
#include "LinkedList.h"
#include "StringLinkedList.h"

class DictionaryA
{
private:
	StringLinkedListA Keys;
	LinkedList Values;
	int Size;

public:
	DictionaryA();
	BOOL Add(PCHAR Key, LPVOID Value);
	BOOL Remove(PCHAR Key);
	LPVOID GetValue(PCHAR Key);
	LPVOID GetValue(int Index);
	PCHAR GetKey(int Index);
	int GetSize();
	StringLinkedListA GetKeys();
	LinkedList GetValues();
	void Clear();
};

class DictionaryW {
private:
	StringLinkedListW Keys;
	LinkedList Values;
	int Size;

public:
	DictionaryW();
	BOOL Add(PWCHAR Key, LPVOID Value);
	BOOL Remove(PWCHAR Key);
	LPVOID GetValue(PWCHAR Key);
	LPVOID GetValue(int Index);
	PWCHAR GetKey(int Index);
	int GetSize();
	StringLinkedListW GetKeys();
	LinkedList GetValues();
	void Clear();
};

