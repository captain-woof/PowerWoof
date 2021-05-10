#include "DictionaryOfLists.h"

DictionaryOfListsA::DictionaryOfListsA() { Size = 0; }

DictionaryOfListsA::~DictionaryOfListsA(){
	Clear();	
}

void DictionaryOfListsA::SetCleanupRequiredInKeys(BOOL Required) {
	Keys.SetCleanUpRequired(Required);
}

void DictionaryOfListsA::SetCleanupRequiredInLists(BOOL Required) {
	LinkedList* List;
	for (int i = 0; i < GetNumOfKeys(); i++) {
		List = (LinkedList*)GetList(i);
		List->SetCleanUpRequired(Required);
	}
	CleanupRequiredInLists = Required;
}

void DictionaryOfListsA::Add(PCHAR Key, LPVOID Value) {
	if (Keys.IsStringPresent(Key, true)) {
		int index = Keys.Find(Key, false, true);
		((LinkedList*)(ValueLists.GetElementP(index)))->Append(Value);
	}
	else {
		Size++;
		Keys.Append(Key);
		LinkedList *ValueList = new LinkedList();
		ValueList->Append(Value);
		ValueLists.Append(ValueList);
		ValueList->SetCleanUpRequired(CleanupRequiredInLists);
	}
}

void DictionaryOfListsA::RemoveList(PCHAR Key) {
	INT index = Keys.Find(Key, false, true);
	if (index < 0) {
		return;
	}
	Keys.Remove(index);
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(index)));
	ValueList->Clear();
	ValueLists.Remove(index);
	Size--;
}

void DictionaryOfListsA::RemoveFromList(PCHAR Key, int Index) {
	INT KeyIndex = Keys.Find(Key, false, true);
	if (KeyIndex < 0) {
		return;
	}
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(KeyIndex)));
	ValueList->Remove(Index);
}

LPVOID DictionaryOfListsA::GetList(PCHAR Key) {
	INT KeyIndex = Keys.Find(Key, false, true);
	if (KeyIndex < 0) {
		return NULL;
	}
	return GetList(KeyIndex);
}

LPVOID DictionaryOfListsA::GetList(int Index) {
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(Index)));
	return ValueList;
}

LPVOID DictionaryOfListsA::GetElementP(PCHAR Key, int Index) {
	INT KeyIndex = Keys.Find(Key, false, true);
	if (KeyIndex < 0) {
		return NULL;
	}
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(KeyIndex)));
	return ValueList->GetElementP(Index);
}

PCHAR DictionaryOfListsA::GetKey(int Index) {
	return Keys.GetString(Index);
}

int DictionaryOfListsA::GetNumOfKeys() {
	return Size;
}

StringLinkedListA DictionaryOfListsA::GetKeys() {
	return Keys;
}

void DictionaryOfListsA::Clear() {	
	LinkedList* List;
	for (int i = 0; i < GetNumOfKeys(); i++) {
		List = (LinkedList*)GetList(i);
		List->Clear();
	}
	Keys.Clear();
}

DictionaryOfListsW::DictionaryOfListsW() { Size = 0; }

DictionaryOfListsW::~DictionaryOfListsW() {
	Clear();
}

void DictionaryOfListsW::SetCleanupRequiredInKeys(BOOL Required) {
	Keys.SetCleanUpRequired(Required);
}

void DictionaryOfListsW::SetCleanupRequiredInLists(BOOL Required) {
	LinkedList* List;
	for (int i = 0; i < GetNumOfKeys(); i++) {
		List = (LinkedList*)GetList(i);
		List->SetCleanUpRequired(Required);
	}
	CleanupRequiredInLists = Required;
}

void DictionaryOfListsW::Add(PWCHAR Key, LPVOID Value) {
	if (Keys.IsStringPresent(Key, true)) {
		int index = Keys.Find(Key, false, true);
		((LinkedList*)(ValueLists.GetElementP(index)))->Append(Value);
	}
	else {
		Size++;
		Keys.Append(Key);
		LinkedList* ValueList = new LinkedList();
		ValueList->Append(Value);
		ValueLists.Append(ValueList);
		ValueList->SetCleanUpRequired(CleanupRequiredInLists);
	}
}

void DictionaryOfListsW::RemoveList(PWCHAR Key) {
	INT index = Keys.Find(Key, false, true);
	if (index < 0) {
		return;
	}
	Keys.Remove(index);
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(index)));
	ValueList->Clear();
	ValueLists.Remove(index);
	Size--;
}

void DictionaryOfListsW::RemoveFromList(PWCHAR Key, int Index) {
	INT KeyIndex = Keys.Find(Key, false, true);
	if (KeyIndex < 0) {
		return;
	}
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(KeyIndex)));
	ValueList->Remove(Index);
}

LPVOID DictionaryOfListsW::GetList(PWCHAR Key) {
	INT KeyIndex = Keys.Find(Key, false, true);
	if (KeyIndex < 0) {
		return NULL;
	}
	return GetList(KeyIndex);
}

LPVOID DictionaryOfListsW::GetList(int Index) {
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(Index)));
	return ValueList;
}

LPVOID DictionaryOfListsW::GetElementP(PWCHAR Key, int Index) {
	INT KeyIndex = Keys.Find(Key, false, true);
	if (KeyIndex < 0) {
		return NULL;
	}
	LinkedList* ValueList = ((LinkedList*)(ValueLists.GetElementP(KeyIndex)));
	return ValueList->GetElementP(Index);
}

PWCHAR DictionaryOfListsW::GetKey(int Index) {
	return Keys.GetString(Index);
}

int DictionaryOfListsW::GetNumOfKeys() {
	return Size;
}

StringLinkedListW DictionaryOfListsW::GetKeys() {
	return Keys;
}

void DictionaryOfListsW::Clear() {
	LinkedList* List;
	for (int i = 0; i < GetNumOfKeys(); i++) {
		List = (LinkedList*)GetList(i);
		List->Clear();
	}
	Keys.Clear();
}