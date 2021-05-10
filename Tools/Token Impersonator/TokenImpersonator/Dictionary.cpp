#include "Dictionary.h"

DictionaryA::DictionaryA() { Size = 0; }

// Append
BOOL DictionaryA::Add(PCHAR Key, LPVOID Value) {
	if (Keys.IsStringPresent(Key, true)) {
		return false;
	}

	if (Keys.Append(Key)) {
		if (Values.Append(Value)) {
			Size++;
			return true;
		}
		else {
			Keys.Remove(Keys.GetSize() - 1);
		}
	}
	return false;
}

// Delete
BOOL DictionaryA::Remove(PCHAR Key) {
	INT index = Keys.Find(Key, false, true);
	if (index < 0) {
		return false;
	}
	size_t CurrentKeySize = 0;
	StringCchLengthA(Keys.GetString(index), STRSAFE_MAX_CCH, &CurrentKeySize);
	PCHAR removed = new CHAR[CurrentKeySize + 1];
	StringCchCopyA(removed, CurrentKeySize + 1, Keys.GetString(index));

	if (Keys.Remove(index)) {
		if (Values.Remove(index)) {
			Size--;
			return true;
		}
		else {
			Keys.Add(removed, index);
		}
	}
	return false;
}

// Search (with key)
LPVOID DictionaryA::GetValue(PCHAR Key) {
	int index = Keys.Find(Key, false, true);
	if (index < 0) {
		return NULL;
	}
	return Values.GetElementP(index);
}

// Search (with index)
LPVOID DictionaryA::GetValue(int Index) {
	return Values.GetElementP(Index);
}

// Return key
PCHAR DictionaryA::GetKey(int Index) {
	return Keys.GetString(Index);
}

// GetSize
int DictionaryA::GetSize() {
	return Size;
}

// GetKeys
StringLinkedListA DictionaryA::GetKeys() {
	return Keys;
}

// GetValues
LinkedList DictionaryA::GetValues() {
	return Values;
}

// Clear
void DictionaryA::Clear() {
	Keys.Clear();
	Values.Clear();
}

DictionaryW::DictionaryW() { Size = 0; }

// Append
BOOL DictionaryW::Add(PWCHAR Key, LPVOID Value) {
	if (Keys.IsStringPresent(Key, true)) {
		return false;
	}

	if (Keys.Append(Key)) {
		if (Values.Append(Value)) {
			Size++;
			return true;
		}
		else {
			Keys.Remove(Keys.GetSize() - 1);
		}
	}
	return false;
}

// Delete
BOOL DictionaryW::Remove(PWCHAR Key) {
	INT index = Keys.Find(Key, false, true);
	if (index < 0) {
		return false;
	}
	size_t CurrentKeySize = 0;
	StringCchLengthW(Keys.GetString(index), STRSAFE_MAX_CCH, &CurrentKeySize);
	PWCHAR removed = new WCHAR[CurrentKeySize + 1];
	StringCchCopyW(removed, CurrentKeySize + 1, Keys.GetString(index));

	if (Keys.Remove(index)) {
		if (Values.Remove(index)) {
			Size--;
			return true;
		}
		else {
			Keys.Add(removed, index);
		}
	}
	return false;
}

// Search (with key)
LPVOID DictionaryW::GetValue(PWCHAR Key) {
	int index = Keys.Find(Key, false, true);
	if (index < 0) {
		return NULL;
	}
	return Values.GetElementP(index);
}

// Search (with index)
LPVOID DictionaryW::GetValue(int Index) {
	return Values.GetElementP(Index);
}

// Return key
PWCHAR DictionaryW::GetKey(int Index) {
	return Keys.GetString(Index);
}

// GetSize
int DictionaryW::GetSize() {
	return Size;
}

// GetKeys
StringLinkedListW DictionaryW::GetKeys() {
	return Keys;
}

// GetValues
LinkedList DictionaryW::GetValues() {
	return Values;
}

// Clear
void DictionaryW::Clear() {
	Keys.Clear();
	Values.Clear();
}