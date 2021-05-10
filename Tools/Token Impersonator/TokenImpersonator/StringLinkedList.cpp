#include "StringLinkedList.h"

struct _CharNode {
    PCHAR ElementP;
    _CharNode* NextCharNodeP;
};

struct _WCharNode {
    PWCHAR ElementP;
    _WCharNode* NextWCharNodeP;
};

StringLinkedListA::StringLinkedListA() {
    Head = NULL;
    Rear = NULL;
    CurrentCharNodeP = NULL;
    TempCharNodeP = NULL;
    Size = 0;
    CurrentIndex = 0;
    CleanUpElementsRequired = true;
}

void StringLinkedListA::SetCleanUpRequired(BOOL CleanUpElements) {
    CleanUpElementsRequired = CleanUpElements;
}

BOOL StringLinkedListA::Remove(int IndexToDeleteAt) {
    if (IsIndexValid(IndexToDeleteAt)) {
        PCharNode PrecedingCharNode, ToRemoveCharNode;

        if (IndexToDeleteAt == 0) {
            ToRemoveCharNode = Head;
            Head = Head->NextCharNodeP;
        }
        else {
            PrecedingCharNode = GetCharNodeP(IndexToDeleteAt - 1);
            ToRemoveCharNode = PrecedingCharNode->NextCharNodeP;
            PrecedingCharNode->NextCharNodeP = PrecedingCharNode->NextCharNodeP->NextCharNodeP;
        }

        if (CleanUpElementsRequired) {
            delete [](ToRemoveCharNode->ElementP);
        }
        delete ToRemoveCharNode;
        Size--;
        return true;
    }
    else {
        return false;
    }
}

StringLinkedListA::~StringLinkedListA() {
    for (int i = 0; i < Size; i++) {
        TempCharNodeP = Head;
        Head = Head->NextCharNodeP;
        if (CleanUpElementsRequired) {
            delete [](TempCharNodeP->ElementP);
        }
        delete TempCharNodeP;
    }
}

INT StringLinkedListA::Find(PCHAR StringToCheck, BOOL IsSubstring, BOOL IsCaseSensitive) {
    if (Size == 0) {
        return -1;
    }
    
    INT result = -1;
    size_t StrLength1, StrLength2;
    PCHAR StringToMatchWith, Temp1, Temp2;
    for (int i = 0; i < Size; i++) {
        StringToMatchWith = GetString(i);
        if (!IsCaseSensitive) {      
            StringCchLengthA(StringToMatchWith, STRSAFE_MAX_CCH, &StrLength1);
            Temp1 = new CHAR[StrLength1];
            StringCchCopyA(Temp1, StrLength1, StringToMatchWith);
            _strlwr_s(Temp1, StrLength1);

            StringCchLengthA(StringToCheck, STRSAFE_MAX_CCH, &StrLength2);
            Temp2 = new CHAR[StrLength2];
            StringCchCopyA(Temp2, StrLength2, StringToCheck);
            _strlwr_s(Temp2, StrLength2);
        }
        else {
            Temp1 = StringToMatchWith;
            Temp2 = StringToCheck;
        }

        if (IsSubstring) {
            if (strstr(Temp1, Temp2) != NULL) {
                result = i;
            }
        }
        else {
            if (strcmp(Temp1, Temp2) == 0) {
                result = i;
            }
        }

        if (!IsCaseSensitive) { 
            delete []Temp1;
            delete []Temp2;
        }

        if (result != -1) {
            break;
        }
    }
    return result;
}


void StringLinkedListA::Clear() {
    if (GetSize() != 0) {
        while (GetSize() != 0) {
            Remove(GetSize() - 1);
        }
    }
}

BOOL StringLinkedListA::IsStringPresent(PCHAR StringToCheck, BOOL IsCaseSensitive) {
    if (Find(StringToCheck, false, IsCaseSensitive) != -1) {
        return true;
    }
    else {
        return false;
    }
}

BOOL StringLinkedListA::IsSubstringPresent(PCHAR SubstringToCheck, BOOL IsCaseSensitive) {
    if (Find(SubstringToCheck, true, IsCaseSensitive) != -1) {
        return true;
    }
    else {
        return false;
    }
}

BOOL StringLinkedListA::Append(PCHAR ElementP) {
    TempCharNodeP = new CharNode;
    if (TempCharNodeP == NULL) {
        return false;
    }

    TempCharNodeP->ElementP = ElementP;
    TempCharNodeP->NextCharNodeP = NULL;

    if (!Size) { // Empty list            
        Head = TempCharNodeP;
        Rear = TempCharNodeP;
        CurrentCharNodeP = TempCharNodeP;
    }
    else { // Non-empty list
        Rear->NextCharNodeP = TempCharNodeP;
        Rear = TempCharNodeP;
    }
    Size++;
    return true;
}

PCHAR StringLinkedListA::GetString(int TargetIndex) {
    if (IsIndexValid(TargetIndex)) {
        return (GetCharNodeP(TargetIndex))->ElementP;
    }
    else {
        return NULL;
    }
}

PCharNode StringLinkedListA::GetCharNodeP(int TargetIndex) {
    if (IsIndexValid(TargetIndex)) {
        if (CurrentIndex > TargetIndex) {
            CurrentIndex = 0;
            CurrentCharNodeP = Head;
        }
        for (int i = CurrentIndex; i < TargetIndex; i++, CurrentIndex++) {
            CurrentCharNodeP = CurrentCharNodeP->NextCharNodeP;
        }
        return CurrentCharNodeP;
    }
    else {
        return NULL;
    }
}

BOOL StringLinkedListA::Add(PCHAR ElementP, int IndexToAddAt) {
    if (IndexToAddAt == 0) {
        if (Append(ElementP)) {
            return true;
        }
        else {
            return false;
        }
    }

    if (IsIndexValid(IndexToAddAt)) {
        if (IndexToAddAt == Size - 1) {
            if (Append(ElementP)) {
                return true;
            }
            else {
                return false;
            }
        }
        else {
            TempCharNodeP = new CharNode;
            if (TempCharNodeP == NULL) {
                return false;
            }
            TempCharNodeP->ElementP = ElementP;

            if (IndexToAddAt == 0) {
                TempCharNodeP->NextCharNodeP = Head;
                Head = TempCharNodeP;
            }
            else {
                PCharNode PrecedingCharNode = GetCharNodeP(IndexToAddAt - 1);
                TempCharNodeP->NextCharNodeP = PrecedingCharNode->NextCharNodeP;
                PrecedingCharNode->NextCharNodeP = TempCharNodeP;
            }
            Size++;
            return true;
        }
    }
    else {
        return false;
    }
}

BOOL StringLinkedListA::IsIndexValid(int IndexToCheck) {
    if ((IndexToCheck >= Size) || (IndexToCheck < 0)) {
        return false;
    }
    else {
        return true;
    }
}

INT StringLinkedListA::GetSize() {
    return Size;
}

StringLinkedListW::StringLinkedListW() {
    Head = NULL;
    Rear = NULL;
    CurrentWCharNodeP = NULL;
    TempWCharNodeP = NULL;
    Size = 0;
    CurrentIndex = 0;
    CleanUpElementsRequired = true;
}

void StringLinkedListW::SetCleanUpRequired(BOOL CleanUpElements) {
    CleanUpElementsRequired = CleanUpElements;
}

BOOL StringLinkedListW::Remove(int IndexToDeleteAt) {
    if (IsIndexValid(IndexToDeleteAt)) {
        PWCharNode PrecedingWCharNode, ToRemoveWCharNode;

        if (IndexToDeleteAt == 0) {
            ToRemoveWCharNode = Head;
            Head = Head->NextWCharNodeP;
        }
        else {
            PrecedingWCharNode = GetWCharNodeP(IndexToDeleteAt - 1);
            ToRemoveWCharNode = PrecedingWCharNode->NextWCharNodeP;
            PrecedingWCharNode->NextWCharNodeP = PrecedingWCharNode->NextWCharNodeP->NextWCharNodeP;
        }

        if (CleanUpElementsRequired) {
            delete [](ToRemoveWCharNode->ElementP);
        }
        delete ToRemoveWCharNode;
        Size--;
        return true;
    }
    else {
        return false;
    }
}



StringLinkedListW::~StringLinkedListW() {
    for (int i = 0; i < Size; i++) {
        TempWCharNodeP = Head;
        Head = Head->NextWCharNodeP;
        if (CleanUpElementsRequired) {
            delete [](TempWCharNodeP->ElementP);
        }
        delete TempWCharNodeP;
    }
}

BOOL StringLinkedListW::Append(PWCHAR ElementP) {
    TempWCharNodeP = new WCharNode;
    if (TempWCharNodeP == NULL) {
        return false;
    }

    TempWCharNodeP->ElementP = ElementP;
    TempWCharNodeP->NextWCharNodeP = NULL;

    if (!Size) { // Empty list            
        Head = TempWCharNodeP;
        Rear = TempWCharNodeP;
        CurrentWCharNodeP = TempWCharNodeP;
    }
    else { // Non-empty list
        Rear->NextWCharNodeP = TempWCharNodeP;
        Rear = TempWCharNodeP;
    }
    Size++;
    return true;
}

PWCHAR StringLinkedListW::GetString(int TargetIndex) {
    if (IsIndexValid(TargetIndex)) {
        return (GetWCharNodeP(TargetIndex))->ElementP;
    }
    else {
        return NULL;
    }
}

PWCharNode StringLinkedListW::GetWCharNodeP(int TargetIndex) {
    if (IsIndexValid(TargetIndex)) {
        if (CurrentIndex > TargetIndex) {
            CurrentIndex = 0;
            CurrentWCharNodeP = Head;
        }
        for (int i = CurrentIndex; i < TargetIndex; i++, CurrentIndex++) {
            CurrentWCharNodeP = CurrentWCharNodeP->NextWCharNodeP;
        }
        return CurrentWCharNodeP;
    }
    else {
        return NULL;
    }
}

BOOL StringLinkedListW::Add(PWCHAR ElementP, int IndexToAddAt) {
    if (IndexToAddAt == 0) {
        if (Append(ElementP)) {
            return true;
        }
        else {
            return false;
        }
    }

    if (IsIndexValid(IndexToAddAt)) {
        if (IndexToAddAt == Size - 1) {
            if (Append(ElementP)) {
                return true;
            }
            else {
                return false;
            }
        }
        else {
            TempWCharNodeP = new WCharNode;
            if (TempWCharNodeP == NULL) {
                return false;
            }
            TempWCharNodeP->ElementP = ElementP;

            if (IndexToAddAt == 0) {
                TempWCharNodeP->NextWCharNodeP = Head;
                Head = TempWCharNodeP;
            }
            else {
                PWCharNode PrecedingWCharNode = GetWCharNodeP(IndexToAddAt - 1);
                TempWCharNodeP->NextWCharNodeP = PrecedingWCharNode->NextWCharNodeP;
                PrecedingWCharNode->NextWCharNodeP = TempWCharNodeP;
            }
            Size++;
            return true;
        }
    }
    else {
        return false;
    }
}

void StringLinkedListW::Clear() {
    if (GetSize() != 0) {
        while (GetSize() != 0) {
            Remove(GetSize() - 1);
        }
    }
}

INT StringLinkedListW::Find(PWCHAR StringToCheck, BOOL IsSubstring, BOOL IsCaseSensitive) {
    if (Size == 0) {
        return -1;
    }

    INT result = -1;
    size_t StrLength1, StrLength2;
    PWCHAR StringToMatchWith, Temp1, Temp2;
    for (int i = 0; i < Size; i++) {
        StringToMatchWith = GetString(i);
        if (!IsCaseSensitive) {
            StringCchLengthW(StringToMatchWith, STRSAFE_MAX_CCH, &StrLength1);
            Temp1 = new WCHAR[StrLength1];
            StringCchCopyW(Temp1, StrLength1, StringToMatchWith);
            _wcslwr_s(Temp1, StrLength1);

            StringCchLengthW(StringToCheck, STRSAFE_MAX_CCH, &StrLength2);
            Temp2 = new WCHAR[StrLength2];
            StringCchCopyW(Temp2, StrLength2, StringToCheck);
            _wcslwr_s(Temp2, StrLength2);
        }
        else {
            Temp1 = StringToMatchWith;
            Temp2 = StringToCheck;
        }

        if (IsSubstring) {
            if (wcsstr(Temp1, Temp2) != NULL) {
                result = i;
            }
        }
        else {
            if (wcscmp(Temp1, Temp2) == 0) {
                result = i;
            }
        }

        if (!IsCaseSensitive) {
            delete[]Temp1;
            delete[]Temp2;
        }

        if (result != -1) {
            break;
        }
    }
    return result;
}

BOOL StringLinkedListW::IsStringPresent(PWCHAR StringToCheck, BOOL IsCaseSensitive) {
    if (Find(StringToCheck, false, IsCaseSensitive) != -1) {
        return true;
    }
    else {
        return false;
    }
}

BOOL StringLinkedListW::IsSubstringPresent(PWCHAR SubstringToCheck, BOOL IsCaseSensitive) {
    if (Find(SubstringToCheck, true, IsCaseSensitive) != -1) {
        return true;
    }
    else {
        return false;
    }
}

BOOL StringLinkedListW::IsIndexValid(int IndexToCheck) {
    if ((IndexToCheck >= Size) || (IndexToCheck < 0)) {
        return false;
    }
    else {
        return true;
    }
}

INT StringLinkedListW::GetSize() {
    return Size;
}