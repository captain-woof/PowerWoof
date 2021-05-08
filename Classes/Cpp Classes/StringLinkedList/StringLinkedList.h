#pragma once
#include <Windows.h>
#include <strsafe.h>

typedef struct _CharNode CharNode, * PCharNode;
typedef struct _WCharNode WCharNode, * PWCharNode;

class StringLinkedListA {
private:
    PCharNode Head, Rear, CurrentCharNodeP, TempCharNodeP;
    int Size, CurrentIndex;
    BOOL CleanUpElementsRequired;

public:
    void SetCleanUpRequired(BOOL CleanUpElements);
    StringLinkedListA();
    ~StringLinkedListA();
    BOOL IsIndexValid(int IndexToCheck);
    BOOL Append(PCHAR ElementP);
    BOOL Add(PCHAR ElementP, int IndexToAddAt);
    BOOL Remove(int IndexToDeleteAt);
    void Clear();
    BOOL IsStringPresent(PCHAR StringToCheck, BOOL IsCaseSensitive);
    BOOL IsSubstringPresent(PCHAR SubstringToCheck, BOOL IsCaseSensitive);
    INT Find(PCHAR StringToCheck, BOOL IsSubstring, BOOL IsCaseSensitive);
    PCHAR GetString(int TargetIndex);
    PCharNode GetCharNodeP(int TargetIndex);
    INT GetSize();
};

class StringLinkedListW {
private:
    PWCharNode Head, Rear, CurrentWCharNodeP, TempWCharNodeP;
    int Size, CurrentIndex;
    BOOL CleanUpElementsRequired;

public:
    void SetCleanUpRequired(BOOL CleanUpElements);
    StringLinkedListW();
    ~StringLinkedListW();
    BOOL IsIndexValid(int IndexToCheck);
    BOOL Append(PWCHAR ElementP);
    BOOL Add(PWCHAR ElementP, int IndexToAddAt);
    BOOL Remove(int IndexToDeleteAt);
    void Clear();
    BOOL IsStringPresent(PWCHAR StringToCheck, BOOL IsCaseSensitive);
    BOOL IsSubstringPresent(PWCHAR SubstringToCheck, BOOL IsCaseSensitive);
    INT Find(PWCHAR StringToCheck, BOOL IsSubstring, BOOL IsCaseSensitive);
    PWCHAR GetString(int TargetIndex);
    PWCharNode GetWCharNodeP(int TargetIndex);
    INT GetSize();
};

