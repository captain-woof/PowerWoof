#pragma once
#include <Windows.h>

typedef struct _Node Node, * PNode;

class LinkedList {
private:
    PNode Head, Rear, CurrentNodeP, TempNodeP;
    int Size, CurrentIndex;
    BOOL CleanUpElementsRequired;   

public:
    void SetCleanUpRequired(BOOL CleanUpElements);
    LinkedList();
    ~LinkedList();
    BOOL IsIndexValid(int IndexToCheck);
    BOOL Append(LPVOID ElementP);
    BOOL Add(LPVOID ElementP, int IndexToAddAt);
    BOOL Remove(int IndexToDeleteAt);
    void Clear();
    LPVOID GetElementP(int TargetIndex);
    PNode GetNodeP(int TargetIndex);
    int GetSize();    
};